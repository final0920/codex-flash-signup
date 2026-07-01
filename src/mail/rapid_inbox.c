#include "mail/rapid_inbox.h"

#include "http_client/http_client.h"
#include "mail/outlook_pool.h"
#include "mongoose.h"

#include <ctype.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>

#define DEFAULT_BASE_URL "http://127.0.0.1:8000"
#define DEFAULT_OTPRELAY_BASE_URL "http://127.0.0.1:8080"
#define MAIL_BACKEND_RAPID_INBOX "rapid_inbox"
#define MAIL_BACKEND_RAPID_INBOX_HEAD "rapid_inbox_head"
#define MAIL_BACKEND_OTPRELAY "otprelay"
#define MAIL_BACKEND_TEMP_MAIL "temp_mail"
#define MAIL_TRANSPORT_HTTP "http"
#define MAIL_TRANSPORT_WS "ws"
#define OTPRELAY_WS_MAX_DOMAINS_JSON 4096
#define OTPRELAY_WS_MAX_URL 768
#define OTPRELAY_WS_CACHE_MAX 512
#define OTPRELAY_WS_ACK_QUEUE_MAX 1024
#define OTPRELAY_WS_RECONNECT_MS 5000ULL
#define OTPRELAY_WS_POLL_MS 100

struct domain_rule {
  char pattern[256];
  char base_domain[256];
  int wildcard_depth;
};

struct otprelay_ws_record {
  char mailbox[320];
  char code[64];
  char id[64];
  char claim_token[96];
  long received_at;
  uint64_t cached_ms;
};

struct otprelay_claimed_record {
  char code[64];
  char id[64];
  char claim_token[96];
  long received_at;
};

struct otprelay_ws_ack {
  char id[64];
  char claim_token[96];
  uint64_t queued_ms;
};

struct otprelay_ws_state {
  pthread_mutex_t mu;
  pthread_t thread;
  bool started;
  bool stop;
  bool connecting;
  bool connected;
  bool subscribed;
  bool poll_requested;
  unsigned generation;
  uint64_t last_poll_sent_ms;
  char base_url[512];
  char ws_url[OTPRELAY_WS_MAX_URL];
  char domains_json[OTPRELAY_WS_MAX_DOMAINS_JSON];
  char last_error[256];
  struct otprelay_ws_record cache[OTPRELAY_WS_CACHE_MAX];
  size_t cache_len;
  size_t cache_next;
  struct otprelay_ws_ack pending_acks[OTPRELAY_WS_ACK_QUEUE_MAX];
  size_t ack_head;
  size_t ack_len;
};

static struct otprelay_ws_state s_otprelay_ws = {
    .mu = PTHREAD_MUTEX_INITIALIZER,
};

static char *trim(char *s) {
  char *end;
  while (*s && isspace((unsigned char) *s)) s++;
  end = s + strlen(s);
  while (end > s && isspace((unsigned char) end[-1])) *--end = '\0';
  return s;
}

static void lower_copy(char *dst, size_t dstlen, const char *src) {
  size_t i = 0;
  if (dstlen == 0) return;
  for (; src != NULL && src[i] && i + 1 < dstlen; i++) {
    dst[i] = (char) tolower((unsigned char) src[i]);
  }
  dst[i] = '\0';
}

static bool valid_domain_label(const char *label, size_t len) {
  if (len == 0 || len > 63) return false;
  if (label[0] == '-' || label[len - 1] == '-') return false;
  for (size_t i = 0; i < len; i++) {
    unsigned char ch = (unsigned char) label[i];
    if (!isalnum(ch) && ch != '-') return false;
  }
  return true;
}

static bool validate_base_domain(const char *domain) {
  const char *p = domain;
  int labels = 0;
  if (domain == NULL || domain[0] == '\0' || strlen(domain) > 253) return false;
  while (*p) {
    const char *dot = strchr(p, '.');
    size_t len = dot == NULL ? strlen(p) : (size_t) (dot - p);
    if (!valid_domain_label(p, len)) return false;
    labels++;
    if (dot == NULL) break;
    p = dot + 1;
  }
  return labels >= 2;
}

static bool parse_domain_rule(const char *pattern, struct domain_rule *rule,
                              char *error, size_t error_len) {
  char buf[256], *p, *base;
  int wildcard_depth = 0;

  if (rule == NULL) return false;
  memset(rule, 0, sizeof(*rule));
  if (pattern == NULL) {
    mg_snprintf(error, error_len, "missing pattern");
    return false;
  }
  lower_copy(buf, sizeof(buf), pattern);
  p = trim(buf);
  if (*p == '\0') {
    mg_snprintf(error, error_len, "domain pattern is empty");
    return false;
  }

  while (strncmp(p, "*.", 2) == 0) {
    wildcard_depth++;
    p += 2;
  }
  if (strchr(p, '*') != NULL || p[0] == '.') {
    mg_snprintf(error, error_len, "wildcard must be leading labels");
    return false;
  }
  base = p;
  if (!validate_base_domain(base)) {
    mg_snprintf(error, error_len, "invalid domain");
    return false;
  }

  rule->wildcard_depth = wildcard_depth;
  mg_snprintf(rule->base_domain, sizeof(rule->base_domain), "%s", base);
  if (wildcard_depth > 0) {
    struct mg_iobuf io = {0, 0, 0, 64};
    for (int i = 0; i < wildcard_depth; i++) mg_xprintf(mg_pfn_iobuf, &io, "*.");
    mg_xprintf(mg_pfn_iobuf, &io, "%s", base);
    mg_iobuf_add(&io, io.len, "", 1);
    mg_snprintf(rule->pattern, sizeof(rule->pattern), "%s", (char *) io.buf);
    mg_iobuf_free(&io);
  } else {
    mg_snprintf(rule->pattern, sizeof(rule->pattern), "%s", base);
  }
  return true;
}

static char *copy_cstr(const char *s) {
  size_t len;
  char *copy;
  if (s == NULL) return NULL;
  len = strlen(s);
  copy = (char *) malloc(len + 1);
  if (copy == NULL) return NULL;
  memcpy(copy, s, len + 1);
  return copy;
}

static bool domain_rule_seen(const struct domain_rule *rules, size_t count,
                             const char *pattern) {
  if (rules == NULL || pattern == NULL) return false;
  for (size_t i = 0; i < count; i++) {
    if (strcmp(rules[i].pattern, pattern) == 0) return true;
  }
  return false;
}

static int append_domain_rule(struct domain_rule **rules, size_t *count,
                              size_t *cap, const struct domain_rule *rule) {
  struct domain_rule *next;
  if (rules == NULL || count == NULL || cap == NULL || rule == NULL) return -1;
  if (*count == *cap) {
    size_t next_cap = *cap == 0 ? 16 : *cap * 2;
    next = (struct domain_rule *) realloc(*rules, next_cap * sizeof(**rules));
    if (next == NULL) return -1;
    *rules = next;
    *cap = next_cap;
  }
  (*rules)[(*count)++] = *rule;
  return 0;
}

static void append_domain_import_error(struct mg_iobuf *io, bool *first,
                                       size_t index, const char *pattern,
                                       const char *error) {
  if (io == NULL || first == NULL) return;
  mg_xprintf(mg_pfn_iobuf, io, "%s{%m:%lu,%m:%m,%m:%m}",
             *first ? "" : ",", MG_ESC("index"), (unsigned long) index,
             MG_ESC("pattern"), MG_ESC(pattern ? pattern : ""),
             MG_ESC("error"), MG_ESC(error ? error : "invalid domain"));
  *first = false;
}

static int upsert_setting(sqlite3 *db, const char *key, const char *value) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "INSERT INTO mail_settings(key,value,updated_at) VALUES(?,?,unixepoch()) "
      "ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
      "updated_at=unixepoch()";
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
  sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, value ? value : "", -1, SQLITE_TRANSIENT);
  int rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  return rc == SQLITE_DONE ? 0 : -1;
}

static char *setting_value(sqlite3 *db, const char *key, const char *fallback) {
  sqlite3_stmt *stmt = NULL;
  char *value = NULL;
  if (sqlite3_prepare_v2(db, "SELECT value FROM mail_settings WHERE key=?", -1,
                         &stmt, NULL) != SQLITE_OK) {
    return strdup(fallback ? fallback : "");
  }
  sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *s = sqlite3_column_text(stmt, 0);
    value = strdup(s == NULL ? "" : (const char *) s);
  }
  sqlite3_finalize(stmt);
  if (value == NULL) value = strdup(fallback ? fallback : "");
  return value;
}

static bool string_is_one_of(const char *value, const char *a, const char *b) {
  return value != NULL &&
         ((a != NULL && strcmp(value, a) == 0) ||
          (b != NULL && strcmp(value, b) == 0));
}

static bool string_is_one_of3(const char *value, const char *a, const char *b,
                              const char *c) {
  return string_is_one_of(value, a, b) || (c != NULL && value != NULL &&
                                          strcmp(value, c) == 0);
}

static void normalize_backend(const char *value, char *out, size_t out_len) {
  char buf[64], *p;
  if (out_len == 0) return;
  mg_snprintf(buf, sizeof(buf), "%s", value != NULL ? value : "");
  p = trim(buf);
  for (char *c = p; *c != '\0'; c++) {
    if (*c == '-') *c = '_';
    *c = (char) tolower((unsigned char) *c);
  }
  if (string_is_one_of(p, MAIL_BACKEND_OTPRELAY, "rapid_inbox_c") ||
      strcmp(p, "otprelay_c") == 0 || strcmp(p, "c") == 0) {
    mg_snprintf(out, out_len, "%s", MAIL_BACKEND_OTPRELAY);
  } else if (string_is_one_of3(p, MAIL_BACKEND_TEMP_MAIL, "tempmail",
                               "cloudflare_temp_email") ||
             strcmp(p, "cloudflare_temp_mail") == 0) {
    mg_snprintf(out, out_len, "%s", MAIL_BACKEND_TEMP_MAIL);
  } else if (string_is_one_of3(p, MAIL_BACKEND_RAPID_INBOX_HEAD,
                               "rapid-inbox-head", "head") ||
             strcmp(p, "rapid_head") == 0) {
    mg_snprintf(out, out_len, "%s", MAIL_BACKEND_RAPID_INBOX_HEAD);
  } else {
    mg_snprintf(out, out_len, "%s", MAIL_BACKEND_RAPID_INBOX);
  }
}

static void normalize_transport(const char *value, char *out, size_t out_len) {
  char buf[32], *p;
  if (out_len == 0) return;
  mg_snprintf(buf, sizeof(buf), "%s", value != NULL ? value : "");
  p = trim(buf);
  for (char *c = p; *c != '\0'; c++) {
    *c = (char) tolower((unsigned char) *c);
  }
  if (strcmp(p, MAIL_TRANSPORT_WS) == 0 ||
      strcmp(p, "websocket") == 0 ||
      strcmp(p, "web_socket") == 0) {
    mg_snprintf(out, out_len, "%s", MAIL_TRANSPORT_WS);
  } else {
    mg_snprintf(out, out_len, "%s", MAIL_TRANSPORT_HTTP);
  }
}

static void read_mail_backend(sqlite3 *db, char *out, size_t out_len) {
  char *value = setting_value(db, "rapid_inbox_backend", MAIL_BACKEND_RAPID_INBOX);
  normalize_backend(value, out, out_len);
  free(value);
}

static void read_mail_transport(sqlite3 *db, char *out, size_t out_len) {
  char *value = setting_value(db, "rapid_inbox_transport", MAIL_TRANSPORT_HTTP);
  normalize_transport(value, out, out_len);
  free(value);
}

static void append_raw(char *out, size_t out_len, size_t *used,
                       const char *value) {
  size_t len;
  if (out == NULL || out_len == 0 || used == NULL || *used >= out_len) return;
  value = value != NULL ? value : "";
  len = strlen(value);
  if (len >= out_len - *used) len = out_len - *used - 1;
  memcpy(out + *used, value, len);
  *used += len;
  out[*used] = '\0';
}

static void append_json_string_buf(char *out, size_t out_len, size_t *used,
                                   const char *value) {
  append_raw(out, out_len, used, "\"");
  for (const unsigned char *p = (const unsigned char *) (value ? value : "");
       *p != '\0' && *used + 8 < out_len; p++) {
    char tmp[8];
    switch (*p) {
      case '"': append_raw(out, out_len, used, "\\\""); break;
      case '\\': append_raw(out, out_len, used, "\\\\"); break;
      case '\n': append_raw(out, out_len, used, "\\n"); break;
      case '\r': append_raw(out, out_len, used, "\\r"); break;
      case '\t': append_raw(out, out_len, used, "\\t"); break;
      default:
        if (*p >= 0x20 && *p <= 0x7e) {
          tmp[0] = (char) *p;
          tmp[1] = '\0';
          append_raw(out, out_len, used, tmp);
        } else {
          mg_snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
          append_raw(out, out_len, used, tmp);
        }
        break;
    }
  }
  append_raw(out, out_len, used, "\"");
}

static bool build_active_domain_array_json(sqlite3 *db, char *out,
                                           size_t out_len) {
  sqlite3_stmt *stmt = NULL;
  bool any = false;
  size_t used = 0;
  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (sqlite3_prepare_v2(db,
                         "SELECT DISTINCT base_domain FROM mail_domain_rules "
                         "WHERE is_active=1 AND base_domain<>'' "
                         "ORDER BY base_domain",
                         -1, &stmt, NULL) != SQLITE_OK) {
    return false;
  }
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *s = sqlite3_column_text(stmt, 0);
    const char *domain = s == NULL ? "" : (const char *) s;
    if (domain[0] == '\0') continue;
    if (any) append_raw(out, out_len, &used, ",");
    append_json_string_buf(out, out_len, &used, domain);
    any = true;
  }
  sqlite3_finalize(stmt);
  return any;
}

static bool build_otprelay_ws_url(const char *base_url, char *out,
                                  size_t out_len) {
  char base[512], *p;
  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  mg_snprintf(base, sizeof(base), "%s",
              base_url != NULL && base_url[0] != '\0'
                  ? base_url
                  : DEFAULT_OTPRELAY_BASE_URL);
  p = trim(base);
  while (strlen(p) > 1 && p[strlen(p) - 1] == '/') p[strlen(p) - 1] = '\0';
  if (strncmp(p, "https://", 8) == 0) {
    mg_snprintf(out, out_len, "wss://%s/api/v1/verification-codes/ws", p + 8);
  } else if (strncmp(p, "http://", 7) == 0) {
    mg_snprintf(out, out_len, "ws://%s/api/v1/verification-codes/ws", p + 7);
  } else if (strncmp(p, "ws://", 5) == 0 ||
             strncmp(p, "wss://", 6) == 0) {
    mg_snprintf(out, out_len, "%s", p);
  } else {
    mg_snprintf(out, out_len, "ws://%s/api/v1/verification-codes/ws", p);
  }
  return out[0] != '\0';
}

static void api_key_preview(const char *key, char *out, size_t outlen) {
  size_t len;
  if (outlen == 0) return;
  out[0] = '\0';
  if (key == NULL || key[0] == '\0') return;
  len = strlen(key);
  if (len <= 4) {
    mg_snprintf(out, outlen, "****");
  } else {
    mg_snprintf(out, outlen, "****%s", key + len - 4);
  }
}

static const char *column_text(sqlite3_stmt *stmt, int col) {
  const unsigned char *s = sqlite3_column_text(stmt, col);
  return s == NULL ? "" : (const char *) s;
}

static void otprelay_ws_set_error(const char *message) {
  pthread_mutex_lock(&s_otprelay_ws.mu);
  mg_snprintf(s_otprelay_ws.last_error, sizeof(s_otprelay_ws.last_error),
              "%s", message != NULL ? message : "");
  pthread_mutex_unlock(&s_otprelay_ws.mu);
}

static bool mailbox_equal(const char *a, const char *b) {
  return a != NULL && b != NULL && strcasecmp(a, b) == 0;
}

static void otprelay_ws_cache_add(const char *mailbox, const char *code,
                                  const char *id, const char *claim_token,
                                  long received_at) {
  struct otprelay_ws_record *record;
  if (mailbox == NULL || mailbox[0] == '\0' || code == NULL ||
      code[0] == '\0') {
    return;
  }
  pthread_mutex_lock(&s_otprelay_ws.mu);
  record = &s_otprelay_ws.cache[s_otprelay_ws.cache_next];
  memset(record, 0, sizeof(*record));
  mg_snprintf(record->mailbox, sizeof(record->mailbox), "%s", mailbox);
  mg_snprintf(record->code, sizeof(record->code), "%s", code);
  mg_snprintf(record->id, sizeof(record->id), "%s", id != NULL ? id : "");
  mg_snprintf(record->claim_token, sizeof(record->claim_token), "%s",
              claim_token != NULL ? claim_token : "");
  record->received_at = received_at;
  record->cached_ms = mg_millis();
  s_otprelay_ws.cache_next =
      (s_otprelay_ws.cache_next + 1) % OTPRELAY_WS_CACHE_MAX;
  if (s_otprelay_ws.cache_len < OTPRELAY_WS_CACHE_MAX) {
    s_otprelay_ws.cache_len++;
  }
  pthread_mutex_unlock(&s_otprelay_ws.mu);
}

static size_t otprelay_ws_cache_count_locked(void) {
  size_t count = 0;
  for (size_t i = 0; i < OTPRELAY_WS_CACHE_MAX; i++) {
    if (s_otprelay_ws.cache[i].code[0] != '\0') count++;
  }
  return count;
}

static void otprelay_ws_clear_pending_acks_locked(void) {
  memset(s_otprelay_ws.pending_acks, 0, sizeof(s_otprelay_ws.pending_acks));
  s_otprelay_ws.ack_head = 0;
  s_otprelay_ws.ack_len = 0;
}

static bool otprelay_ws_enqueue_ack_locked(const char *id,
                                           const char *claim_token) {
  size_t index;
  if (id == NULL || id[0] == '\0' || claim_token == NULL ||
      claim_token[0] == '\0') {
    return false;
  }
  for (size_t i = 0; i < s_otprelay_ws.ack_len; i++) {
    index = (s_otprelay_ws.ack_head + i) % OTPRELAY_WS_ACK_QUEUE_MAX;
    if (strcmp(s_otprelay_ws.pending_acks[index].id, id) == 0) {
      return true;
    }
  }
  if (s_otprelay_ws.ack_len == OTPRELAY_WS_ACK_QUEUE_MAX) {
    memset(&s_otprelay_ws.pending_acks[s_otprelay_ws.ack_head], 0,
           sizeof(s_otprelay_ws.pending_acks[s_otprelay_ws.ack_head]));
    s_otprelay_ws.ack_head =
        (s_otprelay_ws.ack_head + 1) % OTPRELAY_WS_ACK_QUEUE_MAX;
    s_otprelay_ws.ack_len--;
    mg_snprintf(s_otprelay_ws.last_error, sizeof(s_otprelay_ws.last_error),
                "%s", "OTPRelay WS ACK 队列已满，已丢弃最旧 ACK");
  }
  index = (s_otprelay_ws.ack_head + s_otprelay_ws.ack_len) %
          OTPRELAY_WS_ACK_QUEUE_MAX;
  memset(&s_otprelay_ws.pending_acks[index], 0,
         sizeof(s_otprelay_ws.pending_acks[index]));
  mg_snprintf(s_otprelay_ws.pending_acks[index].id,
              sizeof(s_otprelay_ws.pending_acks[index].id), "%s", id);
  mg_snprintf(s_otprelay_ws.pending_acks[index].claim_token,
              sizeof(s_otprelay_ws.pending_acks[index].claim_token), "%s",
              claim_token);
  s_otprelay_ws.pending_acks[index].queued_ms = mg_millis();
  s_otprelay_ws.ack_len++;
  return true;
}

static bool otprelay_ws_enqueue_ack(const char *id, const char *claim_token) {
  bool queued;
  pthread_mutex_lock(&s_otprelay_ws.mu);
  queued = otprelay_ws_enqueue_ack_locked(id, claim_token);
  pthread_mutex_unlock(&s_otprelay_ws.mu);
  return queued;
}

static bool otprelay_ws_dequeue_ack(struct otprelay_ws_ack *out) {
  bool ok = false;
  if (out == NULL) return false;
  memset(out, 0, sizeof(*out));
  pthread_mutex_lock(&s_otprelay_ws.mu);
  if (s_otprelay_ws.ack_len > 0) {
    *out = s_otprelay_ws.pending_acks[s_otprelay_ws.ack_head];
    memset(&s_otprelay_ws.pending_acks[s_otprelay_ws.ack_head], 0,
           sizeof(s_otprelay_ws.pending_acks[s_otprelay_ws.ack_head]));
    s_otprelay_ws.ack_head =
        (s_otprelay_ws.ack_head + 1) % OTPRELAY_WS_ACK_QUEUE_MAX;
    s_otprelay_ws.ack_len--;
    ok = true;
  }
  pthread_mutex_unlock(&s_otprelay_ws.mu);
  return ok;
}

static void otprelay_ws_flush_pending_acks(struct mg_connection *conn) {
  struct otprelay_ws_ack ack;
  if (conn == NULL || !conn->is_websocket || conn->is_closing) return;
  while (otprelay_ws_dequeue_ack(&ack)) {
    mg_ws_printf(conn, WEBSOCKET_OP_TEXT, "{%m:%m,%m:%m,%m:%m}",
                 MG_ESC("type"), MG_ESC("ack"),
                 MG_ESC("id"), MG_ESC(ack.id),
                 MG_ESC("claim_token"), MG_ESC(ack.claim_token));
  }
}

static void otprelay_ws_request_poll(void) {
  pthread_mutex_lock(&s_otprelay_ws.mu);
  s_otprelay_ws.poll_requested = true;
  pthread_mutex_unlock(&s_otprelay_ws.mu);
}

static void otprelay_ws_flush_poll_request(struct mg_connection *conn,
                                           uint64_t now) {
  bool send_poll = false;
  if (conn == NULL || !conn->is_websocket || conn->is_closing) return;
  pthread_mutex_lock(&s_otprelay_ws.mu);
  if (s_otprelay_ws.poll_requested &&
      (s_otprelay_ws.last_poll_sent_ms == 0 ||
       now - s_otprelay_ws.last_poll_sent_ms >= OTPRELAY_WS_POLL_MS)) {
    s_otprelay_ws.poll_requested = false;
    s_otprelay_ws.last_poll_sent_ms = now;
    send_poll = true;
  }
  pthread_mutex_unlock(&s_otprelay_ws.mu);
  if (send_poll) {
    mg_ws_printf(conn, WEBSOCKET_OP_TEXT, "{%m:%m}",
                 MG_ESC("type"), MG_ESC("poll"));
  }
}

static bool otprelay_ws_cache_take(const char *mailbox, long min_received_at,
                                   struct otprelay_claimed_record *out) {
  size_t best = OTPRELAY_WS_CACHE_MAX;
  long best_received = 0;
  if (mailbox == NULL || out == NULL) return false;
  memset(out, 0, sizeof(*out));
  pthread_mutex_lock(&s_otprelay_ws.mu);
  for (size_t i = 0; i < s_otprelay_ws.cache_len; i++) {
    struct otprelay_ws_record *record = &s_otprelay_ws.cache[i];
    if (!mailbox_equal(record->mailbox, mailbox) || record->code[0] == '\0') {
      continue;
    }
    if (min_received_at > 0 && record->received_at > 0 &&
        record->received_at + 10 < min_received_at) {
      otprelay_ws_enqueue_ack_locked(record->id, record->claim_token);
      memset(record, 0, sizeof(*record));
      continue;
    }
    if (best == OTPRELAY_WS_CACHE_MAX ||
        record->received_at >= best_received) {
      best = i;
      best_received = record->received_at;
    }
  }
  if (best != OTPRELAY_WS_CACHE_MAX) {
    struct otprelay_ws_record *record = &s_otprelay_ws.cache[best];
    mg_snprintf(out->code, sizeof(out->code), "%s", record->code);
    mg_snprintf(out->id, sizeof(out->id), "%s", record->id);
    mg_snprintf(out->claim_token, sizeof(out->claim_token), "%s",
                record->claim_token);
    out->received_at = record->received_at;
    memset(record, 0, sizeof(*record));
  }
  pthread_mutex_unlock(&s_otprelay_ws.mu);
  return best != OTPRELAY_WS_CACHE_MAX;
}

static void otprelay_ws_handle_record(struct mg_str data) {
  char *mailbox = mg_json_get_str(data, "$.record.mailbox");
  char *code = mg_json_get_str(data, "$.record.verification_code");
  char *id = mg_json_get_str(data, "$.record.id");
  char *claim_token = mg_json_get_str(data, "$.record.claim_token");
  long received_ms = mg_json_get_long(data, "$.record.received_ms", 0);
  otprelay_ws_cache_add(mailbox, code, id, claim_token,
                        received_ms > 0 ? received_ms / 1000 : 0);
  mg_free(mailbox);
  mg_free(code);
  mg_free(id);
  mg_free(claim_token);
}

static void otprelay_ws_handler(struct mg_connection *c, int ev,
                                void *ev_data) {
  if (ev == MG_EV_ERROR) {
    otprelay_ws_set_error((const char *) ev_data);
  } else if (ev == MG_EV_WS_OPEN) {
    char domains[OTPRELAY_WS_MAX_DOMAINS_JSON];
    char message[OTPRELAY_WS_MAX_DOMAINS_JSON + 64];
    pthread_mutex_lock(&s_otprelay_ws.mu);
    s_otprelay_ws.connecting = false;
    s_otprelay_ws.connected = true;
    s_otprelay_ws.subscribed = false;
    mg_snprintf(domains, sizeof(domains), "%s", s_otprelay_ws.domains_json);
    s_otprelay_ws.last_error[0] = '\0';
    pthread_mutex_unlock(&s_otprelay_ws.mu);
    if (domains[0] == '\0') {
      c->is_closing = 1;
      return;
    }
    mg_snprintf(message, sizeof(message),
                "{\"type\":\"subscribe\",\"domains\":[%s]}", domains);
    mg_ws_send(c, message, strlen(message), WEBSOCKET_OP_TEXT);
  } else if (ev == MG_EV_WS_MSG) {
    struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
    char *type = mg_json_get_str(wm->data, "$.type");
    if (type != NULL && strcmp(type, "verification") == 0) {
      otprelay_ws_handle_record(wm->data);
    } else if (type != NULL && strcmp(type, "subscribed") == 0) {
      pthread_mutex_lock(&s_otprelay_ws.mu);
      s_otprelay_ws.subscribed = true;
      s_otprelay_ws.last_error[0] = '\0';
      pthread_mutex_unlock(&s_otprelay_ws.mu);
    } else if (type != NULL && strcmp(type, "error") == 0) {
      char *error = mg_json_get_str(wm->data, "$.error");
      if (error == NULL) error = mg_json_get_str(wm->data, "$.message");
      otprelay_ws_set_error(error != NULL ? error : "OTPRelay WebSocket error");
      mg_free(error);
    }
    mg_free(type);
  } else if (ev == MG_EV_CLOSE) {
    pthread_mutex_lock(&s_otprelay_ws.mu);
    s_otprelay_ws.connecting = false;
    s_otprelay_ws.connected = false;
    s_otprelay_ws.subscribed = false;
    pthread_mutex_unlock(&s_otprelay_ws.mu);
  }
}

static void *otprelay_ws_thread_main(void *arg) {
  struct mg_mgr mgr;
  struct mg_connection *conn = NULL;
  unsigned active_generation = 0;
  uint64_t next_reconnect_ms = 0;
  (void) arg;

  mg_mgr_init(&mgr);
  for (;;) {
    bool stop, connecting, connected, subscribed;
    unsigned generation;
    char ws_url[OTPRELAY_WS_MAX_URL];
    char domains_json[OTPRELAY_WS_MAX_DOMAINS_JSON];
    uint64_t now = mg_millis();

    pthread_mutex_lock(&s_otprelay_ws.mu);
    stop = s_otprelay_ws.stop;
    connecting = s_otprelay_ws.connecting;
    connected = s_otprelay_ws.connected;
    subscribed = s_otprelay_ws.subscribed;
    generation = s_otprelay_ws.generation;
    mg_snprintf(ws_url, sizeof(ws_url), "%s", s_otprelay_ws.ws_url);
    mg_snprintf(domains_json, sizeof(domains_json), "%s",
                s_otprelay_ws.domains_json);
    pthread_mutex_unlock(&s_otprelay_ws.mu);

    if (stop) break;
    if (!connecting && !connected && conn != NULL) {
      conn = NULL;
      next_reconnect_ms = now + OTPRELAY_WS_RECONNECT_MS;
    }
    if (active_generation != generation) {
      if (conn != NULL && (connecting || connected)) conn->is_closing = 1;
      conn = NULL;
      active_generation = generation;
      next_reconnect_ms = 0;
      pthread_mutex_lock(&s_otprelay_ws.mu);
      s_otprelay_ws.connecting = false;
      s_otprelay_ws.connected = false;
      s_otprelay_ws.subscribed = false;
      s_otprelay_ws.poll_requested = false;
      pthread_mutex_unlock(&s_otprelay_ws.mu);
      connecting = false;
      connected = false;
      subscribed = false;
    }

    if (ws_url[0] != '\0' && domains_json[0] != '\0' &&
        !connecting && !connected && now >= next_reconnect_ms) {
      conn = mg_ws_connect(&mgr, ws_url, otprelay_ws_handler, NULL, NULL);
      if (conn == NULL) {
        otprelay_ws_set_error("OTPRelay WebSocket connect failed");
        next_reconnect_ms = now + OTPRELAY_WS_RECONNECT_MS;
      } else {
        pthread_mutex_lock(&s_otprelay_ws.mu);
        s_otprelay_ws.connecting = true;
        s_otprelay_ws.connected = false;
        s_otprelay_ws.subscribed = false;
        s_otprelay_ws.poll_requested = false;
        s_otprelay_ws.last_error[0] = '\0';
        pthread_mutex_unlock(&s_otprelay_ws.mu);
        active_generation = generation;
      }
    }

    if (connected && conn != NULL) {
      otprelay_ws_flush_pending_acks(conn);
      if (subscribed) otprelay_ws_flush_poll_request(conn, now);
    }
    mg_mgr_poll(&mgr, OTPRELAY_WS_POLL_MS);
  }

  if (conn != NULL) {
    conn->is_closing = 1;
    mg_mgr_poll(&mgr, 0);
  }
  mg_mgr_free(&mgr);

  pthread_mutex_lock(&s_otprelay_ws.mu);
  s_otprelay_ws.started = false;
  s_otprelay_ws.stop = false;
  s_otprelay_ws.connecting = false;
  s_otprelay_ws.connected = false;
  s_otprelay_ws.subscribed = false;
  s_otprelay_ws.poll_requested = false;
  pthread_mutex_unlock(&s_otprelay_ws.mu);
  return NULL;
}

static int otprelay_ws_update(sqlite3 *db, const char *base_url) {
  char domains_json[OTPRELAY_WS_MAX_DOMAINS_JSON];
  char ws_url[OTPRELAY_WS_MAX_URL];
  bool has_domains;
  bool create_thread = false;

  if (!build_otprelay_ws_url(base_url, ws_url, sizeof(ws_url))) return -1;
  has_domains = build_active_domain_array_json(db, domains_json,
                                               sizeof(domains_json));

  pthread_mutex_lock(&s_otprelay_ws.mu);
  if (strcmp(s_otprelay_ws.base_url, base_url ? base_url : "") != 0 ||
      strcmp(s_otprelay_ws.ws_url, ws_url) != 0 ||
      strcmp(s_otprelay_ws.domains_json, domains_json) != 0) {
    mg_snprintf(s_otprelay_ws.base_url, sizeof(s_otprelay_ws.base_url), "%s",
                base_url != NULL ? base_url : "");
    mg_snprintf(s_otprelay_ws.ws_url, sizeof(s_otprelay_ws.ws_url), "%s",
                ws_url);
    mg_snprintf(s_otprelay_ws.domains_json,
                sizeof(s_otprelay_ws.domains_json), "%s", domains_json);
    s_otprelay_ws.generation++;
    otprelay_ws_clear_pending_acks_locked();
    s_otprelay_ws.poll_requested = false;
    s_otprelay_ws.last_poll_sent_ms = 0;
  }
  s_otprelay_ws.stop = false;
  if (!s_otprelay_ws.started && has_domains) {
    s_otprelay_ws.started = true;
    create_thread = true;
  }
  if (!has_domains) {
    mg_snprintf(s_otprelay_ws.last_error, sizeof(s_otprelay_ws.last_error),
                "%s", "OTPRelay WS 没有可订阅域名");
  }
  pthread_mutex_unlock(&s_otprelay_ws.mu);

  if (create_thread &&
      pthread_create(&s_otprelay_ws.thread, NULL, otprelay_ws_thread_main,
                     NULL) != 0) {
    pthread_mutex_lock(&s_otprelay_ws.mu);
    s_otprelay_ws.started = false;
    mg_snprintf(s_otprelay_ws.last_error, sizeof(s_otprelay_ws.last_error),
                "%s", "OTPRelay WebSocket thread create failed");
    pthread_mutex_unlock(&s_otprelay_ws.mu);
    return -1;
  }
  return has_domains ? 0 : -1;
}

static void otprelay_ws_stop(void) {
  pthread_t thread;
  bool join = false;
  pthread_mutex_lock(&s_otprelay_ws.mu);
  if (s_otprelay_ws.started) {
    s_otprelay_ws.stop = true;
    thread = s_otprelay_ws.thread;
    join = true;
  }
  otprelay_ws_clear_pending_acks_locked();
  s_otprelay_ws.poll_requested = false;
  pthread_mutex_unlock(&s_otprelay_ws.mu);
  if (join) pthread_join(thread, NULL);
}

static void append_domain_rules(sqlite3 *db, struct mg_iobuf *io) {
  sqlite3_stmt *stmt = NULL;
  bool first = true;
  const char *sql =
      "SELECT id,pattern,base_domain,wildcard_depth,is_active,created_at,"
      "updated_at FROM mail_domain_rules ORDER BY id DESC";

  mg_xprintf(mg_pfn_iobuf, io, "[");
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      if (!first) mg_xprintf(mg_pfn_iobuf, io, ",");
      first = false;
      mg_xprintf(mg_pfn_iobuf, io,
                 "{%m:%lld,%m:%m,%m:%m,%m:%d,%m:%d,%m:%lld,%m:%lld}",
                 MG_ESC("id"), sqlite3_column_int64(stmt, 0),
                 MG_ESC("pattern"), MG_ESC(column_text(stmt, 1)),
                 MG_ESC("base_domain"), MG_ESC(column_text(stmt, 2)),
                 MG_ESC("wildcard_depth"), sqlite3_column_int(stmt, 3),
                 MG_ESC("is_active"), sqlite3_column_int(stmt, 4),
                 MG_ESC("created_at"), sqlite3_column_int64(stmt, 5),
                 MG_ESC("updated_at"), sqlite3_column_int64(stmt, 6));
    }
  }
  sqlite3_finalize(stmt);
  mg_xprintf(mg_pfn_iobuf, io, "]");
}

char *rapid_inbox_config_json(sqlite3 *db) {
  char backend[32];
  char transport[16];
  char ws_url[OTPRELAY_WS_MAX_URL];
  bool ws_started, ws_connected, ws_subscribed;
  size_t ws_cached_records;
  size_t ws_pending_acks;
  char ws_last_error[256];
  read_mail_backend(db, backend, sizeof(backend));
  read_mail_transport(db, transport, sizeof(transport));
  char *base_url = setting_value(
      db, "rapid_inbox_base_url",
      strcmp(backend, MAIL_BACKEND_OTPRELAY) == 0 ? DEFAULT_OTPRELAY_BASE_URL
                                                  : DEFAULT_BASE_URL);
  char *api_key = setting_value(db, "rapid_inbox_api_key", "");
  char preview[32];
  struct mg_iobuf io = {0, 0, 0, 512};

  build_otprelay_ws_url(base_url, ws_url, sizeof(ws_url));
  api_key_preview(api_key, preview, sizeof(preview));
  pthread_mutex_lock(&s_otprelay_ws.mu);
  ws_started = s_otprelay_ws.started;
  ws_connected = s_otprelay_ws.connected;
  ws_subscribed = s_otprelay_ws.subscribed;
  ws_cached_records = otprelay_ws_cache_count_locked();
  ws_pending_acks = s_otprelay_ws.ack_len;
  mg_snprintf(ws_last_error, sizeof(ws_last_error), "%s",
              s_otprelay_ws.last_error);
  pthread_mutex_unlock(&s_otprelay_ws.mu);
  mg_xprintf(mg_pfn_iobuf, &io,
             "{%m:%m,%m:%m,%m:%m,%m:%d,%m:%m,%m:%m,%m:%d,%m:%d,%m:%d,%m:%lu,%m:%lu,%m:%m,%m:",
             MG_ESC("backend"), MG_ESC(backend),
             MG_ESC("transport"), MG_ESC(transport),
             MG_ESC("base_url"), MG_ESC(base_url ? base_url : DEFAULT_BASE_URL),
             MG_ESC("has_api_key"), api_key != NULL && api_key[0] != '\0',
             MG_ESC("api_key_preview"), MG_ESC(preview),
             MG_ESC("ws_url"), MG_ESC(ws_url),
             MG_ESC("ws_started"), ws_started,
             MG_ESC("ws_connected"), ws_connected,
             MG_ESC("ws_subscribed"), ws_subscribed,
             MG_ESC("ws_cached_records"), (unsigned long) ws_cached_records,
             MG_ESC("ws_pending_acks"), (unsigned long) ws_pending_acks,
             MG_ESC("ws_last_error"), MG_ESC(ws_last_error),
             MG_ESC("domains"));
  append_domain_rules(db, &io);
  mg_xprintf(mg_pfn_iobuf, &io, "}");
  mg_iobuf_add(&io, io.len, "", 1);
  free(base_url);
  free(api_key);
  return (char *) io.buf;
}

int rapid_inbox_save_config(sqlite3 *db, const char *base_url,
                            const char *api_key, const char *backend,
                            const char *transport) {
  char base_buf[512], key_buf[1024], backend_buf[32], transport_buf[16];
  char *base, *key;
  int rc = 0;
  normalize_backend(backend, backend_buf, sizeof(backend_buf));
  normalize_transport(transport, transport_buf, sizeof(transport_buf));
  mg_snprintf(base_buf, sizeof(base_buf), "%s",
              base_url != NULL && base_url[0] != '\0'
                  ? base_url
                  : (strcmp(backend_buf, MAIL_BACKEND_OTPRELAY) == 0
                         ? DEFAULT_OTPRELAY_BASE_URL
                         : DEFAULT_BASE_URL));
  base = trim(base_buf);
  while (strlen(base) > 1 && base[strlen(base) - 1] == '/') {
    base[strlen(base) - 1] = '\0';
  }
  sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
  if (upsert_setting(db, "rapid_inbox_base_url", base) != 0) rc = -1;
  if (rc == 0 &&
      upsert_setting(db, "rapid_inbox_backend", backend_buf) != 0) rc = -1;
  if (rc == 0 &&
      upsert_setting(db, "rapid_inbox_transport", transport_buf) != 0) rc = -1;
  if (rc == 0 && api_key != NULL) {
    mg_snprintf(key_buf, sizeof(key_buf), "%s", api_key);
    key = trim(key_buf);
    if (upsert_setting(db, "rapid_inbox_api_key", key) != 0) rc = -1;
  }
  sqlite3_exec(db, rc == 0 ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
  if (rc == 0) rapid_inbox_start_configured(db);
  return rc;
}

int rapid_inbox_start_configured(sqlite3 *db) {
  char backend[32];
  char transport[16];
  char *base_url;
  int rc = 0;
  read_mail_backend(db, backend, sizeof(backend));
  read_mail_transport(db, transport, sizeof(transport));
  if (strcmp(backend, MAIL_BACKEND_OTPRELAY) != 0 ||
      strcmp(transport, MAIL_TRANSPORT_WS) != 0) {
    otprelay_ws_stop();
    return 0;
  }
  base_url = setting_value(db, "rapid_inbox_base_url",
                           DEFAULT_OTPRELAY_BASE_URL);
  rc = otprelay_ws_update(db, base_url);
  free(base_url);
  return rc;
}

void rapid_inbox_shutdown(void) {
  otprelay_ws_stop();
}

char *rapid_inbox_add_domain_json(sqlite3 *db, const char *pattern) {
  struct domain_rule rule;
  sqlite3_stmt *stmt = NULL;
  char error[160] = "";
  struct mg_iobuf io = {0, 0, 0, 256};
  int rc;

  if (!parse_domain_rule(pattern, &rule, error, sizeof(error))) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC(error));
    mg_iobuf_add(&io, io.len, "", 1);
    return (char *) io.buf;
  }

  const char *sql =
      "INSERT INTO mail_domain_rules(pattern,base_domain,wildcard_depth,"
      "is_active,created_at,updated_at) VALUES(?,?,?,1,unixepoch(),unixepoch()) "
      "ON CONFLICT(pattern) DO UPDATE SET is_active=1,base_domain=excluded.base_domain,"
      "wildcard_depth=excluded.wildcard_depth,updated_at=unixepoch()";
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC(sqlite3_errmsg(db)));
    mg_iobuf_add(&io, io.len, "", 1);
    return (char *) io.buf;
  }
  sqlite3_bind_text(stmt, 1, rule.pattern, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, rule.base_domain, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, rule.wildcard_depth);
  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc == SQLITE_DONE) {
    rapid_inbox_start_configured(db);
    mg_xprintf(mg_pfn_iobuf, &io,
               "{%m:%d,%m:%m,%m:%m,%m:%d}",
               MG_ESC("ok"), 1,
               MG_ESC("pattern"), MG_ESC(rule.pattern),
               MG_ESC("base_domain"), MG_ESC(rule.base_domain),
               MG_ESC("wildcard_depth"), rule.wildcard_depth);
  } else {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC(sqlite3_errmsg(db)));
  }
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

char *rapid_inbox_add_domains_json(sqlite3 *db, const char *text) {
  struct domain_rule *rules = NULL;
  size_t rule_count = 0, rule_cap = 0;
  size_t total_count = 0, saved_count = 0, invalid_count = 0, duplicate_count = 0;
  sqlite3_stmt *stmt = NULL;
  char *copy = NULL;
  char *cursor;
  struct mg_iobuf errors = {0, 0, 0, 512};
  struct mg_iobuf io = {0, 0, 0, 512};
  bool first_error = true;
  int rc = 0;
  char db_error[256] = "";
  const char *sql =
      "INSERT INTO mail_domain_rules(pattern,base_domain,wildcard_depth,"
      "is_active,created_at,updated_at) VALUES(?,?,?,1,unixepoch(),unixepoch()) "
      "ON CONFLICT(pattern) DO UPDATE SET is_active=1,base_domain=excluded.base_domain,"
      "wildcard_depth=excluded.wildcard_depth,updated_at=unixepoch()";

  mg_xprintf(mg_pfn_iobuf, &errors, "[");
  if (db == NULL) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC("数据库不可用"));
    goto done;
  }
  copy = copy_cstr(text);
  if (copy == NULL || trim(copy)[0] == '\0') {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"),
               MG_ESC("请粘贴至少一个域名规则"));
    goto done;
  }

  cursor = copy;
  while (cursor != NULL) {
    struct domain_rule rule;
    char error[160] = "";
    char *next = strpbrk(cursor, "\r\n,;");
    char *token;
    if (next != NULL) {
      *next++ = '\0';
    }
    token = trim(cursor);
    if (token[0] != '\0') {
      total_count++;
      if (!parse_domain_rule(token, &rule, error, sizeof(error))) {
        invalid_count++;
        append_domain_import_error(&errors, &first_error, total_count, token,
                                   error);
      } else if (domain_rule_seen(rules, rule_count, rule.pattern)) {
        duplicate_count++;
      } else if (append_domain_rule(&rules, &rule_count, &rule_cap,
                                    &rule) != 0) {
        mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
                   MG_ESC("ok"), 0, MG_ESC("error"),
                   MG_ESC("内存不足，无法导入域名规则"));
        goto done;
      }
    }
    cursor = next;
  }

  if (total_count == 0) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"),
               MG_ESC("请粘贴至少一个域名规则"));
    goto done;
  }
  if (rule_count == 0) {
    mg_xprintf(mg_pfn_iobuf, &errors, "]");
    mg_iobuf_add(&errors, errors.len, "", 1);
    mg_xprintf(mg_pfn_iobuf, &io,
               "{%m:%d,%m:%m,%m:%lu,%m:%lu,%m:%lu,%m:%lu,%m:%s}",
               MG_ESC("ok"), 0, MG_ESC("error"),
               MG_ESC("没有可导入的有效域名规则"),
               MG_ESC("total_count"), (unsigned long) total_count,
               MG_ESC("saved_count"), (unsigned long) saved_count,
               MG_ESC("invalid_count"), (unsigned long) invalid_count,
               MG_ESC("duplicate_count"), (unsigned long) duplicate_count,
               MG_ESC("errors"), errors.buf ? (char *) errors.buf : "[]");
    goto done;
  }

  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC(sqlite3_errmsg(db)));
    goto done;
  }
  if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC(sqlite3_errmsg(db)));
    goto done;
  }
  for (size_t i = 0; i < rule_count; i++) {
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_text(stmt, 1, rules[i].pattern, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rules[i].base_domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, rules[i].wildcard_depth);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
      mg_snprintf(db_error, sizeof(db_error), "%s", sqlite3_errmsg(db));
      rc = -1;
      break;
    }
    saved_count++;
  }
  if (sqlite3_exec(db, rc == 0 ? "COMMIT" : "ROLLBACK", NULL, NULL,
                   NULL) != SQLITE_OK) {
    if (db_error[0] == '\0') {
      mg_snprintf(db_error, sizeof(db_error), "%s", sqlite3_errmsg(db));
    }
    rc = -1;
  }
  if (rc != 0) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"),
               MG_ESC(db_error[0] ? db_error : sqlite3_errmsg(db)));
    goto done;
  }

  if (saved_count > 0) rapid_inbox_start_configured(db);
  mg_xprintf(mg_pfn_iobuf, &errors, "]");
  mg_iobuf_add(&errors, errors.len, "", 1);
  mg_xprintf(mg_pfn_iobuf, &io,
             "{%m:%d,%m:%lu,%m:%lu,%m:%lu,%m:%lu,%m:%s}",
             MG_ESC("ok"), 1,
             MG_ESC("total_count"), (unsigned long) total_count,
             MG_ESC("saved_count"), (unsigned long) saved_count,
             MG_ESC("invalid_count"), (unsigned long) invalid_count,
             MG_ESC("duplicate_count"), (unsigned long) duplicate_count,
             MG_ESC("errors"), errors.buf ? (char *) errors.buf : "[]");

done:
  sqlite3_finalize(stmt);
  free(rules);
  free(copy);
  mg_iobuf_free(&errors);
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

int rapid_inbox_delete_domain_ids(sqlite3 *db, const long *ids, size_t count) {
  sqlite3_stmt *stmt = NULL;
  int deleted = 0;
  if (db == NULL || ids == NULL || count == 0) return 0;
  if (sqlite3_prepare_v2(db, "DELETE FROM mail_domain_rules WHERE id=?", -1,
                         &stmt, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
  for (size_t i = 0; i < count; i++) {
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_int64(stmt, 1, ids[i]);
    if (sqlite3_step(stmt) == SQLITE_DONE) deleted += sqlite3_changes(db);
  }
  sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
  sqlite3_finalize(stmt);
  if (deleted > 0) rapid_inbox_start_configured(db);
  return deleted;
}

static bool build_public_url(const char *base_url, const char *mailbox,
                             const char *backend, const char *action,
                             const char *delivery_id, long limit, char *url,
                             size_t url_len) {
  char mailbox_enc[512], delivery_enc[256];
  if (base_url == NULL || mailbox == NULL || action == NULL || url_len == 0) {
    return false;
  }
  if (mg_url_encode(mailbox, strlen(mailbox), mailbox_enc, sizeof(mailbox_enc)) >=
      sizeof(mailbox_enc)) {
    return false;
  }

  if (strcmp(action, "codes") == 0) {
    if (backend != NULL && strcmp(backend, MAIL_BACKEND_RAPID_INBOX_HEAD) == 0) {
      mg_snprintf(url, url_len,
                  "%s/api/v1/public/mailboxes/%s/messages?limit=%ld",
                  base_url, mailbox_enc, limit > 0 ? limit : 20);
    } else {
      mg_snprintf(url, url_len,
                  "%s/api/v1/public/mailboxes/%s/verification-codes?limit=%ld",
                  base_url, mailbox_enc, limit > 0 ? limit : 20);
    }
    return true;
  }
  if (strcmp(action, "messages") == 0) {
    mg_snprintf(url, url_len,
                "%s/api/v1/public/mailboxes/%s/messages?limit=%ld",
                base_url, mailbox_enc, limit > 0 ? limit : 20);
    return true;
  }
  if ((strcmp(action, "message") == 0 || strcmp(action, "message-code") == 0) &&
      delivery_id != NULL && delivery_id[0] != '\0') {
    if (mg_url_encode(delivery_id, strlen(delivery_id), delivery_enc,
                      sizeof(delivery_enc)) >= sizeof(delivery_enc)) {
      return false;
    }
    mg_snprintf(url, url_len, "%s/api/v1/public/mailboxes/%s/messages/%s%s",
                base_url, mailbox_enc, delivery_enc,
                strcmp(action, "message-code") == 0 &&
                        (backend == NULL ||
                         strcmp(backend, MAIL_BACKEND_RAPID_INBOX_HEAD) != 0)
                    ? "/verification-code"
                    : "");
    return true;
  }
  return false;
}

static char *otprelay_fetch_json(sqlite3 *db, const char *mailbox,
                                 const char *action, const char *delivery_id,
                                 long limit);
static char *temp_mail_fetch_json(sqlite3 *db, const char *mailbox,
                                  const char *action, const char *delivery_id,
                                  long limit);
static int temp_mail_fetch_latest_code(const char *base_url,
                                       const char *api_key,
                                       const char *mailbox,
                                       long min_received_at, char *code,
                                       size_t code_len, char *error,
                                       size_t error_len);
static int otprelay_claim_code(sqlite3 *db, const char *base_url,
                               const char *mailbox, long min_received_at,
                               struct otprelay_claimed_record *out,
                               char *error, size_t error_len);
static void otprelay_http_ack(const char *base_url, const char *id,
                              const char *claim_token);
static char *rapid_inbox_head_codes_json(const char *json, long limit);
static char *temp_mail_codes_json(const char *json, long limit);
static long parse_rfc3339_epoch(const char *value);
static long normalize_otprelay_received_at(long value);

char *rapid_inbox_fetch_json(sqlite3 *db, const char *mailbox,
                             const char *action, const char *delivery_id,
                             long limit) {
  char backend[32];
  char *base_url = setting_value(db, "rapid_inbox_base_url", DEFAULT_BASE_URL);
  char *api_key = setting_value(db, "rapid_inbox_api_key", "");
  char url[1200];
  struct http_client_header headers[] = {{"X-API-Key", api_key}};
  struct http_client_request req;
  struct http_client_response res = {0};
  struct mg_iobuf io = {0, 0, 0, 512};

  read_mail_backend(db, backend, sizeof(backend));
  if (strcmp(backend, MAIL_BACKEND_OTPRELAY) == 0) {
    free(base_url);
    free(api_key);
    return otprelay_fetch_json(db, mailbox, action, delivery_id, limit);
  }
  if (strcmp(backend, MAIL_BACKEND_TEMP_MAIL) == 0) {
    free(base_url);
    free(api_key);
    return temp_mail_fetch_json(db, mailbox, action, delivery_id, limit);
  }

  if (api_key == NULL || api_key[0] == '\0') {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC("Rapid-Inbox API Key 未配置"));
    goto done;
  }
  if (mailbox == NULL || strchr(mailbox, '@') == NULL) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC("邮箱地址不完整"));
    goto done;
  }
  if (!build_public_url(base_url, mailbox, backend, action, delivery_id, limit,
                        url, sizeof(url))) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC("请求类型或 delivery_id 无效"));
    goto done;
  }

  memset(&req, 0, sizeof(req));
  req.method = "GET";
  req.url = url;
  req.timeout_ms = 15000;
  req.headers = headers;
  req.num_headers = 1;

  if (http_client_perform(&req, &res) != 0) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m,%m:%m}",
               MG_ESC("ok"), 0,
               MG_ESC("endpoint"), MG_ESC(url),
               MG_ESC("error"), MG_ESC(res.error));
    goto done;
  }

  {
    const char *body = res.body ? res.body : "";
    char *normalized_body = NULL;
    if (res.status_code >= 200 && res.status_code < 300 &&
        strcmp(backend, MAIL_BACKEND_RAPID_INBOX_HEAD) == 0 &&
        action != NULL && strcmp(action, "codes") == 0) {
      normalized_body = rapid_inbox_head_codes_json(body, limit);
      if (normalized_body != NULL) body = normalized_body;
    }
    mg_xprintf(mg_pfn_iobuf, &io,
               "{%m:%d,%m:%ld,%m:%m,%m:%m}",
               MG_ESC("ok"), res.status_code >= 200 && res.status_code < 300,
               MG_ESC("status_code"), res.status_code,
               MG_ESC("endpoint"), MG_ESC(url),
               MG_ESC("body"), MG_ESC(body));
    free(normalized_body);
  }
  http_client_response_free(&res);

done:
  mg_iobuf_add(&io, io.len, "", 1);
  free(base_url);
  free(api_key);
  return (char *) io.buf;
}

static void set_fetch_error(char *error, size_t error_len,
                            const char *message) {
  if (error_len == 0) return;
  mg_snprintf(error, error_len, "%s", message ? message : "Rapid-Inbox 请求失败");
}

static bool copy_json_string_field(const char *json, const char *path,
                                   char *out, size_t out_len) {
  char *value;
  if (json == NULL || path == NULL || out == NULL || out_len == 0) return false;
  value = mg_json_get_str(mg_str(json), path);
  if (value == NULL || value[0] == '\0') {
    mg_free(value);
    return false;
  }
  mg_snprintf(out, out_len, "%s", value);
  mg_free(value);
  return true;
}

static void copy_compact_preview(const char *text, char *out, size_t out_len) {
  size_t used = 0;
  bool spacing = false;
  if (out == NULL || out_len == 0) return;
  out[0] = '\0';
  if (text == NULL) return;
  for (const unsigned char *p = (const unsigned char *) text;
       *p != '\0' && used + 1 < out_len; p++) {
    if (isspace(*p)) {
      spacing = used > 0;
      continue;
    }
    if (spacing && used + 1 < out_len) out[used++] = ' ';
    spacing = false;
    out[used++] = (char) *p;
  }
  out[used] = '\0';
}

static void copy_json_error_reason(const char *json, char *out,
                                   size_t out_len) {
  if (out == NULL || out_len == 0) return;
  out[0] = '\0';
  if (copy_json_string_field(json, "$.error", out, out_len) ||
      copy_json_string_field(json, "$.message", out, out_len)) {
    return;
  }
  copy_compact_preview(json, out, out_len);
}

static bool copy_six_digit_run(const char *text, char *code, size_t code_len) {
  size_t run = 0;
  const char *start = NULL;
  if (text == NULL || code == NULL || code_len <= 6) return false;
  for (const char *p = text;; p++) {
    if (isdigit((unsigned char) *p)) {
      if (run == 0) start = p;
      run++;
    } else {
      if (run == 6) {
        memcpy(code, start, 6);
        code[6] = '\0';
        return true;
      }
      run = 0;
      start = NULL;
    }
    if (*p == '\0') break;
  }
  return false;
}

static bool build_temp_mail_api_url(const char *base_url, const char *path,
                                    char *url, size_t url_len) {
  char base[512], *p;
  if (base_url == NULL || path == NULL || url == NULL || url_len == 0) {
    return false;
  }
  mg_snprintf(base, sizeof(base), "%s",
              base_url[0] != '\0' ? base_url : DEFAULT_BASE_URL);
  p = trim(base);
  while (strlen(p) > 1 && p[strlen(p) - 1] == '/') p[strlen(p) - 1] = '\0';
  mg_snprintf(url, url_len, "%s%s", p, path);
  return url[0] != '\0';
}

static bool build_temp_mail_mails_url(const char *base_url,
                                      const char *mailbox, long limit,
                                      char *url, size_t url_len) {
  char mailbox_enc[512], path[768];
  if (mailbox == NULL || strchr(mailbox, '@') == NULL) return false;
  if (mg_url_encode(mailbox, strlen(mailbox), mailbox_enc,
                    sizeof(mailbox_enc)) >= sizeof(mailbox_enc)) {
    return false;
  }
  mg_snprintf(path, sizeof(path), "/admin/mails?limit=%ld&offset=0&address=%s",
              limit > 0 && limit <= 100 ? limit : 20, mailbox_enc);
  return build_temp_mail_api_url(base_url, path, url, url_len);
}

static bool temp_mail_copy_item_string(const char *json, const char *array,
                                       int index, const char *field, char *out,
                                       size_t out_len) {
  char path[128];
  if (array == NULL || field == NULL) return false;
  mg_snprintf(path, sizeof(path), "$.%s[%d].%s", array, index, field);
  return copy_json_string_field(json, path, out, out_len);
}

static bool temp_mail_copy_item_long_string(const char *json,
                                            const char *array, int index,
                                            const char *field, char *out,
                                            size_t out_len) {
  char path[128];
  long value;
  if (array == NULL || field == NULL || out == NULL || out_len == 0) {
    return false;
  }
  if (temp_mail_copy_item_string(json, array, index, field, out, out_len)) {
    return true;
  }
  mg_snprintf(path, sizeof(path), "$.%s[%d].%s", array, index, field);
  value = mg_json_get_long(mg_str(json), path, -1);
  if (value < 0) return false;
  mg_snprintf(out, out_len, "%ld", value);
  return true;
}

static bool temp_mail_code_from_text_path(const char *json, const char *path,
                                          char *code, size_t code_len) {
  char *value;
  bool ok = false;
  if (json == NULL || path == NULL) return false;
  value = mg_json_get_str(mg_str(json), path);
  if (value != NULL) ok = copy_six_digit_run(value, code, code_len);
  mg_free(value);
  return ok;
}

static bool temp_mail_copy_code_from_item(const char *json, const char *array,
                                          int index, char *code,
                                          size_t code_len) {
  char path[128];
  char text[512];
  if (temp_mail_copy_item_string(json, array, index, "verification_code", code,
                                 code_len) ||
      temp_mail_copy_item_string(json, array, index, "code", code, code_len)) {
    return true;
  }
  mg_snprintf(path, sizeof(path), "$.%s[%d].subject", array, index);
  if (temp_mail_code_from_text_path(json, path, code, code_len)) return true;
  mg_snprintf(path, sizeof(path), "$.%s[%d].text", array, index);
  if (temp_mail_code_from_text_path(json, path, code, code_len)) return true;
  mg_snprintf(path, sizeof(path), "$.%s[%d].html", array, index);
  if (temp_mail_code_from_text_path(json, path, code, code_len)) return true;
  mg_snprintf(path, sizeof(path), "$.%s[%d].message", array, index);
  if (temp_mail_code_from_text_path(json, path, code, code_len)) return true;
  mg_snprintf(path, sizeof(path), "$.%s[%d].raw", array, index);
  if (temp_mail_code_from_text_path(json, path, code, code_len)) return true;
  if (temp_mail_copy_item_string(json, array, index, "source", text,
                                 sizeof(text)) &&
      copy_six_digit_run(text, code, code_len)) {
    return true;
  }
  return false;
}

static bool temp_mail_item_exists(const char *json, const char *array,
                                  int index) {
  char value[32];
  return temp_mail_copy_item_string(json, array, index, "raw", value,
                                    sizeof(value)) ||
         temp_mail_copy_item_string(json, array, index, "message_id", value,
                                    sizeof(value)) ||
         temp_mail_copy_item_long_string(json, array, index, "id", value,
                                         sizeof(value)) ||
         temp_mail_copy_item_string(json, array, index, "subject", value,
                                    sizeof(value));
}

static const char *temp_mail_first_array(const char *json) {
  if (temp_mail_item_exists(json, "results", 0)) return "results";
  if (temp_mail_item_exists(json, "items", 0)) return "items";
  return "results";
}

static bool temp_mail_copy_received_at_string(const char *json,
                                              const char *array, int index,
                                              char *out, size_t out_len) {
  return temp_mail_copy_item_string(json, array, index, "received_at", out,
                                    out_len) ||
         temp_mail_copy_item_string(json, array, index, "delivered_at", out,
                                    out_len) ||
         temp_mail_copy_item_string(json, array, index, "created_at", out,
                                    out_len);
}

static long temp_mail_item_received_at(const char *json, const char *array,
                                       int index) {
  char path[128];
  char value[96];
  long epoch;
  if (temp_mail_copy_received_at_string(json, array, index, value,
                                        sizeof(value))) {
    return parse_rfc3339_epoch(value);
  }
  mg_snprintf(path, sizeof(path), "$.%s[%d].received_at", array, index);
  epoch = mg_json_get_long(mg_str(json), path, 0);
  if (epoch > 0) return normalize_otprelay_received_at(epoch);
  mg_snprintf(path, sizeof(path), "$.%s[%d].created_at", array, index);
  epoch = mg_json_get_long(mg_str(json), path, 0);
  return epoch > 0 ? normalize_otprelay_received_at(epoch) : 0;
}

static char *temp_mail_codes_json(const char *json, long limit) {
  struct mg_iobuf io = {0, 0, 0, 512};
  const char *array = temp_mail_first_array(json);
  long max_items = limit > 0 && limit <= 100 ? limit : 20;
  bool first = true;

  mg_xprintf(mg_pfn_iobuf, &io, "{%m:[", MG_ESC("items"));
  for (int i = 0; i < max_items; i++) {
    char code[64] = "";
    char delivery_id[128] = "";
    char message_id[128] = "";
    char subject[512] = "";
    char from_addr[256] = "";
    char received_at[96] = "";

    if (!temp_mail_item_exists(json, array, i)) break;
    if (!temp_mail_copy_code_from_item(json, array, i, code, sizeof(code))) {
      continue;
    }
    temp_mail_copy_item_long_string(json, array, i, "id", delivery_id,
                                    sizeof(delivery_id));
    temp_mail_copy_item_string(json, array, i, "message_id", message_id,
                               sizeof(message_id));
    if (delivery_id[0] == '\0') {
      mg_snprintf(delivery_id, sizeof(delivery_id), "%s", message_id);
    }
    temp_mail_copy_item_string(json, array, i, "subject", subject,
                               sizeof(subject));
    if (!temp_mail_copy_item_string(json, array, i, "from_addr", from_addr,
                                    sizeof(from_addr))) {
      temp_mail_copy_item_string(json, array, i, "source", from_addr,
                                 sizeof(from_addr));
    }
    temp_mail_copy_received_at_string(json, array, i, received_at,
                                      sizeof(received_at));
    mg_xprintf(mg_pfn_iobuf, &io,
               "%s{%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m}",
               first ? "" : ",",
               MG_ESC("code"), MG_ESC(code),
               MG_ESC("delivery_id"), MG_ESC(delivery_id),
               MG_ESC("message_id"), MG_ESC(message_id),
               MG_ESC("subject"), MG_ESC(subject),
               MG_ESC("from_addr"), MG_ESC(from_addr),
               MG_ESC("received_at"), MG_ESC(received_at));
    first = false;
  }
  mg_xprintf(mg_pfn_iobuf, &io, "]}");
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

static bool build_otprelay_api_url(const char *base_url, const char *path,
                                   char *url, size_t url_len) {
  char base[512], *p;
  if (base_url == NULL || path == NULL || url == NULL || url_len == 0) {
    return false;
  }
  mg_snprintf(base, sizeof(base), "%s",
              base_url[0] != '\0' ? base_url : DEFAULT_OTPRELAY_BASE_URL);
  p = trim(base);
  while (strlen(p) > 1 && p[strlen(p) - 1] == '/') p[strlen(p) - 1] = '\0';
  mg_snprintf(url, url_len, "%s%s", p, path);
  return url[0] != '\0';
}

static long normalize_otprelay_received_at(long value) {
  if (value <= 0) return 0;
  return value > 100000000000L ? value / 1000 : value;
}

static long otprelay_json_epoch_field(const char *json,
                                      const char *path) {
  char value[96];
  long epoch =
      normalize_otprelay_received_at(mg_json_get_long(mg_str(json), path, 0));
  if (epoch > 0) return epoch;
  if (copy_json_string_field(json, path, value, sizeof(value))) {
    epoch = parse_rfc3339_epoch(value);
    if (epoch > 0) return epoch;
  }
  return 0;
}

static long otprelay_claim_received_at(const char *json) {
  long epoch = otprelay_json_epoch_field(json, "$.record.received_ms");
  if (epoch > 0) return epoch;
  epoch = otprelay_json_epoch_field(json, "$.received_ms");
  if (epoch > 0) return epoch;
  epoch = otprelay_json_epoch_field(json, "$.record.received_at");
  if (epoch > 0) return epoch;
  epoch = otprelay_json_epoch_field(json, "$.received_at");
  if (epoch > 0) return epoch;
  epoch = otprelay_json_epoch_field(json, "$.record.created_at");
  if (epoch > 0) return epoch;
  return otprelay_json_epoch_field(json, "$.created_at");
}

static bool extract_otprelay_claimed_record(
    const char *json, struct otprelay_claimed_record *out) {
  if (json == NULL || out == NULL) return false;
  memset(out, 0, sizeof(*out));
  if (!copy_json_string_field(json, "$.record.verification_code", out->code,
                              sizeof(out->code)) &&
      !copy_json_string_field(json, "$.verification_code", out->code,
                              sizeof(out->code)) &&
      !copy_json_string_field(json, "$.record.code", out->code,
                              sizeof(out->code)) &&
      !copy_json_string_field(json, "$.code", out->code,
                              sizeof(out->code))) {
    return false;
  }
  copy_json_string_field(json, "$.record.id", out->id, sizeof(out->id));
  copy_json_string_field(json, "$.id", out->id, sizeof(out->id));
  copy_json_string_field(json, "$.record.claim_token", out->claim_token,
                         sizeof(out->claim_token));
  copy_json_string_field(json, "$.claim_token", out->claim_token,
                         sizeof(out->claim_token));
  out->received_at = otprelay_claim_received_at(json);
  return out->code[0] != '\0';
}

static void otprelay_http_ack(const char *base_url, const char *id,
                              const char *claim_token) {
  char id_enc[128], token_enc[160], path[220], url[900], body[220];
  struct http_client_header headers[] = {
      {"Content-Type", "application/x-www-form-urlencoded"}};
  struct http_client_request req;
  struct http_client_response res;

  if (base_url == NULL || id == NULL || id[0] == '\0' ||
      claim_token == NULL || claim_token[0] == '\0') {
    return;
  }
  if (mg_url_encode(id, strlen(id), id_enc, sizeof(id_enc)) >=
      sizeof(id_enc) ||
      mg_url_encode(claim_token, strlen(claim_token), token_enc,
                    sizeof(token_enc)) >= sizeof(token_enc)) {
    return;
  }
  mg_snprintf(path, sizeof(path), "/api/v1/verification-codes/%s/ack", id_enc);
  if (!build_otprelay_api_url(base_url, path, url, sizeof(url))) return;
  mg_snprintf(body, sizeof(body), "claim_token=%s", token_enc);
  memset(&req, 0, sizeof(req));
  req.method = "POST";
  req.url = url;
  req.body = body;
  req.body_len = strlen(body);
  req.timeout_ms = 5000;
  req.headers = headers;
  req.num_headers = 1;
  if (http_client_perform(&req, &res) == 0) http_client_response_free(&res);
}

static void otprelay_ack_claimed_code(sqlite3 *db, const char *base_url,
                                      const char *id,
                                      const char *claim_token) {
  char transport[16];
  if (id == NULL || id[0] == '\0' || claim_token == NULL ||
      claim_token[0] == '\0') {
    return;
  }
  read_mail_transport(db, transport, sizeof(transport));
  if (strcmp(transport, MAIL_TRANSPORT_WS) == 0) {
    otprelay_ws_enqueue_ack(id, claim_token);
    return;
  }
  otprelay_http_ack(base_url, id, claim_token);
}

static int otprelay_claim_http(const char *base_url, const char *mailbox,
                               long min_received_at,
                               struct otprelay_claimed_record *out,
                               char *error, size_t error_len) {
  char url[900], mailbox_enc[512], body[600];
  struct http_client_header headers[] = {
      {"Content-Type", "application/x-www-form-urlencoded"}};
  struct http_client_request req;
  struct http_client_response res;
  int result = -1;

  if (out != NULL) memset(out, 0, sizeof(*out));
  if (mailbox == NULL || strchr(mailbox, '@') == NULL) {
    set_fetch_error(error, error_len, "邮箱地址不完整");
    return -1;
  }
  if (mg_url_encode(mailbox, strlen(mailbox), mailbox_enc,
                    sizeof(mailbox_enc)) >= sizeof(mailbox_enc)) {
    set_fetch_error(error, error_len, "邮箱地址过长");
    return -1;
  }
  if (!build_otprelay_api_url(base_url, "/api/v1/verification-codes/claim",
                              url, sizeof(url))) {
    set_fetch_error(error, error_len, "OTPRelay claim 接口构造失败");
    return -1;
  }
  mg_snprintf(body, sizeof(body), "mailbox=%s", mailbox_enc);
  memset(&req, 0, sizeof(req));
  req.method = "POST";
  req.url = url;
  req.body = body;
  req.body_len = strlen(body);
  req.timeout_ms = 5000;
  req.headers = headers;
  req.num_headers = 1;

  if (http_client_perform(&req, &res) != 0) {
    mg_snprintf(error, error_len,
                "OTPRelay claim 请求失败: email=%s endpoint=%s error=%s",
                mailbox, url, res.error[0] ? res.error : "unknown");
    return -1;
  }
  if (res.status_code == 404) {
    char reason[160];
    copy_json_error_reason(res.body, reason, sizeof(reason));
    mg_snprintf(error, error_len,
                "OTPRelay claim 未找到验证码: email=%s HTTP 404 reason=%s",
                mailbox, reason[0] ? reason : "verification code not found");
    result = 0;
    goto done;
  }
  if (res.status_code < 200 || res.status_code >= 300) {
    char reason[160];
    copy_json_error_reason(res.body, reason, sizeof(reason));
    mg_snprintf(error, error_len,
                "OTPRelay claim HTTP %ld: email=%s reason=%s",
                res.status_code, mailbox, reason[0] ? reason : "-");
    goto done;
  }
  if (!extract_otprelay_claimed_record(res.body, out)) {
    char reason[160];
    copy_json_error_reason(res.body, reason, sizeof(reason));
    mg_snprintf(error, error_len,
                "OTPRelay claim 响应未包含验证码: email=%s HTTP %ld body=%s",
                mailbox, res.status_code, reason[0] ? reason : "-");
    result = 0;
    goto done;
  }
  if (min_received_at > 0 && out->received_at > 0 &&
      out->received_at + 10 < min_received_at) {
    mg_snprintf(error, error_len,
                "OTPRelay claim 返回旧验证码已跳过: email=%s code_id=%s "
                "received_at=%ld min_received_at=%ld",
                mailbox, out->id[0] ? out->id : "-", out->received_at,
                min_received_at);
    otprelay_http_ack(base_url, out->id, out->claim_token);
    memset(out, 0, sizeof(*out));
    result = 0;
    goto done;
  }
  result = 1;

done:
  http_client_response_free(&res);
  return result;
}

static int otprelay_claim_code(sqlite3 *db, const char *base_url,
                               const char *mailbox, long min_received_at,
                               struct otprelay_claimed_record *out,
                               char *error, size_t error_len) {
  char transport[16];
  int rc;
  read_mail_transport(db, transport, sizeof(transport));
  if (strcmp(transport, MAIL_TRANSPORT_WS) == 0) {
    rc = otprelay_ws_update(db, base_url);
    if (rc != 0) {
      set_fetch_error(error, error_len, "OTPRelay WS 订阅未就绪");
      return -1;
    }
    if (otprelay_ws_cache_take(mailbox, min_received_at, out)) return 1;
    otprelay_ws_request_poll();
    mg_snprintf(error, error_len, "OTPRelay WS 缓存未命中: email=%s",
                mailbox ? mailbox : "-");
    return 0;
  }
  return otprelay_claim_http(base_url, mailbox, min_received_at, out, error,
                             error_len);
}

static char *otprelay_fetch_json(sqlite3 *db, const char *mailbox,
                                 const char *action, const char *delivery_id,
                                 long limit) {
  char *base_url = setting_value(db, "rapid_inbox_base_url",
                                 DEFAULT_OTPRELAY_BASE_URL);
  char transport[16];
  char endpoint[OTPRELAY_WS_MAX_URL];
  struct otprelay_claimed_record claimed;
  char error[256] = "";
  struct mg_iobuf io = {0, 0, 0, 512};
  int rc;
  (void) delivery_id;
  (void) limit;

  read_mail_transport(db, transport, sizeof(transport));
  if (action != NULL && strcmp(action, "codes") != 0 &&
      strcmp(action, "claim") != 0) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("OTPRelay 仅支持验证码 claim 读取"));
    goto done;
  }
  if (strcmp(transport, MAIL_TRANSPORT_WS) == 0) {
    build_otprelay_ws_url(base_url, endpoint, sizeof(endpoint));
  } else {
    build_otprelay_api_url(base_url, "/api/v1/verification-codes/claim",
                           endpoint, sizeof(endpoint));
  }
  rc = otprelay_claim_code(db, base_url, mailbox, 0, &claimed, error,
                           sizeof(error));
  if (rc < 0) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m,%m:%m}",
               MG_ESC("ok"), 0,
               MG_ESC("endpoint"), MG_ESC(endpoint),
               MG_ESC("error"), MG_ESC(error));
  } else if (rc == 0) {
    mg_xprintf(mg_pfn_iobuf, &io,
               "{%m:%d,%m:%ld,%m:%m,%m:%m}",
               MG_ESC("ok"), 1,
               MG_ESC("status_code"), 204L,
               MG_ESC("endpoint"), MG_ESC(endpoint),
               MG_ESC("body"), MG_ESC("{\"ok\":true,\"record\":null}"));
  } else {
    char body[512];
    mg_snprintf(body, sizeof(body),
                "{\"ok\":true,\"record\":{\"verification_code\":\"%s\","
                "\"id\":\"%s\",\"claim_token\":\"%s\","
                "\"received_at\":%ld}}",
                claimed.code, claimed.id, claimed.claim_token,
                claimed.received_at);
    mg_xprintf(mg_pfn_iobuf, &io,
               "{%m:%d,%m:%ld,%m:%m,%m:%m}",
               MG_ESC("ok"), 1,
               MG_ESC("status_code"), 200L,
               MG_ESC("endpoint"), MG_ESC(endpoint),
               MG_ESC("body"), MG_ESC(body));
  }

done:
  mg_iobuf_add(&io, io.len, "", 1);
  free(base_url);
  return (char *) io.buf;
}

static int temp_mail_fetch_latest_code(const char *base_url,
                                       const char *api_key,
                                       const char *mailbox,
                                       long min_received_at, char *code,
                                       size_t code_len, char *error,
                                       size_t error_len) {
  char url[1200];
  struct http_client_header headers[] = {{"x-admin-auth", api_key}};
  struct http_client_request req;
  struct http_client_response res;
  const char *array;
  int result = -1;
  int scanned = 0;

  if (code != NULL && code_len > 0) code[0] = '\0';
  if (api_key == NULL || api_key[0] == '\0') {
    set_fetch_error(error, error_len, "Temp-Mail Admin 密钥未配置");
    return -1;
  }
  if (mailbox == NULL || strchr(mailbox, '@') == NULL) {
    set_fetch_error(error, error_len, "邮箱地址不完整");
    return -1;
  }
  if (!build_temp_mail_mails_url(base_url, mailbox, 20, url, sizeof(url))) {
    set_fetch_error(error, error_len, "Temp-Mail 邮件接口构造失败");
    return -1;
  }

  memset(&req, 0, sizeof(req));
  memset(&res, 0, sizeof(res));
  req.method = "GET";
  req.url = url;
  req.timeout_ms = 5000;
  req.headers = headers;
  req.num_headers = 1;

  if (http_client_perform(&req, &res) != 0) {
    mg_snprintf(error, error_len,
                "Temp-Mail 请求失败: email=%s endpoint=%s error=%s",
                mailbox, url, res.error[0] ? res.error : "unknown");
    return -1;
  }
  if (res.status_code < 200 || res.status_code >= 300) {
    char reason[160];
    copy_json_error_reason(res.body, reason, sizeof(reason));
    mg_snprintf(error, error_len,
                "Temp-Mail HTTP %ld: email=%s reason=%s",
                res.status_code, mailbox, reason[0] ? reason : "-");
    http_client_response_free(&res);
    return -1;
  }

  array = temp_mail_first_array(res.body);
  for (int i = 0; i < 20; i++) {
    long received_at;
    if (!temp_mail_item_exists(res.body, array, i)) break;
    scanned++;
    received_at = temp_mail_item_received_at(res.body, array, i);
    if (min_received_at > 0 && received_at > 0 &&
        received_at + 10 < min_received_at) {
      continue;
    }
    if (temp_mail_copy_code_from_item(res.body, array, i, code, code_len)) {
      result = 1;
      break;
    }
  }
  if (result < 0) {
    if (min_received_at > 0) {
      mg_snprintf(error, error_len,
                  "Temp-Mail 未找到本次请求后的验证码: email=%s "
                  "min_received_at=%ld scanned=%d",
                  mailbox, min_received_at, scanned);
    } else {
      mg_snprintf(error, error_len,
                  "Temp-Mail 未找到验证码: email=%s scanned=%d",
                  mailbox, scanned);
    }
    result = 0;
  }
  http_client_response_free(&res);
  return result;
}

static char *temp_mail_fetch_json(sqlite3 *db, const char *mailbox,
                                  const char *action, const char *delivery_id,
                                  long limit) {
  char *base_url = setting_value(db, "rapid_inbox_base_url", DEFAULT_BASE_URL);
  char *api_key = setting_value(db, "rapid_inbox_api_key", "");
  char url[1200];
  struct http_client_header headers[] = {{"x-admin-auth", api_key}};
  struct http_client_request req;
  struct http_client_response res;
  struct mg_iobuf io = {0, 0, 0, 512};
  (void) delivery_id;

  if (action != NULL && strcmp(action, "codes") != 0 &&
      strcmp(action, "messages") != 0) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0,
               MG_ESC("error"),
               MG_ESC("Temp-Mail 仅支持验证码列表和邮件列表读取"));
    goto done;
  }
  if (api_key == NULL || api_key[0] == '\0') {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("Temp-Mail Admin 密钥未配置"));
    goto done;
  }
  if (mailbox == NULL || strchr(mailbox, '@') == NULL) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC("邮箱地址不完整"));
    goto done;
  }
  if (!build_temp_mail_mails_url(base_url, mailbox, limit, url, sizeof(url))) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}",
               MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("Temp-Mail 邮件接口构造失败"));
    goto done;
  }

  memset(&req, 0, sizeof(req));
  memset(&res, 0, sizeof(res));
  req.method = "GET";
  req.url = url;
  req.timeout_ms = 15000;
  req.headers = headers;
  req.num_headers = 1;

  if (http_client_perform(&req, &res) != 0) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m,%m:%m}",
               MG_ESC("ok"), 0,
               MG_ESC("endpoint"), MG_ESC(url),
               MG_ESC("error"), MG_ESC(res.error));
    goto done;
  }

  {
    const char *body = res.body ? res.body : "";
    char *normalized_body = NULL;
    if (res.status_code >= 200 && res.status_code < 300 &&
        (action == NULL || strcmp(action, "codes") == 0)) {
      normalized_body = temp_mail_codes_json(body, limit);
      if (normalized_body != NULL) body = normalized_body;
    }
    mg_xprintf(mg_pfn_iobuf, &io,
               "{%m:%d,%m:%ld,%m:%m,%m:%m}",
               MG_ESC("ok"), res.status_code >= 200 && res.status_code < 300,
               MG_ESC("status_code"), res.status_code,
               MG_ESC("endpoint"), MG_ESC(url),
               MG_ESC("body"), MG_ESC(body));
    free(normalized_body);
  }
  http_client_response_free(&res);

done:
  mg_iobuf_add(&io, io.len, "", 1);
  free(base_url);
  free(api_key);
  return (char *) io.buf;
}

int rapid_inbox_provision_mailbox(sqlite3 *db, const char *mailbox,
                                  char *error, size_t error_len) {
  char backend[32];
  char *base_url = NULL;
  char *api_key = NULL;
  char local[160], domain[256], url[900], body[640], address[320];
  const char *at;
  struct http_client_header headers[] = {
      {"x-admin-auth", NULL},
      {"Content-Type", "application/json"}};
  struct http_client_request req;
  struct http_client_response res = {0};
  int rc = -1;

  read_mail_backend(db, backend, sizeof(backend));
  if (strcmp(backend, MAIL_BACKEND_TEMP_MAIL) != 0) return 0;
  if (mailbox == NULL || (at = strchr(mailbox, '@')) == NULL || at == mailbox ||
      at[1] == '\0') {
    set_fetch_error(error, error_len, "邮箱地址不完整");
    return -1;
  }
  if ((size_t) (at - mailbox) >= sizeof(local) || strlen(at + 1) >= sizeof(domain)) {
    set_fetch_error(error, error_len, "邮箱地址过长");
    return -1;
  }
  mg_snprintf(local, sizeof(local), "%.*s", (int) (at - mailbox), mailbox);
  mg_snprintf(domain, sizeof(domain), "%s", at + 1);

  base_url = setting_value(db, "rapid_inbox_base_url", DEFAULT_BASE_URL);
  api_key = setting_value(db, "rapid_inbox_api_key", "");
  if (api_key == NULL || api_key[0] == '\0') {
    set_fetch_error(error, error_len, "Temp-Mail Admin 密钥未配置");
    goto done;
  }
  if (!build_temp_mail_api_url(base_url, "/admin/new_address", url,
                               sizeof(url))) {
    set_fetch_error(error, error_len, "Temp-Mail 新建地址接口构造失败");
    goto done;
  }
  mg_snprintf(body, sizeof(body), "{%m:false,%m:%m,%m:%m}",
              MG_ESC("enablePrefix"), MG_ESC("name"), MG_ESC(local),
              MG_ESC("domain"), MG_ESC(domain));
  headers[0].value = api_key;
  memset(&req, 0, sizeof(req));
  memset(&res, 0, sizeof(res));
  req.method = "POST";
  req.url = url;
  req.body = body;
  req.body_len = strlen(body);
  req.timeout_ms = 10000;
  req.headers = headers;
  req.num_headers = 2;

  if (http_client_perform(&req, &res) != 0) {
    mg_snprintf(error, error_len,
                "Temp-Mail 新建地址请求失败: email=%s endpoint=%s error=%s",
                mailbox, url, res.error[0] ? res.error : "unknown");
    goto done;
  }
  if (res.status_code < 200 || res.status_code >= 300) {
    char reason[180];
    copy_json_error_reason(res.body, reason, sizeof(reason));
    mg_snprintf(error, error_len,
                "Temp-Mail 新建地址 HTTP %ld: email=%s reason=%s",
                res.status_code, mailbox, reason[0] ? reason : "-");
    goto done;
  }
  if (!copy_json_string_field(res.body, "$.address", address, sizeof(address))) {
    char reason[180];
    copy_json_error_reason(res.body, reason, sizeof(reason));
    mg_snprintf(error, error_len,
                "Temp-Mail 新建地址响应缺少 address: email=%s body=%s",
                mailbox, reason[0] ? reason : "-");
    goto done;
  }
  if (strcasecmp(address, mailbox) != 0) {
    mg_snprintf(error, error_len,
                "Temp-Mail 新建地址与请求邮箱不一致: requested=%s returned=%s",
                mailbox, address);
    goto done;
  }
  rc = 0;

done:
  http_client_response_free(&res);
  free(base_url);
  free(api_key);
  return rc;
}

static long parse_rfc3339_epoch(const char *value) {
  struct tm tm_value;
  char *end;
  long epoch;

  if (value == NULL || value[0] == '\0') return 0;
  memset(&tm_value, 0, sizeof(tm_value));
  end = strptime(value, "%Y-%m-%dT%H:%M:%S", &tm_value);
  if (end == NULL) {
    memset(&tm_value, 0, sizeof(tm_value));
    end = strptime(value, "%Y-%m-%d %H:%M:%S", &tm_value);
  }
  if (end == NULL) return 0;
  epoch = (long) timegm(&tm_value);
  return epoch > 0 ? epoch : 0;
}

static bool copy_code_from_item(const char *json, int index, char *code,
                                size_t code_len) {
  char path[96];
  char text[512];
  mg_snprintf(path, sizeof(path), "$.items[%d].verification_code", index);
  if (copy_json_string_field(json, path, code, code_len)) return true;
  mg_snprintf(path, sizeof(path), "$.items[%d].code", index);
  if (copy_json_string_field(json, path, code, code_len)) return true;
  mg_snprintf(path, sizeof(path), "$.items[%d].subject", index);
  if (copy_json_string_field(json, path, text, sizeof(text)) &&
      copy_six_digit_run(text, code, code_len)) {
    return true;
  }
  mg_snprintf(path, sizeof(path), "$.items[%d].text_preview", index);
  if (copy_json_string_field(json, path, text, sizeof(text)) &&
      copy_six_digit_run(text, code, code_len)) {
    return true;
  }
  mg_snprintf(path, sizeof(path), "$.items[%d].text_body", index);
  if (copy_json_string_field(json, path, text, sizeof(text)) &&
      copy_six_digit_run(text, code, code_len)) {
    return true;
  }
  return false;
}

static long item_received_at(const char *json, int index) {
  char path[96];
  char value[96];

  mg_snprintf(path, sizeof(path), "$.items[%d].received_at", index);
  if (copy_json_string_field(json, path, value, sizeof(value))) {
    return parse_rfc3339_epoch(value);
  }
  mg_snprintf(path, sizeof(path), "$.items[%d].delivered_at", index);
  if (copy_json_string_field(json, path, value, sizeof(value))) {
    return parse_rfc3339_epoch(value);
  }
  mg_snprintf(path, sizeof(path), "$.items[%d].created_at", index);
  if (copy_json_string_field(json, path, value, sizeof(value))) {
    return parse_rfc3339_epoch(value);
  }
  return 0;
}

static bool copy_item_string_field(const char *json, int index,
                                   const char *field, char *out,
                                   size_t out_len) {
  char path[128];
  if (field == NULL) return false;
  mg_snprintf(path, sizeof(path), "$.items[%d].%s", index, field);
  return copy_json_string_field(json, path, out, out_len);
}

static bool copy_item_received_at_string(const char *json, int index,
                                         char *out, size_t out_len) {
  return copy_item_string_field(json, index, "received_at", out, out_len) ||
         copy_item_string_field(json, index, "delivered_at", out, out_len) ||
         copy_item_string_field(json, index, "created_at", out, out_len);
}

static bool item_exists(const char *json, int index) {
  char value[16];
  return copy_item_string_field(json, index, "delivery_id", value,
                                sizeof(value)) ||
         copy_item_string_field(json, index, "message_id", value,
                                sizeof(value)) ||
         copy_item_string_field(json, index, "subject", value, sizeof(value));
}

static char *rapid_inbox_head_codes_json(const char *json, long limit) {
  struct mg_iobuf io = {0, 0, 0, 512};
  long max_items = limit > 0 && limit <= 100 ? limit : 20;
  bool first = true;

  mg_xprintf(mg_pfn_iobuf, &io, "{%m:[", MG_ESC("items"));
  for (int i = 0; i < max_items; i++) {
    char code[64] = "";
    char delivery_id[128] = "";
    char message_id[128] = "";
    char subject[512] = "";
    char from_addr[256] = "";
    char received_at[96] = "";

    if (!item_exists(json, i)) break;
    if (!copy_code_from_item(json, i, code, sizeof(code))) continue;
    copy_item_string_field(json, i, "delivery_id", delivery_id,
                           sizeof(delivery_id));
    copy_item_string_field(json, i, "message_id", message_id,
                           sizeof(message_id));
    copy_item_string_field(json, i, "subject", subject, sizeof(subject));
    copy_item_string_field(json, i, "from_addr", from_addr, sizeof(from_addr));
    copy_item_received_at_string(json, i, received_at, sizeof(received_at));
    mg_xprintf(mg_pfn_iobuf, &io,
               "%s{%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m}",
               first ? "" : ",",
               MG_ESC("code"), MG_ESC(code),
               MG_ESC("delivery_id"), MG_ESC(delivery_id),
               MG_ESC("message_id"), MG_ESC(message_id),
               MG_ESC("subject"), MG_ESC(subject),
               MG_ESC("from_addr"), MG_ESC(from_addr),
               MG_ESC("received_at"), MG_ESC(received_at));
    first = false;
  }
  mg_xprintf(mg_pfn_iobuf, &io, "]}");
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

static int fetch_latest_code_impl(sqlite3 *db, const char *mailbox,
                                  long min_received_at, char *code,
                                  size_t code_len, char *error,
                                  size_t error_len) {
  char backend[32];
  char *base_url;
  char *api_key = NULL;
  char url[1200];
  struct http_client_header headers[] = {{"X-API-Key", NULL}};
  struct http_client_request req;
  struct http_client_response res;
  struct otprelay_claimed_record claimed;
  int result = -1;

  if (code != NULL && code_len > 0) code[0] = '\0';
  // outlook007: 若母邮箱命中 outlook 池, 用其专属接码链接(别名注册透明路由,
  // 其它渠道不受影响)。返回 NOT_MINE 表示母邮箱不在池中, 继续走原有后端。
  {
    int oc = outlook_pool_try_fetch_code(db, mailbox, min_received_at, code,
                                         code_len, error, error_len);
    if (oc != OUTLOOK_POOL_NOT_MINE) return oc;
  }
  read_mail_backend(db, backend, sizeof(backend));
  base_url = setting_value(
      db, "rapid_inbox_base_url",
      strcmp(backend, MAIL_BACKEND_OTPRELAY) == 0 ? DEFAULT_OTPRELAY_BASE_URL
                                                  : DEFAULT_BASE_URL);
  if (strcmp(backend, MAIL_BACKEND_OTPRELAY) == 0) {
    result = otprelay_claim_code(db, base_url, mailbox, min_received_at,
                                 &claimed, error, error_len);
    if (result == 1) {
      mg_snprintf(code, code_len, "%s", claimed.code);
      otprelay_ack_claimed_code(db, base_url, claimed.id, claimed.claim_token);
    }
    goto done;
  }
  if (strcmp(backend, MAIL_BACKEND_TEMP_MAIL) == 0) {
    api_key = setting_value(db, "rapid_inbox_api_key", "");
    result = temp_mail_fetch_latest_code(base_url, api_key, mailbox,
                                         min_received_at, code, code_len,
                                         error, error_len);
    goto done;
  }

  api_key = setting_value(db, "rapid_inbox_api_key", "");
  headers[0].value = api_key;
  if (api_key == NULL || api_key[0] == '\0') {
    set_fetch_error(error, error_len, "Rapid-Inbox API Key 未配置");
    goto done;
  }
  if (mailbox == NULL || strchr(mailbox, '@') == NULL) {
    set_fetch_error(error, error_len, "邮箱地址不完整");
    goto done;
  }
  if (!build_public_url(base_url, mailbox, backend, "codes", NULL, 20, url,
                        sizeof(url))) {
    set_fetch_error(error, error_len, "Rapid-Inbox 验证码接口构造失败");
    goto done;
  }

  memset(&req, 0, sizeof(req));
  req.method = "GET";
  req.url = url;
  req.timeout_ms = 5000;
  req.headers = headers;
  req.num_headers = 1;

  if (http_client_perform(&req, &res) != 0) {
    mg_snprintf(error, error_len,
                "Rapid-Inbox 请求失败: email=%s endpoint=%s error=%s",
                mailbox ? mailbox : "-", url,
                res.error[0] ? res.error : "unknown");
    goto done;
  }
  if (res.status_code < 200 || res.status_code >= 300) {
    char reason[160];
    copy_json_error_reason(res.body, reason, sizeof(reason));
    mg_snprintf(error, error_len,
                "Rapid-Inbox HTTP %ld: email=%s reason=%s",
                res.status_code, mailbox ? mailbox : "-",
                reason[0] ? reason : "-");
    http_client_response_free(&res);
    goto done;
  }

  if (min_received_at > 0) {
    for (int i = 0; i < 20; i++) {
      long received_at = item_received_at(res.body, i);
      if (received_at == 0) break;
      if (received_at + 10 < min_received_at) continue;
      if (copy_code_from_item(res.body, i, code, code_len)) {
        result = 1;
        break;
      }
    }
    if (result < 0) {
      mg_snprintf(error, error_len,
                  "Rapid-Inbox 未找到本次请求后的验证码: email=%s "
                  "min_received_at=%ld",
                  mailbox ? mailbox : "-", min_received_at);
      result = 0;
    }
  } else if (copy_code_from_item(res.body, 0, code, code_len) ||
             copy_json_string_field(res.body, "$.verification_code", code,
                                    code_len) ||
             copy_json_string_field(res.body, "$.code", code, code_len)) {
    result = 1;
  } else {
    mg_snprintf(error, error_len, "Rapid-Inbox 未找到验证码: email=%s",
                mailbox ? mailbox : "-");
    result = 0;
  }
  http_client_response_free(&res);

done:
  free(base_url);
  free(api_key);
  return result;
}

int rapid_inbox_fetch_latest_code(sqlite3 *db, const char *mailbox,
                                  char *code, size_t code_len,
                                  char *error, size_t error_len) {
  return fetch_latest_code_impl(db, mailbox, 0, code, code_len, error,
                                error_len);
}

int rapid_inbox_fetch_latest_code_since(sqlite3 *db, const char *mailbox,
                                        long min_received_at, char *code,
                                        size_t code_len, char *error,
                                        size_t error_len) {
  return fetch_latest_code_impl(db, mailbox, min_received_at, code, code_len,
                                error, error_len);
}
