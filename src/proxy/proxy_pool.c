#include "proxy/proxy_pool.h"

#include "http_client/browser_profile.h"
#include "http_client/http_client.h"
#include "mongoose.h"
#include "proxy/mihomo_manager.h"

#include <ctype.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define TRACE_URL "https://cloudflare.com/cdn-cgi/trace"
#define TRACE_DOH_URL "https://1.1.1.1/dns-query"

struct parsed_proxy {
  char scheme[16];
  char host[256];
  int port;
  char username[128];
  char password[128];
  char proxy_url[768];
};

struct trace_result {
  bool ok;
  long http_status;
  char exit_ip[128];
  char loc[16];
  char colo[16];
  char http[32];
  char tls[32];
  char error[256];
};

static char *trim(char *s) {
  char *end;
  while (*s && isspace((unsigned char) *s)) s++;
  end = s + strlen(s);
  while (end > s && isspace((unsigned char) end[-1])) *--end = '\0';
  return s;
}

static bool valid_scheme(const char *scheme) {
  return strcasecmp(scheme, "http") == 0 ||
         strcasecmp(scheme, "socks5") == 0 ||
         strcasecmp(scheme, "socks5h") == 0;
}

static void lower_copy(char *dst, size_t dstlen, const char *src) {
  size_t i = 0;
  if (dstlen == 0) return;
  for (; src[i] && i + 1 < dstlen; i++) {
    dst[i] = (char) tolower((unsigned char) src[i]);
  }
  dst[i] = '\0';
}

static int parse_proxy_line(const char *line, struct parsed_proxy *out) {
  char buf[1024], work[1024], *p, *scheme_end, *authority, *at, *hostport;
  char *colon;

  if (line == NULL || out == NULL) return -1;
  memset(out, 0, sizeof(*out));
  mg_snprintf(buf, sizeof(buf), "%s", line);
  p = trim(buf);
  if (*p == '\0' || *p == '#') return 1;

  if (strstr(p, "://") == NULL) {
    mg_snprintf(work, sizeof(work), "http://%s", p);
  } else {
    mg_snprintf(work, sizeof(work), "%s", p);
  }

  scheme_end = strstr(work, "://");
  if (scheme_end == NULL) return -1;
  *scheme_end = '\0';
  lower_copy(out->scheme, sizeof(out->scheme), work);
  if (!valid_scheme(out->scheme)) return -1;

  authority = scheme_end + 3;
  if (*authority == '\0' || strchr(authority, '/') != NULL) return -1;

  at = strrchr(authority, '@');
  hostport = authority;
  if (at != NULL) {
    char *cred = authority;
    *at = '\0';
    hostport = at + 1;
    colon = strchr(cred, ':');
    if (colon != NULL) {
      *colon = '\0';
      mg_snprintf(out->username, sizeof(out->username), "%s", cred);
      mg_snprintf(out->password, sizeof(out->password), "%s", colon + 1);
    } else {
      mg_snprintf(out->username, sizeof(out->username), "%s", cred);
    }
  }

  if (hostport[0] == '[') {
    char *close = strchr(hostport, ']');
    if (close == NULL || close[1] != ':') return -1;
    *close = '\0';
    mg_snprintf(out->host, sizeof(out->host), "%s", hostport + 1);
    out->port = atoi(close + 2);
  } else {
    colon = strrchr(hostport, ':');
    if (colon == NULL) return -1;
    *colon = '\0';
    mg_snprintf(out->host, sizeof(out->host), "%s", hostport);
    out->port = atoi(colon + 1);
  }

  if (out->host[0] == '\0' || out->port <= 0 || out->port > 65535) return -1;
  if (out->username[0] != '\0') {
    mg_snprintf(out->proxy_url, sizeof(out->proxy_url), "%s://%s:%s@%s:%d",
                out->scheme, out->username, out->password, out->host, out->port);
  } else {
    mg_snprintf(out->proxy_url, sizeof(out->proxy_url), "%s://%s:%d",
                out->scheme, out->host, out->port);
  }
  return 0;
}

static int insert_proxy(sqlite3 *db, const struct parsed_proxy *p) {
  sqlite3_stmt *stmt = NULL;
  int rc, changed;
  const char *sql =
      "INSERT OR IGNORE INTO proxy_nodes "
      "(scheme,host,port,username,password,proxy_url,status,created_at,updated_at) "
      "VALUES (?,?,?,?,?,?,'new',unixepoch(),unixepoch())";
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
  sqlite3_bind_text(stmt, 1, p->scheme, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, p->host, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, p->port);
  if (p->username[0]) sqlite3_bind_text(stmt, 4, p->username, -1, SQLITE_TRANSIENT);
  else sqlite3_bind_null(stmt, 4);
  if (p->password[0]) sqlite3_bind_text(stmt, 5, p->password, -1, SQLITE_TRANSIENT);
  else sqlite3_bind_null(stmt, 5);
  sqlite3_bind_text(stmt, 6, p->proxy_url, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(stmt);
  changed = sqlite3_changes(db);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return -1;
  return changed > 0 ? 1 : 0;
}

int proxy_pool_import_text(sqlite3 *db, const char *text,
                           struct proxy_import_result *result) {
  char *copy, *line, *save = NULL;
  if (db == NULL || text == NULL || result == NULL) return -1;
  memset(result, 0, sizeof(*result));
  copy = strdup(text);
  if (copy == NULL) return -1;

  sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
  for (line = strtok_r(copy, "\r\n", &save); line != NULL;
       line = strtok_r(NULL, "\r\n", &save)) {
    struct parsed_proxy parsed;
    int rc = parse_proxy_line(line, &parsed);
    if (rc == 1) continue;
    if (rc != 0) {
      result->invalid++;
      continue;
    }
    rc = insert_proxy(db, &parsed);
    if (rc > 0) result->imported++;
    else if (rc == 0) result->skipped++;
    else result->invalid++;
  }
  sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
  free(copy);
  return 0;
}

static const char *column_text(sqlite3_stmt *stmt, int col) {
  const unsigned char *s = sqlite3_column_text(stmt, col);
  return s == NULL ? "" : (const char *) s;
}

char *proxy_pool_list_json(sqlite3 *db) {
  sqlite3_stmt *stmt = NULL;
  struct mg_iobuf io = {0, 0, 0, 512};
  bool first = true;
  const char *sql =
      "SELECT id,scheme,host,port,username,proxy_url,status,last_test_ok,"
      "last_http_status,exit_ip,exit_loc,exit_colo,trace_http,trace_tls,"
      "last_error,last_tested_at,created_at,updated_at "
      "FROM proxy_nodes ORDER BY id DESC";

  mg_xprintf(mg_pfn_iobuf, &io, "{\"items\":[");
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      if (!first) mg_xprintf(mg_pfn_iobuf, &io, ",");
      first = false;
      mg_xprintf(
          mg_pfn_iobuf, &io,
          "{%m:%lld,%m:%m,%m:%m,%m:%d,%m:%m,%m:%m,%m:%m,%m:%d,%m:%lld,"
          "%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%lld,%m:%lld,%m:%lld}",
          MG_ESC("id"), sqlite3_column_int64(stmt, 0),
          MG_ESC("scheme"), MG_ESC(column_text(stmt, 1)),
          MG_ESC("host"), MG_ESC(column_text(stmt, 2)),
          MG_ESC("port"), sqlite3_column_int(stmt, 3),
          MG_ESC("username"), MG_ESC(column_text(stmt, 4)),
          MG_ESC("proxy_url"), MG_ESC(column_text(stmt, 5)),
          MG_ESC("status"), MG_ESC(column_text(stmt, 6)),
          MG_ESC("last_test_ok"), sqlite3_column_int(stmt, 7),
          MG_ESC("last_http_status"), sqlite3_column_int64(stmt, 8),
          MG_ESC("exit_ip"), MG_ESC(column_text(stmt, 9)),
          MG_ESC("exit_loc"), MG_ESC(column_text(stmt, 10)),
          MG_ESC("exit_colo"), MG_ESC(column_text(stmt, 11)),
          MG_ESC("trace_http"), MG_ESC(column_text(stmt, 12)),
          MG_ESC("trace_tls"), MG_ESC(column_text(stmt, 13)),
          MG_ESC("last_error"), MG_ESC(column_text(stmt, 14)),
          MG_ESC("last_tested_at"), sqlite3_column_int64(stmt, 15),
          MG_ESC("created_at"), sqlite3_column_int64(stmt, 16),
          MG_ESC("updated_at"), sqlite3_column_int64(stmt, 17));
    }
  }
  sqlite3_finalize(stmt);
  mg_xprintf(mg_pfn_iobuf, &io, "]}");
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

int proxy_pool_delete_ids(sqlite3 *db, const long *ids, size_t count) {
  sqlite3_stmt *stmt = NULL;
  int deleted = 0;
  if (db == NULL || ids == NULL || count == 0) return 0;
  if (sqlite3_prepare_v2(db, "DELETE FROM proxy_nodes WHERE id=?", -1, &stmt,
                         NULL) != SQLITE_OK) {
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
  return deleted;
}

static void trace_value(const char *body, const char *key, char *out,
                        size_t outlen) {
  const char *p;
  size_t keylen = strlen(key), len = 0;
  if (outlen == 0) return;
  out[0] = '\0';
  if (body == NULL) return;
  for (p = body; *p; p++) {
    if ((p == body || p[-1] == '\n') && strncmp(p, key, keylen) == 0 &&
        p[keylen] == '=') {
      p += keylen + 1;
      while (p[len] && p[len] != '\r' && p[len] != '\n') len++;
      if (len >= outlen) len = outlen - 1;
      memcpy(out, p, len);
      out[len] = '\0';
      return;
    }
  }
}

static bool proxy_url_has_scheme(const char *url, const char *scheme) {
  size_t len;
  if (url == NULL || scheme == NULL) return false;
  len = strlen(scheme);
  return strncasecmp(url, scheme, len) == 0 && strncmp(url + len, "://", 3) == 0;
}

static void test_proxy(const char *proxy_url, struct trace_result *result) {
  struct browser_profile profile;
  struct http_client_request req;
  struct http_client_response res;

  memset(result, 0, sizeof(*result));
  browser_profile_generate(&profile, "US", "desktop");
  memset(&req, 0, sizeof(req));
  req.method = "GET";
  req.url = TRACE_URL;
  req.proxy_url = proxy_url;
  req.timeout_ms = 12000;
  req.profile = &profile;
  if (proxy_url_has_scheme(proxy_url, "socks5")) {
    req.ip_resolve = HTTP_CLIENT_IPRESOLVE_V4;
    req.doh_url = TRACE_DOH_URL;
  }

  if (http_client_perform(&req, &res) != 0) {
    mg_snprintf(result->error, sizeof(result->error), "%s", res.error);
    return;
  }
  result->http_status = res.status_code;
  trace_value(res.body, "ip", result->exit_ip, sizeof(result->exit_ip));
  trace_value(res.body, "loc", result->loc, sizeof(result->loc));
  trace_value(res.body, "colo", result->colo, sizeof(result->colo));
  trace_value(res.body, "http", result->http, sizeof(result->http));
  trace_value(res.body, "tls", result->tls, sizeof(result->tls));
  if (res.status_code == 200 && result->exit_ip[0] != '\0') {
    result->ok = true;
  } else {
    mg_snprintf(result->error, sizeof(result->error), "HTTP %ld",
                res.status_code);
  }
  http_client_response_free(&res);
}

static void update_test_result(sqlite3 *db, long id,
                               const struct trace_result *result) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "UPDATE proxy_nodes SET status=?,last_test_ok=?,last_http_status=?,"
      "exit_ip=?,exit_loc=?,exit_colo=?,trace_http=?,trace_tls=?,last_error=?,"
      "last_tested_at=unixepoch(),updated_at=unixepoch() WHERE id=?";
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return;
  sqlite3_bind_text(stmt, 1, result->ok ? "active" : "failed", -1,
                    SQLITE_STATIC);
  sqlite3_bind_int(stmt, 2, result->ok ? 1 : 0);
  sqlite3_bind_int64(stmt, 3, result->http_status);
  sqlite3_bind_text(stmt, 4, result->exit_ip, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, result->loc, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, result->colo, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 7, result->http, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 8, result->tls, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 9, result->error, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 10, id);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

static char **load_proxy_urls(sqlite3 *db, const long *ids, size_t count,
                              long **out_ids, size_t *out_count) {
  sqlite3_stmt *stmt = NULL;
  char **urls = NULL;
  long *loaded_ids = NULL;
  size_t len = 0, cap = 0;
  const char *sql_all = "SELECT id,proxy_url FROM proxy_nodes ORDER BY id";
  const char *sql_one = "SELECT id,proxy_url FROM proxy_nodes WHERE id=?";

  *out_ids = NULL;
  *out_count = 0;
  if (count == 0) {
    if (sqlite3_prepare_v2(db, sql_all, -1, &stmt, NULL) != SQLITE_OK) return NULL;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      if (len == cap) {
        cap = cap == 0 ? 16 : cap * 2;
        urls = (char **) realloc(urls, cap * sizeof(*urls));
        loaded_ids = (long *) realloc(loaded_ids, cap * sizeof(*loaded_ids));
      }
      loaded_ids[len] = (long) sqlite3_column_int64(stmt, 0);
      urls[len] = strdup(column_text(stmt, 1));
      len++;
    }
    sqlite3_finalize(stmt);
  } else {
    if (sqlite3_prepare_v2(db, sql_one, -1, &stmt, NULL) != SQLITE_OK) return NULL;
    for (size_t i = 0; i < count; i++) {
      sqlite3_reset(stmt);
      sqlite3_clear_bindings(stmt);
      sqlite3_bind_int64(stmt, 1, ids[i]);
      if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (len == cap) {
          cap = cap == 0 ? 16 : cap * 2;
          urls = (char **) realloc(urls, cap * sizeof(*urls));
          loaded_ids = (long *) realloc(loaded_ids, cap * sizeof(*loaded_ids));
        }
        loaded_ids[len] = (long) sqlite3_column_int64(stmt, 0);
        urls[len] = strdup(column_text(stmt, 1));
        len++;
      }
    }
    sqlite3_finalize(stmt);
  }
  *out_ids = loaded_ids;
  *out_count = len;
  return urls;
}

char *proxy_pool_test_ids(sqlite3 *db, const long *ids, size_t count) {
  long *loaded_ids = NULL;
  char **urls = load_proxy_urls(db, ids, count, &loaded_ids, &count);
  struct mg_iobuf io = {0, 0, 0, 512};

  mg_xprintf(mg_pfn_iobuf, &io, "{\"items\":[");
  for (size_t i = 0; i < count; i++) {
    struct trace_result result;
    test_proxy(urls[i], &result);
    update_test_result(db, loaded_ids[i], &result);
    if (i > 0) mg_xprintf(mg_pfn_iobuf, &io, ",");
    mg_xprintf(mg_pfn_iobuf, &io,
               "{%m:%ld,%m:%m,%m:%d,%m:%ld,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,"
               "%m:%m}",
               MG_ESC("id"), loaded_ids[i],
               MG_ESC("proxy_url"), MG_ESC(urls[i]),
               MG_ESC("ok"), result.ok ? 1 : 0,
               MG_ESC("http_status"), result.http_status,
               MG_ESC("exit_ip"), MG_ESC(result.exit_ip),
               MG_ESC("exit_loc"), MG_ESC(result.loc),
               MG_ESC("exit_colo"), MG_ESC(result.colo),
               MG_ESC("trace_http"), MG_ESC(result.http),
               MG_ESC("trace_tls"), MG_ESC(result.tls),
               MG_ESC("error"), MG_ESC(result.error));
    free(urls[i]);
  }
  free(urls);
  free(loaded_ids);
  mg_xprintf(mg_pfn_iobuf, &io, "]}");
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

int proxy_pool_pick_active_url(sqlite3 *db, char *url, size_t url_len) {
  sqlite3_stmt *stmt = NULL;
  int result = 0;
  int runtime_handled = 0;
  const char *sql =
      "SELECT proxy_url FROM proxy_nodes WHERE status='active' "
      "ORDER BY CASE scheme "
      "WHEN 'socks5h' THEN 0 WHEN 'http' THEN 1 WHEN 'socks5' THEN 2 "
      "ELSE 3 END, random() LIMIT 1";

  if (url != NULL && url_len > 0) url[0] = '\0';
  if (db == NULL || url == NULL || url_len == 0) return -1;
  result = mihomo_proxy_pick_url(db, url, url_len, &runtime_handled);
  if (runtime_handled) return result;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    mg_snprintf(url, url_len, "%s", column_text(stmt, 0));
    result = url[0] != '\0' ? 1 : 0;
  }
  sqlite3_finalize(stmt);
  return result;
}
