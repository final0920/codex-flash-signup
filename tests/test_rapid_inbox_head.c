#include "http_client/http_client.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_http_rc = -1;
static long g_http_status = 0;
static const char *g_http_body = NULL;
static const char *g_http_error = NULL;
static char g_last_method[16];
static char g_last_url[1024];
static char g_last_body[1024];
static char g_last_header_name[64];
static char g_last_header_value[256];

int http_client_perform(const struct http_client_request *request,
                        struct http_client_response *response) {
  g_last_method[0] = '\0';
  g_last_url[0] = '\0';
  g_last_body[0] = '\0';
  g_last_header_name[0] = '\0';
  g_last_header_value[0] = '\0';
  if (request != NULL) {
    snprintf(g_last_method, sizeof(g_last_method), "%s",
             request->method ? request->method : "GET");
    snprintf(g_last_url, sizeof(g_last_url), "%s",
             request->url ? request->url : "");
    if (request->body != NULL) {
      snprintf(g_last_body, sizeof(g_last_body), "%.*s",
               (int) request->body_len, request->body);
    }
    if (request->num_headers > 0 && request->headers != NULL) {
      snprintf(g_last_header_name, sizeof(g_last_header_name), "%s",
               request->headers[0].name ? request->headers[0].name : "");
      snprintf(g_last_header_value, sizeof(g_last_header_value), "%s",
               request->headers[0].value ? request->headers[0].value : "");
    }
  }
  if (response != NULL) memset(response, 0, sizeof(*response));
  if (response != NULL) {
    response->status_code = g_http_status;
    if (g_http_body != NULL) {
      response->body = strdup(g_http_body);
      response->body_len = strlen(g_http_body);
    }
    if (g_http_error != NULL) {
      snprintf(response->error, sizeof(response->error), "%s", g_http_error);
    }
  }
  return g_http_rc;
}

void http_client_response_free(struct http_client_response *response) {
  if (response != NULL) free(response->body);
}

#include "../src/mail/rapid_inbox.c"

static int expect_string(const char *label, const char *actual,
                         const char *expected) {
  if (strcmp(actual, expected) == 0) return 0;
  fprintf(stderr, "%s: expected %s, got %s\n", label, expected, actual);
  return 1;
}

static sqlite3 *open_mail_test_db(const char *backend) {
  sqlite3 *db = NULL;
  char sql[1024];
  if (sqlite3_open(":memory:", &db) != SQLITE_OK) return NULL;
  snprintf(sql, sizeof(sql),
           "CREATE TABLE mail_settings(key TEXT PRIMARY KEY,value TEXT NOT "
           "NULL,updated_at INTEGER NOT NULL DEFAULT 0);"
           "INSERT INTO mail_settings(key,value) VALUES"
           "('rapid_inbox_base_url','https://temp-mail.example'),"
           "('rapid_inbox_api_key','admin-secret'),"
           "('rapid_inbox_backend','%s'),"
           "('rapid_inbox_transport','http');",
           backend);
  if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return NULL;
  }
  return db;
}

static void reset_otprelay_ws_state_for_test(void) {
  pthread_mutex_lock(&s_otprelay_ws.mu);
  s_otprelay_ws.started = false;
  s_otprelay_ws.stop = false;
  s_otprelay_ws.connecting = false;
  s_otprelay_ws.connected = false;
  s_otprelay_ws.subscribed = false;
  s_otprelay_ws.poll_requested = false;
  s_otprelay_ws.generation = 0;
  s_otprelay_ws.last_poll_sent_ms = 0;
  s_otprelay_ws.base_url[0] = '\0';
  s_otprelay_ws.ws_url[0] = '\0';
  s_otprelay_ws.domains_json[0] = '\0';
  s_otprelay_ws.last_error[0] = '\0';
  memset(s_otprelay_ws.cache, 0, sizeof(s_otprelay_ws.cache));
  s_otprelay_ws.cache_len = 0;
  s_otprelay_ws.cache_next = 0;
  otprelay_ws_clear_pending_acks_locked();
  pthread_mutex_unlock(&s_otprelay_ws.mu);
}

static int test_head_messages_extracts_preview_code(void) {
  const char *json =
      "{\"items\":[{\"delivery_id\":\"del_1\","
      "\"delivered_at\":\"2026-05-28T10:11:12Z\","
      "\"subject\":\"Verify your email\","
      "\"from_addr\":\"noreply@openai.com\","
      "\"text_preview\":\"Your OpenAI verification code is 123456.\","
      "\"verification_code\":null}]}";
  char code[16] = "";
  if (!copy_code_from_item(json, 0, code, sizeof(code))) {
    fprintf(stderr, "expected code in Rapid-Inbox-Head text_preview\n");
    return 1;
  }
  return expect_string("preview code", code, "123456");
}

static int test_head_messages_uses_delivered_at_timestamp(void) {
  const char *json =
      "{\"items\":[{\"delivery_id\":\"del_1\","
      "\"delivered_at\":\"2026-05-28T10:11:12Z\","
      "\"subject\":\"Verify your email\","
      "\"text_preview\":\"Your OpenAI verification code is 123456.\"}]}";
  long received_at = item_received_at(json, 0);
  if (received_at <= 0) {
    fprintf(stderr, "expected delivered_at to be parsed as epoch seconds\n");
    return 1;
  }
  return 0;
}

static int test_head_backend_codes_url_uses_messages_endpoint(void) {
  char backend[32];
  char url[512];
  normalize_backend("rapid-inbox-head", backend, sizeof(backend));
  if (expect_string("backend", backend, "rapid_inbox_head") != 0) return 1;
  if (!build_public_url("http://127.0.0.1:8000", "foo@adb.com", backend,
                        "codes", NULL, 20, url, sizeof(url))) {
    fprintf(stderr, "expected Rapid-Inbox-Head codes URL to build\n");
    return 1;
  }
  if (strstr(url, "/api/v1/public/mailboxes/foo%40adb.com/messages?limit=20") ==
      NULL) {
    fprintf(stderr, "unexpected Rapid-Inbox-Head codes URL: %s\n", url);
    return 1;
  }
  if (strstr(url, "verification-codes") != NULL) {
    fprintf(stderr, "Rapid-Inbox-Head codes URL used legacy endpoint: %s\n",
            url);
    return 1;
  }
  return 0;
}

static int test_head_codes_response_is_normalized_for_fetch_ui(void) {
  const char *json =
      "{\"items\":[{\"delivery_id\":\"del_1\","
      "\"delivered_at\":\"2026-05-28T10:11:12Z\","
      "\"message_id\":\"msg_1\","
      "\"subject\":\"Verify your email\","
      "\"from_addr\":\"noreply@openai.com\","
      "\"text_preview\":\"Your OpenAI verification code is 123456.\","
      "\"verification_code\":null}]}";
  char *normalized = rapid_inbox_head_codes_json(json, 20);
  int failed = 0;
  if (normalized == NULL) {
    fprintf(stderr, "expected normalized Head codes response\n");
    return 1;
  }
  if (strstr(normalized, "\"code\":\"123456\"") == NULL) {
    fprintf(stderr, "normalized response missing code: %s\n", normalized);
    failed = 1;
  }
  if (strstr(normalized, "\"received_at\":\"2026-05-28T10:11:12Z\"") == NULL) {
    fprintf(stderr, "normalized response missing delivered_at: %s\n",
            normalized);
    failed = 1;
  }
  free(normalized);
  return failed;
}

static int test_otprelay_claim_accepts_top_level_code_and_seconds_received_at(void) {
  const char *json =
      "{\"ok\":true,\"code\":\"654321\",\"id\":\"otp_1\","
      "\"claim_token\":\"claim_1\",\"received_at\":1772129472}";
  struct otprelay_claimed_record record;
  if (!extract_otprelay_claimed_record(json, &record)) {
    fprintf(stderr, "expected OTPRelay top-level code claim to parse\n");
    return 1;
  }
  if (expect_string("otprelay code", record.code, "654321") != 0) return 1;
  if (expect_string("otprelay id", record.id, "otp_1") != 0) return 1;
  if (expect_string("otprelay claim token", record.claim_token, "claim_1") != 0) {
    return 1;
  }
  if (record.received_at != 1772129472L) {
    fprintf(stderr, "otprelay received_at: expected 1772129472, got %ld\n",
            record.received_at);
    return 1;
  }
  return 0;
}

static int test_otprelay_claim_404_reports_mailbox_and_reason(void) {
  struct otprelay_claimed_record record;
  char error[256] = "";
  int rc;
  g_http_rc = 0;
  g_http_status = 404;
  g_http_body = "{\"ok\":false,\"error\":\"verification code not found\"}";
  g_http_error = NULL;

  rc = otprelay_claim_http("https://mailbot-web.nexahub.one",
                           "missing@codingplan.asia", 0, &record, error,
                           sizeof(error));
  if (rc != 0) {
    fprintf(stderr, "expected OTPRelay 404 to be a no-code result, got %d\n",
            rc);
    return 1;
  }
  if (strstr(error, "missing@codingplan.asia") == NULL ||
      strstr(error, "HTTP 404") == NULL ||
      strstr(error, "verification code not found") == NULL) {
    fprintf(stderr, "expected detailed OTPRelay 404 reason, got: %s\n", error);
    return 1;
  }
  return 0;
}

static int test_temp_mail_backend_normalizes_alias(void) {
  char backend[32];
  normalize_backend("temp-mail", backend, sizeof(backend));
  return expect_string("temp-mail backend", backend, "temp_mail");
}

static int test_temp_mail_fetch_latest_code_reads_admin_raw_mime(void) {
  sqlite3 *db = open_mail_test_db("temp_mail");
  char code[16] = "";
  char error[256] = "";
  int rc;
  if (db == NULL) {
    fprintf(stderr, "failed to open temp mail test db\n");
    return 1;
  }

  g_http_rc = 0;
  g_http_status = 200;
  g_http_body =
      "{\"results\":[{\"id\":42,\"message_id\":\"msg_1\","
      "\"source\":\"noreply@example.com\",\"address\":\"alice@example.com\","
      "\"created_at\":\"2026-05-30 10:00:00\","
      "\"raw\":\"Subject: Verify your email\\r\\n\\r\\nYour code is 112233.\"}],"
      "\"count\":1}";
  g_http_error = NULL;

  rc = rapid_inbox_fetch_latest_code_since(
      db, "alice@example.com", 0, code, sizeof(code), error, sizeof(error));
  sqlite3_close(db);
  if (rc != 1) {
    fprintf(stderr, "expected Temp-Mail code, rc=%d error=%s\n", rc, error);
    return 1;
  }
  if (expect_string("temp-mail code", code, "112233") != 0) return 1;
  if (expect_string("temp-mail method", g_last_method, "GET") != 0) return 1;
  if (strstr(g_last_url,
             "https://temp-mail.example/admin/mails?limit=20&offset=0&address=alice%40example.com") ==
      NULL) {
    fprintf(stderr, "unexpected Temp-Mail mails URL: %s\n", g_last_url);
    return 1;
  }
  if (expect_string("temp-mail auth header", g_last_header_name,
                    "x-admin-auth") != 0) {
    return 1;
  }
  return expect_string("temp-mail auth value", g_last_header_value,
                       "admin-secret");
}

static int test_temp_mail_fetch_ui_normalizes_codes_response(void) {
  sqlite3 *db = open_mail_test_db("temp_mail");
  char *json;
  int failed = 0;
  if (db == NULL) {
    fprintf(stderr, "failed to open temp mail test db\n");
    return 1;
  }
  g_http_rc = 0;
  g_http_status = 200;
  g_http_body =
      "{\"results\":[{\"id\":42,\"message_id\":\"msg_1\","
      "\"source\":\"noreply@example.com\","
      "\"created_at\":\"2026-05-30 10:00:00\","
      "\"raw\":\"Subject: Verify your email\\r\\n\\r\\nYour code is 112233.\"}],"
      "\"count\":1}";
  g_http_error = NULL;

  json = rapid_inbox_fetch_json(db, "alice@example.com", "codes", NULL, 20);
  sqlite3_close(db);
  if (json == NULL) {
    fprintf(stderr, "expected Temp-Mail fetch JSON\n");
    return 1;
  }
  if (strstr(json, "\"status_code\":200") == NULL ||
      strstr(json, "/admin/mails?limit=20") == NULL) {
    fprintf(stderr, "Temp-Mail fetch response missing status or endpoint: %s\n",
            json);
    failed = 1;
  }
  if (strstr(json, "\\\"code\\\":\\\"112233\\\"") == NULL ||
      strstr(json, "\\\"received_at\\\":\\\"2026-05-30 10:00:00\\\"") == NULL) {
    fprintf(stderr, "Temp-Mail codes response not normalized: %s\n", json);
    failed = 1;
  }
  free(json);
  return failed;
}

static int test_temp_mail_provision_posts_new_address(void) {
  sqlite3 *db = open_mail_test_db("temp_mail");
  char error[256] = "";
  int rc;
  if (db == NULL) {
    fprintf(stderr, "failed to open temp mail test db\n");
    return 1;
  }
  g_http_rc = 0;
  g_http_status = 200;
  g_http_body =
      "{\"jwt\":\"jwt_1\",\"address\":\"alice@example.com\",\"address_id\":7}";
  g_http_error = NULL;

  rc = rapid_inbox_provision_mailbox(db, "alice@example.com", error,
                                     sizeof(error));
  sqlite3_close(db);
  if (rc != 0) {
    fprintf(stderr, "expected Temp-Mail provision success, got error=%s\n",
            error);
    return 1;
  }
  if (expect_string("temp-mail provision method", g_last_method, "POST") != 0) {
    return 1;
  }
  if (expect_string("temp-mail provision url", g_last_url,
                    "https://temp-mail.example/admin/new_address") != 0) {
    return 1;
  }
  if (expect_string("temp-mail provision auth header", g_last_header_name,
                    "x-admin-auth") != 0) {
    return 1;
  }
  if (strstr(g_last_body, "\"enablePrefix\":false") == NULL ||
      strstr(g_last_body, "\"name\":\"alice\"") == NULL ||
      strstr(g_last_body, "\"domain\":\"example.com\"") == NULL) {
    fprintf(stderr, "unexpected Temp-Mail provision body: %s\n", g_last_body);
    return 1;
  }
  return 0;
}

static int test_otprelay_ws_transport_queues_ack_without_http(void) {
  sqlite3 *db = open_mail_test_db("otprelay");
  size_t ack_len = 0;
  char id[64] = "";
  char claim_token[96] = "";
  if (db == NULL) {
    fprintf(stderr, "failed to open OTPRelay test db\n");
    return 1;
  }
  if (sqlite3_exec(db,
                   "UPDATE mail_settings SET value='ws' "
                   "WHERE key='rapid_inbox_transport';",
                   NULL, NULL, NULL) != SQLITE_OK) {
    fprintf(stderr, "failed to switch OTPRelay transport to ws\n");
    sqlite3_close(db);
    return 1;
  }

  reset_otprelay_ws_state_for_test();
  g_last_method[0] = '\0';
  g_last_url[0] = '\0';

  otprelay_ack_claimed_code(db, "https://mailbot.example", "ver_ws_1",
                            "claim_ws_1");

  pthread_mutex_lock(&s_otprelay_ws.mu);
  ack_len = s_otprelay_ws.ack_len;
  if (ack_len == 1) {
    snprintf(id, sizeof(id), "%s",
             s_otprelay_ws.pending_acks[s_otprelay_ws.ack_head].id);
    snprintf(claim_token, sizeof(claim_token), "%s",
             s_otprelay_ws.pending_acks[s_otprelay_ws.ack_head].claim_token);
  }
  otprelay_ws_clear_pending_acks_locked();
  pthread_mutex_unlock(&s_otprelay_ws.mu);
  sqlite3_close(db);

  if (ack_len != 1) {
    fprintf(stderr, "expected one pending WS ACK, got %zu\n", ack_len);
    return 1;
  }
  if (expect_string("ws ack id", id, "ver_ws_1") != 0) return 1;
  if (expect_string("ws ack claim token", claim_token, "claim_ws_1") != 0) {
    return 1;
  }
  if (g_last_method[0] != '\0' || g_last_url[0] != '\0') {
    fprintf(stderr, "expected no HTTP ACK in ws mode, got %s %s\n",
            g_last_method, g_last_url);
    return 1;
  }
  return 0;
}

static int test_otprelay_ws_cache_miss_requests_ws_poll_without_http(void) {
  sqlite3 *db = open_mail_test_db("otprelay");
  struct otprelay_claimed_record record;
  char error[256] = "";
  bool poll_requested;
  int rc;
  if (db == NULL) {
    fprintf(stderr, "failed to open OTPRelay test db\n");
    return 1;
  }
  if (sqlite3_exec(db,
                   "UPDATE mail_settings SET value='ws' "
                   "WHERE key='rapid_inbox_transport';"
                   "CREATE TABLE mail_domain_rules("
                   "base_domain TEXT,is_active INTEGER);"
                   "INSERT INTO mail_domain_rules(base_domain,is_active) "
                   "VALUES('example.com',1);",
                   NULL, NULL, NULL) != SQLITE_OK) {
    fprintf(stderr, "failed to prepare OTPRelay ws domain config\n");
    sqlite3_close(db);
    return 1;
  }

  reset_otprelay_ws_state_for_test();
  pthread_mutex_lock(&s_otprelay_ws.mu);
  s_otprelay_ws.started = true;
  pthread_mutex_unlock(&s_otprelay_ws.mu);
  g_last_method[0] = '\0';
  g_last_url[0] = '\0';

  rc = otprelay_claim_code(db, "https://mailbot.example",
                           "alice@example.com", 0, &record, error,
                           sizeof(error));

  pthread_mutex_lock(&s_otprelay_ws.mu);
  poll_requested = s_otprelay_ws.poll_requested;
  pthread_mutex_unlock(&s_otprelay_ws.mu);
  reset_otprelay_ws_state_for_test();
  sqlite3_close(db);

  if (rc != 0) {
    fprintf(stderr, "expected ws cache miss, rc=%d error=%s\n", rc, error);
    return 1;
  }
  if (!poll_requested) {
    fprintf(stderr, "expected ws cache miss to request websocket poll\n");
    return 1;
  }
  if (g_last_method[0] != '\0' || g_last_url[0] != '\0') {
    fprintf(stderr, "expected no HTTP claim in ws mode, got %s %s\n",
            g_last_method, g_last_url);
    return 1;
  }
  return 0;
}

int main(void) {
  int failures = 0;
  failures += test_head_messages_extracts_preview_code();
  failures += test_head_messages_uses_delivered_at_timestamp();
  failures += test_head_backend_codes_url_uses_messages_endpoint();
  failures += test_head_codes_response_is_normalized_for_fetch_ui();
  failures += test_otprelay_claim_accepts_top_level_code_and_seconds_received_at();
  failures += test_otprelay_claim_404_reports_mailbox_and_reason();
  failures += test_temp_mail_backend_normalizes_alias();
  failures += test_temp_mail_fetch_latest_code_reads_admin_raw_mime();
  failures += test_temp_mail_fetch_ui_normalizes_codes_response();
  failures += test_temp_mail_provision_posts_new_address();
  failures += test_otprelay_ws_transport_queues_ack_without_http();
  failures += test_otprelay_ws_cache_miss_requests_ws_poll_without_http();
  if (failures != 0) return 1;
  puts("rapid_inbox_head parser tests passed");
  return 0;
}
