#include "account/account_token_validator.h"

#include "flow/flow_libcurl_impersonate.h"
#include "http_client/browser_profile.h"
#include "mongoose.h"
#include "proxy/proxy_pool.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define OAUTH_TOKEN_URL "https://auth.openai.com/oauth/token"
#define OAUTH_CLIENT_ID "app_EMoamEEZ73f0CkXaXp7hrann"
#define OAUTH_REDIRECT_URI "http://localhost:1455/auth/callback"
#define TOKEN_REFRESH_TIMEOUT_MS 30000L
#define TOKEN_VALIDATE_URL "https://chatgpt.com/backend-api/me"
#define TOKEN_VALIDATE_TIMEOUT_MS 30000L

struct token_validation_result {
  bool valid;
  bool definitive;
  long http_status;
  char error[256];
};

struct token_refresh_result {
  bool success;
  bool definitive;
  bool rotated;
  long http_status;
  long expires_in;
  char *access_token;
  char *refresh_token;
  char error[256];
};

static const char *column_text(sqlite3_stmt *stmt, int col) {
  const unsigned char *s = sqlite3_column_text(stmt, col);
  return s == NULL ? "" : (const char *) s;
}

static bool body_looks_html_challenge(const char *body) {
  const char *p = body;
  if (p == NULL) return false;
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
  return strncasecmp(p, "<html", 5) == 0 || strstr(p, "Just a moment") != NULL ||
         strstr(p, "cf-mitigated") != NULL;
}

static void classify_http_status(struct token_validation_result *result,
                                 long status, const char *body) {
  result->http_status = status;
  if (status == 200) {
    result->valid = true;
    result->definitive = true;
  } else if (status == 401) {
    result->definitive = true;
    mg_snprintf(result->error, sizeof(result->error), "Token 无效或已过期");
  } else if (status == 403 && body_looks_html_challenge(body)) {
    mg_snprintf(result->error, sizeof(result->error),
                "验证被风控拦截: HTTP 403");
  } else if (status == 403) {
    result->definitive = true;
    mg_snprintf(result->error, sizeof(result->error), "账号可能被封禁");
  } else {
    mg_snprintf(result->error, sizeof(result->error), "验证失败: HTTP %ld",
                status);
  }
}

static void trim_line(char *s) {
  size_t len;
  if (s == NULL) return;
  len = strlen(s);
  while (len > 0 && (s[len - 1] == '\r' || s[len - 1] == '\n' ||
                     s[len - 1] == ' ' || s[len - 1] == '\t')) {
    s[--len] = '\0';
  }
  while (*s == ' ' || *s == '\t') memmove(s, s + 1, strlen(s));
}

static int load_access_token(sqlite3 *db, long id, char **out_token) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "SELECT COALESCE(s.access_token,'') "
      "FROM accounts a LEFT JOIN account_secrets s ON s.account_id=a.id "
      "WHERE a.id=?";
  int result = -1;

  if (out_token != NULL) *out_token = NULL;
  if (db == NULL || id <= 0 || out_token == NULL) return -1;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
  sqlite3_bind_int64(stmt, 1, id);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *token = column_text(stmt, 0);
    *out_token = strdup(token);
    result = *out_token != NULL ? 1 : -1;
  } else {
    result = 0;
  }
  sqlite3_finalize(stmt);
  return result;
}

static int load_refresh_token(sqlite3 *db, long id, char **out_token) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "SELECT COALESCE(s.refresh_token,'') "
      "FROM accounts a LEFT JOIN account_secrets s ON s.account_id=a.id "
      "WHERE a.id=?";
  int result = -1;

  if (out_token != NULL) *out_token = NULL;
  if (db == NULL || id <= 0 || out_token == NULL) return -1;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
  sqlite3_bind_int64(stmt, 1, id);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *token = column_text(stmt, 0);
    *out_token = strdup(token);
    result = *out_token != NULL ? 1 : -1;
  } else {
    result = 0;
  }
  sqlite3_finalize(stmt);
  return result;
}

static void update_status(sqlite3 *db, long id, const char *status) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "UPDATE accounts SET status=?,updated_at=unixepoch() "
      "WHERE id=? AND status<>?";

  if (db == NULL || id <= 0 || status == NULL || status[0] == '\0') return;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return;
  sqlite3_bind_text(stmt, 1, status, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 2, id);
  sqlite3_bind_text(stmt, 3, status, -1, SQLITE_TRANSIENT);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

static void apply_validation_status(sqlite3 *db, long id,
                                    const struct token_validation_result *r) {
  if (r == NULL) return;
  if (r->valid) {
    update_status(db, id, "active");
  } else if (r->definitive && r->http_status == 403) {
    update_status(db, id, "failed");
  } else if (r->definitive) {
    update_status(db, id, "expired");
  }
}

static char *form_encode(const char *value) {
  size_t len = value == NULL ? 0 : strlen(value);
  size_t out_len = len * 3 + 1;
  char *out = (char *) calloc(1, out_len == 0 ? 1 : out_len);
  if (out == NULL) return NULL;
  if (len == 0) return out;
  if (mg_url_encode(value, len, out, out_len) >= out_len) {
    free(out);
    return NULL;
  }
  return out;
}

static char *build_refresh_request_body(const char *refresh_token) {
  char *refresh_enc = NULL;
  char *redirect_enc = NULL;
  char *body = NULL;
  size_t body_len;

  refresh_enc = form_encode(refresh_token);
  redirect_enc = form_encode(OAUTH_REDIRECT_URI);
  if (refresh_enc == NULL || redirect_enc == NULL) goto done;

  body_len = strlen("grant_type=refresh_token&client_id=&refresh_token=&redirect_uri=") +
             strlen(OAUTH_CLIENT_ID) + strlen(refresh_enc) +
             strlen(redirect_enc) + 1;
  body = (char *) calloc(1, body_len);
  if (body == NULL) goto done;
  mg_snprintf(body, body_len,
              "grant_type=refresh_token&client_id=%s&refresh_token=%s"
              "&redirect_uri=%s",
              OAUTH_CLIENT_ID, refresh_enc, redirect_enc);

done:
  free(refresh_enc);
  free(redirect_enc);
  return body;
}

static char *json_string_or_null(struct mg_str json, const char *path) {
  char *value = mg_json_get_str(json, path);
  if (value == NULL || value[0] == '\0') {
    mg_free(value);
    return NULL;
  }
  return value;
}

static void parse_refresh_error(struct token_refresh_result *result,
                                long status, const char *body) {
  struct mg_str json = mg_str(body ? body : "");
  char *message = NULL;
  const char *fallback = body ? body : "";
  char preview[180];

  result->http_status = status;
  message = json_string_or_null(json, "$.error.message");
  if (message == NULL) message = json_string_or_null(json, "$.error_description");
  if (message == NULL) message = json_string_or_null(json, "$.message");
  if (message == NULL) message = json_string_or_null(json, "$.error");

  if (message != NULL &&
      strcasestr(message, "refresh token has already been used") != NULL) {
    result->definitive = true;
    mg_snprintf(result->error, sizeof(result->error),
                "OAuth refresh_token 已失效（一次性令牌已被使用），请重新登录该账号");
  } else if (message != NULL &&
             (strcasestr(message, "invalid_grant") != NULL ||
              strcasestr(message, "invalidated") != NULL ||
              (strcasestr(message, "refresh") != NULL &&
               strcasestr(message, "invalid") != NULL))) {
    result->definitive = true;
    mg_snprintf(result->error, sizeof(result->error),
                "OAuth refresh_token 已失效: %s", message);
  } else if (status == 401) {
    result->definitive = true;
    if (message != NULL) {
      mg_snprintf(result->error, sizeof(result->error),
                  "OAuth token 刷新失败: %s", message);
    } else {
      mg_snprintf(result->error, sizeof(result->error),
                  "OAuth token 刷新失败: refresh_token 无效或已过期，请重新登录账号");
    }
  } else if (message != NULL) {
    mg_snprintf(result->error, sizeof(result->error),
                "OAuth token 刷新失败: %s", message);
  } else if (fallback[0] != '\0') {
    mg_snprintf(preview, sizeof(preview), "%.*s", 160, fallback);
    trim_line(preview);
    mg_snprintf(result->error, sizeof(result->error),
                "OAuth token 刷新失败: HTTP %ld, 响应: %s", status, preview);
  } else {
    mg_snprintf(result->error, sizeof(result->error),
                "OAuth token 刷新失败: HTTP %ld", status);
  }
  mg_free(message);
}

static void parse_refresh_success_or_error(struct token_refresh_result *result,
                                           long status, const char *body,
                                           const char *old_refresh_token) {
  struct mg_str json = mg_str(body ? body : "");
  char *access_token = NULL;
  char *new_refresh_token = NULL;
  long expires_in;

  result->http_status = status;
  if (status != 200) {
    parse_refresh_error(result, status, body);
    return;
  }

  access_token = mg_json_get_str(json, "$.access_token");
  new_refresh_token = mg_json_get_str(json, "$.refresh_token");
  expires_in = mg_json_get_long(json, "$.expires_in", 0);
  if (access_token == NULL || access_token[0] == '\0') {
    mg_free(access_token);
    mg_free(new_refresh_token);
    mg_snprintf(result->error, sizeof(result->error),
                "OAuth token 刷新失败: 未找到 access_token");
    return;
  }

  if (new_refresh_token == NULL || new_refresh_token[0] == '\0') {
    mg_free(new_refresh_token);
    new_refresh_token = strdup(old_refresh_token ? old_refresh_token : "");
    if (new_refresh_token == NULL) {
      mg_free(access_token);
      mg_snprintf(result->error, sizeof(result->error), "内存分配失败");
      return;
    }
  }

  result->success = true;
  result->definitive = true;
  result->access_token = access_token;
  result->refresh_token = new_refresh_token;
  result->expires_in = expires_in > 0 ? expires_in : 3600;
  result->rotated =
      old_refresh_token != NULL && strcmp(new_refresh_token, old_refresh_token) != 0;
}

static void token_refresh_result_free(struct token_refresh_result *result) {
  if (result == NULL) return;
  mg_free(result->access_token);
  free(result->refresh_token);
  result->access_token = NULL;
  result->refresh_token = NULL;
}

static void refresh_token_with_libcurl_impersonate(
    const char *refresh_token, const char *proxy_url,
    struct token_refresh_result *result) {
  struct browser_profile profile;
  struct flow_http_header headers[2];
  struct flow_http_request req;
  struct flow_http_response res;
  char *body = NULL;
  char error[FLOW_ERROR_LEN] = "";

  body = build_refresh_request_body(refresh_token);
  if (body == NULL) {
    mg_snprintf(result->error, sizeof(result->error), "构造刷新请求失败");
    return;
  }

  browser_profile_generate(&profile, "US", "desktop");
  headers[0].name = "Content-Type";
  headers[0].value = "application/x-www-form-urlencoded";
  headers[1].name = "Accept";
  headers[1].value = "application/json";

  memset(&req, 0, sizeof(req));
  memset(&res, 0, sizeof(res));
  req.method = "POST";
  req.url = OAUTH_TOKEN_URL;
  req.timeout_ms = TOKEN_REFRESH_TIMEOUT_MS;
  req.body = body;
  req.body_len = strlen(body);
  req.headers = headers;
  req.num_headers = sizeof(headers) / sizeof(headers[0]);

  if (flow_libcurl_impersonate_perform(&req, proxy_url, &profile, &res, error,
                                       sizeof(error)) != 0) {
    mg_snprintf(result->error, sizeof(result->error),
                "OAuth token 刷新异常: libcurl-impersonate: %s",
                error[0] ? error : "请求失败");
    free(body);
    free(res.body);
    return;
  }

  parse_refresh_success_or_error(result, res.status_code, res.body,
                                 refresh_token);
  free(res.body);
  free(body);
}

static void refresh_by_oauth_token(const char *refresh_token,
                                   const char *proxy_url,
                                   struct token_refresh_result *result) {
  memset(result, 0, sizeof(*result));
  if (refresh_token == NULL || refresh_token[0] == '\0') {
    result->definitive = true;
    mg_snprintf(result->error, sizeof(result->error),
                "账号没有 refresh_token");
    return;
  }
  refresh_token_with_libcurl_impersonate(refresh_token, proxy_url, result);
}

static int update_refreshed_tokens(sqlite3 *db, long id,
                                   const struct token_refresh_result *result) {
  sqlite3_stmt *secret_stmt = NULL;
  sqlite3_stmt *account_stmt = NULL;
  int ok = 0;
  const char *secret_sql =
      "UPDATE account_secrets SET access_token=?,"
      "refresh_token=CASE WHEN ?<>'' THEN ? ELSE refresh_token END,"
      "updated_at=unixepoch() WHERE account_id=?";
  const char *account_sql =
      "UPDATE accounts SET status='active',last_refreshed_at=unixepoch(),"
      "updated_at=unixepoch() WHERE id=?";

  if (db == NULL || id <= 0 || result == NULL || !result->success ||
      result->access_token == NULL || result->access_token[0] == '\0') {
    return -1;
  }
  if (sqlite3_prepare_v2(db, secret_sql, -1, &secret_stmt, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(db, account_sql, -1, &account_stmt, NULL) != SQLITE_OK) {
    sqlite3_finalize(secret_stmt);
    sqlite3_finalize(account_stmt);
    return -1;
  }

  sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
  sqlite3_bind_text(secret_stmt, 1, result->access_token, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_stmt, 2,
                    result->refresh_token ? result->refresh_token : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_stmt, 3,
                    result->refresh_token ? result->refresh_token : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_int64(secret_stmt, 4, id);
  if (sqlite3_step(secret_stmt) != SQLITE_DONE) goto done;
  sqlite3_bind_int64(account_stmt, 1, id);
  if (sqlite3_step(account_stmt) != SQLITE_DONE || sqlite3_changes(db) <= 0) {
    goto done;
  }
  ok = 1;

done:
  sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
  sqlite3_finalize(secret_stmt);
  sqlite3_finalize(account_stmt);
  return ok ? 0 : -1;
}

char *account_refresh_tokens_json(sqlite3 *db, const long *ids, size_t count) {
  struct mg_iobuf io = {0, 0, 0, 1024};
  char proxy_url[768] = "";
  int proxy_rc;
  int success_count = 0;
  int failed_count = 0;
  bool first = true;

  if (db == NULL) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("数据库未初始化"));
    mg_iobuf_add(&io, io.len, "", 1);
    return (char *) io.buf;
  }
  if (ids == NULL || count == 0) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("请选择账号"));
    mg_iobuf_add(&io, io.len, "", 1);
    return (char *) io.buf;
  }

  proxy_rc = proxy_pool_pick_active_url(db, proxy_url, sizeof(proxy_url));
  if (proxy_rc < 0) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("读取代理池失败"));
    mg_iobuf_add(&io, io.len, "", 1);
    return (char *) io.buf;
  }

  mg_xprintf(mg_pfn_iobuf, &io,
             "{%m:%d,%m:%d,%m:%s,%m:[", MG_ESC("ok"), 1,
             MG_ESC("checked_count"), (int) count, MG_ESC("proxy_used"),
             proxy_url[0] ? "true" : "false", MG_ESC("details"));

  for (size_t i = 0; i < count; i++) {
    char *refresh_token = NULL;
    int load_rc = load_refresh_token(db, ids[i], &refresh_token);
    struct token_refresh_result result;

    memset(&result, 0, sizeof(result));
    if (load_rc == 1) {
      refresh_by_oauth_token(refresh_token, proxy_url[0] ? proxy_url : NULL,
                             &result);
      if (result.success) {
        if (update_refreshed_tokens(db, ids[i], &result) != 0) {
          result.success = false;
          mg_snprintf(result.error, sizeof(result.error),
                      "Token 刷新成功但数据库更新失败");
        }
      } else if (result.definitive && result.http_status > 0) {
        update_status(db, ids[i], "expired");
      }
    } else if (load_rc == 0) {
      mg_snprintf(result.error, sizeof(result.error), "账号不存在");
    } else {
      mg_snprintf(result.error, sizeof(result.error), "读取账号 Refresh Token 失败");
    }

    if (result.success) success_count++;
    else failed_count++;

    if (!first) mg_xprintf(mg_pfn_iobuf, &io, ",");
    first = false;
    mg_xprintf(mg_pfn_iobuf, &io,
               "{%m:%ld,%m:%s,%m:%ld,%m:%s,%m:%ld,%m:%m}",
               MG_ESC("id"), ids[i], MG_ESC("success"),
               result.success ? "true" : "false", MG_ESC("http_status"),
               result.http_status, MG_ESC("rotated"),
               result.rotated ? "true" : "false", MG_ESC("expires_in"),
               result.expires_in, MG_ESC("error"), MG_ESC(result.error));

    token_refresh_result_free(&result);
    free(refresh_token);
  }

  mg_xprintf(mg_pfn_iobuf, &io,
             "],%m:%d,%m:%d,%m:%d}", MG_ESC("success_count"),
             success_count, MG_ESC("failed_count"), failed_count,
             MG_ESC("affected"), success_count);
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

static void validate_access_token(const char *access_token,
                                  const char *proxy_url,
                                  struct token_validation_result *result) {
  struct browser_profile profile;
  struct flow_http_header headers[4];
  struct flow_http_request req;
  struct flow_http_response res;
  char *auth_header = NULL;
  char error[FLOW_ERROR_LEN] = "";
  size_t token_len;

  memset(result, 0, sizeof(*result));
  if (access_token == NULL || access_token[0] == '\0') {
    result->definitive = true;
    mg_snprintf(result->error, sizeof(result->error), "账号没有 access_token");
    return;
  }

  token_len = strlen(access_token);
  auth_header = (char *) malloc(token_len + sizeof("Bearer "));
  if (auth_header == NULL) {
    mg_snprintf(result->error, sizeof(result->error), "内存分配失败");
    return;
  }
  mg_snprintf(auth_header, token_len + sizeof("Bearer "), "Bearer %s",
              access_token);

  browser_profile_generate(&profile, "US", "desktop");
  headers[0].name = "Authorization";
  headers[0].value = auth_header;
  headers[1].name = "Accept";
  headers[1].value = "application/json";
  headers[2].name = "Origin";
  headers[2].value = "https://chatgpt.com";
  headers[3].name = "Referer";
  headers[3].value = "https://chatgpt.com/";

  memset(&req, 0, sizeof(req));
  memset(&res, 0, sizeof(res));
  req.method = "GET";
  req.url = TOKEN_VALIDATE_URL;
  req.timeout_ms = TOKEN_VALIDATE_TIMEOUT_MS;
  req.headers = headers;
  req.num_headers = sizeof(headers) / sizeof(headers[0]);

  if (flow_libcurl_impersonate_perform(&req, proxy_url, &profile, &res, error,
                                       sizeof(error)) != 0) {
    mg_snprintf(result->error, sizeof(result->error),
                "验证异常: libcurl-impersonate: %s",
                error[0] ? error : "请求失败");
    free(auth_header);
    free(res.body);
    return;
  }

  classify_http_status(result, res.status_code, res.body);

  free(res.body);
  free(auth_header);
}

char *account_validate_tokens_json(sqlite3 *db, const long *ids, size_t count) {
  struct mg_iobuf io = {0, 0, 0, 1024};
  char proxy_url[768] = "";
  int proxy_rc;
  int valid_count = 0;
  int invalid_count = 0;
  bool first = true;

  if (db == NULL) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("数据库未初始化"));
    mg_iobuf_add(&io, io.len, "", 1);
    return (char *) io.buf;
  }
  if (ids == NULL || count == 0) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("请选择账号"));
    mg_iobuf_add(&io, io.len, "", 1);
    return (char *) io.buf;
  }

  proxy_rc = proxy_pool_pick_active_url(db, proxy_url, sizeof(proxy_url));
  if (proxy_rc < 0) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("读取代理池失败"));
    mg_iobuf_add(&io, io.len, "", 1);
    return (char *) io.buf;
  }

  mg_xprintf(mg_pfn_iobuf, &io,
             "{%m:%d,%m:%d,%m:%s,%m:[", MG_ESC("ok"), 1,
             MG_ESC("checked_count"), (int) count, MG_ESC("proxy_used"),
             proxy_url[0] ? "true" : "false", MG_ESC("details"));

  for (size_t i = 0; i < count; i++) {
    char *access_token = NULL;
    int load_rc = load_access_token(db, ids[i], &access_token);
    struct token_validation_result result;

    memset(&result, 0, sizeof(result));
    if (load_rc == 1) {
      validate_access_token(access_token, proxy_url[0] ? proxy_url : NULL,
                            &result);
      apply_validation_status(db, ids[i], &result);
    } else if (load_rc == 0) {
      result.definitive = true;
      mg_snprintf(result.error, sizeof(result.error), "账号不存在");
    } else {
      mg_snprintf(result.error, sizeof(result.error), "读取账号 Token 失败");
    }

    if (result.valid) valid_count++;
    else invalid_count++;

    if (!first) mg_xprintf(mg_pfn_iobuf, &io, ",");
    first = false;
    mg_xprintf(mg_pfn_iobuf, &io,
               "{%m:%ld,%m:%s,%m:%ld,%m:%m}",
               MG_ESC("id"), ids[i], MG_ESC("valid"),
               result.valid ? "true" : "false", MG_ESC("http_status"),
               result.http_status, MG_ESC("error"), MG_ESC(result.error));
    free(access_token);
  }

  mg_xprintf(mg_pfn_iobuf, &io,
             "],%m:%d,%m:%d}", MG_ESC("valid_count"), valid_count,
             MG_ESC("invalid_count"), invalid_count);
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}
