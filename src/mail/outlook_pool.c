#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "mail/outlook_pool.h"

#include "http_client/http_client.h"
#include "mongoose.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// 母邮箱被占用后, 超过该秒数视为可再次 claim(防 worker 崩溃导致永久占用)
#define OUTLOOK_CLAIM_TIMEOUT_SEC 300L
#define OUTLOOK_FETCH_TIMEOUT_MS 8000L

// ---------------------------------------------------------------------------
// 通用小工具(与 rapid_inbox.c 同构, 保持行为一致)
// ---------------------------------------------------------------------------
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

static bool copy_json_string_field(const char *json, const char *path, char *out,
                                   size_t out_len) {
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

// 提取一段"恰好 6 位"的连续数字(与 rapid_inbox.c copy_six_digit_run 一致)
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

static void set_error(char *error, size_t error_len, const char *message) {
  if (error == NULL || error_len == 0) return;
  mg_snprintf(error, error_len, "%s", message ? message : "outlook pool error");
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
    return copy_cstr(fallback ? fallback : "");
  }
  sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *s = sqlite3_column_text(stmt, 0);
    value = copy_cstr(s == NULL ? "" : (const char *) s);
  }
  sqlite3_finalize(stmt);
  if (value == NULL) value = copy_cstr(fallback ? fallback : "");
  return value;
}

// 别名邮箱 -> 母邮箱: 去掉 local 部分的 "+子标签"
// shascarafrfnz6565+a3k9@outlook.com -> shascarafrfnz6565@outlook.com
void outlook_pool_alias_to_mother(const char *alias, char *out,
                                  size_t out_len) {
  const char *at, *plus;
  size_t local_len;
  if (out_len == 0) return;
  out[0] = '\0';
  if (alias == NULL) return;
  at = strchr(alias, '@');
  if (at == NULL) {
    mg_snprintf(out, out_len, "%s", alias);
    return;
  }
  plus = (const char *) memchr(alias, '+', (size_t) (at - alias));
  if (plus == NULL) {
    mg_snprintf(out, out_len, "%s", alias);
    return;
  }
  local_len = (size_t) (plus - alias);
  mg_snprintf(out, out_len, "%.*s%s", (int) local_len, alias, at);
}

// ---------------------------------------------------------------------------
// 批量导入去重(本批次内)
// ---------------------------------------------------------------------------
static bool seen_contains(char **seen, size_t count, const char *email_lc) {
  for (size_t i = 0; i < count; i++) {
    if (seen[i] != NULL && strcmp(seen[i], email_lc) == 0) return true;
  }
  return false;
}

static int seen_add(char ***seen, size_t *count, size_t *cap,
                    const char *email_lc) {
  if (*count == *cap) {
    size_t next_cap = *cap == 0 ? 16 : *cap * 2;
    char **next = (char **) realloc(*seen, next_cap * sizeof(char *));
    if (next == NULL) return -1;
    *seen = next;
    *cap = next_cap;
  }
  (*seen)[*count] = copy_cstr(email_lc);
  if ((*seen)[*count] == NULL) return -1;
  (*count)++;
  return 0;
}

static void seen_free(char **seen, size_t count) {
  for (size_t i = 0; i < count; i++) free(seen[i]);
  free(seen);
}

static void append_import_error(struct mg_iobuf *io, bool *first,
                                unsigned long index, const char *raw,
                                const char *error) {
  if (io == NULL || first == NULL) return;
  mg_xprintf(mg_pfn_iobuf, io, "%s{%m:%lu,%m:%m,%m:%m}", *first ? "" : ",",
             MG_ESC("index"), index, MG_ESC("raw"), MG_ESC(raw ? raw : ""),
             MG_ESC("error"), MG_ESC(error ? error : "invalid"));
  *first = false;
}

// ---------------------------------------------------------------------------
// 列表
// ---------------------------------------------------------------------------
char *outlook_pool_list_json(sqlite3 *db) {
  struct mg_iobuf io = {0, 0, 0, 512};
  sqlite3_stmt *stmt = NULL;
  char *ws = setting_value(db, "outlook_workspace_id", "");
  char *jm = setting_value(db, "outlook_join_mode", "request");
  bool first = true;
  const char *sql =
      "SELECT id,email,code_api_url,alias_count,max_aliases,in_use,is_active,"
      "COALESCE(last_used_at,0),created_at FROM outlook_mailboxes ORDER BY id DESC";

  mg_xprintf(mg_pfn_iobuf, &io, "{%m:%m,%m:%m,%m:[", MG_ESC("workspace_id"),
             MG_ESC(ws), MG_ESC("join_mode"), MG_ESC(jm), MG_ESC("items"));
  if (db != NULL &&
      sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      const unsigned char *email = sqlite3_column_text(stmt, 1);
      const unsigned char *url = sqlite3_column_text(stmt, 2);
      mg_xprintf(mg_pfn_iobuf, &io,
                 "%s{%m:%lld,%m:%m,%m:%m,%m:%lld,%m:%lld,%m:%d,%m:%d,%m:%lld,"
                 "%m:%lld}",
                 first ? "" : ",", MG_ESC("id"),
                 (long long) sqlite3_column_int64(stmt, 0), MG_ESC("email"),
                 MG_ESC(email == NULL ? "" : (const char *) email),
                 MG_ESC("code_api_url"),
                 MG_ESC(url == NULL ? "" : (const char *) url),
                 MG_ESC("alias_count"),
                 (long long) sqlite3_column_int64(stmt, 3),
                 MG_ESC("max_aliases"),
                 (long long) sqlite3_column_int64(stmt, 4), MG_ESC("in_use"),
                 sqlite3_column_int(stmt, 5), MG_ESC("is_active"),
                 sqlite3_column_int(stmt, 6), MG_ESC("last_used_at"),
                 (long long) sqlite3_column_int64(stmt, 7), MG_ESC("created_at"),
                 (long long) sqlite3_column_int64(stmt, 8));
      first = false;
    }
    sqlite3_finalize(stmt);
  }
  mg_xprintf(mg_pfn_iobuf, &io, "]}");
  mg_iobuf_add(&io, io.len, "", 1);
  free(ws);
  free(jm);
  return (char *) io.buf;
}

// ---------------------------------------------------------------------------
// 批量导入: 每行 "母邮箱----接码URL"
// ---------------------------------------------------------------------------
char *outlook_pool_import_json(sqlite3 *db, const char *text) {
  struct mg_iobuf err_io = {0, 0, 0, 128};
  struct mg_iobuf res_io = {0, 0, 0, 256};
  bool first_err = true;
  unsigned long total = 0, saved = 0, invalid = 0, dup = 0;
  char **seen = NULL;
  size_t seen_n = 0, seen_cap = 0;
  char *copy = copy_cstr(text ? text : "");
  char *cursor;
  sqlite3_stmt *up = NULL;
  const char *up_sql =
      "INSERT INTO outlook_mailboxes(email,password,code_api_url,is_active,"
      "created_at,updated_at) VALUES(?,?,?,1,unixepoch(),unixepoch()) "
      "ON CONFLICT(email) DO UPDATE SET code_api_url=excluded.code_api_url,"
      "password=CASE WHEN excluded.password<>'' THEN excluded.password "
      "ELSE outlook_mailboxes.password END,"
      "is_active=1,updated_at=unixepoch()";

  if (db == NULL || copy == NULL) {
    free(copy);
    return copy_cstr("{\"ok\":0,\"error\":\"数据库未打开\"}");
  }
  // outlook_mailboxes.password 列迁移(幂等: 显式判存在, 已有则不动, 杜绝重复改表)
  {
    sqlite3_stmt *ms = NULL;
    int has_pw = 0;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(outlook_mailboxes)", -1, &ms,
                           NULL) == SQLITE_OK) {
      while (sqlite3_step(ms) == SQLITE_ROW) {
        const unsigned char *cn = sqlite3_column_text(ms, 1);
        if (cn != NULL && strcmp((const char *) cn, "password") == 0) {
          has_pw = 1;
          break;
        }
      }
      sqlite3_finalize(ms);
    }
    if (!has_pw) {
      sqlite3_exec(db, "ALTER TABLE outlook_mailboxes ADD COLUMN password TEXT",
                   NULL, NULL, NULL);
    }
  }
  if (sqlite3_prepare_v2(db, up_sql, -1, &up, NULL) != SQLITE_OK) {
    free(copy);
    return copy_cstr("{\"ok\":0,\"error\":\"导入语句准备失败\"}");
  }
  sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);

  cursor = copy;
  while (cursor != NULL && *cursor != '\0') {
    char *next = strpbrk(cursor, "\r\n");
    char *line;
    if (next != NULL) *next = '\0';
    line = trim(cursor);
    if (*line != '\0') {
      char *sep = strstr(line, "----");
      total++;
      if (sep == NULL) {
        invalid++;
        append_import_error(&err_io, &first_err, total, line,
                            "缺少 ---- 分隔符");
      } else {
        char email_lc[320];
        char *email;
        char *url;
        char *password;
        char *sep2;
        *sep = '\0';
        email = trim(line);
        // 3 段: 邮箱----密码----接码URL; 兼容旧 2 段(无密码, 注册时随机兜底)
        sep2 = strstr(sep + 4, "----");
        if (sep2 != NULL) {
          *sep2 = '\0';
          password = trim(sep + 4);
          url = trim(sep2 + 4);
        } else {
          password = (char *) "";
          url = trim(sep + 4);
        }
        lower_copy(email_lc, sizeof(email_lc), email);
        if (strchr(email, '@') == NULL) {
          invalid++;
          append_import_error(&err_io, &first_err, total, email,
                              "邮箱格式无效");
        } else if (strstr(url, "http") == NULL) {
          invalid++;
          append_import_error(&err_io, &first_err, total, email,
                              "接码链接无效");
        } else if (seen_contains(seen, seen_n, email_lc)) {
          dup++;
        } else {
          seen_add(&seen, &seen_n, &seen_cap, email_lc);
          sqlite3_reset(up);
          sqlite3_clear_bindings(up);
          sqlite3_bind_text(up, 1, email, -1, SQLITE_TRANSIENT);
          sqlite3_bind_text(up, 2, password, -1, SQLITE_TRANSIENT);
          sqlite3_bind_text(up, 3, url, -1, SQLITE_TRANSIENT);
          if (sqlite3_step(up) == SQLITE_DONE) {
            saved++;
          } else {
            invalid++;
            append_import_error(&err_io, &first_err, total, email, "写入失败");
          }
        }
      }
    }
    if (next == NULL) break;
    cursor = next + 1;
  }

  sqlite3_finalize(up);
  sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
  seen_free(seen, seen_n);
  free(copy);

  mg_iobuf_add(&err_io, err_io.len, "", 1);
  mg_xprintf(mg_pfn_iobuf, &res_io,
             "{%m:%d,%m:%lu,%m:%lu,%m:%lu,%m:%lu,%m:[%s]}", MG_ESC("ok"), 1,
             MG_ESC("total_count"), total, MG_ESC("saved_count"), saved,
             MG_ESC("invalid_count"), invalid, MG_ESC("duplicate_count"), dup,
             MG_ESC("errors"), err_io.buf ? (char *) err_io.buf : "");
  mg_iobuf_add(&res_io, res_io.len, "", 1);
  mg_iobuf_free(&err_io);
  return (char *) res_io.buf;
}

// ---------------------------------------------------------------------------
// 删除
// ---------------------------------------------------------------------------
int outlook_pool_delete_ids(sqlite3 *db, const long *ids, size_t count) {
  sqlite3_stmt *stmt = NULL;
  int deleted = 0;
  if (db == NULL || ids == NULL || count == 0) return 0;
  if (sqlite3_prepare_v2(db, "DELETE FROM outlook_mailboxes WHERE id=?", -1,
                         &stmt, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
  for (size_t i = 0; i < count; i++) {
    sqlite3_reset(stmt);
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64) ids[i]);
    if (sqlite3_step(stmt) == SQLITE_DONE) deleted += sqlite3_changes(db);
  }
  sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
  sqlite3_finalize(stmt);
  return deleted;
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------
int outlook_pool_save_config(sqlite3 *db, const char *workspace_id,
                             const char *join_mode) {
  if (db == NULL) return -1;
  if (workspace_id != NULL) {
    char trimmed[256];
    mg_snprintf(trimmed, sizeof(trimmed), "%s", workspace_id);
    if (upsert_setting(db, "outlook_workspace_id", trim(trimmed)) != 0)
      return -1;
  }
  if (join_mode != NULL && join_mode[0] != '\0') {
    if (upsert_setting(db, "outlook_join_mode", join_mode) != 0) return -1;
  }
  return 0;
}

char *outlook_pool_workspace_id(sqlite3 *db) {
  return setting_value(db, "outlook_workspace_id", "");
}

// ---------------------------------------------------------------------------
// 单线程占用锁: claim / release
// ---------------------------------------------------------------------------
int outlook_pool_claim(sqlite3 *db, char *email, size_t email_len,
                       char *code_api_url, size_t code_api_url_len,
                       long *out_id, char *error, size_t error_len) {
  sqlite3_stmt *sel = NULL;
  sqlite3_stmt *upd = NULL;
  long id = -1;
  char *alias_mode;
  int direct;
  const char *sel_sql;

  if (email != NULL && email_len > 0) email[0] = '\0';
  if (code_api_url != NULL && code_api_url_len > 0) code_api_url[0] = '\0';
  if (out_id != NULL) *out_id = -1;
  if (db == NULL) {
    set_error(error, error_len, "数据库未打开");
    return -1;
  }

  // direct(母号直注)模式: 一号一注册, 只认领没注册过的母号(alias_count=0),
  // 注册成功后 alias_count=1 便不再被选; alias(别名复用)模式: 按 max_aliases 限额
  alias_mode = setting_value(db, "outlook_alias_mode", "alias");
  direct = (alias_mode != NULL && strcmp(alias_mode, "direct") == 0);
  free(alias_mode);
  sel_sql =
      direct
          ? "SELECT id,email,code_api_url FROM outlook_mailboxes "
            "WHERE is_active=1 AND (in_use=0 OR locked_at < unixepoch()-?) "
            "AND alias_count=0 "
            "ORDER BY COALESCE(last_used_at,0) ASC, id ASC LIMIT 1"
          : "SELECT id,email,code_api_url FROM outlook_mailboxes "
            "WHERE is_active=1 AND (in_use=0 OR locked_at < unixepoch()-?) "
            "AND (max_aliases=0 OR alias_count<max_aliases) "
            "ORDER BY in_use ASC, alias_count ASC, COALESCE(last_used_at,0) ASC, "
            "id ASC LIMIT 1";

  // BEGIN IMMEDIATE 立即拿写锁, 保证 SELECT+UPDATE 原子(WAL 下写串行)
  if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
    set_error(error, error_len, "邮箱池繁忙, 稍后重试");
    return -1;
  }
  if (sqlite3_prepare_v2(db, sel_sql, -1, &sel, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(sel, 1, (sqlite3_int64) OUTLOOK_CLAIM_TIMEOUT_SEC);
    if (sqlite3_step(sel) == SQLITE_ROW) {
      const unsigned char *e = sqlite3_column_text(sel, 1);
      const unsigned char *u = sqlite3_column_text(sel, 2);
      id = (long) sqlite3_column_int64(sel, 0);
      if (email != NULL)
        mg_snprintf(email, email_len, "%s",
                    e == NULL ? "" : (const char *) e);
      if (code_api_url != NULL)
        mg_snprintf(code_api_url, code_api_url_len, "%s",
                    u == NULL ? "" : (const char *) u);
    }
    sqlite3_finalize(sel);
  }
  if (id < 0) {
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    set_error(error, error_len, "没有可用的 outlook 母邮箱(全部占用或已达别名上限)");
    return -1;
  }
  if (sqlite3_prepare_v2(db,
                         "UPDATE outlook_mailboxes SET in_use=1,"
                         "locked_at=unixepoch(),updated_at=unixepoch() "
                         "WHERE id=?",
                         -1, &upd, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(upd, 1, (sqlite3_int64) id);
    sqlite3_step(upd);
    sqlite3_finalize(upd);
  }
  if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    set_error(error, error_len, "占用母邮箱提交失败");
    return -1;
  }
  if (out_id != NULL) *out_id = id;
  return 0;
}

int outlook_pool_release(sqlite3 *db, long id, bool success) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      success ? "UPDATE outlook_mailboxes SET in_use=0,alias_count=alias_count+1,"
                "last_used_at=unixepoch(),updated_at=unixepoch() WHERE id=?"
              : "UPDATE outlook_mailboxes SET in_use=0,updated_at=unixepoch() "
                "WHERE id=?";
  if (db == NULL || id < 0) return -1;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
  sqlite3_bind_int64(stmt, 1, (sqlite3_int64) id);
  int rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  return rc == SQLITE_DONE ? 0 : -1;
}

// ---------------------------------------------------------------------------
// 接码: 用母邮箱专属 code_api_url 拉最新一封邮件, 提取 6 位验证码
// ---------------------------------------------------------------------------
static char *lookup_code_api_url(sqlite3 *db, const char *mother_email) {
  sqlite3_stmt *stmt = NULL;
  char *url = NULL;
  if (sqlite3_prepare_v2(db,
                         "SELECT code_api_url FROM outlook_mailboxes "
                         "WHERE email=? LIMIT 1",
                         -1, &stmt, NULL) != SQLITE_OK) {
    return NULL;
  }
  sqlite3_bind_text(stmt, 1, mother_email, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *s = sqlite3_column_text(stmt, 0);
    url = copy_cstr(s == NULL ? "" : (const char *) s);
  }
  sqlite3_finalize(stmt);
  return url;
}

int outlook_pool_try_fetch_code(sqlite3 *db, const char *alias_email,
                                long min_received_at, char *code,
                                size_t code_len, char *error, size_t error_len) {
  char mother[320];
  char *code_api_url;
  struct http_client_request req;
  struct http_client_response res;
  char status[32] = "";
  char received[96] = "";
  char subject[512] = "";
  char *body = NULL;
  long recv_epoch = 0;
  int result = 0;

  if (code != NULL && code_len > 0) code[0] = '\0';
  if (db == NULL || alias_email == NULL) return OUTLOOK_POOL_NOT_MINE;
  outlook_pool_alias_to_mother(alias_email, mother, sizeof(mother));
  code_api_url = lookup_code_api_url(db, mother);
  if (code_api_url == NULL || code_api_url[0] == '\0') {
    free(code_api_url);
    return OUTLOOK_POOL_NOT_MINE;
  }

  memset(&req, 0, sizeof(req));
  req.method = "GET";
  req.url = code_api_url;
  req.timeout_ms = OUTLOOK_FETCH_TIMEOUT_MS;  // 直连接码服务, 不走代理
  if (http_client_perform(&req, &res) != 0) {
    mg_snprintf(error, error_len, "outlook007 请求失败: mailbox=%s error=%s",
                mother, res.error[0] ? res.error : "unknown");
    free(code_api_url);
    return -1;
  }
  if (res.status_code < 200 || res.status_code >= 300) {
    mg_snprintf(error, error_len, "outlook007 HTTP %ld: mailbox=%s",
                res.status_code, mother);
    http_client_response_free(&res);
    free(code_api_url);
    return -1;
  }

  copy_json_string_field(res.body, "$.status", status, sizeof(status));
  if (status[0] != '\0' && strcmp(status, "success") != 0) {
    // 接口明确表示无邮件 / 未就绪
    mg_snprintf(error, error_len, "outlook007 暂无邮件: mailbox=%s status=%s",
                mother, status);
    http_client_response_free(&res);
    free(code_api_url);
    return 0;
  }

  if (copy_json_string_field(res.body, "$.received_at", received,
                             sizeof(received))) {
    recv_epoch = parse_rfc3339_epoch(received);
  }
  // 只接受本次请求之后到达的邮件(10s 容差), 避免拿到上一次的旧验证码
  if (min_received_at > 0 && recv_epoch > 0 &&
      recv_epoch + 10 < min_received_at) {
    mg_snprintf(error, error_len,
                "outlook007 仅有旧邮件: mailbox=%s received=%ld min=%ld", mother,
                recv_epoch, min_received_at);
    http_client_response_free(&res);
    free(code_api_url);
    return 0;
  }

  // outlook007 对验证码邮件直接返回 code 字段; 否则从 subject/body 提取 6 位
  if (copy_json_string_field(res.body, "$.code", code, code_len)) {
    result = 1;
  } else if (copy_json_string_field(res.body, "$.subject", subject,
                                    sizeof(subject)) &&
             copy_six_digit_run(subject, code, code_len)) {
    result = 1;
  } else {
    body = mg_json_get_str(mg_str(res.body ? res.body : ""), "$.body");
    if (body != NULL && copy_six_digit_run(body, code, code_len)) {
      result = 1;
    } else if (copy_six_digit_run(res.body, code, code_len)) {
      // 部分验证码邮件正文含非 UTF-8 字节(如葡语 código/verificação),
      // mongoose mg_json 解析 $.body/$.subject 失败返回 NULL; 退而在原始响应
      // 字节上直接扫 6 位码(OTP 在正文靠前, sendgrid URL 里的数字被字母打断
      // 凑不成 6 位连续, received_at/status 也无 6 位连续, 不会误匹配)
      result = 1;
    }
    mg_free(body);
  }
  if (result != 1) {
    mg_snprintf(error, error_len, "outlook007 未找到验证码: mailbox=%s", mother);
    result = 0;
  }

  http_client_response_free(&res);
  free(code_api_url);
  return result;
}
