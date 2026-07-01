#include "upload/aether_upload.h"

#include "account/account_store.h"
#include "http_client/http_client.h"
#include "mongoose.h"

#include <ctype.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define AETHER_URL_LEN 768
#define AETHER_TEXT_LEN 256
#define AETHER_TOKEN_PREVIEW_LEN 20
#define AETHER_TIMEOUT_MS 90000L
#define AETHER_DEFAULT_RETRY_COUNT 2
#define AETHER_MAX_RETRY_COUNT 10
#define AETHER_RETRY_BACKOFF_INITIAL_MS 500
#define AETHER_RETRY_BACKOFF_MAX_MS 3000
#define AETHER_PROXY_MODE_FIXED "fixed"
#define AETHER_PROXY_MODE_NONE "none"
#define AETHER_PROXY_MODE_RANDOM "random"

struct aether_service {
  long id;
  char name[AETHER_TEXT_LEN];
  char api_url[512];
  char *management_token;
  char provider_id[AETHER_TEXT_LEN];
  char provider_name[AETHER_TEXT_LEN];
  char *oauth_provider_ids_json;
  char *oauth_provider_names_json;
  char chatgpt_web_provider_id[AETHER_TEXT_LEN];
  char chatgpt_web_provider_name[AETHER_TEXT_LEN];
  char proxy_node_id[AETHER_TEXT_LEN];
  char proxy_node_name[AETHER_TEXT_LEN];
  char proxy_node_mode[16];
  int enabled;
  int priority;
  int retry_count;
};

struct aether_proxy_node {
  char id[AETHER_TEXT_LEN];
  char name[AETHER_TEXT_LEN];
};

struct aether_provider_target {
  char id[AETHER_TEXT_LEN];
  char name[AETHER_TEXT_LEN];
};

struct upload_account {
  long id;
  char *email;
  char *access_token;
  char *refresh_token;
  char *external_account_id;
  char *workspace_id;
};

struct aether_service_upload_result {
  long service_id;
  char service_name[AETHER_TEXT_LEN];
  char provider_id[AETHER_TEXT_LEN];
  int retry_count;
  int attempts;
  long http_status;
  long success_count;
  long failed_count;
  unsigned char *account_success;
  char error[512];
};

struct aether_upload_worker {
  const struct aether_service *service;
  const char *provider_id;
  const struct upload_account *accounts;
  bool include_web_credentials;
  size_t account_count;
  struct aether_service_upload_result *result;
};

struct aether_upload_assignment_group {
  size_t provider_index;
  size_t node_index;
  size_t *account_indexes;
  size_t count;
  size_t cap;
};

static const char *column_text(sqlite3_stmt *stmt, int col) {
  const unsigned char *s = sqlite3_column_text(stmt, col);
  return s == NULL ? "" : (const char *) s;
}

static char *str_dup(const char *s) {
  size_t len;
  char *copy;
  if (s == NULL) s = "";
  len = strlen(s);
  copy = (char *) malloc(len + 1);
  if (copy == NULL) return NULL;
  memcpy(copy, s, len + 1);
  return copy;
}

static char *trim_in_place(char *s) {
  char *end;
  if (s == NULL) return NULL;
  while (*s && isspace((unsigned char) *s)) s++;
  end = s + strlen(s);
  while (end > s && isspace((unsigned char) end[-1])) *--end = '\0';
  return s;
}

static char *json_get_trim(struct mg_str body, const char *path) {
  char *raw = mg_json_get_str(body, path);
  char *trimmed;
  char *copy;
  if (raw == NULL) return NULL;
  trimmed = trim_in_place(raw);
  copy = str_dup(trimmed);
  mg_free(raw);
  return copy;
}

static bool has_text(const char *s) {
  if (s == NULL) return false;
  while (*s) {
    if (!isspace((unsigned char) *s)) return true;
    s++;
  }
  return false;
}

static int clamp_retry_count(long value) {
  if (value < 0) return 0;
  if (value > AETHER_MAX_RETRY_COUNT) return AETHER_MAX_RETRY_COUNT;
  return (int) value;
}

static bool text_equals_ci(const char *a, const char *b) {
  if (a == NULL || b == NULL) return false;
  return strcasecmp(a, b) == 0;
}

static const char *normalize_proxy_node_mode(const char *mode) {
  if (text_equals_ci(mode, AETHER_PROXY_MODE_RANDOM)) {
    return AETHER_PROXY_MODE_RANDOM;
  }
  if (text_equals_ci(mode, AETHER_PROXY_MODE_NONE)) {
    return AETHER_PROXY_MODE_NONE;
  }
  return AETHER_PROXY_MODE_FIXED;
}

static bool service_uses_random_proxy(const struct aether_service *svc) {
  return svc != NULL &&
         text_equals_ci(svc->proxy_node_mode, AETHER_PROXY_MODE_RANDOM);
}

static const char *service_request_proxy_node_id(
    const struct aether_service *svc) {
  if (svc == NULL ||
      text_equals_ci(svc->proxy_node_mode, AETHER_PROXY_MODE_NONE) ||
      service_uses_random_proxy(svc)) {
    return "";
  }
  return svc->proxy_node_id;
}

static char *json_get_raw_trim(struct mg_str body, const char *path) {
  int len = 0;
  int off = mg_json_get(body, path, &len);
  char *copy;

  if (off < 0 || len <= 0) return NULL;
  while (len > 0 && isspace((unsigned char) body.buf[off])) {
    off++;
    len--;
  }
  while (len > 0 && isspace((unsigned char) body.buf[off + len - 1])) {
    len--;
  }
  if (len <= 0) return NULL;
  copy = (char *) malloc((size_t) len + 1);
  if (copy == NULL) return NULL;
  memcpy(copy, body.buf + off, (size_t) len);
  copy[len] = '\0';
  return copy;
}

static char *json_get_raw_array(struct mg_str body, const char *path) {
  char *raw = json_get_raw_trim(body, path);
  char *trimmed;

  if (raw == NULL) return NULL;
  trimmed = trim_in_place(raw);
  if (trimmed[0] != '[') {
    free(raw);
    return NULL;
  }
  if (trimmed != raw) memmove(raw, trimmed, strlen(trimmed) + 1);
  return raw;
}

static int append_provider_target(struct aether_provider_target **targets,
                                  size_t *count, size_t *cap,
                                  const char *id, const char *name) {
  struct aether_provider_target *next;

  if (targets == NULL || count == NULL || cap == NULL) return -1;
  if (!has_text(id)) return 0;
  if (*count == *cap) {
    *cap = *cap == 0 ? 4 : *cap * 2;
    next = (struct aether_provider_target *) realloc(
        *targets, *cap * sizeof(**targets));
    if (next == NULL) return -1;
    *targets = next;
  }
  memset(&(*targets)[*count], 0, sizeof((*targets)[*count]));
  mg_snprintf((*targets)[*count].id, sizeof((*targets)[*count].id), "%s",
              id);
  mg_snprintf((*targets)[*count].name, sizeof((*targets)[*count].name), "%s",
              has_text(name) ? name : id);
  (*count)++;
  return 0;
}

static int load_provider_targets_from_json(
    const char *ids_json, const char *names_json, const char *fallback_id,
    const char *fallback_name, struct aether_provider_target **out,
    size_t *out_len) {
  struct aether_provider_target *items = NULL;
  size_t len = 0, cap = 0;

  if (out != NULL) *out = NULL;
  if (out_len != NULL) *out_len = 0;
  if (out == NULL || out_len == NULL) return -1;

  if (has_text(ids_json)) {
    struct mg_str ids = mg_str(ids_json);
    struct mg_str names = mg_str(names_json ? names_json : "");
    for (size_t i = 0; i < 2000; i++) {
      char path[64];
      char *id = NULL;
      char *name = NULL;
      mg_snprintf(path, sizeof(path), "$[%lu]", (unsigned long) i);
      id = mg_json_get_str(ids, path);
      if (id == NULL) break;
      name = has_text(names_json) ? mg_json_get_str(names, path) : NULL;
      if (append_provider_target(&items, &len, &cap, id, name) != 0) {
        mg_free(id);
        mg_free(name);
        free(items);
        return -1;
      }
      mg_free(id);
      mg_free(name);
    }
  }

  if (len == 0 && append_provider_target(&items, &len, &cap, fallback_id,
                                         fallback_name) != 0) {
    free(items);
    return -1;
  }
  if (len == 0) {
    free(items);
    return -1;
  }

  *out = items;
  *out_len = len;
  return 0;
}

static int load_service_provider_targets(
    const struct aether_service *svc, bool include_web,
    struct aether_provider_target **out, size_t *out_len) {
  if (include_web) {
    return load_provider_targets_from_json(NULL, NULL,
                                           svc ? svc->chatgpt_web_provider_id : "",
                                           svc ? svc->chatgpt_web_provider_name : "",
                                           out, out_len);
  }
  return load_provider_targets_from_json(
      svc ? svc->oauth_provider_ids_json : NULL,
      svc ? svc->oauth_provider_names_json : NULL,
      svc ? svc->provider_id : "", svc ? svc->provider_name : "", out,
      out_len);
}

static char *provider_targets_json_array(
    const struct aether_provider_target *targets, size_t count, bool names) {
  struct mg_iobuf out = {0, 0, 0, 256};
  mg_xprintf(mg_pfn_iobuf, &out, "[");
  for (size_t i = 0; i < count; i++) {
    const char *value = names ? targets[i].name : targets[i].id;
    mg_xprintf(mg_pfn_iobuf, &out, "%s%m", i == 0 ? "" : ",",
               MG_ESC(value));
  }
  mg_xprintf(mg_pfn_iobuf, &out, "]");
  mg_iobuf_add(&out, out.len, "", 1);
  return (char *) out.buf;
}

static bool contains_ci(const char *haystack, const char *needle) {
  if (haystack == NULL || needle == NULL || *needle == '\0') return false;
  return strcasestr(haystack, needle) != NULL;
}

static bool is_already_exists_error(const char *message) {
  return contains_ci(message, "已存在") ||
         contains_ci(message, "already exists") ||
         contains_ci(message, "already exist") ||
         contains_ci(message, "duplicate");
}

static void free_service(struct aether_service *svc) {
  if (svc == NULL) return;
  free(svc->management_token);
  free(svc->oauth_provider_ids_json);
  free(svc->oauth_provider_names_json);
  svc->management_token = NULL;
  svc->oauth_provider_ids_json = NULL;
  svc->oauth_provider_names_json = NULL;
}

static void fill_service_from_stmt(struct aether_service *svc,
                                   sqlite3_stmt *stmt) {
  memset(svc, 0, sizeof(*svc));
  svc->id = (long) sqlite3_column_int64(stmt, 0);
  mg_snprintf(svc->name, sizeof(svc->name), "%s", column_text(stmt, 1));
  mg_snprintf(svc->api_url, sizeof(svc->api_url), "%s", column_text(stmt, 2));
  svc->management_token = str_dup(column_text(stmt, 3));
  mg_snprintf(svc->provider_id, sizeof(svc->provider_id), "%s",
              column_text(stmt, 4));
  mg_snprintf(svc->provider_name, sizeof(svc->provider_name), "%s",
              column_text(stmt, 5));
  svc->oauth_provider_ids_json = str_dup(column_text(stmt, 6));
  svc->oauth_provider_names_json = str_dup(column_text(stmt, 7));
  mg_snprintf(svc->chatgpt_web_provider_id,
              sizeof(svc->chatgpt_web_provider_id), "%s",
              column_text(stmt, 8));
  mg_snprintf(svc->chatgpt_web_provider_name,
              sizeof(svc->chatgpt_web_provider_name), "%s",
              column_text(stmt, 9));
  mg_snprintf(svc->proxy_node_id, sizeof(svc->proxy_node_id), "%s",
              column_text(stmt, 10));
  mg_snprintf(svc->proxy_node_name, sizeof(svc->proxy_node_name), "%s",
              column_text(stmt, 11));
  mg_snprintf(svc->proxy_node_mode, sizeof(svc->proxy_node_mode), "%s",
              normalize_proxy_node_mode(column_text(stmt, 12)));
  svc->enabled = sqlite3_column_int(stmt, 13);
  svc->priority = sqlite3_column_int(stmt, 14);
  svc->retry_count = clamp_retry_count(sqlite3_column_int(stmt, 15));
}

static int load_service_by_id(sqlite3 *db, long id, struct aether_service *out) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "SELECT id,name,api_url,management_token,provider_id,provider_name,"
      "COALESCE(oauth_provider_ids,'[]'),"
      "COALESCE(oauth_provider_names,'[]'),"
      "COALESCE(chatgpt_web_provider_id,''),"
      "COALESCE(chatgpt_web_provider_name,''),"
      "COALESCE(proxy_node_id,''),COALESCE(proxy_node_name,''),"
      "COALESCE(proxy_node_mode,'fixed'),enabled,priority,"
      "COALESCE(retry_count,2) "
      "FROM aether_services WHERE id=?";
  int rc = -1;

  if (out != NULL) memset(out, 0, sizeof(*out));
  if (db == NULL || id <= 0 || out == NULL) return -1;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
  sqlite3_bind_int64(stmt, 1, id);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    fill_service_from_stmt(out, stmt);
    rc = 0;
  }
  sqlite3_finalize(stmt);
  return rc;
}

static int load_enabled_services(sqlite3 *db, struct aether_service **out,
                                 size_t *out_len) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "SELECT id,name,api_url,management_token,provider_id,provider_name,"
      "COALESCE(oauth_provider_ids,'[]'),"
      "COALESCE(oauth_provider_names,'[]'),"
      "COALESCE(chatgpt_web_provider_id,''),"
      "COALESCE(chatgpt_web_provider_name,''),"
      "COALESCE(proxy_node_id,''),COALESCE(proxy_node_name,''),"
      "COALESCE(proxy_node_mode,'fixed'),enabled,priority,"
      "COALESCE(retry_count,2) FROM aether_services "
      "WHERE enabled=1 ORDER BY priority ASC,id ASC";
  struct aether_service *items = NULL;
  size_t len = 0, cap = 0;

  if (out != NULL) *out = NULL;
  if (out_len != NULL) *out_len = 0;
  if (db == NULL || out == NULL || out_len == NULL) return -1;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    struct aether_service *next;
    if (len == cap) {
      cap = cap == 0 ? 4 : cap * 2;
      next = (struct aether_service *) realloc(items, cap * sizeof(*items));
      if (next == NULL) {
        sqlite3_finalize(stmt);
        for (size_t i = 0; i < len; i++) free_service(&items[i]);
        free(items);
        return -1;
      }
      items = next;
    }
    fill_service_from_stmt(&items[len++], stmt);
  }
  sqlite3_finalize(stmt);
  *out = items;
  *out_len = len;
  return len > 0 ? 0 : -1;
}

int aether_resolve_enabled_upload_service(sqlite3 *db, long requested_id,
                                          bool random, long *out_id,
                                          char *out_name,
                                          size_t out_name_len, char *error,
                                          size_t error_len) {
  sqlite3_stmt *stmt = NULL;
  const char *sql_random =
      "SELECT id,name FROM aether_services WHERE enabled=1 "
      "ORDER BY random() LIMIT 1";
  const char *sql_fixed =
      "SELECT id,name FROM aether_services WHERE enabled=1 AND id=? LIMIT 1";
  int rc = -1;

  if (out_id != NULL) *out_id = 0;
  if (out_name != NULL && out_name_len > 0) out_name[0] = '\0';
  if (error != NULL && error_len > 0) error[0] = '\0';
  if (db == NULL) {
    if (error != NULL && error_len > 0) {
      mg_snprintf(error, error_len, "%s", "无法打开上传配置数据库");
    }
    return -1;
  }
  if (!random && requested_id <= 0) {
    if (error != NULL && error_len > 0) {
      mg_snprintf(error, error_len, "%s", "请选择 Aether 上传服务");
    }
    return -1;
  }

  if (sqlite3_prepare_v2(db, random ? sql_random : sql_fixed, -1, &stmt,
                         NULL) != SQLITE_OK) {
    if (error != NULL && error_len > 0) {
      mg_snprintf(error, error_len, "%s", "读取 Aether 上传服务失败");
    }
    return -1;
  }
  if (!random) sqlite3_bind_int64(stmt, 1, requested_id);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    if (out_id != NULL) *out_id = (long) sqlite3_column_int64(stmt, 0);
    if (out_name != NULL && out_name_len > 0) {
      mg_snprintf(out_name, out_name_len, "%s", column_text(stmt, 1));
    }
    rc = 0;
  } else if (error != NULL && error_len > 0) {
    mg_snprintf(error, error_len, "%s",
                random ? "未找到已启用的 Aether 上传服务"
                       : "指定的 Aether 上传服务不存在或未启用");
  }
  sqlite3_finalize(stmt);
  return rc;
}

static void free_service_array(struct aether_service *items, size_t count) {
  if (items == NULL) return;
  for (size_t i = 0; i < count; i++) free_service(&items[i]);
  free(items);
}

static void filter_service_by_id(struct aether_service *services,
                                 size_t *service_count, long service_id) {
  size_t write = 0;

  if (services == NULL || service_count == NULL || service_id <= 0) return;
  for (size_t i = 0; i < *service_count; i++) {
    if (services[i].id == service_id) {
      if (write != i) {
        services[write] = services[i];
        memset(&services[i], 0, sizeof(services[i]));
      }
      write++;
    } else {
      free_service(&services[i]);
    }
  }
  *service_count = write;
}

static void filter_web_upload_services(struct aether_service *services,
                                       size_t *service_count) {
  size_t write = 0;

  if (services == NULL || service_count == NULL) return;
  for (size_t i = 0; i < *service_count; i++) {
    if (has_text(services[i].chatgpt_web_provider_id)) {
      if (write != i) {
        services[write] = services[i];
        memset(&services[i], 0, sizeof(services[i]));
      }
      write++;
    } else {
      free_service(&services[i]);
    }
  }
  *service_count = write;
}

bool aether_has_chatgpt_web_upload_service_id(sqlite3 *db, long service_id) {
  sqlite3_stmt *stmt = NULL;
  bool found = false;
  const char *sql =
      "SELECT 1 FROM aether_services "
      "WHERE enabled=1 AND LENGTH(TRIM(COALESCE(chatgpt_web_provider_id,''))) > 0 "
      "AND (?1<=0 OR id=?1) "
      "LIMIT 1";

  if (db == NULL) return false;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return false;
  sqlite3_bind_int64(stmt, 1, service_id);
  found = sqlite3_step(stmt) == SQLITE_ROW;
  sqlite3_finalize(stmt);
  return found;
}

bool aether_has_chatgpt_web_upload_service(sqlite3 *db) {
  return aether_has_chatgpt_web_upload_service_id(db, 0);
}

static void normalize_root_url(const char *api_url, char *out, size_t len) {
  static const char *suffixes[] = {
      "/openapi.json",
      "/redoc",
      "/docs",
      "/api/admin/provider-oauth",
      "/api/admin/providers",
      "/api/admin/pool",
      "/api/admin",
      "/api",
  };
  size_t n;

  if (out == NULL || len == 0) return;
  mg_snprintf(out, len, "%s", api_url ? api_url : "");
  n = strlen(out);
  while (n > 0 && out[n - 1] == '/') out[--n] = '\0';
  for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
    size_t suffix_len = strlen(suffixes[i]);
    if (n >= suffix_len &&
        strcasecmp(out + n - suffix_len, suffixes[i]) == 0) {
      out[n - suffix_len] = '\0';
      return;
    }
  }
}

static int build_aether_url(const char *api_url, const char *path, char *out,
                            size_t len) {
  char root[512];
  normalize_root_url(api_url, root, sizeof(root));
  if (!has_text(root) || path == NULL || out == NULL || len == 0) return -1;
  mg_snprintf(out, len, "%s%s%s", root, path[0] == '/' ? "" : "/", path);
  return 0;
}

static void append_json_field(struct mg_iobuf *io, bool *first, const char *key,
                              const char *value) {
  if (!has_text(value)) return;
  mg_xprintf(mg_pfn_iobuf, io, "%s%m:%m", *first ? "" : ",", MG_ESC(key),
             MG_ESC(value));
  *first = false;
}

static void append_detail(struct mg_iobuf *details, bool *first, long id,
                          const char *email, bool success, const char *message,
                          const char *error) {
  mg_xprintf(mg_pfn_iobuf, details, "%s{%m:%ld,%m:%m,%m:%d",
             *first ? "" : ",", MG_ESC("id"), id, MG_ESC("email"),
             MG_ESC(email ? email : ""), MG_ESC("success"), success);
  if (success) {
    mg_xprintf(mg_pfn_iobuf, details, ",%m:%m", MG_ESC("message"),
               MG_ESC(message ? message : "上传成功"));
  } else {
    mg_xprintf(mg_pfn_iobuf, details, ",%m:%m", MG_ESC("error"),
               MG_ESC(error ? error : "上传失败"));
  }
  mg_xprintf(mg_pfn_iobuf, details, "}");
  *first = false;
}

static void free_upload_account(struct upload_account *account) {
  if (account == NULL) return;
  free(account->email);
  free(account->access_token);
  free(account->refresh_token);
  free(account->external_account_id);
  free(account->workspace_id);
}

static int load_upload_account(sqlite3 *db, long id,
                               struct upload_account *out) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "SELECT a.id,a.email,COALESCE(s.access_token,''),"
      "COALESCE(s.refresh_token,''),COALESCE(s.external_account_id,''),"
      "COALESCE(s.workspace_id,'') "
      "FROM accounts a LEFT JOIN account_secrets s ON s.account_id=a.id "
      "WHERE a.id=?";

  memset(out, 0, sizeof(*out));
  if (db == NULL || id <= 0 || out == NULL) return -1;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
  sqlite3_bind_int64(stmt, 1, id);
  if (sqlite3_step(stmt) != SQLITE_ROW) {
    sqlite3_finalize(stmt);
    return -1;
  }
  out->id = (long) sqlite3_column_int64(stmt, 0);
  out->email = str_dup(column_text(stmt, 1));
  out->access_token = str_dup(column_text(stmt, 2));
  out->refresh_token = str_dup(column_text(stmt, 3));
  out->external_account_id = str_dup(column_text(stmt, 4));
  out->workspace_id = str_dup(column_text(stmt, 5));
  sqlite3_finalize(stmt);
  return out->email == NULL ? -1 : 0;
}

static void append_credential_entry(struct mg_iobuf *credentials,
                                    const struct upload_account *account,
                                    bool include_web_credentials) {
  bool first = true;
  mg_xprintf(mg_pfn_iobuf, credentials, "{");
  if (include_web_credentials) {
    append_json_field(credentials, &first, "accessToken",
                      account->access_token);
    append_json_field(credentials, &first, "email", account->email);
    append_json_field(credentials, &first, "accountId",
                      account->external_account_id);
    append_json_field(credentials, &first, "workspaceId",
                      account->workspace_id);
  } else {
    append_json_field(credentials, &first, "refresh_token",
                      account->refresh_token);
    append_json_field(credentials, &first, "access_token",
                      account->access_token);
    append_json_field(credentials, &first, "email", account->email);
    append_json_field(credentials, &first, "account_id",
                      account->external_account_id);
    append_json_field(credentials, &first, "workspace_id",
                      account->workspace_id);
  }
  mg_xprintf(mg_pfn_iobuf, credentials, "}");
}

static char *build_credentials_json(const struct upload_account *accounts,
                                    const size_t *indexes, size_t count,
                                    bool include_web_credentials) {
  struct mg_iobuf credentials = {0, 0, 0, 2048};
  bool first = true;

  if (accounts == NULL && count > 0) return NULL;
  mg_xprintf(mg_pfn_iobuf, &credentials, "[");
  for (size_t i = 0; i < count; i++) {
    size_t account_index = indexes != NULL ? indexes[i] : i;
    mg_xprintf(mg_pfn_iobuf, &credentials, "%s", first ? "" : ",");
    append_credential_entry(&credentials, &accounts[account_index],
                            include_web_credentials);
    first = false;
  }
  mg_xprintf(mg_pfn_iobuf, &credentials, "]");
  mg_iobuf_add(&credentials, credentials.len, "", 1);
  return (char *) credentials.buf;
}

static char *extract_error_message(const struct http_client_response *res,
                                   const char *fallback) {
  char *msg = NULL;
  if (res != NULL && res->body != NULL) {
    msg = mg_json_get_str(mg_str(res->body), "$.message");
    if (msg == NULL) msg = mg_json_get_str(mg_str(res->body), "$.detail");
    if (msg == NULL) msg = mg_json_get_str(mg_str(res->body), "$.error.message");
    if (msg == NULL) msg = mg_json_get_str(mg_str(res->body), "$.error");
  }
  if (msg == NULL) {
    char buf[320];
    if (res != NULL && res->status_code > 0) {
      mg_snprintf(buf, sizeof(buf), "%s: HTTP %ld", fallback ? fallback : "请求失败",
                  res->status_code);
    } else if (res != NULL && res->error[0] != '\0') {
      mg_snprintf(buf, sizeof(buf), "%s: %s", fallback ? fallback : "请求失败",
                  res->error);
    } else {
      mg_snprintf(buf, sizeof(buf), "%s", fallback ? fallback : "请求失败");
    }
    return str_dup(buf);
  }
  return msg;
}

static int aether_get_json(const char *api_url, const char *management_token,
                           const char *path,
                           struct http_client_response *res) {
  struct http_client_header headers[1];
  struct http_client_request req;
  char auth_header[1024];
  char url[AETHER_URL_LEN];

  if (build_aether_url(api_url, path, url, sizeof(url)) != 0) {
    if (res != NULL) memset(res, 0, sizeof(*res));
    return -1;
  }
  mg_snprintf(auth_header, sizeof(auth_header), "Bearer %s",
              management_token ? management_token : "");
  headers[0].name = "Authorization";
  headers[0].value = auth_header;

  memset(&req, 0, sizeof(req));
  req.method = "GET";
  req.url = url;
  req.timeout_ms = 15000L;
  req.headers = headers;
  req.num_headers = 1;
  return http_client_perform(&req, res);
}

static int post_batch_import(const struct aether_service *svc,
                             const char *provider_id,
                             const char *credentials_json,
                             struct http_client_response *res) {
  struct http_client_header headers[2];
  struct http_client_request req;
  struct mg_iobuf body = {0, 0, 0, 1024};
  char auth_header[1024];
  char root[512], url[AETHER_URL_LEN];
  const char *proxy_node_id;
  int rc;

  normalize_root_url(svc->api_url, root, sizeof(root));
  if (!has_text(root)) {
    if (res != NULL) memset(res, 0, sizeof(*res));
    return -1;
  }
  mg_snprintf(url, sizeof(url),
              "%s/api/admin/provider-oauth/providers/%s/batch-import",
              root, provider_id);
  mg_snprintf(auth_header, sizeof(auth_header), "Bearer %s",
              svc->management_token ? svc->management_token : "");
  headers[0].name = "Authorization";
  headers[0].value = auth_header;
  headers[1].name = "Content-Type";
  headers[1].value = "application/json";

  mg_xprintf(mg_pfn_iobuf, &body, "{%m:%m", MG_ESC("credentials"),
             MG_ESC(credentials_json));
  proxy_node_id = service_request_proxy_node_id(svc);
  if (has_text(proxy_node_id)) {
    mg_xprintf(mg_pfn_iobuf, &body, ",%m:%m", MG_ESC("proxy_node_id"),
               MG_ESC(proxy_node_id));
  }
  mg_xprintf(mg_pfn_iobuf, &body, "}");
  mg_iobuf_add(&body, body.len, "", 1);

  memset(&req, 0, sizeof(req));
  req.method = "POST";
  req.url = url;
  req.body = (char *) body.buf;
  req.body_len = body.len > 0 ? body.len - 1 : 0;
  req.timeout_ms = AETHER_TIMEOUT_MS;
  req.headers = headers;
  req.num_headers = 2;

  rc = http_client_perform(&req, res);
  free(body.buf);
  return rc;
}

static bool is_retryable_upload_response(
    int rc, const struct http_client_response *res) {
  long status = res != NULL ? res->status_code : 0;
  if (rc != 0) return true;
  return status == 408 || status == 425 || status == 429 ||
         (status >= 500 && status < 600);
}

static void sleep_before_upload_retry(int completed_attempts) {
  long delay_ms = AETHER_RETRY_BACKOFF_INITIAL_MS * completed_attempts;
  if (delay_ms < AETHER_RETRY_BACKOFF_INITIAL_MS) {
    delay_ms = AETHER_RETRY_BACKOFF_INITIAL_MS;
  }
  if (delay_ms > AETHER_RETRY_BACKOFF_MAX_MS) {
    delay_ms = AETHER_RETRY_BACKOFF_MAX_MS;
  }
  usleep((useconds_t) delay_ms * 1000U);
}

static int post_batch_import_with_retry(const struct aether_service *svc,
                                        const char *provider_id,
                                        const char *credentials_json,
                                        struct http_client_response *res,
                                        int *attempt_count) {
  int retries = svc != NULL ? clamp_retry_count(svc->retry_count) : 0;
  int max_attempts = retries + 1;
  int rc = -1;

  if (res != NULL) memset(res, 0, sizeof(*res));
  if (attempt_count != NULL) *attempt_count = 0;
  for (int attempt = 0; attempt < max_attempts; attempt++) {
    rc = post_batch_import(svc, provider_id, credentials_json, res);
    if (attempt_count != NULL) *attempt_count = attempt + 1;
    if (!is_retryable_upload_response(rc, res) ||
        attempt + 1 >= max_attempts) {
      break;
    }
    http_client_response_free(res);
    sleep_before_upload_retry(attempt + 1);
  }
  return rc;
}

static char *json_item_str(struct mg_str json, const char *array_path,
                           size_t index, const char *field) {
  char path[160];
  mg_snprintf(path, sizeof(path), "%s[%lu].%s", array_path,
              (unsigned long) index, field);
  return mg_json_get_str(json, path);
}

static long json_item_long(struct mg_str json, const char *array_path,
                           size_t index, const char *field, long fallback) {
  char path[160];
  int len = 0;
  mg_snprintf(path, sizeof(path), "%s[%lu].%s", array_path,
              (unsigned long) index, field);
  if (mg_json_get(json, path, &len) < 0) return fallback;
  return mg_json_get_long(json, path, fallback);
}

static bool json_item_bool(struct mg_str json, const char *array_path,
                           size_t index, const char *field, bool fallback) {
  char path[160];
  bool value = fallback;
  mg_snprintf(path, sizeof(path), "%s[%lu].%s", array_path,
              (unsigned long) index, field);
  mg_json_get_bool(json, path, &value);
  return value;
}

static void append_aether_pools(struct mg_iobuf *out, const char *body) {
  struct mg_str json = mg_str(body ? body : "");
  bool first = true;

  for (size_t i = 0; i < 2000; i++) {
    char *provider_id = json_item_str(json, "$.items", i, "provider_id");
    char *provider_name = NULL;
    char *provider_type = NULL;
    long total_keys, active_keys, cooldown_count;
    bool pool_enabled;

    if (provider_id == NULL) provider_id = json_item_str(json, "$.items", i, "id");
    if (provider_id == NULL) break;
    if (!has_text(provider_id)) {
      mg_free(provider_id);
      continue;
    }
    provider_name = json_item_str(json, "$.items", i, "provider_name");
    if (provider_name == NULL) provider_name = json_item_str(json, "$.items", i, "name");
    provider_type = json_item_str(json, "$.items", i, "provider_type");
    total_keys = json_item_long(json, "$.items", i, "total_keys", 0);
    active_keys = json_item_long(json, "$.items", i, "active_keys", 0);
    cooldown_count = json_item_long(json, "$.items", i, "cooldown_count", 0);
    pool_enabled = json_item_bool(json, "$.items", i, "pool_enabled", true);

    mg_xprintf(
        mg_pfn_iobuf, out,
        "%s{%m:%m,%m:%m,%m:%m,%m:%ld,%m:%ld,%m:%ld,%m:%d}",
        first ? "" : ",", MG_ESC("provider_id"), MG_ESC(provider_id),
        MG_ESC("provider_name"), MG_ESC(has_text(provider_name) ? provider_name : provider_id),
        MG_ESC("provider_type"), MG_ESC(provider_type ? provider_type : ""),
        MG_ESC("total_keys"), total_keys, MG_ESC("active_keys"), active_keys,
        MG_ESC("cooldown_count"), cooldown_count, MG_ESC("pool_enabled"),
        pool_enabled);
    first = false;
    mg_free(provider_id);
    mg_free(provider_name);
    mg_free(provider_type);
  }
}

static void append_aether_proxy_nodes(struct mg_iobuf *out, const char *body) {
  struct mg_str json = mg_str(body ? body : "");
  bool first = true;

  for (size_t i = 0; i < 2000; i++) {
    char *id = json_item_str(json, "$.items", i, "id");
    char *name = NULL;
    char *ip = NULL;
    char *region = NULL;
    char *status = NULL;
    long port;
    bool is_manual, tunnel_mode, tunnel_connected;

    if (id == NULL) id = json_item_str(json, "$.items", i, "node_id");
    if (id == NULL) break;
    if (!has_text(id)) {
      mg_free(id);
      continue;
    }
    name = json_item_str(json, "$.items", i, "name");
    ip = json_item_str(json, "$.items", i, "ip");
    region = json_item_str(json, "$.items", i, "region");
    status = json_item_str(json, "$.items", i, "status");
    port = json_item_long(json, "$.items", i, "port", 0);
    is_manual = json_item_bool(json, "$.items", i, "is_manual", false);
    tunnel_mode = json_item_bool(json, "$.items", i, "tunnel_mode", false);
    tunnel_connected = json_item_bool(json, "$.items", i, "tunnel_connected", false);

    mg_xprintf(
        mg_pfn_iobuf, out,
        "%s{%m:%m,%m:%m,%m:%m,%m:%ld,%m:%m,%m:%m,%m:%d,%m:%d,%m:%d}",
        first ? "" : ",", MG_ESC("id"), MG_ESC(id), MG_ESC("name"),
        MG_ESC(has_text(name) ? name : id), MG_ESC("ip"), MG_ESC(ip ? ip : ""),
        MG_ESC("port"), port, MG_ESC("region"), MG_ESC(region ? region : ""),
        MG_ESC("status"), MG_ESC(status ? status : ""), MG_ESC("is_manual"),
        is_manual, MG_ESC("tunnel_mode"), tunnel_mode,
        MG_ESC("tunnel_connected"), tunnel_connected);
    first = false;
    mg_free(id);
    mg_free(name);
    mg_free(ip);
    mg_free(region);
    mg_free(status);
  }
}

static bool is_codex_oauth_provider_type(const char *provider_type) {
  return text_equals_ci(provider_type, "codex");
}

static bool provider_target_has_id(const struct aether_provider_target *targets,
                                   size_t count, const char *provider_id,
                                   size_t *index) {
  if (targets == NULL || !has_text(provider_id)) return false;
  for (size_t i = 0; i < count; i++) {
    if (strcmp(targets[i].id, provider_id) == 0) {
      if (index != NULL) *index = i;
      return true;
    }
  }
  return false;
}

static int filter_codex_oauth_provider_targets(
    const struct aether_service *svc, struct aether_provider_target **targets,
    size_t *target_count, char *error, size_t error_len) {
  struct http_client_response res;
  struct mg_str json;
  struct aether_provider_target *filtered = NULL;
  size_t filtered_count = 0, filtered_cap = 0;
  char first_rejected[AETHER_TEXT_LEN] = "";
  char first_rejected_type[AETHER_TEXT_LEN] = "";
  char *message = NULL;

  if (error != NULL && error_len > 0) error[0] = '\0';
  if (svc == NULL || targets == NULL || target_count == NULL ||
      *targets == NULL || *target_count == 0) {
    return -1;
  }

  memset(&res, 0, sizeof(res));
  if (aether_get_json(svc->api_url, svc->management_token,
                      "/api/admin/pool/overview", &res) != 0 ||
      res.status_code != 200) {
    message = extract_error_message(&res, "读取 Aether Provider 类型失败");
    if (error != NULL && error_len > 0) {
      mg_snprintf(error, error_len, "%s", message ? message : "");
    }
    mg_free(message);
    http_client_response_free(&res);
    return -1;
  }

  json = mg_str(res.body ? res.body : "");
  for (size_t i = 0; i < 2000; i++) {
    char *provider_id = json_item_str(json, "$.items", i, "provider_id");
    char *provider_name = NULL;
    char *provider_type = NULL;
    size_t target_index = 0;

    if (provider_id == NULL) provider_id = json_item_str(json, "$.items", i, "id");
    if (provider_id == NULL) break;
    if (!provider_target_has_id(*targets, *target_count, provider_id,
                                &target_index)) {
      mg_free(provider_id);
      continue;
    }

    provider_name = json_item_str(json, "$.items", i, "provider_name");
    if (provider_name == NULL) provider_name = json_item_str(json, "$.items", i, "name");
    provider_type = json_item_str(json, "$.items", i, "provider_type");
    if (is_codex_oauth_provider_type(provider_type)) {
      const char *name = has_text((*targets)[target_index].name)
                             ? (*targets)[target_index].name
                             : (has_text(provider_name) ? provider_name : provider_id);
      if (append_provider_target(&filtered, &filtered_count, &filtered_cap,
                                 provider_id, name) != 0) {
        mg_free(provider_id);
        mg_free(provider_name);
        mg_free(provider_type);
        http_client_response_free(&res);
        free(filtered);
        if (error != NULL && error_len > 0) {
          mg_snprintf(error, error_len, "%s",
                      "内存不足，无法筛选 Codex OAuth 号池");
        }
        return -1;
      }
    } else if (!has_text(first_rejected)) {
      mg_snprintf(first_rejected, sizeof(first_rejected), "%s",
                  has_text(provider_name) ? provider_name : provider_id);
      mg_snprintf(first_rejected_type, sizeof(first_rejected_type), "%s",
                  has_text(provider_type) ? provider_type : "unknown");
    }
    mg_free(provider_id);
    mg_free(provider_name);
    mg_free(provider_type);
  }
  http_client_response_free(&res);

  if (filtered_count == 0) {
    free(filtered);
    if (error != NULL && error_len > 0) {
      if (has_text(first_rejected)) {
        mg_snprintf(error, error_len,
                    "配置的 OAuth 号池不是 Codex 固定类型，无法使用 "
                    "provider-oauth：%s (%s)",
                    first_rejected, first_rejected_type);
      } else {
        mg_snprintf(error, error_len,
                    "%s", "配置的 OAuth 号池未在 Aether Provider 列表中找到");
      }
    }
    return -1;
  }

  free(*targets);
  *targets = filtered;
  *target_count = filtered_count;
  return 0;
}

static void free_upload_assignment_groups(
    struct aether_upload_assignment_group *groups, size_t count) {
  if (groups == NULL) return;
  for (size_t i = 0; i < count; i++) free(groups[i].account_indexes);
  free(groups);
}

static int append_upload_group_account(
    struct aether_upload_assignment_group *group, size_t account_index) {
  size_t *next;
  if (group == NULL) return -1;
  if (group->count == group->cap) {
    group->cap = group->cap == 0 ? 4 : group->cap * 2;
    next = (size_t *) realloc(group->account_indexes,
                              group->cap * sizeof(*group->account_indexes));
    if (next == NULL) return -1;
    group->account_indexes = next;
  }
  group->account_indexes[group->count++] = account_index;
  return 0;
}

static int add_upload_assignment_group(
    struct aether_upload_assignment_group **groups, size_t *count, size_t *cap,
    size_t provider_index, size_t node_index, size_t account_index) {
  struct aether_upload_assignment_group *next;

  if (groups == NULL || count == NULL || cap == NULL) return -1;
  for (size_t i = 0; i < *count; i++) {
    if ((*groups)[i].provider_index == provider_index &&
        (*groups)[i].node_index == node_index) {
      return append_upload_group_account(&(*groups)[i], account_index);
    }
  }
  if (*count == *cap) {
    *cap = *cap == 0 ? 4 : *cap * 2;
    next = (struct aether_upload_assignment_group *) realloc(
        *groups, *cap * sizeof(**groups));
    if (next == NULL) return -1;
    *groups = next;
  }
  memset(&(*groups)[*count], 0, sizeof((*groups)[*count]));
  (*groups)[*count].provider_index = provider_index;
  (*groups)[*count].node_index = node_index;
  if (append_upload_group_account(&(*groups)[*count], account_index) != 0) {
    return -1;
  }
  (*count)++;
  return 0;
}

static int load_online_proxy_nodes(const struct aether_service *svc,
                                   struct aether_proxy_node **out,
                                   size_t *out_len, char *error,
                                   size_t error_len) {
  struct http_client_response res;
  struct mg_str json;
  struct aether_proxy_node *items = NULL;
  size_t len = 0, cap = 0;
  char *message = NULL;

  if (out != NULL) *out = NULL;
  if (out_len != NULL) *out_len = 0;
  if (error != NULL && error_len > 0) error[0] = '\0';
  if (svc == NULL || out == NULL || out_len == NULL) return -1;

  memset(&res, 0, sizeof(res));
  if (aether_get_json(svc->api_url, svc->management_token,
                      "/api/admin/proxy-nodes?status=online&limit=1000",
                      &res) != 0 ||
      res.status_code != 200) {
    message = extract_error_message(&res, "读取 Aether 在线代理节点失败");
    if (error != NULL && error_len > 0) {
      mg_snprintf(error, error_len, "%s", message ? message : "");
    }
    mg_free(message);
    http_client_response_free(&res);
    return -1;
  }

  json = mg_str(res.body ? res.body : "");
  for (size_t i = 0; i < 2000; i++) {
    char *id = json_item_str(json, "$.items", i, "id");
    char *name = NULL;
    struct aether_proxy_node *next;

    if (id == NULL) id = json_item_str(json, "$.items", i, "node_id");
    if (id == NULL) break;
    if (!has_text(id)) {
      mg_free(id);
      continue;
    }
    name = json_item_str(json, "$.items", i, "name");
    if (len == cap) {
      cap = cap == 0 ? 8 : cap * 2;
      next = (struct aether_proxy_node *) realloc(items,
                                                  cap * sizeof(*items));
      if (next == NULL) {
        mg_free(id);
        mg_free(name);
        free(items);
        http_client_response_free(&res);
        if (error != NULL && error_len > 0) {
          mg_snprintf(error, error_len, "%s", "内存不足，无法读取代理节点");
        }
        return -1;
      }
      items = next;
    }
    mg_snprintf(items[len].id, sizeof(items[len].id), "%s", id);
    mg_snprintf(items[len].name, sizeof(items[len].name), "%s",
                has_text(name) ? name : id);
    len++;
    mg_free(id);
    mg_free(name);
  }
  http_client_response_free(&res);

  if (len == 0) {
    free(items);
    if (error != NULL && error_len > 0) {
      mg_snprintf(error, error_len, "%s", "Aether 没有可用在线代理节点");
    }
    return -1;
  }
  *out = items;
  *out_len = len;
  return 0;
}

static long json_long_default(struct mg_str body, const char *path,
                              long fallback) {
  int len = 0;
  if (mg_json_get(body, path, &len) < 0) return fallback;
  return mg_json_get_long(body, path, fallback);
}

static char *json_result_string(struct mg_str body, size_t index,
                                const char *field) {
  char path[96];
  mg_snprintf(path, sizeof(path), "$.results[%lu].%s", (unsigned long) index,
              field);
  return mg_json_get_str(body, path);
}

static void update_upload_stats(sqlite3 *db, long attempted, long success,
                                long failed, long skipped,
                                const char *message) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "UPDATE aether_upload_stats SET "
      "total_attempted=total_attempted+?,"
      "success_count=success_count+?,"
      "failed_count=failed_count+?,"
      "skipped_count=skipped_count+?,"
      "last_success_at=CASE WHEN ?>0 THEN unixepoch() ELSE last_success_at END,"
      "last_failed_at=CASE WHEN ?>0 THEN unixepoch() ELSE last_failed_at END,"
      "last_message=?,updated_at=unixepoch() WHERE id=1";
  if (db == NULL) return;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return;
  sqlite3_bind_int64(stmt, 1, attempted);
  sqlite3_bind_int64(stmt, 2, success);
  sqlite3_bind_int64(stmt, 3, failed);
  sqlite3_bind_int64(stmt, 4, skipped);
  sqlite3_bind_int64(stmt, 5, success);
  sqlite3_bind_int64(stmt, 6, failed);
  sqlite3_bind_text(stmt, 7, message ? message : "", -1, SQLITE_TRANSIENT);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

static void parse_upload_result_map(
    const struct http_client_response *res, size_t count,
    unsigned char *account_success, long *success_count, long *failed_count,
    char *first_error, size_t first_error_len) {
  struct mg_str body = mg_str(res->body ? res->body : "");
  long top_failed = json_long_default(body, "$.failed", -1);
  bool has_results = false;

  if (success_count != NULL) *success_count = 0;
  if (failed_count != NULL) *failed_count = 0;
  if (account_success != NULL && count > 0) memset(account_success, 0, count);
  for (size_t i = 0; i < count; i++) {
    char *status = json_result_string(body, i, "status");
    char *message = json_result_string(body, i, "message");
    char *error = json_result_string(body, i, "error");
    bool success = false;
    const char *failure_message = "Aether 返回结果不完整，无法确认该账号导入状态";

    if (status != NULL || message != NULL || error != NULL) has_results = true;
    if (status == NULL && message == NULL && error == NULL) {
      if (!has_results && top_failed == 0) {
        success = true;
      }
    } else if (text_equals_ci(status, "success") ||
               text_equals_ci(status, "ok") ||
               text_equals_ci(status, "uploaded")) {
      success = true;
    } else if (is_already_exists_error(error) || is_already_exists_error(message)) {
      success = true;
    } else {
      failure_message = has_text(error) ? error :
                        (has_text(message) ? message : failure_message);
    }

    if (success) {
      if (account_success != NULL) account_success[i] = 1;
      if (success_count != NULL) (*success_count)++;
    } else {
      if (failed_count != NULL) (*failed_count)++;
      if (first_error != NULL && first_error_len > 0 &&
          first_error[0] == '\0') {
        mg_snprintf(first_error, first_error_len, "%s", failure_message);
      }
    }

    mg_free(status);
    mg_free(message);
    mg_free(error);
  }
  if (count > 0 && failed_count != NULL && *failed_count > 0 &&
      first_error != NULL && first_error_len > 0 &&
      first_error[0] == '\0') {
    mg_snprintf(first_error, first_error_len, "%s",
                "Aether 返回结果不完整，无法确认该账号导入状态");
  }
}

static void init_service_upload_result(
    struct aether_service_upload_result *result,
    const struct aether_service *svc, const char *provider_id) {
  if (result == NULL || svc == NULL) return;
  result->service_id = svc->id;
  mg_snprintf(result->service_name, sizeof(result->service_name), "%s",
              has_text(svc->name) ? svc->name : "Aether 上传服务");
  mg_snprintf(result->provider_id, sizeof(result->provider_id), "%s",
              provider_id ? provider_id : "");
  result->retry_count = clamp_retry_count(svc->retry_count);
}

static void mark_service_result_failed(struct aether_service_upload_result *result,
                                       size_t account_count,
                                       const char *message) {
  if (result == NULL) return;
  result->success_count = 0;
  result->failed_count = (long) account_count;
  mg_snprintf(result->error, sizeof(result->error), "%s",
              has_text(message) ? message : "Aether 上传失败");
}

static unsigned int make_proxy_assignment_seed(
    const struct aether_upload_worker *worker) {
  struct timespec ts;
  uintptr_t seed;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    ts.tv_sec = time(NULL);
    ts.tv_nsec = 0;
  }
  seed = (uintptr_t) ts.tv_sec ^ (uintptr_t) ts.tv_nsec ^
         (uintptr_t) getpid() ^ (uintptr_t) worker ^
         (uintptr_t) (worker != NULL ? worker->service : NULL);
  return (unsigned int) (seed ^ (seed >> 32));
}

static void run_fixed_proxy_upload_group(
    struct aether_upload_worker *worker, const struct aether_service *svc,
    const char *provider_id, const struct aether_upload_assignment_group *group,
    struct aether_service_upload_result *result) {
  struct http_client_response res;
  char *credentials_json;
  unsigned char *group_success = NULL;
  char *message = NULL;
  char group_error[512] = "";
  long group_success_count = 0;
  long group_failed_count = 0;
  int group_attempts = 0;
  int rc;

  if (worker == NULL || svc == NULL || provider_id == NULL || group == NULL ||
      result == NULL || group->count == 0) {
    return;
  }

  credentials_json = build_credentials_json(worker->accounts,
                                            group->account_indexes,
                                            group->count,
                                            worker->include_web_credentials);
  group_success = (unsigned char *) calloc(group->count, 1);
  if (credentials_json == NULL || group_success == NULL) {
    result->failed_count += (long) group->count;
    if (!has_text(result->error)) {
      mg_snprintf(result->error, sizeof(result->error), "%s",
                  "内存不足，无法构建上传凭据");
    }
    free(credentials_json);
    free(group_success);
    return;
  }

  memset(&res, 0, sizeof(res));
  rc = post_batch_import_with_retry(svc, provider_id, credentials_json, &res,
                                    &group_attempts);
  result->attempts += group_attempts;
  result->http_status = res.status_code;
  if (rc != 0 || res.status_code < 200 || res.status_code >= 300) {
    message = extract_error_message(&res, "Aether 上传失败");
    result->failed_count += (long) group->count;
    if (!has_text(result->error)) {
      mg_snprintf(result->error, sizeof(result->error), "%s",
                  message ? message : "Aether 上传失败");
    }
    mg_free(message);
    http_client_response_free(&res);
    free(credentials_json);
    free(group_success);
    return;
  }

  parse_upload_result_map(&res, group->count, group_success,
                          &group_success_count, &group_failed_count,
                          group_error, sizeof(group_error));
  result->success_count += group_success_count;
  result->failed_count += group_failed_count;
  for (size_t i = 0; i < group->count; i++) {
    if (group_success[i] && result->account_success != NULL) {
      result->account_success[group->account_indexes[i]] = 1;
    }
  }
  if (group_failed_count > 0 && !has_text(result->error)) {
    mg_snprintf(result->error, sizeof(result->error), "%s",
                has_text(group_error) ? group_error : "部分账号上传失败");
  }
  http_client_response_free(&res);
  free(credentials_json);
  free(group_success);
}

static void run_random_proxy_upload_group(
    struct aether_upload_worker *worker, const struct aether_service *svc,
    const char *provider_id, const struct aether_proxy_node *node,
    const struct aether_upload_assignment_group *group,
    struct aether_service_upload_result *result) {
  struct aether_service request_svc;
  struct http_client_response res;
  unsigned char *group_success = NULL;
  char *credentials_json = NULL;
  char *message = NULL;
  char group_error[512] = "";
  long group_success_count = 0;
  long group_failed_count = 0;
  int group_attempts = 0;
  int rc;

  if (worker == NULL || svc == NULL || provider_id == NULL || node == NULL ||
      group == NULL || result == NULL || group->count == 0) {
    return;
  }

  credentials_json = build_credentials_json(worker->accounts,
                                            group->account_indexes,
                                            group->count,
                                            worker->include_web_credentials);
  group_success = (unsigned char *) calloc(group->count, 1);
  if (credentials_json == NULL || group_success == NULL) {
    result->failed_count += (long) group->count;
    if (!has_text(result->error)) {
      mg_snprintf(result->error, sizeof(result->error), "%s",
                  "内存不足，无法构建随机代理上传任务");
    }
    free(credentials_json);
    free(group_success);
    return;
  }

  request_svc = *svc;
  mg_snprintf(request_svc.proxy_node_id, sizeof(request_svc.proxy_node_id),
              "%s", node->id);
  mg_snprintf(request_svc.proxy_node_name, sizeof(request_svc.proxy_node_name),
              "%s", node->name);
  mg_snprintf(request_svc.proxy_node_mode, sizeof(request_svc.proxy_node_mode),
              "%s", AETHER_PROXY_MODE_FIXED);

  memset(&res, 0, sizeof(res));
  rc = post_batch_import_with_retry(&request_svc, provider_id,
                                    credentials_json, &res, &group_attempts);
  result->attempts += group_attempts;
  result->http_status = res.status_code;
  if (rc != 0 || res.status_code < 200 || res.status_code >= 300) {
    message = extract_error_message(&res, "Aether 上传失败");
    result->failed_count += (long) group->count;
    if (!has_text(result->error)) {
      mg_snprintf(result->error, sizeof(result->error), "%s",
                  message ? message : "Aether 上传失败");
    }
    mg_free(message);
    http_client_response_free(&res);
    free(credentials_json);
    free(group_success);
    return;
  }

  parse_upload_result_map(&res, group->count, group_success,
                          &group_success_count, &group_failed_count,
                          group_error, sizeof(group_error));
  result->success_count += group_success_count;
  result->failed_count += group_failed_count;
  for (size_t i = 0; i < group->count; i++) {
    if (group_success[i] && result->account_success != NULL) {
      result->account_success[group->account_indexes[i]] = 1;
    }
  }
  if (group_failed_count > 0 && !has_text(result->error)) {
    mg_snprintf(result->error, sizeof(result->error), "%s",
                has_text(group_error) ? group_error : "部分账号上传失败");
  }

  http_client_response_free(&res);
  free(credentials_json);
  free(group_success);
}

static void run_assigned_upload_groups(
    struct aether_upload_worker *worker, const struct aether_service *svc,
    const struct aether_provider_target *providers, size_t provider_count,
    struct aether_service_upload_result *result) {
  struct aether_proxy_node *nodes = NULL;
  size_t node_count = 0;
  struct aether_upload_assignment_group *groups = NULL;
  size_t group_count = 0, group_cap = 0;
  char error[512] = "";
  unsigned int rng;
  bool random_proxy;

  if (worker == NULL || svc == NULL || providers == NULL ||
      provider_count == 0 || result == NULL) {
    return;
  }

  random_proxy = service_uses_random_proxy(svc);
  if (random_proxy &&
      load_online_proxy_nodes(svc, &nodes, &node_count, error,
                              sizeof(error)) != 0) {
    mark_service_result_failed(
        result, worker->account_count,
        has_text(error) ? error : "读取 Aether 在线代理节点失败");
    return;
  }

  rng = make_proxy_assignment_seed(worker);
  for (size_t i = 0; i < worker->account_count; i++) {
    size_t provider_index =
        (size_t) (rand_r(&rng) % (unsigned int) provider_count);
    size_t node_index = random_proxy
                            ? (size_t) (rand_r(&rng) % (unsigned int) node_count)
                            : (size_t) -1;
    if (add_upload_assignment_group(&groups, &group_count, &group_cap,
                                    provider_index, node_index, i) != 0) {
      free_upload_assignment_groups(groups, group_count);
      free(nodes);
      mark_service_result_failed(result, worker->account_count,
                                 "内存不足，无法随机分配上传目标");
      return;
    }
  }

  for (size_t i = 0; i < group_count; i++) {
    const struct aether_provider_target *provider =
        &providers[groups[i].provider_index];
    if (random_proxy) {
      const struct aether_proxy_node *node = &nodes[groups[i].node_index];
      run_random_proxy_upload_group(worker, svc, provider->id, node, &groups[i],
                                    result);
    } else {
      run_fixed_proxy_upload_group(worker, svc, provider->id, &groups[i],
                                   result);
    }
  }

  free_upload_assignment_groups(groups, group_count);
  free(nodes);
}

static void run_aether_upload_worker(struct aether_upload_worker *worker) {
  const struct aether_service *svc;
  struct aether_service_upload_result *result;
  struct aether_provider_target *providers = NULL;
  size_t provider_count = 0;
  char provider_error[512] = "";

  if (worker == NULL || worker->service == NULL || worker->result == NULL) {
    return;
  }
  svc = worker->service;
  result = worker->result;
  init_service_upload_result(result, svc, worker->provider_id);

  if (!has_text(svc->api_url)) {
    mark_service_result_failed(result, worker->account_count,
                               "服务配置缺少 Aether 地址");
    return;
  }
  if (!has_text(svc->management_token)) {
    mark_service_result_failed(result, worker->account_count,
                               "服务配置缺少管理员 Token");
    return;
  }
  if (load_service_provider_targets(svc, worker->include_web_credentials,
                                    &providers, &provider_count) != 0) {
    mark_service_result_failed(result, worker->account_count,
                               "服务未配置当前号池的 Provider ID");
    return;
  }
  if (!worker->include_web_credentials &&
      filter_codex_oauth_provider_targets(svc, &providers, &provider_count,
                                          provider_error,
                                          sizeof(provider_error)) != 0) {
    mark_service_result_failed(
        result, worker->account_count,
        has_text(provider_error) ? provider_error
                                 : "服务未配置可用于导入的 Codex OAuth 号池");
    free(providers);
    return;
  }

  init_service_upload_result(result, svc, providers[0].id);
  run_assigned_upload_groups(worker, svc, providers, provider_count, result);
  free(providers);
}

static void *aether_upload_worker_main(void *arg) {
  run_aether_upload_worker((struct aether_upload_worker *) arg);
  return NULL;
}

static void append_service_results_json(
    struct mg_iobuf *out, const struct aether_service_upload_result *results,
    size_t count) {
  mg_xprintf(mg_pfn_iobuf, out, "[");
  if (results == NULL) {
    mg_xprintf(mg_pfn_iobuf, out, "]");
    return;
  }
  for (size_t i = 0; i < count; i++) {
    const struct aether_service_upload_result *r = &results[i];
    mg_xprintf(
        mg_pfn_iobuf, out,
        "%s{%m:%ld,%m:%m,%m:%m,%m:%d,%m:%d,%m:%ld,%m:%ld,%m:%ld,%m:%m}",
        i == 0 ? "" : ",", MG_ESC("id"), r->service_id, MG_ESC("name"),
        MG_ESC(r->service_name), MG_ESC("provider_id"), MG_ESC(r->provider_id),
        MG_ESC("retry_count"), r->retry_count, MG_ESC("attempts"),
        r->attempts, MG_ESC("http_status"), r->http_status,
        MG_ESC("success_count"), r->success_count, MG_ESC("failed_count"),
        r->failed_count, MG_ESC("error"), MG_ESC(r->error));
  }
  mg_xprintf(mg_pfn_iobuf, out, "]");
}

static void first_failed_service_message(
    const struct aether_service_upload_result *results, size_t service_count,
    size_t account_index, char *out, size_t out_len) {
  if (out == NULL || out_len == 0) return;
  out[0] = '\0';
  for (size_t i = 0; i < service_count; i++) {
    const struct aether_service_upload_result *r = &results[i];
    if (r->account_success == NULL || r->account_success[account_index]) {
      continue;
    }
    mg_snprintf(out, out_len, "%s：%s", r->service_name,
                has_text(r->error) ? r->error : "上传失败");
    return;
  }
  mg_snprintf(out, out_len, "%s", "未能上传到全部启用服务");
}

static int normalize_pool_type(const char *pool_type, bool *include_web) {
  if (include_web != NULL) *include_web = false;
  if (!has_text(pool_type) || text_equals_ci(pool_type, "oauth") ||
      text_equals_ci(pool_type, "normal") || text_equals_ci(pool_type, "default")) {
    return 0;
  }
  if (text_equals_ci(pool_type, "chatgpt_web") ||
      text_equals_ci(pool_type, "web") || text_equals_ci(pool_type, "chatgpt")) {
    if (include_web != NULL) *include_web = true;
    return 0;
  }
  return -1;
}

char *aether_upload_accounts_to_service_json(sqlite3 *db, const long *ids,
                                             size_t count,
                                             const char *pool_type,
                                             long service_id) {
  struct aether_service *services = NULL;
  size_t service_count = 0;
  struct aether_service_upload_result *service_results = NULL;
  struct aether_upload_worker *workers = NULL;
  pthread_t *threads = NULL;
  unsigned char *thread_started = NULL;
  struct upload_account *valid = NULL;
  size_t valid_len = 0, valid_cap = 0;
  struct mg_iobuf details = {0, 0, 0, 2048};
  struct mg_iobuf out = {0, 0, 0, 2048};
  bool first_detail = true;
  bool include_web = false;
  char first_error[512] = "";
  long success_count = 0, failed_count = 0, skipped_count = 0;
  long *success_ids = NULL;
  size_t success_id_count = 0;
  int max_retry_count = 0;
  int max_attempt_count = 0;

  mg_xprintf(mg_pfn_iobuf, &details, "[");
  if (count == 0 || ids == NULL) {
    mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("请选择要上传的账号"));
    goto done;
  }
  if (normalize_pool_type(pool_type, &include_web) != 0) {
    mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("不支持的 Aether 上传号池类型"));
    goto done;
  }
  if (load_enabled_services(db, &services, &service_count) != 0 ||
      service_count == 0) {
    mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"),
               MG_ESC("未找到已启用的 Aether 上传服务，请先配置"));
    goto done;
  }
  if (service_id > 0) {
    filter_service_by_id(services, &service_count, service_id);
    if (service_count == 0) {
      mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
                 MG_ESC("error"),
                 MG_ESC("指定的 Aether 上传服务不存在或未启用"));
      goto done;
    }
  }
  if (include_web) {
    filter_web_upload_services(services, &service_count);
    if (service_count == 0) {
      mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
                 MG_ESC("error"),
                 MG_ESC(service_id > 0
                            ? "指定的 Aether 上传服务未配置 ChatGPT Web 账号池"
                            : "未找到已配置 ChatGPT Web 账号池的 Aether 上传服务，请先配置"));
      goto done;
    }
  }

  for (size_t i = 0; i < count; i++) {
    struct upload_account account;
    bool has_credentials;
    if (load_upload_account(db, ids[i], &account) != 0) {
      failed_count++;
      if (!has_text(first_error)) {
        mg_snprintf(first_error, sizeof(first_error), "%s", "账号不存在");
      }
      append_detail(&details, &first_detail, ids[i], "", false, NULL,
                    "账号不存在");
      continue;
    }
    has_credentials = include_web ? has_text(account.access_token)
                                  : (has_text(account.refresh_token) ||
                                     has_text(account.access_token));
    if (!has_credentials) {
      skipped_count++;
      append_detail(
          &details, &first_detail, account.id, account.email, false, NULL,
          include_web ? "缺少 ChatGPT Web 上传所需 Access Token"
                      : "缺少 refresh_token/access_token，无法上传到 Aether");
      free_upload_account(&account);
      continue;
    }
    if (valid_len == valid_cap) {
      struct upload_account *next;
      valid_cap = valid_cap == 0 ? 8 : valid_cap * 2;
      next = (struct upload_account *) realloc(valid,
                                               valid_cap * sizeof(*valid));
      if (next == NULL) {
        failed_count++;
        append_detail(&details, &first_detail, account.id, account.email, false,
                      NULL, "内存不足，无法构建上传任务");
        free_upload_account(&account);
        continue;
      }
      valid = next;
    }
    valid[valid_len++] = account;
  }

  if (valid_len > 0) {
    service_results = (struct aether_service_upload_result *) calloc(
        service_count, sizeof(*service_results));
    workers = (struct aether_upload_worker *) calloc(service_count,
                                                     sizeof(*workers));
    threads = (pthread_t *) calloc(service_count, sizeof(*threads));
    thread_started = (unsigned char *) calloc(service_count, 1);
    success_ids = (long *) calloc(valid_len, sizeof(*success_ids));
    if (service_results == NULL || workers == NULL || threads == NULL ||
        thread_started == NULL || success_ids == NULL) {
      mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
                 MG_ESC("error"), MG_ESC("内存不足，无法启动多服务上传"));
      goto done;
    }

    for (size_t i = 0; i < service_count; i++) {
      service_results[i].account_success =
          (unsigned char *) calloc(valid_len, 1);
      if (service_results[i].account_success == NULL) {
        mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
                   MG_ESC("error"), MG_ESC("内存不足，无法记录上传结果"));
        goto done;
      }
    }

    for (size_t i = 0; i < service_count; i++) {
      const char *provider_id = include_web ? services[i].chatgpt_web_provider_id
                                            : services[i].provider_id;
      workers[i].service = &services[i];
      workers[i].provider_id = provider_id;
      workers[i].accounts = valid;
      workers[i].include_web_credentials = include_web;
      workers[i].account_count = valid_len;
      workers[i].result = &service_results[i];
      if (service_count > 1 &&
          pthread_create(&threads[i], NULL, aether_upload_worker_main,
                         &workers[i]) == 0) {
        thread_started[i] = 1;
      } else {
        run_aether_upload_worker(&workers[i]);
      }
    }
    for (size_t i = 0; i < service_count; i++) {
      if (thread_started[i]) pthread_join(threads[i], NULL);
      if (service_results[i].retry_count > max_retry_count) {
        max_retry_count = service_results[i].retry_count;
      }
      if (service_results[i].attempts > max_attempt_count) {
        max_attempt_count = service_results[i].attempts;
      }
    }

    for (size_t i = 0; i < valid_len; i++) {
      char failure_message[768];
      bool account_ok = true;
      for (size_t svc_i = 0; svc_i < service_count; svc_i++) {
        if (service_results[svc_i].account_success == NULL ||
            !service_results[svc_i].account_success[i]) {
          account_ok = false;
          break;
        }
      }
      if (account_ok) {
        success_count++;
        success_ids[success_id_count++] = valid[i].id;
        if (service_count == 1) {
          mg_snprintf(failure_message, sizeof(failure_message),
                      "已上传到 Aether 服务：%s", services[0].name);
        } else {
          mg_snprintf(failure_message, sizeof(failure_message),
                      "已上传到 %lu 个启用服务",
                      (unsigned long) service_count);
        }
        append_detail(&details, &first_detail, valid[i].id, valid[i].email,
                      true, failure_message, NULL);
      } else {
        failed_count++;
        first_failed_service_message(service_results, service_count, i,
                                     failure_message,
                                     sizeof(failure_message));
        if (!has_text(first_error)) {
          mg_snprintf(first_error, sizeof(first_error), "%s", failure_message);
        }
        append_detail(&details, &first_detail, valid[i].id, valid[i].email,
                      false, NULL, failure_message);
      }
    }
  }

  if (success_id_count > 0) {
    account_set_upload_state(db, success_ids, success_id_count, 1);
  }
  update_upload_stats(db, (long) count, success_count, failed_count,
                      skipped_count,
                      success_count > 0 ? "多服务上传完成" :
                      (has_text(first_error) ? first_error : "上传未成功"));

  mg_xprintf(mg_pfn_iobuf, &details, "]");
  mg_xprintf(mg_pfn_iobuf, &out,
             "{%m:%d,%m:%ld,%m:%ld,%m:%ld,%m:%ld,%m:%m,%m:%d,%m:%lu,%m:%d,%m:",
             MG_ESC("ok"), 1, MG_ESC("attempted"), (long) count,
             MG_ESC("success_count"), success_count, MG_ESC("failed_count"),
             failed_count, MG_ESC("skipped_count"), skipped_count,
             MG_ESC("pool_type"), MG_ESC(include_web ? "chatgpt_web" : "oauth"),
             MG_ESC("retry_count"), max_retry_count,
             MG_ESC("service_count"), (unsigned long) service_count,
             MG_ESC("attempts"), max_attempt_count,
             MG_ESC("services"));
  append_service_results_json(&out, service_results, service_count);
  mg_xprintf(mg_pfn_iobuf, &out, ",%m:%s}", MG_ESC("details"),
             (char *) details.buf);

done:
  mg_iobuf_add(&out, out.len, "", 1);
  for (size_t i = 0; i < valid_len; i++) free_upload_account(&valid[i]);
  free(valid);
  if (service_results != NULL) {
    for (size_t i = 0; i < service_count; i++) {
      free(service_results[i].account_success);
    }
  }
  free(service_results);
  free(workers);
  free(threads);
  free(thread_started);
  free(success_ids);
  free(details.buf);
  free_service_array(services, service_count);
  return (char *) out.buf;
}

char *aether_upload_accounts_json(sqlite3 *db, const long *ids, size_t count,
                                  const char *pool_type) {
  return aether_upload_accounts_to_service_json(db, ids, count, pool_type, 0);
}

char *aether_config_json(sqlite3 *db) {
  sqlite3_stmt *stmt = NULL;
  struct mg_iobuf out = {0, 0, 0, 2048};
  sqlite3_int64 uploaded = 0, not_uploaded = 0;
  sqlite3_int64 attempted = 0, success = 0, failed = 0, skipped = 0;
  sqlite3_int64 last_success_at = 0, last_failed_at = 0, updated_at = 0;
  char last_message[AETHER_TEXT_LEN] = "";
  bool first = true;

  if (db != NULL &&
      sqlite3_prepare_v2(db,
                         "SELECT uploaded_count,not_uploaded_count FROM "
                         "account_stats WHERE id=1",
                         -1, &stmt, NULL) == SQLITE_OK &&
      sqlite3_step(stmt) == SQLITE_ROW) {
    uploaded = sqlite3_column_int64(stmt, 0);
    not_uploaded = sqlite3_column_int64(stmt, 1);
  }
  sqlite3_finalize(stmt);
  stmt = NULL;

  if (db != NULL &&
      sqlite3_prepare_v2(db,
                         "SELECT total_attempted,success_count,failed_count,"
                         "skipped_count,COALESCE(last_success_at,0),"
                         "COALESCE(last_failed_at,0),COALESCE(last_message,''),"
                         "updated_at FROM aether_upload_stats WHERE id=1",
                         -1, &stmt, NULL) == SQLITE_OK &&
      sqlite3_step(stmt) == SQLITE_ROW) {
    attempted = sqlite3_column_int64(stmt, 0);
    success = sqlite3_column_int64(stmt, 1);
    failed = sqlite3_column_int64(stmt, 2);
    skipped = sqlite3_column_int64(stmt, 3);
    last_success_at = sqlite3_column_int64(stmt, 4);
    last_failed_at = sqlite3_column_int64(stmt, 5);
    mg_snprintf(last_message, sizeof(last_message), "%s", column_text(stmt, 6));
    updated_at = sqlite3_column_int64(stmt, 7);
  }
  sqlite3_finalize(stmt);
  stmt = NULL;

  mg_xprintf(mg_pfn_iobuf, &out,
             "{%m:{%m:%lld,%m:%lld,%m:%lld,%m:%lld,%m:%lld,%m:%lld,%m:%lld,"
             "%m:%lld,%m:%m,%m:%lld},%m:[",
             MG_ESC("stats"), MG_ESC("account_uploaded"), uploaded,
             MG_ESC("account_not_uploaded"), not_uploaded,
             MG_ESC("total_attempted"), attempted, MG_ESC("success_count"),
             success, MG_ESC("failed_count"), failed, MG_ESC("skipped_count"),
             skipped, MG_ESC("last_success_at"), last_success_at,
             MG_ESC("last_failed_at"), last_failed_at, MG_ESC("last_message"),
             MG_ESC(last_message), MG_ESC("updated_at"), updated_at,
             MG_ESC("services"));

  if (db != NULL &&
      sqlite3_prepare_v2(
          db,
          "SELECT id,name,api_url,management_token,provider_id,provider_name,"
          "COALESCE(oauth_provider_ids,'[]'),"
          "COALESCE(oauth_provider_names,'[]'),"
          "COALESCE(chatgpt_web_provider_id,''),"
          "COALESCE(chatgpt_web_provider_name,''),COALESCE(proxy_node_id,''),"
          "COALESCE(proxy_node_name,''),COALESCE(proxy_node_mode,'fixed'),"
          "enabled,priority,"
          "COALESCE(retry_count,2),created_at,updated_at "
          "FROM aether_services ORDER BY priority ASC,id ASC",
          -1, &stmt, NULL) == SQLITE_OK) {
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      const char *token = column_text(stmt, 3);
      struct aether_provider_target *oauth_targets = NULL;
      size_t oauth_target_count = 0;
      char *oauth_provider_ids_json = NULL;
      char *oauth_provider_names_json = NULL;

      if (load_provider_targets_from_json(
              column_text(stmt, 6), column_text(stmt, 7),
              column_text(stmt, 4), column_text(stmt, 5),
              &oauth_targets, &oauth_target_count) == 0) {
        oauth_provider_ids_json = provider_targets_json_array(
            oauth_targets, oauth_target_count, false);
        oauth_provider_names_json = provider_targets_json_array(
            oauth_targets, oauth_target_count, true);
      }
      mg_xprintf(
          mg_pfn_iobuf, &out,
          "%s{%m:%lld,%m:%m,%m:%m,%m:%m,%m:%m,%m:%s,%m:%s,%m:%m,%m:%m,"
          "%m:%m,%m:%m,%m:%m,%m:%d,%m:%d,%m:%d,%m:%d,%m:%lld,%m:%lld}",
          first ? "" : ",", MG_ESC("id"), sqlite3_column_int64(stmt, 0),
          MG_ESC("name"), MG_ESC(column_text(stmt, 1)), MG_ESC("api_url"),
          MG_ESC(column_text(stmt, 2)), MG_ESC("provider_id"),
          MG_ESC(column_text(stmt, 4)), MG_ESC("provider_name"),
          MG_ESC(column_text(stmt, 5)), MG_ESC("oauth_provider_ids"),
          oauth_provider_ids_json ? oauth_provider_ids_json : "[]",
          MG_ESC("oauth_provider_names"),
          oauth_provider_names_json ? oauth_provider_names_json : "[]",
          MG_ESC("chatgpt_web_provider_id"), MG_ESC(column_text(stmt, 8)),
          MG_ESC("chatgpt_web_provider_name"), MG_ESC(column_text(stmt, 9)),
          MG_ESC("proxy_node_id"), MG_ESC(column_text(stmt, 10)),
          MG_ESC("proxy_node_name"), MG_ESC(column_text(stmt, 11)),
          MG_ESC("proxy_node_mode"),
          MG_ESC(normalize_proxy_node_mode(column_text(stmt, 12))),
          MG_ESC("has_management_token"),
          has_text(token), MG_ESC("enabled"), sqlite3_column_int(stmt, 13),
          MG_ESC("priority"), sqlite3_column_int(stmt, 14),
          MG_ESC("retry_count"),
          clamp_retry_count(sqlite3_column_int(stmt, 15)),
          MG_ESC("created_at"), sqlite3_column_int64(stmt, 16),
          MG_ESC("updated_at"), sqlite3_column_int64(stmt, 17));
      free(oauth_provider_ids_json);
      free(oauth_provider_names_json);
      free(oauth_targets);
      first = false;
    }
  }
  sqlite3_finalize(stmt);
  mg_xprintf(mg_pfn_iobuf, &out, "]}");
  mg_iobuf_add(&out, out.len, "", 1);
  return (char *) out.buf;
}

static char *ok_message_json(const char *message, long id) {
  struct mg_iobuf out = {0, 0, 0, 256};
  mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%ld,%m:%m}", MG_ESC("ok"), 1,
             MG_ESC("id"), id, MG_ESC("message"), MG_ESC(message));
  mg_iobuf_add(&out, out.len, "", 1);
  return (char *) out.buf;
}

static char *error_json(const char *message) {
  struct mg_iobuf out = {0, 0, 0, 256};
  mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
             MG_ESC("error"), MG_ESC(message ? message : "操作失败"));
  mg_iobuf_add(&out, out.len, "", 1);
  return (char *) out.buf;
}

char *aether_service_save_json(sqlite3 *db, struct mg_str body) {
  sqlite3_stmt *stmt = NULL;
  long id = mg_json_get_long(body, "$.id", 0);
  bool is_update = id > 0;
  char *name = json_get_trim(body, "$.name");
  char *api_url = json_get_trim(body, "$.api_url");
  char *management_token = json_get_trim(body, "$.management_token");
  char *provider_id = json_get_trim(body, "$.provider_id");
  char *provider_name = json_get_trim(body, "$.provider_name");
  char *web_provider_id = json_get_trim(body, "$.chatgpt_web_provider_id");
  char *web_provider_name = json_get_trim(body, "$.chatgpt_web_provider_name");
  char *proxy_node_id = json_get_trim(body, "$.proxy_node_id");
  char *proxy_node_name = json_get_trim(body, "$.proxy_node_name");
  char *proxy_node_mode_raw = json_get_trim(body, "$.proxy_node_mode");
  char *oauth_provider_ids_json = json_get_raw_array(body, "$.oauth_provider_ids");
  char *oauth_provider_names_json = json_get_raw_array(body, "$.oauth_provider_names");
  const char *proxy_node_mode = normalize_proxy_node_mode(proxy_node_mode_raw);
  bool enabled = true;
  long priority = mg_json_get_long(body, "$.priority", 0);
  int retry_count = clamp_retry_count(
      mg_json_get_long(body, "$.retry_count", AETHER_DEFAULT_RETRY_COUNT));
  int ok = 0;
  struct aether_provider_target *oauth_targets = NULL;
  size_t oauth_target_count = 0;
  char *oauth_provider_ids_store = NULL;
  char *oauth_provider_names_store = NULL;

  mg_json_get_bool(body, "$.enabled", &enabled);
  if (!has_text(name) || !has_text(api_url)) {
    free(name); free(api_url); free(management_token); free(provider_id);
    free(provider_name); free(web_provider_id); free(web_provider_name);
    free(proxy_node_id); free(proxy_node_name); free(proxy_node_mode_raw);
    free(oauth_provider_ids_json); free(oauth_provider_names_json);
    return error_json("请填写名称、Aether 地址和 OAuth Provider ID");
  }
  if (id <= 0 && !has_text(management_token)) {
    free(name); free(api_url); free(management_token); free(provider_id);
    free(provider_name); free(web_provider_id); free(web_provider_name);
    free(proxy_node_id); free(proxy_node_name); free(proxy_node_mode_raw);
    free(oauth_provider_ids_json); free(oauth_provider_names_json);
    return error_json("请填写 Aether 管理员 Token");
  }

  if (load_provider_targets_from_json(
          oauth_provider_ids_json, oauth_provider_names_json, provider_id,
          provider_name, &oauth_targets, &oauth_target_count) != 0) {
    free(name); free(api_url); free(management_token); free(provider_id);
    free(provider_name); free(web_provider_id); free(web_provider_name);
    free(proxy_node_id); free(proxy_node_name); free(proxy_node_mode_raw);
    free(oauth_provider_ids_json); free(oauth_provider_names_json);
    return error_json("请至少配置一个 OAuth Provider");
  }

  free(provider_id);
  free(provider_name);
  provider_id = str_dup(oauth_targets[0].id);
  provider_name = str_dup(oauth_targets[0].name);
  if (provider_id == NULL || provider_name == NULL) {
    free(name); free(api_url); free(management_token);
    free(provider_id); free(provider_name); free(web_provider_id);
    free(web_provider_name); free(proxy_node_id); free(proxy_node_name);
    free(proxy_node_mode_raw); free(oauth_provider_ids_json);
    free(oauth_provider_names_json); free(oauth_targets);
    return error_json("内存不足，无法保存 OAuth Provider");
  }

  oauth_provider_ids_store = provider_targets_json_array(oauth_targets,
                                                         oauth_target_count,
                                                         false);
  oauth_provider_names_store = provider_targets_json_array(oauth_targets,
                                                           oauth_target_count,
                                                           true);
  if (oauth_provider_ids_store == NULL || oauth_provider_names_store == NULL) {
    free(name); free(api_url); free(management_token); free(provider_id);
    free(provider_name); free(web_provider_id); free(web_provider_name);
    free(proxy_node_id); free(proxy_node_name); free(proxy_node_mode_raw);
    free(oauth_provider_ids_json); free(oauth_provider_names_json);
    free(oauth_provider_ids_store); free(oauth_provider_names_store);
    free(oauth_targets);
    return error_json("内存不足，无法保存 OAuth Provider");
  }

  if (id > 0) {
    struct aether_service existing;
    const char *sql_with_token =
        "UPDATE aether_services SET name=?,api_url=?,management_token=?,"
        "provider_id=?,provider_name=?,oauth_provider_ids=?,"
        "oauth_provider_names=?,chatgpt_web_provider_id=?,"
        "chatgpt_web_provider_name=?,proxy_node_id=?,proxy_node_name=?,"
        "proxy_node_mode=?,enabled=?,priority=?,retry_count=?,"
        "updated_at=unixepoch() WHERE id=?";
    const char *sql_without_token =
        "UPDATE aether_services SET name=?,api_url=?,provider_id=?,"
        "provider_name=?,oauth_provider_ids=?,oauth_provider_names=?,"
        "chatgpt_web_provider_id=?,chatgpt_web_provider_name=?,"
        "proxy_node_id=?,proxy_node_name=?,proxy_node_mode=?,enabled=?,"
        "priority=?,retry_count=?,updated_at=unixepoch() WHERE id=?";
    const bool update_token = has_text(management_token);
    const char *sql = update_token ? sql_with_token : sql_without_token;
    int bind = 1;
    if (load_service_by_id(db, id, &existing) != 0) {
      free(name); free(api_url); free(management_token); free(provider_id);
      free(provider_name); free(web_provider_id); free(web_provider_name);
      free(proxy_node_id); free(proxy_node_name); free(proxy_node_mode_raw);
      free(oauth_provider_ids_json); free(oauth_provider_names_json);
      free(oauth_provider_ids_store); free(oauth_provider_names_store);
      free(oauth_targets);
      return error_json("Aether 上传服务不存在");
    }
    free_service(&existing);
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
      sqlite3_bind_text(stmt, bind++, name, -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, bind++, api_url, -1, SQLITE_TRANSIENT);
      if (update_token) {
        sqlite3_bind_text(stmt, bind++, management_token, -1, SQLITE_TRANSIENT);
      }
      sqlite3_bind_text(stmt, bind++, provider_id, -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, bind++, provider_name ? provider_name : "", -1,
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, bind++, oauth_provider_ids_store, -1,
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, bind++, oauth_provider_names_store, -1,
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, bind++, web_provider_id ? web_provider_id : "",
                        -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, bind++, web_provider_name ? web_provider_name : "",
                        -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, bind++, proxy_node_id ? proxy_node_id : "", -1,
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, bind++, proxy_node_name ? proxy_node_name : "",
                        -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, bind++, proxy_node_mode, -1, SQLITE_TRANSIENT);
      sqlite3_bind_int(stmt, bind++, enabled ? 1 : 0);
      sqlite3_bind_int64(stmt, bind++, priority);
      sqlite3_bind_int(stmt, bind++, retry_count);
      sqlite3_bind_int64(stmt, bind++, id);
      ok = sqlite3_step(stmt) == SQLITE_DONE;
    }
  } else {
    const char *sql =
        "INSERT INTO aether_services(name,api_url,management_token,provider_id,"
        "provider_name,oauth_provider_ids,oauth_provider_names,"
        "chatgpt_web_provider_id,chatgpt_web_provider_name,"
        "proxy_node_id,proxy_node_name,proxy_node_mode,enabled,priority,"
        "retry_count,"
        "created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,unixepoch(),unixepoch())";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
      sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 2, api_url, -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 3, management_token, -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 4, provider_id, -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 5, provider_name ? provider_name : "", -1,
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 6, oauth_provider_ids_store, -1,
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 7, oauth_provider_names_store, -1,
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 8, web_provider_id ? web_provider_id : "", -1,
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 9, web_provider_name ? web_provider_name : "", -1,
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 10, proxy_node_id ? proxy_node_id : "", -1,
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 11, proxy_node_name ? proxy_node_name : "", -1,
                        SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, 12, proxy_node_mode, -1, SQLITE_TRANSIENT);
      sqlite3_bind_int(stmt, 13, enabled ? 1 : 0);
      sqlite3_bind_int64(stmt, 14, priority);
      sqlite3_bind_int(stmt, 15, retry_count);
      ok = sqlite3_step(stmt) == SQLITE_DONE;
      if (ok) id = (long) sqlite3_last_insert_rowid(db);
    }
  }

  sqlite3_finalize(stmt);
  free(name); free(api_url); free(management_token); free(provider_id);
  free(provider_name); free(web_provider_id); free(web_provider_name);
  free(proxy_node_id); free(proxy_node_name); free(proxy_node_mode_raw);
  free(oauth_provider_ids_json); free(oauth_provider_names_json);
  free(oauth_provider_ids_store); free(oauth_provider_names_store);
  free(oauth_targets);
  if (!ok) return error_json("Aether 上传服务保存失败");
  return ok_message_json(is_update ? "Aether 上传服务已保存" : "Aether 上传服务已创建",
                         id);
}

char *aether_service_delete_json(sqlite3 *db, struct mg_str body) {
  sqlite3_stmt *stmt = NULL;
  long id = mg_json_get_long(body, "$.id", 0);
  int ok = 0;
  if (db == NULL || id <= 0) return error_json("请选择要删除的 Aether 服务");
  if (sqlite3_prepare_v2(db, "DELETE FROM aether_services WHERE id=?", -1,
                         &stmt, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(stmt, 1, id);
    ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) > 0;
  }
  sqlite3_finalize(stmt);
  return ok ? ok_message_json("Aether 上传服务已删除", id)
            : error_json("Aether 上传服务不存在或删除失败");
}

char *aether_options_json(sqlite3 *db, struct mg_str body) {
  struct aether_service svc;
  struct http_client_response pools_res;
  struct http_client_response nodes_res;
  struct mg_iobuf out = {0, 0, 0, 4096};
  char *api_url = json_get_trim(body, "$.api_url");
  char *management_token = json_get_trim(body, "$.management_token");
  long id = mg_json_get_long(body, "$.id", 0);
  char *pools_error = NULL;
  char *nodes_error = NULL;

  memset(&svc, 0, sizeof(svc));
  memset(&pools_res, 0, sizeof(pools_res));
  memset(&nodes_res, 0, sizeof(nodes_res));

  if (id > 0 && load_service_by_id(db, id, &svc) == 0) {
    if (!has_text(api_url)) {
      free(api_url);
      api_url = str_dup(svc.api_url);
    }
    if (!has_text(management_token)) {
      free(management_token);
      management_token = str_dup(svc.management_token);
    }
  }

  if (!has_text(api_url) || !has_text(management_token)) {
    free_service(&svc);
    free(api_url);
    free(management_token);
    return error_json("请先填写 Aether 地址和管理员 Token");
  }

  if (aether_get_json(api_url, management_token, "/api/admin/pool/overview",
                      &pools_res) != 0 ||
      pools_res.status_code != 200) {
    pools_error = extract_error_message(&pools_res, "读取 Aether Provider 失败");
    mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC(pools_error));
    goto done;
  }

  if (aether_get_json(api_url, management_token,
                      "/api/admin/proxy-nodes?status=online&limit=1000",
                      &nodes_res) != 0 ||
      nodes_res.status_code != 200) {
    nodes_error = extract_error_message(&nodes_res, "读取 Aether 代理节点失败");
  }

  mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m,%m:[", MG_ESC("ok"), 1,
             MG_ESC("message"), MG_ESC("Aether 选项已读取"),
             MG_ESC("pools"));
  append_aether_pools(&out, pools_res.body);
  mg_xprintf(mg_pfn_iobuf, &out, "],%m:[", MG_ESC("proxy_nodes"));
  if (nodes_error == NULL) append_aether_proxy_nodes(&out, nodes_res.body);
  mg_xprintf(mg_pfn_iobuf, &out, "],%m:%m}", MG_ESC("proxy_nodes_error"),
             MG_ESC(nodes_error ? nodes_error : ""));

done:
  mg_iobuf_add(&out, out.len, "", 1);
  mg_free(pools_error);
  mg_free(nodes_error);
  http_client_response_free(&pools_res);
  http_client_response_free(&nodes_res);
  free_service(&svc);
  free(api_url);
  free(management_token);
  return (char *) out.buf;
}

char *aether_service_test_json(sqlite3 *db, struct mg_str body) {
  struct aether_service svc;
  struct http_client_header headers[1];
  struct http_client_request req;
  struct http_client_response res;
  struct mg_iobuf out = {0, 0, 0, 512};
  char auth_header[1024], url[AETHER_URL_LEN], path[128];
  char *api_url = json_get_trim(body, "$.api_url");
  char *management_token = json_get_trim(body, "$.management_token");
  char *provider_id = json_get_trim(body, "$.provider_id");
  char *oauth_provider_ids_json = json_get_raw_array(body, "$.oauth_provider_ids");
  char *oauth_provider_names_json = json_get_raw_array(body, "$.oauth_provider_names");
  struct aether_provider_target *oauth_targets = NULL;
  size_t oauth_target_count = 0;
  long id = mg_json_get_long(body, "$.id", 0);
  bool found = false;
  bool compatible = false;
  char provider_name[AETHER_TEXT_LEN] = "";
  char provider_type[AETHER_TEXT_LEN] = "";

  memset(&svc, 0, sizeof(svc));
  if (id > 0 && load_service_by_id(db, id, &svc) == 0) {
    if (!has_text(api_url)) {
      free(api_url);
      api_url = str_dup(svc.api_url);
    }
    if (!has_text(management_token)) {
      free(management_token);
      management_token = str_dup(svc.management_token);
    }
    if (!has_text(provider_id)) {
      free(provider_id);
      provider_id = str_dup(svc.provider_id);
    }
  }
  if (load_provider_targets_from_json(
          oauth_provider_ids_json, oauth_provider_names_json, provider_id,
          "", &oauth_targets, &oauth_target_count) == 0) {
    char *first_provider_id = str_dup(oauth_targets[0].id);
    if (first_provider_id == NULL) {
      free_service(&svc);
      free(api_url); free(management_token); free(provider_id);
      free(oauth_provider_ids_json); free(oauth_provider_names_json);
      free(oauth_targets);
      return error_json("内存不足，无法测试 Provider");
    }
    free(provider_id);
    provider_id = first_provider_id;
  }
  if (!has_text(api_url) || !has_text(management_token) ||
      !has_text(provider_id)) {
    free_service(&svc);
    free(api_url); free(management_token); free(provider_id);
    free(oauth_provider_ids_json); free(oauth_provider_names_json);
    free(oauth_targets);
    return error_json("请填写 Aether 地址、管理员 Token 和 Provider ID 后再测试");
  }
  if (build_aether_url(api_url, "/api/admin/pool/overview", url,
                       sizeof(url)) != 0) {
    free_service(&svc);
    free(api_url); free(management_token); free(provider_id);
    free(oauth_provider_ids_json); free(oauth_provider_names_json);
    free(oauth_targets);
    return error_json("Aether 地址无效");
  }

  mg_snprintf(auth_header, sizeof(auth_header), "Bearer %s", management_token);
  headers[0].name = "Authorization";
  headers[0].value = auth_header;
  memset(&req, 0, sizeof(req));
  req.method = "GET";
  req.url = url;
  req.timeout_ms = 15000L;
  req.headers = headers;
  req.num_headers = 1;

  if (http_client_perform(&req, &res) != 0 || res.status_code != 200) {
    char *message = extract_error_message(&res, "Aether 连接测试失败");
    mg_xprintf(mg_pfn_iobuf, &out,
               "{%m:%d,%m:%d,%m:%ld,%m:%m}", MG_ESC("ok"), 1,
               MG_ESC("success"), 0, MG_ESC("http_status"), res.status_code,
               MG_ESC("message"), MG_ESC(message));
    mg_free(message);
    http_client_response_free(&res);
    goto done;
  }

  for (size_t i = 0; i < 1000; i++) {
    char *pid;
    char *pname;
    mg_snprintf(path, sizeof(path), "$.items[%lu].provider_id",
                (unsigned long) i);
    pid = mg_json_get_str(mg_str(res.body ? res.body : ""), path);
    if (pid == NULL) break;
    if (strcmp(pid, provider_id) == 0) {
      char *ptype;
      mg_snprintf(path, sizeof(path), "$.items[%lu].provider_name",
                  (unsigned long) i);
      pname = mg_json_get_str(mg_str(res.body ? res.body : ""), path);
      mg_snprintf(provider_name, sizeof(provider_name), "%s",
                  pname ? pname : provider_id);
      mg_free(pname);
      mg_snprintf(path, sizeof(path), "$.items[%lu].provider_type",
                  (unsigned long) i);
      ptype = mg_json_get_str(mg_str(res.body ? res.body : ""), path);
      mg_snprintf(provider_type, sizeof(provider_type), "%s",
                  ptype ? ptype : "");
      mg_free(ptype);
      found = true;
      compatible = is_codex_oauth_provider_type(provider_type);
      mg_free(pid);
      break;
    }
    mg_free(pid);
  }
  http_client_response_free(&res);
  mg_xprintf(mg_pfn_iobuf, &out,
             "{%m:%d,%m:%d,%m:%ld,%m:%m}", MG_ESC("ok"), 1,
             MG_ESC("success"), found && compatible, MG_ESC("http_status"), 200L,
             MG_ESC("message"),
             MG_ESC(found && compatible
                        ? "Aether 连接成功，已找到目标 Codex OAuth Provider"
                        : (found ? "连接成功，但该 Provider 不是 Codex 固定类型，无法用于 OAuth 导入"
                                 : "连接成功，但未找到指定 Provider ID")));
  if (found) {
    out.len--;
    mg_xprintf(mg_pfn_iobuf, &out, ",%m:%m,%m:%m}", MG_ESC("provider_name"),
               MG_ESC(provider_name), MG_ESC("provider_type"),
               MG_ESC(provider_type));
  }

done:
  mg_iobuf_add(&out, out.len, "", 1);
  free_service(&svc);
  free(api_url); free(management_token); free(provider_id);
  free(oauth_provider_ids_json); free(oauth_provider_names_json);
  free(oauth_targets);
  return (char *) out.buf;
}
