#include "mongoose.h"
#include "account/account_store.h"
#include "account/account_token_validator.h"
#include "auth/app_auth.h"
#include "flow/flow_impersonate.h"
#include "flow/flow_libcurl_impersonate.h"
#include "http_client/browser_profile.h"
#include "http_client/http_client.h"
#include "mail/rapid_inbox.h"
#include "proxy/mihomo_manager.h"
#include "proxy/proxy_pool.h"
#include "registration/registration_tasks.h"
#include "storage/app_db.h"
#include "system/system_monitor.h"
#include "upload/aether_upload.h"

#include <signal.h>
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define JSON_HEADERS "Content-Type: application/json\r\nCache-Control: no-store\r\n"
#define ASYNC_JOB_CAP 64
#define ASYNC_JOB_ID_LEN 64
#define ASYNC_JOB_KIND_LEN 32
#define ASYNC_JOB_STATE_LEN 16
#define ASYNC_JOB_TTL_MS (15ULL * 60ULL * 1000ULL)

extern const struct mg_mem_file mg_packed_files[];

static volatile sig_atomic_t s_running = 1;
static uint64_t s_started_ms;
static sqlite3 *s_db;

struct async_job {
  bool used;
  char id[ASYNC_JOB_ID_LEN];
  char kind[ASYNC_JOB_KIND_LEN];
  char state[ASYNC_JOB_STATE_LEN];
  char *result_json;
  uint64_t created_ms;
  uint64_t updated_ms;
};

struct mihomo_sample_job_args {
  char job_id[ASYNC_JOB_ID_LEN];
  int samples;
};

struct aether_upload_job_args {
  char job_id[ASYNC_JOB_ID_LEN];
  long *ids;
  size_t count;
  char *pool_type;
};

static pthread_mutex_t s_async_jobs_mu = PTHREAD_MUTEX_INITIALIZER;
static struct async_job s_async_jobs[ASYNC_JOB_CAP];
static unsigned long s_async_job_seq = 0;

static void signal_handler(int signo) {
  (void) signo;
  s_running = 0;
}

static void configure_mongoose_log(void) {
  const char *level = getenv("MONGOOSE_LOG");
  if (level == NULL || *level == '\0' || strcmp(level, "error") == 0) {
    mg_log_set(MG_LL_ERROR);
  } else if (strcmp(level, "none") == 0 || strcmp(level, "off") == 0) {
    mg_log_set(MG_LL_NONE);
  } else if (strcmp(level, "info") == 0) {
    mg_log_set(MG_LL_INFO);
  } else if (strcmp(level, "debug") == 0) {
    mg_log_set(MG_LL_DEBUG);
  } else if (strcmp(level, "verbose") == 0) {
    mg_log_set(MG_LL_VERBOSE);
  } else {
    mg_log_set(MG_LL_ERROR);
  }
}

static unsigned count_connections(struct mg_mgr *mgr) {
  unsigned count = 0;
  for (struct mg_connection *c = mgr->conns; c != NULL; c = c->next) count++;
  return count;
}

static bool uri_has_prefix(struct mg_str uri, const char *prefix) {
  size_t len = strlen(prefix);
  return uri.len >= len && memcmp(uri.buf, prefix, len) == 0;
}

static size_t parse_id_array(struct mg_str body, long **out) {
  struct mg_str tok = mg_json_get_tok(body, "$.ids");
  char *copy, *p, *end;
  long *ids = NULL;
  size_t len = 0, cap = 0;

  *out = NULL;
  if (tok.len == 0) return 0;
  copy = (char *) calloc(1, tok.len + 1);
  if (copy == NULL) return 0;
  memcpy(copy, tok.buf, tok.len);
  p = copy;
  while (*p) {
    long id;
    while (*p && !isdigit((unsigned char) *p) && *p != '-') p++;
    if (*p == '\0') break;
    id = strtol(p, &end, 10);
    if (end == p) break;
    if (id > 0) {
      if (len == cap) {
        cap = cap == 0 ? 8 : cap * 2;
        ids = (long *) realloc(ids, cap * sizeof(*ids));
        if (ids == NULL) {
          free(copy);
          return 0;
        }
      }
      ids[len++] = id;
    }
    p = end;
  }
  free(copy);
  *out = ids;
  return len;
}

static void async_job_clear_locked(struct async_job *job) {
  if (job == NULL) return;
  free(job->result_json);
  memset(job, 0, sizeof(*job));
}

static void async_job_prune_locked(uint64_t now_ms) {
  for (size_t i = 0; i < ASYNC_JOB_CAP; i++) {
    struct async_job *job = &s_async_jobs[i];
    if (!job->used || strcmp(job->state, "running") == 0) continue;
    if (now_ms >= job->updated_ms &&
        now_ms - job->updated_ms > ASYNC_JOB_TTL_MS) {
      async_job_clear_locked(job);
    }
  }
}

static struct async_job *async_job_find_locked(const char *id) {
  if (id == NULL || id[0] == '\0') return NULL;
  for (size_t i = 0; i < ASYNC_JOB_CAP; i++) {
    if (s_async_jobs[i].used && strcmp(s_async_jobs[i].id, id) == 0) {
      return &s_async_jobs[i];
    }
  }
  return NULL;
}

static int async_job_create(const char *kind, char *id, size_t id_len,
                            char *error, size_t error_len) {
  uint64_t now = mg_millis();
  struct async_job *slot = NULL;
  pthread_mutex_lock(&s_async_jobs_mu);
  async_job_prune_locked(now);
  for (size_t i = 0; i < ASYNC_JOB_CAP; i++) {
    if (!s_async_jobs[i].used) {
      slot = &s_async_jobs[i];
      break;
    }
  }
  if (slot == NULL) {
    pthread_mutex_unlock(&s_async_jobs_mu);
    mg_snprintf(error, error_len, "后台任务队列已满，请稍后再试");
    return -1;
  }
  memset(slot, 0, sizeof(*slot));
  slot->used = true;
  slot->created_ms = now;
  slot->updated_ms = now;
  mg_snprintf(slot->id, sizeof(slot->id), "job-%llx-%lu",
              (unsigned long long) now, ++s_async_job_seq);
  mg_snprintf(slot->kind, sizeof(slot->kind), "%s", kind ? kind : "job");
  mg_snprintf(slot->state, sizeof(slot->state), "%s", "running");
  mg_snprintf(id, id_len, "%s", slot->id);
  pthread_mutex_unlock(&s_async_jobs_mu);
  return 0;
}

static void async_job_release(const char *id) {
  pthread_mutex_lock(&s_async_jobs_mu);
  async_job_clear_locked(async_job_find_locked(id));
  pthread_mutex_unlock(&s_async_jobs_mu);
}

static char *json_error_response(const char *message) {
  struct mg_iobuf out = {0, 0, 0, 256};
  mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
             MG_ESC("error"), MG_ESC(message ? message : "后台任务失败"));
  mg_iobuf_add(&out, out.len, "", 1);
  return (char *) out.buf;
}

static void async_job_complete(const char *id, char *result_json,
                               const char *fallback_error) {
  uint64_t now = mg_millis();
  if (result_json == NULL) {
    result_json = json_error_response(fallback_error);
  }
  pthread_mutex_lock(&s_async_jobs_mu);
  struct async_job *job = async_job_find_locked(id);
  if (job != NULL) {
    free(job->result_json);
    job->result_json = result_json;
    job->updated_ms = now;
    mg_snprintf(job->state, sizeof(job->state), "%s", "done");
    result_json = NULL;
  }
  pthread_mutex_unlock(&s_async_jobs_mu);
  free(result_json);
}

static char *async_job_status_json(const char *id) {
  struct mg_iobuf out = {0, 0, 0, 1024};
  pthread_mutex_lock(&s_async_jobs_mu);
  async_job_prune_locked(mg_millis());
  struct async_job *job = async_job_find_locked(id);
  if (job == NULL) {
    mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("后台任务不存在或已过期"));
  } else {
    mg_xprintf(mg_pfn_iobuf, &out,
               "{%m:%d,%m:%m,%m:%m,%m:%m,%m:%s}",
               MG_ESC("ok"), 1, MG_ESC("job_id"), MG_ESC(job->id),
               MG_ESC("kind"), MG_ESC(job->kind), MG_ESC("state"),
               MG_ESC(job->state), MG_ESC("result"),
               job->result_json ? job->result_json : "null");
  }
  pthread_mutex_unlock(&s_async_jobs_mu);
  mg_iobuf_add(&out, out.len, "", 1);
  return (char *) out.buf;
}

static int start_detached_thread(void *(*entry)(void *), void *arg) {
  pthread_t thread;
  pthread_attr_t attr;
  int rc = pthread_attr_init(&attr);
  if (rc == 0) {
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&thread, &attr, entry, arg);
    pthread_attr_destroy(&attr);
  } else {
    rc = pthread_create(&thread, NULL, entry, arg);
    if (rc == 0) pthread_detach(thread);
  }
  return rc;
}

static void *mihomo_sample_job_main(void *arg) {
  struct mihomo_sample_job_args *job = (struct mihomo_sample_job_args *) arg;
  sqlite3 *db = NULL;
  char *json = NULL;
  if (job == NULL) return NULL;
  if (app_db_open("data/app.db", &db) != 0) {
    json = json_error_response("无法打开数据库，出口采样失败");
  } else {
    json = mihomo_sample_json(db, job->samples);
    app_db_close(db);
  }
  async_job_complete(job->job_id, json, "出口采样失败");
  free(job);
  return NULL;
}

static int start_mihomo_sample_job(int samples, char *job_id, size_t job_id_len,
                                   char *error, size_t error_len) {
  struct mihomo_sample_job_args *args =
      (struct mihomo_sample_job_args *) calloc(1, sizeof(*args));
  if (args == NULL) {
    mg_snprintf(error, error_len, "内存不足，无法启动出口采样");
    return -1;
  }
  if (async_job_create("mihomo_sample", job_id, job_id_len, error,
                       error_len) != 0) {
    free(args);
    return -1;
  }
  mg_snprintf(args->job_id, sizeof(args->job_id), "%s", job_id);
  args->samples = samples;
  if (start_detached_thread(mihomo_sample_job_main, args) != 0) {
    async_job_release(job_id);
    free(args);
    mg_snprintf(error, error_len, "无法启动出口采样后台任务");
    return -1;
  }
  return 0;
}

static void *aether_upload_job_main(void *arg) {
  struct aether_upload_job_args *job = (struct aether_upload_job_args *) arg;
  sqlite3 *db = NULL;
  char *json = NULL;
  if (job == NULL) return NULL;
  if (app_db_open("data/app.db", &db) != 0) {
    json = json_error_response("无法打开数据库，Aether 上传失败");
  } else {
    json = aether_upload_accounts_json(db, job->ids, job->count,
                                       job->pool_type);
    app_db_close(db);
  }
  async_job_complete(job->job_id, json, "Aether 上传失败");
  free(job->ids);
  mg_free(job->pool_type);
  free(job);
  return NULL;
}

static int start_aether_upload_job(long **ids, size_t count, char **pool_type,
                                   char *job_id, size_t job_id_len,
                                   char *error, size_t error_len) {
  struct aether_upload_job_args *args;
  if (ids == NULL || *ids == NULL || count == 0) {
    mg_snprintf(error, error_len, "请选择要上传的账号");
    return -1;
  }
  args = (struct aether_upload_job_args *) calloc(1, sizeof(*args));
  if (args == NULL) {
    mg_snprintf(error, error_len, "内存不足，无法启动 Aether 上传");
    return -1;
  }
  if (async_job_create("aether_upload", job_id, job_id_len, error,
                       error_len) != 0) {
    free(args);
    return -1;
  }
  mg_snprintf(args->job_id, sizeof(args->job_id), "%s", job_id);
  args->ids = *ids;
  args->count = count;
  args->pool_type = pool_type != NULL ? *pool_type : NULL;
  if (start_detached_thread(aether_upload_job_main, args) != 0) {
    async_job_release(job_id);
    free(args);
    mg_snprintf(error, error_len, "无法启动 Aether 上传后台任务");
    return -1;
  }
  *ids = NULL;
  if (pool_type != NULL) *pool_type = NULL;
  return 0;
}

static void handle_jobs_api(struct mg_connection *c,
                            struct mg_http_message *hm) {
  if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
      mg_match(hm->uri, mg_str("/api/jobs"), NULL)) {
    char id[ASYNC_JOB_ID_LEN] = "";
    char *json;
    mg_http_get_var(&hm->query, "id", id, sizeof(id));
    json = async_job_status_json(id);
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n", json ? json : "{}");
    free(json);
  } else {
    mg_http_reply(c, 404, JSON_HEADERS, "{\"error\":\"not found\"}\n");
  }
}

static enum registration_request_core parse_registration_request_core(
    const char *value) {
  if (value != NULL &&
      (strcmp(value, "curl_impersonate") == 0 ||
       strcmp(value, "curl-impersonate") == 0)) {
    return REG_REQUEST_CORE_CURL_IMPERSONATE;
  }
  if (value != NULL &&
      (strcmp(value, "libcurl_impersonate") == 0 ||
       strcmp(value, "libcurl-impersonate") == 0 ||
       strcmp(value, "libcurl") == 0 || strcmp(value, "curl") == 0)) {
    return REG_REQUEST_CORE_LIBCURL_IMPERSONATE;
  }
  if (value != NULL &&
      (strcmp(value, "plain_libcurl") == 0 ||
       strcmp(value, "libcurl_plain") == 0)) {
    return REG_REQUEST_CORE_LIBCURL;
  }
  return REG_REQUEST_CORE_LIBCURL_IMPERSONATE;
}

static sqlite3_int64 count_query(const char *sql) {
  sqlite3_stmt *stmt = NULL;
  sqlite3_int64 count = 0;
  if (s_db == NULL || sql == NULL) return 0;
  if (sqlite3_prepare_v2(s_db, sql, -1, &stmt, NULL) == SQLITE_OK &&
      sqlite3_step(stmt) == SQLITE_ROW) {
    count = sqlite3_column_int64(stmt, 0);
  }
  sqlite3_finalize(stmt);
  return count;
}

static void handle_proxy_api(struct mg_connection *c, struct mg_http_message *hm) {
  if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
      mg_match(hm->uri, mg_str("/api/proxies"), NULL)) {
    char *json = proxy_pool_list_json(s_db);
    mg_http_reply(c, 200, JSON_HEADERS, "%s", json ? json : "{\"items\":[]}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
             mg_match(hm->uri, mg_str("/api/proxies/mihomo"), NULL)) {
    char *json = mihomo_config_json(s_db);
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n", json ? json : "{}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/proxies/mihomo"), NULL)) {
    char *json = mihomo_save_config_json(s_db, hm->body);
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n", json ? json : "{}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
             mg_match(hm->uri, mg_str("/api/proxies/mihomo/nodes"), NULL)) {
    char *json = mihomo_nodes_json(s_db);
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n", json ? json : "{}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/proxies/mihomo/select"), NULL)) {
    char *json = mihomo_select_node_json(s_db, hm->body);
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n", json ? json : "{}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/proxies/mihomo/start"), NULL)) {
    char *json = mihomo_start_json(s_db);
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n", json ? json : "{}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/proxies/mihomo/stop"), NULL)) {
    char *json = mihomo_stop_json(s_db);
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n", json ? json : "{}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/proxies/mihomo/sample"), NULL)) {
    int samples = (int) mg_json_get_long(hm->body, "$.samples", 12);
    bool async = false;
    mg_json_get_bool(hm->body, "$.async", &async);
    if (async) {
      char job_id[ASYNC_JOB_ID_LEN];
      char error[256] = "";
      if (start_mihomo_sample_job(samples, job_id, sizeof(job_id), error,
                                  sizeof(error)) != 0) {
        mg_http_reply(c, 503, JSON_HEADERS, "{%m:%d,%m:%m}\n",
                      MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC(error));
        return;
      }
      mg_http_reply(c, 202, JSON_HEADERS,
                    "{%m:%d,%m:%d,%m:%m}\n", MG_ESC("ok"), 1,
                    MG_ESC("async"), 1, MG_ESC("job_id"), MG_ESC(job_id));
      return;
    }
    char *json = mihomo_sample_json(s_db, samples);
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n", json ? json : "{}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/proxies/import"), NULL)) {
    char *text = mg_json_get_str(hm->body, "$.text");
    struct proxy_import_result result;
    if (text == NULL) {
      mg_http_reply(c, 400, JSON_HEADERS, "{\"error\":\"missing text\"}\n");
      return;
    }
    proxy_pool_import_text(s_db, text, &result);
    mg_free(text);
    mg_http_reply(c, 200, JSON_HEADERS,
                  "{%m:%d,%m:%d,%m:%d}\n",
                  MG_ESC("imported"), result.imported,
                  MG_ESC("skipped"), result.skipped,
                  MG_ESC("invalid"), result.invalid);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/proxies/test"), NULL)) {
    long *ids = NULL;
    size_t count = parse_id_array(hm->body, &ids);
    char *json = proxy_pool_test_ids(s_db, ids, count);
    free(ids);
    mg_http_reply(c, 200, JSON_HEADERS, "%s", json ? json : "{\"items\":[]}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/proxies/delete"), NULL)) {
    long *ids = NULL;
    size_t count = parse_id_array(hm->body, &ids);
    int deleted = proxy_pool_delete_ids(s_db, ids, count);
    free(ids);
    mg_http_reply(c, deleted < 0 ? 500 : 200, JSON_HEADERS, "{%m:%d}\n",
                  MG_ESC("deleted"), deleted < 0 ? 0 : deleted);
  } else {
    mg_http_reply(c, 404, JSON_HEADERS, "{\"error\":\"not found\"}\n");
  }
}

static void handle_mail_api(struct mg_connection *c, struct mg_http_message *hm) {
  if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
      mg_match(hm->uri, mg_str("/api/mail/config"), NULL)) {
    char *json = rapid_inbox_config_json(s_db);
    mg_http_reply(c, 200, JSON_HEADERS, "%s", json ? json : "{}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/mail/config"), NULL)) {
    int api_key_len = 0;
    bool has_api_key_field =
        mg_json_get(hm->body, "$.api_key", &api_key_len) >= 0;
    char *base_url = mg_json_get_str(hm->body, "$.base_url");
    char *api_key = mg_json_get_str(hm->body, "$.api_key");
    char *backend = mg_json_get_str(hm->body, "$.backend");
    char *transport = mg_json_get_str(hm->body, "$.transport");
    int rc = rapid_inbox_save_config(
        s_db, base_url, has_api_key_field ? (api_key ? api_key : "") : NULL,
        backend, transport);
    mg_free(base_url);
    mg_free(api_key);
    mg_free(backend);
    mg_free(transport);
    mg_http_reply(c, rc == 0 ? 200 : 500, JSON_HEADERS, "{%m:%d}\n",
                  MG_ESC("ok"), rc == 0);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/mail/domains"), NULL)) {
    char *pattern = mg_json_get_str(hm->body, "$.pattern");
    char *text = mg_json_get_str(hm->body, "$.text");
    char *json = (text != NULL && text[0] != '\0')
                     ? rapid_inbox_add_domains_json(s_db, text)
                     : rapid_inbox_add_domain_json(s_db, pattern);
    mg_free(pattern);
    mg_free(text);
    mg_http_reply(c, 200, JSON_HEADERS, "%s", json ? json : "{\"ok\":0}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/mail/domains/delete"), NULL)) {
    long *ids = NULL;
    size_t count = parse_id_array(hm->body, &ids);
    int deleted = rapid_inbox_delete_domain_ids(s_db, ids, count);
    free(ids);
    mg_http_reply(c, deleted < 0 ? 500 : 200, JSON_HEADERS, "{%m:%d}\n",
                  MG_ESC("deleted"), deleted < 0 ? 0 : deleted);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/mail/fetch"), NULL)) {
    char *mailbox = mg_json_get_str(hm->body, "$.mailbox");
    char *action = mg_json_get_str(hm->body, "$.action");
    char *delivery_id = mg_json_get_str(hm->body, "$.delivery_id");
    long limit = mg_json_get_long(hm->body, "$.limit", 20);
    char *json = rapid_inbox_fetch_json(s_db, mailbox,
                                        action ? action : "codes",
                                        delivery_id, limit);
    mg_free(mailbox);
    mg_free(action);
    mg_free(delivery_id);
    mg_http_reply(c, 200, JSON_HEADERS, "%s", json ? json : "{\"ok\":0}");
    free(json);
  } else {
    mg_http_reply(c, 404, JSON_HEADERS, "{\"error\":\"not found\"}\n");
  }
}

static void handle_registration_api(struct mg_connection *c,
                                    struct mg_http_message *hm) {
  if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
      mg_match(hm->uri, mg_str("/api/registration/status"), NULL)) {
    sqlite3_int64 domains =
        count_query("SELECT count(*) FROM mail_domain_rules WHERE is_active=1");
    sqlite3_int64 proxies =
        count_query("SELECT count(*) FROM proxy_nodes WHERE status='active'");
    sqlite3_int64 temp_accounts =
        count_query("SELECT count(*) FROM accounts WHERE status='temp'");
    int active_tasks = 0, active_flows = 0, queued_flows = 0;
    int provider_ready = 0;
    int libcurl_impersonate_ready = 0;
    char impersonate_bin[512];
    char libcurl_impersonate_lib[512];
    registration_tasks_counts(&active_tasks, &active_flows, &queued_flows);
    provider_ready = flow_impersonate_available(impersonate_bin,
                                                sizeof(impersonate_bin)) == 0;
    libcurl_impersonate_ready =
        flow_libcurl_impersonate_available(libcurl_impersonate_lib,
                                           sizeof(libcurl_impersonate_lib)) == 0;
    mg_http_reply(c, 200, JSON_HEADERS,
                  "{%m:%d,%m:%m,%m:%m,%m:[%m,%m],%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%lld,%m:%lld,%m:%lld}\n",
                  MG_ESC("ok"), 1, MG_ESC("engine"), MG_ESC("libcurl_impersonate"),
                  MG_ESC("default_request_core"), MG_ESC("libcurl_impersonate"),
                  MG_ESC("request_cores"), MG_ESC("libcurl_impersonate"),
                  MG_ESC("curl_impersonate"), MG_ESC("provider_ready"), provider_ready,
                  MG_ESC("curl_impersonate_ready"), provider_ready,
                  MG_ESC("libcurl_impersonate_ready"), libcurl_impersonate_ready,
                  MG_ESC("libcurl_ready"), 1, MG_ESC("active_tasks"),
                  active_tasks, MG_ESC("active_flows"), active_flows,
                  MG_ESC("queued_flows"), queued_flows,
                  MG_ESC("active_domains"), domains,
                  MG_ESC("active_proxies"), proxies, MG_ESC("temp_accounts"),
                  temp_accounts);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/registration/start"), NULL)) {
    struct registration_start_options options;
    char task_id[REG_TASK_ID_LEN];
    char error[256] = "";
    char libcurl_impersonate_target_buf[FLOW_IMPERSONATE_TARGET_LEN] = "";
    char mihomo_node_buf[512] = "";
    char *workflow = mg_json_get_str(hm->body, "$.workflow");
    char *mode = mg_json_get_str(hm->body, "$.mode");
    char *scheduler_mode = mg_json_get_str(hm->body, "$.scheduler_mode");
    const char *workflow_value;
    char *register_provider = mg_json_get_str(hm->body, "$.register_provider");
    char *target_metric = mg_json_get_str(hm->body, "$.target_metric");
    char *request_core = mg_json_get_str(hm->body, "$.request_core");
    char *current_session_oauth_fallback_mode =
        mg_json_get_str(hm->body, "$.current_session_oauth_fallback_mode");
    char *auto_upload_service_mode =
        mg_json_get_str(hm->body, "$.auto_upload_service_mode");
    char *libcurl_impersonate_target =
        mg_json_get_str(hm->body, "$.libcurl_impersonate_target");
    char *mihomo_node = mg_json_get_str(hm->body, "$.mihomo_node");
    long auto_upload_service_id =
        mg_json_get_long(hm->body, "$.auto_upload_service_id", 0);
    if (auto_upload_service_mode == NULL) {
      auto_upload_service_mode =
          mg_json_get_str(hm->body, "$.upload_service_mode");
    }
    if (auto_upload_service_id <= 0) {
      auto_upload_service_id =
          mg_json_get_long(hm->body, "$.upload_service_id",
                           mg_json_get_long(hm->body, "$.aether_service_id", 0));
    }
    if (libcurl_impersonate_target == NULL) {
      libcurl_impersonate_target =
          mg_json_get_str(hm->body, "$.impersonate_target");
    }
    if (mihomo_node == NULL) {
      mihomo_node = mg_json_get_str(hm->body, "$.clash_node");
    }
    if (mihomo_node == NULL) {
      mihomo_node = mg_json_get_str(hm->body, "$.proxy_node");
    }
    bool detailed = false;
    bool infinite = false;
    bool auto_upload_oauth_success = false;
    bool current_session_oauth_fallback = false;
    bool current_session_oauth_fallback_set = false;
    bool discard_oauth_failed_accounts = false;
    bool save_oauth_failed_accounts = true;
    bool fast_email_otp_resend = false;

    memset(&options, 0, sizeof(options));
    options.workflow = REG_WORKFLOW_REGISTER_ONLY;
    options.target_metric = REG_TARGET_REGISTER_TASK;
    options.request_core = parse_registration_request_core(request_core);
    if (libcurl_impersonate_target != NULL) {
      mg_snprintf(libcurl_impersonate_target_buf,
                  sizeof(libcurl_impersonate_target_buf), "%s",
                  libcurl_impersonate_target);
      options.libcurl_impersonate_target = libcurl_impersonate_target_buf;
    }
    if (mihomo_node != NULL && mihomo_node[0] != '\0') {
      mg_snprintf(mihomo_node_buf, sizeof(mihomo_node_buf), "%s",
                  mihomo_node);
      options.mihomo_node = mihomo_node_buf;
    }
    options.count = (int) mg_json_get_long(
        hm->body, "$.target_count", mg_json_get_long(hm->body, "$.count", 1));
    options.concurrency = (int) mg_json_get_long(hm->body, "$.concurrency", 1);
    options.max_inflight =
        (int) mg_json_get_long(hm->body, "$.max_inflight", 0);
    options.oauth_delay_seconds =
        (int) mg_json_get_long(hm->body, "$.oauth_delay_seconds", 0);
    options.current_session_oauth_retry_after_seconds =
        (int) mg_json_get_long(
            hm->body, "$.current_session_oauth_retry_after_seconds",
            mg_json_get_long(hm->body,
                             "$.current_session_oauth_fallback_retry_seconds",
                             0));
    if (mg_json_get_bool(hm->body, "$.detailed_logs", &detailed)) {
      options.detailed_logs = detailed;
    }
    if (mg_json_get_bool(hm->body, "$.infinite", &infinite)) {
      options.infinite = infinite;
    }
    if (mg_json_get_bool(hm->body, "$.auto_upload_oauth_success",
                         &auto_upload_oauth_success)) {
      options.auto_upload_oauth_success = auto_upload_oauth_success;
    }
    if (auto_upload_service_mode != NULL) {
      if (strcmp(auto_upload_service_mode, "random") == 0) {
        options.auto_upload_service_mode = REG_AUTO_UPLOAD_SERVICE_RANDOM;
      } else if (strcmp(auto_upload_service_mode, "fixed") == 0 ||
                 strcmp(auto_upload_service_mode, "service") == 0) {
        options.auto_upload_service_mode = REG_AUTO_UPLOAD_SERVICE_FIXED;
      } else {
        options.auto_upload_service_mode = REG_AUTO_UPLOAD_SERVICE_ALL;
      }
    } else if (auto_upload_service_id > 0) {
      options.auto_upload_service_mode = REG_AUTO_UPLOAD_SERVICE_FIXED;
    }
    options.auto_upload_service_id = auto_upload_service_id;
    if (mg_json_get_bool(hm->body, "$.current_session_oauth_fallback",
                         &current_session_oauth_fallback)) {
      options.current_session_oauth_fallback =
          current_session_oauth_fallback;
      current_session_oauth_fallback_set = true;
    }
    if (mg_json_get_bool(hm->body, "$.discard_oauth_failed_accounts",
                         &discard_oauth_failed_accounts) ||
        mg_json_get_bool(hm->body, "$.discard_oauth_failed_account",
                         &discard_oauth_failed_accounts) ||
        mg_json_get_bool(hm->body, "$.delete_oauth_failed_accounts",
                         &discard_oauth_failed_accounts) ||
        mg_json_get_bool(hm->body, "$.delete_oauth_failed_account",
                         &discard_oauth_failed_accounts) ||
        mg_json_get_bool(hm->body, "$.drop_oauth_failed_accounts",
                         &discard_oauth_failed_accounts)) {
      options.discard_oauth_failed_accounts = discard_oauth_failed_accounts;
    }
    if (mg_json_get_bool(hm->body, "$.save_oauth_failed_accounts",
                         &save_oauth_failed_accounts)) {
      options.discard_oauth_failed_accounts = !save_oauth_failed_accounts;
    }
    if (mg_json_get_bool(hm->body, "$.fast_email_otp_resend",
                         &fast_email_otp_resend) ||
        mg_json_get_bool(hm->body, "$.quick_email_otp_resend",
                         &fast_email_otp_resend) ||
        mg_json_get_bool(hm->body, "$.fast_otp_resend",
                         &fast_email_otp_resend)) {
      options.fast_email_otp_resend = fast_email_otp_resend;
    }
    if (current_session_oauth_fallback_mode != NULL) {
      if (strcmp(current_session_oauth_fallback_mode, "single") == 0 ||
          strcmp(current_session_oauth_fallback_mode, "single_oa") == 0) {
        options.current_session_oauth_fallback_mode =
            REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE;
        options.current_session_oauth_fallback = true;
      } else if (strcmp(current_session_oauth_fallback_mode, "double") == 0 ||
                 strcmp(current_session_oauth_fallback_mode, "double_oa") == 0 ||
                 strcmp(current_session_oauth_fallback_mode, "race") == 0) {
        options.current_session_oauth_fallback_mode =
            REG_CURRENT_SESSION_OAUTH_FALLBACK_DOUBLE;
        options.current_session_oauth_fallback = true;
      } else if (strcmp(current_session_oauth_fallback_mode,
                        "single_timeout_retry") == 0 ||
                 strcmp(current_session_oauth_fallback_mode,
                        "single_then_retry") == 0 ||
                 strcmp(current_session_oauth_fallback_mode,
                        "timeout_retry") == 0) {
        options.current_session_oauth_fallback_mode =
            REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE_TIMEOUT_RETRY;
        options.current_session_oauth_fallback = true;
      } else if (strcmp(current_session_oauth_fallback_mode, "none") == 0 ||
                 strcmp(current_session_oauth_fallback_mode, "off") == 0 ||
                 strcmp(current_session_oauth_fallback_mode, "disabled") == 0) {
        options.current_session_oauth_fallback_mode =
            REG_CURRENT_SESSION_OAUTH_FALLBACK_NONE;
        options.current_session_oauth_fallback = false;
      }
    }
    if (current_session_oauth_fallback_set &&
        !current_session_oauth_fallback) {
      options.current_session_oauth_fallback_mode =
          REG_CURRENT_SESSION_OAUTH_FALLBACK_NONE;
      options.current_session_oauth_fallback = false;
    }
    workflow_value = workflow != NULL ? workflow : mode;
    if (workflow_value != NULL &&
        strcmp(workflow_value, "register_then_oauth") == 0) {
      options.workflow = REG_WORKFLOW_REGISTER_THEN_OAUTH;
    } else if (workflow_value != NULL &&
               (strcmp(workflow_value, "register_then_current_codex") == 0 ||
                strcmp(workflow_value, "register_then_fast_codex") == 0 ||
                strcmp(workflow_value, "register_then_codex_fast") == 0 ||
                strcmp(workflow_value, "register_then_codex_quick") == 0 ||
                strcmp(workflow_value, "register_then_session_codex") == 0 ||
                strcmp(workflow_value, "register_then_current_session_codex") == 0)) {
      options.workflow = REG_WORKFLOW_REGISTER_THEN_CURRENT_CODEX;
    } else if (workflow_value != NULL &&
               strcmp(workflow_value, "oauth_only") == 0) {
      options.workflow = REG_WORKFLOW_OAUTH_ONLY;
    } else if (workflow_value != NULL &&
               (strcmp(workflow_value, "chatgpt_login_only") == 0 ||
                strcmp(workflow_value, "chatgpt_login") == 0)) {
      options.workflow = REG_WORKFLOW_CHATGPT_LOGIN_ONLY;
    } else if (workflow_value != NULL &&
               (strcmp(workflow_value, "codex_cli_simplified") == 0 ||
                strcmp(workflow_value, "codex_direct") == 0 ||
                strcmp(workflow_value, "codex_team") == 0)) {
      options.workflow = REG_WORKFLOW_CODEX_CLI_SIMPLIFIED;
    } else if (workflow_value != NULL &&
               (strcmp(workflow_value, "chatgpt2api_register") == 0 ||
                strcmp(workflow_value, "chatgpt2api") == 0)) {
      options.workflow = REG_WORKFLOW_CHATGPT2API_REGISTER;
    } else if (workflow_value != NULL &&
               strcmp(workflow_value, "fastlane") == 0) {
      options.scheduler_mode = REG_SCHEDULER_FASTLANE;
    }
    if ((scheduler_mode != NULL && strcmp(scheduler_mode, "fastlane") == 0) ||
        (mode != NULL && strcmp(mode, "fastlane") == 0)) {
      options.scheduler_mode = REG_SCHEDULER_FASTLANE;
    }
    if (target_metric != NULL && strcmp(target_metric, "oauth_success") == 0) {
      options.target_metric = REG_TARGET_OAUTH_SUCCESS;
    }
    if (register_provider != NULL &&
        (strcmp(register_provider, "temporary") == 0 ||
         strcmp(register_provider, "temp") == 0 ||
         strcmp(register_provider, "web") == 0 ||
         strcmp(register_provider, "web_register") == 0)) {
      options.register_provider = REG_REGISTER_PROVIDER_TEMPORARY;
    }
    mg_free(workflow);
    mg_free(mode);
    mg_free(scheduler_mode);
    mg_free(register_provider);
    mg_free(target_metric);
    mg_free(request_core);
    mg_free(current_session_oauth_fallback_mode);
    mg_free(auto_upload_service_mode);
    mg_free(libcurl_impersonate_target);
    mg_free(mihomo_node);

    if (registration_tasks_start(&options, task_id, sizeof(task_id), error,
                                 sizeof(error)) != 0) {
      mg_http_reply(c, 400, JSON_HEADERS,
                    "{%m:%d,%m:%m}\n", MG_ESC("ok"), 0,
                    MG_ESC("error"), MG_ESC(error));
      return;
    }
    mg_http_reply(c, 200, JSON_HEADERS,
                  "{%m:%d,%m:%m}\n", MG_ESC("ok"), 1,
                  MG_ESC("task_id"), MG_ESC(task_id));
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/registration/stop"), NULL)) {
    char *id = mg_json_get_str(hm->body, "$.task_id");
    char error[256] = "";
    int rc = registration_tasks_stop(id, error, sizeof(error));
    mg_free(id);
    if (rc != 0) {
      mg_http_reply(c, 400, JSON_HEADERS, "{%m:%d,%m:%m}\n",
                    MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC(error));
    } else {
      mg_http_reply(c, 200, JSON_HEADERS, "{%m:%d}\n", MG_ESC("ok"), 1);
    }
  } else if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
             mg_match(hm->uri, mg_str("/api/registration/tasks"), NULL)) {
    char *json = registration_tasks_list_json();
    mg_http_reply(c, 200, JSON_HEADERS, "%s", json ? json : "{\"items\":[]}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
             mg_match(hm->uri, mg_str("/api/registration/task"), NULL)) {
    char id[REG_TASK_ID_LEN] = "";
    char limit_buf[32] = "";
    long log_limit = 80;
    char *json;
    mg_http_get_var(&hm->query, "id", id, sizeof(id));
    if (mg_http_get_var(&hm->query, "log_limit", limit_buf,
                        sizeof(limit_buf)) > 0) {
      log_limit = strtol(limit_buf, NULL, 10);
    }
    if (log_limit < 0) log_limit = 0;
    if (log_limit > 300) log_limit = 300;
    json = registration_task_detail_json(id, true, (size_t) log_limit);
    mg_http_reply(c, 200, JSON_HEADERS, "%s", json ? json : "{\"ok\":0}");
    free(json);
  } else {
    mg_http_reply(c, 404, JSON_HEADERS, "{\"error\":\"not found\"}\n");
  }
}

static void handle_accounts_api(struct mg_connection *c, struct mg_http_message *hm) {
  if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
      mg_match(hm->uri, mg_str("/api/accounts/summary"), NULL)) {
    char *json = account_summary_json(s_db);
    mg_http_reply(c, 200, JSON_HEADERS, "%s", json ? json : "{}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
             mg_match(hm->uri, mg_str("/api/accounts/detail"), NULL)) {
    char id_buf[32] = "";
    long id = 0;
    char *json;
    if (mg_http_get_var(&hm->query, "id", id_buf, sizeof(id_buf)) > 0) {
      id = strtol(id_buf, NULL, 10);
    }
    json = account_detail_json(s_db, id);
    mg_http_reply(c, 200, JSON_HEADERS, "%s", json ? json : "{\"ok\":0}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
             mg_match(hm->uri, mg_str("/api/accounts"), NULL)) {
    char q[256] = "";
    char status[32] = "";
    char upload_state[32] = "";
    char auth_source[32] = "";
    char cursor_buf[32] = "";
    char limit_buf[32] = "";
    char page_buf[32] = "";
    long cursor = 0, limit = 50, page = 0;
    char *json;

    mg_http_get_var(&hm->query, "q", q, sizeof(q));
    mg_http_get_var(&hm->query, "status", status, sizeof(status));
    mg_http_get_var(&hm->query, "upload_state", upload_state,
                    sizeof(upload_state));
    mg_http_get_var(&hm->query, "auth_source", auth_source,
                    sizeof(auth_source));
    if (mg_http_get_var(&hm->query, "cursor", cursor_buf,
                        sizeof(cursor_buf)) > 0) {
      cursor = strtol(cursor_buf, NULL, 10);
    }
    if (mg_http_get_var(&hm->query, "limit", limit_buf,
                        sizeof(limit_buf)) > 0) {
      limit = strtol(limit_buf, NULL, 10);
    }
    if (mg_http_get_var(&hm->query, "page", page_buf, sizeof(page_buf)) > 0) {
      page = strtol(page_buf, NULL, 10);
    }
    json = account_list_json(s_db, q, status, upload_state, auth_source, cursor,
                             limit, page);
    mg_http_reply(c, 200, JSON_HEADERS, "%s", json ? json : "{\"items\":[]}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/accounts/action"), NULL)) {
    long *ids = NULL;
    size_t count = parse_id_array(hm->body, &ids);
    char *action = mg_json_get_str(hm->body, "$.action");
    int changed = -1;

    if (action != NULL && strcmp(action, "refresh-token") == 0) {
      char *json = account_refresh_tokens_json(s_db, ids, count);
      mg_free(action);
      free(ids);
      mg_http_reply(c, 200, JSON_HEADERS, "%s\n",
                    json ? json : "{\"ok\":0,\"error\":\"Token 刷新失败\"}");
      free(json);
      return;
    } else if (action != NULL && strcmp(action, "validate-token") == 0) {
      char *json = account_validate_tokens_json(s_db, ids, count);
      mg_free(action);
      free(ids);
      mg_http_reply(c, 200, JSON_HEADERS, "%s\n",
                    json ? json : "{\"ok\":0,\"error\":\"Token 验证失败\"}");
      free(json);
      return;
    } else if (action != NULL && strcmp(action, "reupload") == 0) {
      char *pool_type = mg_json_get_str(hm->body, "$.pool_type");
      bool async = false;
      mg_json_get_bool(hm->body, "$.async", &async);
      if (async) {
        char job_id[ASYNC_JOB_ID_LEN];
        char error[256] = "";
        if (start_aether_upload_job(&ids, count, &pool_type, job_id,
                                    sizeof(job_id), error,
                                    sizeof(error)) != 0) {
          mg_free(pool_type);
          mg_free(action);
          free(ids);
          mg_http_reply(c, 503, JSON_HEADERS, "{%m:%d,%m:%m}\n",
                        MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC(error));
          return;
        }
        mg_free(action);
        mg_http_reply(c, 202, JSON_HEADERS,
                      "{%m:%d,%m:%d,%m:%m,%m:%d}\n", MG_ESC("ok"), 1,
                      MG_ESC("async"), 1, MG_ESC("job_id"), MG_ESC(job_id),
                      MG_ESC("affected"), (int) count);
        return;
      }
      char *json = aether_upload_accounts_json(s_db, ids, count, pool_type);
      mg_free(pool_type);
      mg_free(action);
      free(ids);
      mg_http_reply(c, 200, JSON_HEADERS, "%s\n",
                    json ? json : "{\"ok\":0,\"error\":\"Aether 上传失败\"}");
      free(json);
      return;
    } else if (action != NULL && strcmp(action, "delete") == 0) {
      changed = account_delete_ids(s_db, ids, count);
    } else if (action != NULL &&
               (strcmp(action, "oauth") == 0 ||
                strcmp(action, "chatgpt-login") == 0)) {
      struct registration_start_options options;
      char task_id[REG_TASK_ID_LEN];
      char error[256] = "";
      char *request_core = mg_json_get_str(hm->body, "$.request_core");
      char *libcurl_impersonate_target =
          mg_json_get_str(hm->body, "$.libcurl_impersonate_target");
      char *mihomo_node = mg_json_get_str(hm->body, "$.mihomo_node");
      bool detailed = false;
      if (libcurl_impersonate_target == NULL) {
        libcurl_impersonate_target =
            mg_json_get_str(hm->body, "$.impersonate_target");
      }
      if (mihomo_node == NULL) {
        mihomo_node = mg_json_get_str(hm->body, "$.clash_node");
      }
      if (mihomo_node == NULL) {
        mihomo_node = mg_json_get_str(hm->body, "$.proxy_node");
      }
      memset(&options, 0, sizeof(options));
      options.workflow = strcmp(action, "chatgpt-login") == 0
                             ? REG_WORKFLOW_CHATGPT_LOGIN_ONLY
                             : REG_WORKFLOW_OAUTH_ONLY;
      options.target_metric = REG_TARGET_OAUTH_SUCCESS;
      options.request_core = parse_registration_request_core(request_core);
      options.libcurl_impersonate_target = libcurl_impersonate_target;
      options.mihomo_node = mihomo_node;
      options.count = (int) count;
      options.concurrency = (int) mg_json_get_long(hm->body, "$.concurrency", 10);
      if (mg_json_get_bool(hm->body, "$.detailed_logs", &detailed)) {
        options.detailed_logs = detailed;
      }
      options.account_ids = ids;
      options.account_id_count = count;
      if (registration_tasks_start(&options, task_id, sizeof(task_id), error,
                                   sizeof(error)) == 0) {
        mg_free(request_core);
        mg_free(libcurl_impersonate_target);
        mg_free(mihomo_node);
        mg_free(action);
        free(ids);
        mg_http_reply(c, 200, JSON_HEADERS,
                      "{%m:%d,%m:%m,%m:%d}\n", MG_ESC("ok"), 1,
                      MG_ESC("task_id"), MG_ESC(task_id), MG_ESC("affected"),
                      (int) count);
        return;
      }
      mg_free(request_core);
      mg_free(libcurl_impersonate_target);
      mg_free(mihomo_node);
      mg_free(action);
      free(ids);
      mg_http_reply(c, 400, JSON_HEADERS, "{%m:%d,%m:%m}\n",
                    MG_ESC("ok"), 0, MG_ESC("error"), MG_ESC(error));
      return;
    }

    mg_free(action);
    free(ids);
    if (changed < 0) {
      mg_http_reply(c, 400, JSON_HEADERS, "{%m:%d,%m:%m}\n",
                    MG_ESC("ok"), 0, MG_ESC("error"),
                    MG_ESC("账号动作无效或执行失败"));
    } else {
      mg_http_reply(c, 200, JSON_HEADERS, "{%m:%d,%m:%d}\n",
                    MG_ESC("ok"), 1, MG_ESC("affected"), changed);
    }
  } else {
    mg_http_reply(c, 404, JSON_HEADERS, "{\"error\":\"not found\"}\n");
  }
}

static void handle_upload_api(struct mg_connection *c,
                              struct mg_http_message *hm) {
  if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
      mg_match(hm->uri, mg_str("/api/upload/aether"), NULL)) {
    char *json = aether_config_json(s_db);
    mg_http_reply(c, 200, JSON_HEADERS, "%s", json ? json : "{}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/upload/aether/service"), NULL)) {
    char *json = aether_service_save_json(s_db, hm->body);
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n",
                  json ? json : "{\"ok\":0,\"error\":\"保存失败\"}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/upload/aether/options"), NULL)) {
    char *json = aether_options_json(s_db, hm->body);
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n",
                  json ? json : "{\"ok\":0,\"error\":\"读取选项失败\"}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/upload/aether/service/delete"),
                      NULL)) {
    char *json = aether_service_delete_json(s_db, hm->body);
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n",
                  json ? json : "{\"ok\":0,\"error\":\"删除失败\"}");
    free(json);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/upload/aether/test"), NULL)) {
    char *json = aether_service_test_json(s_db, hm->body);
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n",
                  json ? json : "{\"ok\":0,\"error\":\"测试失败\"}");
    free(json);
  } else {
    mg_http_reply(c, 404, JSON_HEADERS, "{\"error\":\"not found\"}\n");
  }
}

static void handle_http(struct mg_connection *c, struct mg_http_message *hm) {
  if (uri_has_prefix(hm->uri, "/api/auth")) {
    app_auth_handle_api(s_db, c, hm);
    return;
  }
  if (app_auth_enabled() && !app_auth_is_public_route(hm) &&
      !app_auth_is_authenticated(s_db, hm)) {
    app_auth_reply_unauthorized(c, hm);
    return;
  }

  if (mg_match(hm->uri, mg_str("/api/status"), NULL)) {
    uint64_t uptime = mg_millis() - s_started_ms;
    char *json = system_monitor_status_json(s_db, uptime,
                                            count_connections(c->mgr));
    mg_http_reply(c, 200, JSON_HEADERS, "%s\n", json ? json : "{}");
    free(json);
  } else if (mg_match(hm->uri, mg_str("/api/browser-profile"), NULL)) {
    char region[16] = "";
    char device[16] = "";
    char json[2048];
    struct browser_profile profile;

    mg_http_get_var(&hm->query, "region", region, sizeof(region));
    mg_http_get_var(&hm->query, "device", device, sizeof(device));
    browser_profile_generate(&profile, region, device);
    browser_profile_to_json(&profile, json, sizeof(json));
    mg_http_reply(c, 200, JSON_HEADERS, "%s", json);
  } else if (uri_has_prefix(hm->uri, "/api/jobs")) {
    handle_jobs_api(c, hm);
  } else if (uri_has_prefix(hm->uri, "/api/proxies")) {
    handle_proxy_api(c, hm);
  } else if (uri_has_prefix(hm->uri, "/api/mail")) {
    handle_mail_api(c, hm);
  } else if (uri_has_prefix(hm->uri, "/api/upload")) {
    handle_upload_api(c, hm);
  } else if (uri_has_prefix(hm->uri, "/api/accounts")) {
    handle_accounts_api(c, hm);
  } else if (uri_has_prefix(hm->uri, "/api/registration")) {
    handle_registration_api(c, hm);
  } else if (mg_match(hm->uri, mg_str("/api/echo"), NULL)) {
    mg_http_reply(c, 200, JSON_HEADERS,
                  "{%m:%m,%m:%m,%m:%m}\n",
                  MG_ESC("status"), MG_ESC("ok"),
                  MG_ESC("method"), mg_print_esc, (int) hm->method.len,
                  hm->method.buf, MG_ESC("body"), mg_print_esc,
                  (int) hm->body.len, hm->body.buf);
  } else if (uri_has_prefix(hm->uri, "/api/")) {
    mg_http_reply(c, 404, JSON_HEADERS, "{\"error\":\"not found\"}\n");
  } else if (mg_match(hm->uri, mg_str("/ws"), NULL)) {
    mg_ws_upgrade(c, hm, NULL);
  } else if (mg_match(hm->uri, mg_str("/"), NULL) ||
             mg_match(hm->uri, mg_str("/index.html"), NULL)) {
    mg_http_reply(c, 302, "Location: /console\r\nCache-Control: no-store\r\n", "");
  } else {
    struct mg_http_serve_opts opts = {
        .root_dir = "/web",
        .page404 = "/web/index.html",
        .fs = &mg_fs_packed,
        .extra_headers = "Cache-Control: no-cache\r\n",
    };
    mg_http_serve_dir(c, hm, &opts);
  }
}

static void event_handler(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_HTTP_MSG) {
    handle_http(c, (struct mg_http_message *) ev_data);
  } else if (ev == MG_EV_POLL) {
    registration_ws_poll(c->mgr, s_db, s_started_ms);
  } else if (ev == MG_EV_WS_OPEN) {
    registration_ws_open(c);
    mg_ws_printf(c, WEBSOCKET_OP_TEXT, "{%m:%m,%m:%llu}",
                 MG_ESC("type"), MG_ESC("hello"),
                 MG_ESC("time_ms"), (unsigned long long) mg_millis());
  } else if (ev == MG_EV_WS_MSG) {
    struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
    if (!registration_ws_handle_message(c, wm->data, s_db, s_started_ms)) {
      mg_ws_printf(c, WEBSOCKET_OP_TEXT, "{%m:%m,%m:%m,%m:%m}",
                   MG_ESC("type"), MG_ESC("echo"),
                   MG_ESC("status"), MG_ESC("ok"),
                   MG_ESC("message"), mg_print_esc, (int) wm->data.len,
                   wm->data.buf);
    }
  } else if (ev == MG_EV_CLOSE) {
    if (c->fn_data != NULL) registration_ws_close(c);
  }
}

int main(int argc, char **argv) {
  const char *listen_url = argc > 1 ? argv[1] : "http://0.0.0.0:8000";
  struct mg_mgr mgr;

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  configure_mongoose_log();
  mg_mgr_init(&mgr);
  if (http_client_global_init() != 0) {
    fprintf(stderr, "Cannot initialize libcurl\n");
    mg_mgr_free(&mgr);
    return 1;
  }
  if (app_db_init("data/app.db", &s_db) != 0) {
    fprintf(stderr, "Cannot open data/app.db\n");
    http_client_global_cleanup();
    mg_mgr_free(&mgr);
    return 1;
  }
  if (app_auth_init(s_db) != 0) {
    app_db_close(s_db);
    http_client_global_cleanup();
    mg_mgr_free(&mgr);
    return 1;
  }
  rapid_inbox_start_configured(s_db);
  mihomo_start_configured(s_db);
  browser_profile_seed((uint64_t) time(NULL) ^ (uint64_t) mg_millis());
  mg_mem_files = mg_packed_files;
  s_started_ms = mg_millis();

  if (mg_http_listen(&mgr, listen_url, event_handler, NULL) == NULL) {
    fprintf(stderr, "Cannot listen on %s\n", listen_url);
    mihomo_shutdown(s_db);
    rapid_inbox_shutdown();
    app_db_close(s_db);
    http_client_global_cleanup();
    mg_mgr_free(&mgr);
    return 1;
  }

  printf("Mongoose app listening on %s\n", listen_url);
  printf("Open http://127.0.0.1:8000\n");

  while (s_running) mg_mgr_poll(&mgr, 50);
  mihomo_shutdown(s_db);
  rapid_inbox_shutdown();
  app_db_close(s_db);
  http_client_global_cleanup();
  mg_mgr_free(&mgr);
  return 0;
}
