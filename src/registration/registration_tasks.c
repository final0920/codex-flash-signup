#include "registration/registration_tasks.h"

#include "account/account_store.h"
#include "flow/flow_impersonate.h"
#include "flow/flow_libcurl_impersonate.h"
#include "http_client/browser_profile.h"
#include "identity/identity_generator.h"
#include "mail/outlook_pool.h"
#include "oauth/oauth_provider.h"
#include "proxy/mihomo_manager.h"
#include "proxy/proxy_pool.h"
#include "registration/codex_direct_provider.h"
#include "registration/platform_register_provider.h"
#include "registration/web_register_provider.h"
#include "storage/app_db.h"
#include "system/system_monitor.h"
#include "upload/aether_upload.h"

#include <ctype.h>
#include <limits.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define REG_TASK_STATUS_LEN 24
#define REG_TASK_ERROR_LEN 256
#define REG_TASK_LOG_MSG_LEN 768
#define REG_TASK_DEFAULT_MAX_LOGS 160
#define REG_TASK_DETAILED_MAX_LOGS 800
#define REG_TASK_DETAIL_LOG_LIMIT 80
#define REG_TASK_WS_LOG_BATCH_LIMIT 80
#define REG_TASK_IDLE_RETENTION_MS (10ULL * 60ULL * 1000ULL)
#define REG_TASK_MIHOMO_NODE_LEN 512
#define REG_TASK_UPLOAD_SERVICE_NAME_LEN 256
#define OAUTH_RACE_BRANCHES 2
#define ENVIRONMENT_RETRY_LIMIT 2
#define IDENTITY_RETRY_LIMIT 8
#define CURRENT_SESSION_OAUTH_RETRY_AFTER_DEFAULT_SECONDS 30
#define CURRENT_SESSION_OAUTH_RETRY_AFTER_MAX_SECONDS 300
#define CURRENT_SESSION_SECOND_OAUTH_OTP_TIMEOUT_MS 30000
#define FASTLANE_DEFAULT_MAX_INFLIGHT 20
#define FASTLANE_MAX_INFLIGHT_LIMIT 1000
#define FLOW_THREAD_DEFAULT_STACK_KB 512
#define FLOW_THREAD_MIN_STACK_KB 128
#define FLOW_THREAD_MAX_STACK_KB 8192

enum registration_fastlane_stage {
  REG_FLOW_STAGE_NONE = 0,
  REG_FLOW_STAGE_PRE_EMAIL_ACTIVE,
  REG_FLOW_STAGE_WAITING_EMAIL,
  REG_FLOW_STAGE_POST_EMAIL_ACTIVE,
  REG_FLOW_STAGE_TERMINAL
};

struct registration_log_entry {
  uint64_t seq;
  uint64_t ts_ms;
  char level[12];
  char flow_id[FLOW_ID_LEN];
  char message[REG_TASK_LOG_MSG_LEN];
};

struct registration_task {
  char id[REG_TASK_ID_LEN];
  enum registration_workflow workflow;
  enum registration_scheduler_mode scheduler_mode;
  enum registration_target_metric target_metric;
  enum registration_register_provider register_provider;
  enum registration_request_core request_core;
  char libcurl_impersonate_target[FLOW_IMPERSONATE_TARGET_LEN];
  char mihomo_node[REG_TASK_MIHOMO_NODE_LEN];
  char mihomo_proxy_url[FLOW_PROXY_LEN];
  bool mihomo_task_proxy;
  int target_count;
  int concurrency;
  int max_inflight;
  int oauth_delay_seconds;
  int current_session_oauth_retry_after_seconds;
  bool detailed_logs;
  bool infinite;
  bool auto_upload_oauth_success;
  bool discard_oauth_failed_accounts;
  enum registration_auto_upload_service_mode auto_upload_service_mode;
  long auto_upload_service_id;
  char auto_upload_service_name[REG_TASK_UPLOAD_SERVICE_NAME_LEN];
  bool current_session_oauth_fallback;
  bool fast_email_otp_resend;
  enum registration_current_session_oauth_fallback_mode
      current_session_oauth_fallback_mode;
  bool stop_requested;
  int started;
  int active;
  int success;
  int failed;
  int register_success;
  int register_failed;
  int oauth_success;
  int oauth_failed;
  int expired_written;
  int temp_written;
  int upload_success;
  int upload_failed;
  int upload_skipped;
  int fastlane_pre_email_active;
  int fastlane_waiting_email;
  int fastlane_post_email_active;
  char status[REG_TASK_STATUS_LEN];
  char error[REG_TASK_ERROR_LEN];
  uint64_t created_ms;
  uint64_t started_ms;
  uint64_t updated_ms;
  uint64_t finished_ms;
  long *account_ids;
  size_t account_id_count;
  size_t next_account_index;
  struct registration_log_entry *logs;
  size_t log_len;
  size_t log_cap;
  pthread_t thread;
  struct registration_task *next;
};

struct registration_ws_state {
  char task_id[REG_TASK_ID_LEN];
  uint64_t last_seq;
  uint64_t last_status_ms;
  bool system_subscribed;
  uint64_t system_interval_ms;
  uint64_t last_system_status_ms;
};

struct registration_flow_job {
  struct registration_task *task;
  enum registration_workflow workflow;
  enum registration_register_provider register_provider;
  enum registration_request_core request_core;
  char libcurl_impersonate_target[FLOW_IMPERSONATE_TARGET_LEN];
  struct identity_result identity;
  struct browser_profile profile;
  char proxy_url[FLOW_PROXY_LEN];
  char workspace_id[FLOW_WORKSPACE_ID_LEN];
  long account_id;
  long deadline_ms;
  int oauth_delay_seconds;
  int current_session_oauth_retry_after_seconds;
  bool auto_upload_oauth_success;
  bool discard_oauth_failed_accounts;
  enum registration_auto_upload_service_mode auto_upload_service_mode;
  long auto_upload_service_id;
  char auto_upload_service_name[REG_TASK_UPLOAD_SERVICE_NAME_LEN];
  bool current_session_oauth_fallback;
  bool fast_email_otp_resend;
  enum registration_current_session_oauth_fallback_mode
      current_session_oauth_fallback_mode;
  enum registration_fastlane_stage scheduler_stage;
  long outlook_mailbox_id;
};

struct oauth_race_state {
  pthread_mutex_t mu;
  int winner_index;
  bool cancel[OAUTH_RACE_BRANCHES];
};

struct oauth_race_runner {
  struct oauth_race_state *race;
  int index;
  bool launched;
  int rc;
  pthread_t thread;
  struct registration_flow_job job;
  struct flow_context flow;
};

static int reassign_job_environment(sqlite3 *db, struct registration_flow_job *job,
                                    const char *phase, int attempt,
                                    int limit);
static int reassign_job_identity(sqlite3 *db, struct registration_flow_job *job,
                                 const char *flow_id, int attempt, int limit);
static void task_log(struct registration_task *task, const char *flow_id,
                     const char *level, const char *fmt, ...);
static void fastlane_set_job_stage(struct registration_flow_job *job,
                                   enum registration_fastlane_stage next_stage,
                                   const char *flow_id,
                                   const char *reason);
static bool task_stop_requested(struct registration_task *task);
static const char *auto_upload_service_mode_name(
    enum registration_auto_upload_service_mode mode);
static const char *auto_upload_service_mode_label(
    enum registration_auto_upload_service_mode mode);

static pthread_mutex_t s_tasks_mu = PTHREAD_MUTEX_INITIALIZER;
static struct registration_task *s_tasks;
static uint64_t s_log_seq;

static uint64_t now_ms(void) {
  struct timeval tv;
  if (gettimeofday(&tv, NULL) == 0) {
    return (uint64_t) tv.tv_sec * 1000ULL + (uint64_t) tv.tv_usec / 1000ULL;
  }
  return mg_millis();
}

static void set_error(char *error, size_t error_len, const char *message) {
  if (error_len == 0) return;
  mg_snprintf(error, error_len, "%s", message ? message : "注册任务失败");
}

static int init_flow_thread_attr(pthread_attr_t *attr) {
  const char *env;
  char *end = NULL;
  long stack_kb = FLOW_THREAD_DEFAULT_STACK_KB;
  size_t stack_size;

  if (attr == NULL || pthread_attr_init(attr) != 0) return -1;
  env = getenv("REG_FLOW_THREAD_STACK_KB");
  if (env != NULL && env[0] != '\0') {
    long value = strtol(env, &end, 10);
    if (end != env && value > 0) stack_kb = value;
  }
  if (stack_kb < FLOW_THREAD_MIN_STACK_KB) stack_kb = FLOW_THREAD_MIN_STACK_KB;
  if (stack_kb > FLOW_THREAD_MAX_STACK_KB) stack_kb = FLOW_THREAD_MAX_STACK_KB;
  stack_size = (size_t) stack_kb * 1024U;
#ifdef PTHREAD_STACK_MIN
  if (stack_size < (size_t) PTHREAD_STACK_MIN) {
    stack_size = (size_t) PTHREAD_STACK_MIN;
  }
#endif
  (void) pthread_attr_setstacksize(attr, stack_size);
  return 0;
}

static const char *workflow_name(enum registration_workflow workflow) {
  switch (workflow) {
    case REG_WORKFLOW_REGISTER_THEN_OAUTH: return "register_then_oauth";
    case REG_WORKFLOW_REGISTER_THEN_CURRENT_CODEX:
      return "register_then_current_codex";
    case REG_WORKFLOW_OAUTH_ONLY: return "oauth_only";
    case REG_WORKFLOW_CHATGPT_LOGIN_ONLY: return "chatgpt_login_only";
    case REG_WORKFLOW_CODEX_CLI_SIMPLIFIED: return "codex_cli_simplified";
    case REG_WORKFLOW_OUTLOOK_DIRECT: return "outlook_direct";
    case REG_WORKFLOW_REGISTER_ONLY:
    default: return "register_only";
  }
}

static bool workflow_is_account_task(enum registration_workflow workflow) {
  return workflow == REG_WORKFLOW_OAUTH_ONLY ||
         workflow == REG_WORKFLOW_CHATGPT_LOGIN_ONLY;
}

static bool workflow_uses_current_session_codex(
    enum registration_workflow workflow) {
  return workflow == REG_WORKFLOW_REGISTER_THEN_CURRENT_CODEX ||
         workflow == REG_WORKFLOW_CODEX_CLI_SIMPLIFIED ||
         workflow == REG_WORKFLOW_OUTLOOK_DIRECT;
}

static bool workflow_has_oauth(enum registration_workflow workflow) {
  return workflow == REG_WORKFLOW_REGISTER_THEN_OAUTH ||
         workflow == REG_WORKFLOW_REGISTER_THEN_CURRENT_CODEX ||
         workflow == REG_WORKFLOW_CODEX_CLI_SIMPLIFIED ||
         workflow == REG_WORKFLOW_OAUTH_ONLY;
}

static const char *current_session_fallback_mode_name(
    enum registration_current_session_oauth_fallback_mode mode) {
  switch (mode) {
    case REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE: return "single";
    case REG_CURRENT_SESSION_OAUTH_FALLBACK_DOUBLE: return "double";
    case REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE_TIMEOUT_RETRY:
      return "single_timeout_retry";
    case REG_CURRENT_SESSION_OAUTH_FALLBACK_NONE:
    default: return "none";
  }
}

static const char *current_session_fallback_mode_label(
    enum registration_current_session_oauth_fallback_mode mode) {
  switch (mode) {
    case REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE: return "单 OAuth 兜底";
    case REG_CURRENT_SESSION_OAUTH_FALLBACK_DOUBLE: return "双 OAuth 抢码兜底";
    case REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE_TIMEOUT_RETRY:
      return "超时二次 OAuth 兜底";
    case REG_CURRENT_SESSION_OAUTH_FALLBACK_NONE:
    default: return "不兜底";
  }
}

static const char *scheduler_mode_name(enum registration_scheduler_mode mode) {
  return mode == REG_SCHEDULER_FASTLANE ? "fastlane" : "normal";
}

static const char *fastlane_stage_name(enum registration_fastlane_stage stage) {
  switch (stage) {
    case REG_FLOW_STAGE_PRE_EMAIL_ACTIVE: return "pre_email_active";
    case REG_FLOW_STAGE_WAITING_EMAIL: return "waiting_email";
    case REG_FLOW_STAGE_POST_EMAIL_ACTIVE: return "post_email_active";
    case REG_FLOW_STAGE_TERMINAL: return "terminal";
    case REG_FLOW_STAGE_NONE:
    default: return "none";
  }
}

static const char *fastlane_stage_label(enum registration_fastlane_stage stage) {
  switch (stage) {
    case REG_FLOW_STAGE_PRE_EMAIL_ACTIVE: return "注册前置阶段";
    case REG_FLOW_STAGE_WAITING_EMAIL: return "等待邮箱验证码";
    case REG_FLOW_STAGE_POST_EMAIL_ACTIVE: return "验证码后置阶段";
    case REG_FLOW_STAGE_TERMINAL: return "已结束";
    case REG_FLOW_STAGE_NONE:
    default: return "-";
  }
}

static const char *target_metric_name(enum registration_target_metric metric) {
  return metric == REG_TARGET_OAUTH_SUCCESS ? "oauth_success"
                                            : "register_task";
}

static const char *register_provider_name(
    enum registration_register_provider provider) {
  return provider == REG_REGISTER_PROVIDER_TEMPORARY ? "temporary" : "platform";
}

static const char *register_provider_label(
    enum registration_register_provider provider) {
  return provider == REG_REGISTER_PROVIDER_TEMPORARY ? "临时账号注册"
                                                     : "过期账号注册";
}

static const char *request_core_name(enum registration_request_core core) {
  if (core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE) {
    return "libcurl_impersonate";
  }
  if (core == REG_REQUEST_CORE_LIBCURL) return "libcurl";
  return "curl_impersonate";
}

static const char *request_core_label(enum registration_request_core core) {
  if (core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE) {
    return "libcurl-impersonate";
  }
  if (core == REG_REQUEST_CORE_LIBCURL) return "libcurl";
  return "curl-impersonate";
}

static const char *task_libcurl_impersonate_target(
    const struct registration_task *task) {
  if (task == NULL || task->libcurl_impersonate_target[0] == '\0') {
    return flow_libcurl_impersonate_default_target();
  }
  return task->libcurl_impersonate_target;
}

static const char *task_register_label(const struct registration_task *task) {
  if (task == NULL) return "-";
  if (task->workflow == REG_WORKFLOW_OAUTH_ONLY) return "账号池 OAuth";
  if (task->workflow == REG_WORKFLOW_CHATGPT_LOGIN_ONLY) {
    return "ChatGPT Web 登录";
  }
  return register_provider_label(task->register_provider);
}

static const char *credential_action_label(const struct registration_task *task) {
  return task != NULL && task->workflow == REG_WORKFLOW_CHATGPT_LOGIN_ONLY
             ? "ChatGPT 登录"
             : "OAuth";
}

static bool contains_casefold_text(const char *s, const char *needle) {
  size_t nlen;
  if (s == NULL || needle == NULL) return false;
  nlen = strlen(needle);
  if (nlen == 0) return true;
  for (; *s != '\0'; s++) {
    size_t i = 0;
    while (i < nlen && s[i] != '\0' &&
           tolower((unsigned char) s[i]) ==
               tolower((unsigned char) needle[i])) {
      i++;
    }
    if (i == nlen) return true;
  }
  return false;
}

static bool flow_has_phone_binding_required(
    const struct flow_context *flow, const char *fallback_message) {
  return (flow != NULL &&
          contains_casefold_text(flow->error, "phone_binding_required")) ||
         contains_casefold_text(fallback_message, "phone_binding_required");
}

static bool task_uses_fastlane_unlocked(const struct registration_task *task) {
  return task != NULL && task->scheduler_mode == REG_SCHEDULER_FASTLANE &&
         !workflow_is_account_task(task->workflow);
}

static int task_fastlane_alive_unlocked(const struct registration_task *task) {
  if (task == NULL) return 0;
  return task->fastlane_pre_email_active + task->fastlane_waiting_email +
         task->fastlane_post_email_active;
}

static void adjust_fastlane_stage_count_unlocked(
    struct registration_task *task, enum registration_fastlane_stage stage,
    int delta) {
  int *slot = NULL;
  if (task == NULL || delta == 0) return;
  switch (stage) {
    case REG_FLOW_STAGE_PRE_EMAIL_ACTIVE:
      slot = &task->fastlane_pre_email_active;
      break;
    case REG_FLOW_STAGE_WAITING_EMAIL:
      slot = &task->fastlane_waiting_email;
      break;
    case REG_FLOW_STAGE_POST_EMAIL_ACTIVE:
      slot = &task->fastlane_post_email_active;
      break;
    default:
      return;
  }
  *slot += delta;
  if (*slot < 0) *slot = 0;
}

static void proxy_scheme_label(const char *proxy_url, char *out, size_t out_len) {
  const char *p;
  size_t len;
  if (out_len == 0) return;
  out[0] = '\0';
  if (proxy_url == NULL || proxy_url[0] == '\0') {
    mg_snprintf(out, out_len, "direct");
    return;
  }
  p = strstr(proxy_url, "://");
  if (p == NULL) {
    mg_snprintf(out, out_len, "proxy");
    return;
  }
  len = (size_t) (p - proxy_url);
  if (len >= out_len) len = out_len - 1;
  memcpy(out, proxy_url, len);
  out[len] = '\0';
}

static bool proxy_mode_allows_direct(sqlite3 *db) {
  char mode[16];
  if (mihomo_current_proxy_mode(db, mode, sizeof(mode)) != 0) return false;
  return strcmp(mode, "direct") == 0;
}

static int ensure_non_direct_proxy_available(sqlite3 *db, int proxy_rc,
                                             char *error, size_t error_len) {
  if (proxy_rc > 0) return 0;
  if (proxy_rc < 0) {
    set_error(error, error_len, "读取代理池失败");
    return -1;
  }
  if (proxy_mode_allows_direct(db)) return 0;
  set_error(error, error_len,
            "当前代理模式没有可用代理。代理池模式需要至少一个测试通过的可用节点，或切换为直连模式");
  return -1;
}

static int prepare_task_mihomo_proxy(sqlite3 *db,
                                     struct registration_task *task,
                                     char *error, size_t error_len) {
  char proxy_url[FLOW_PROXY_LEN] = "";
  char selected_node[REG_TASK_MIHOMO_NODE_LEN] = "";
  char requested_node[REG_TASK_MIHOMO_NODE_LEN];
  int rc;

  if (task == NULL) return 0;
  mg_snprintf(requested_node, sizeof(requested_node), "%s", task->mihomo_node);
  rc = mihomo_task_proxy_pick_url(db, task->id, requested_node, proxy_url,
                                  sizeof(proxy_url), selected_node,
                                  sizeof(selected_node), error, error_len);
  if (rc < 0) return -1;
  if (rc == 0) return 0;

  task->mihomo_task_proxy = true;
  mg_snprintf(task->mihomo_proxy_url, sizeof(task->mihomo_proxy_url), "%s",
              proxy_url);
  mg_snprintf(task->mihomo_node, sizeof(task->mihomo_node), "%s",
              selected_node);
  if (task->detailed_logs) {
    if (requested_node[0] != '\0') {
      task_log(task, "", "info",
               "任务已绑定 Mihomo 订阅节点: %s proxy=%s",
               task->mihomo_node, task->mihomo_proxy_url);
    } else {
      task_log(task, "", "info",
               "任务未手动指定 Mihomo 节点，已随机绑定: %s proxy=%s",
               task->mihomo_node, task->mihomo_proxy_url);
    }
  } else if (requested_node[0] != '\0') {
    task_log(task, "", "info",
             "已绑定指定 Mihomo 节点: %s", task->mihomo_node);
  } else {
    task_log(task, "", "info",
             "已随机绑定 Mihomo 节点: %s", task->mihomo_node);
  }
  return 0;
}

static void generate_task_id(char *out, size_t out_len) {
  uint64_t seed = 0;
  if (out_len == 0) return;
  if (!mg_random(&seed, sizeof(seed))) seed = now_ms();
  mg_snprintf(out, out_len, "rt-%llx", (unsigned long long) seed);
}

static struct registration_task *find_task_locked(const char *task_id) {
  for (struct registration_task *task = s_tasks; task != NULL; task = task->next) {
    if (strcmp(task->id, task_id) == 0) return task;
  }
  return NULL;
}

static bool task_is_operating_unlocked(const struct registration_task *task) {
  if (task == NULL) return false;
  return task->active > 0 || strcmp(task->status, "queued") == 0 ||
         strcmp(task->status, "running") == 0 ||
         strcmp(task->status, "stopping") == 0;
}

static bool task_is_expired_unlocked(const struct registration_task *task,
                                     uint64_t now) {
  uint64_t idle_since;
  if (task == NULL || task_is_operating_unlocked(task)) return false;
  idle_since = task->finished_ms > 0 ? task->finished_ms : task->updated_ms;
  return idle_since > 0 && now >= idle_since &&
         now - idle_since >= REG_TASK_IDLE_RETENTION_MS;
}

static void free_task(struct registration_task *task) {
  if (task == NULL) return;
  free(task->account_ids);
  free(task->logs);
  free(task);
}

static void purge_expired_tasks_locked(void) {
  struct registration_task **link = &s_tasks;
  uint64_t now = now_ms();
  while (*link != NULL) {
    struct registration_task *task = *link;
    if (task_is_expired_unlocked(task, now)) {
      *link = task->next;
      free_task(task);
    } else {
      link = &task->next;
    }
  }
}

static void append_log_locked(struct registration_task *task,
                              const char *flow_id, const char *level,
                              const char *message) {
  struct registration_log_entry *entry;
  size_t limit;

  if (task == NULL || message == NULL) return;
  limit = task->detailed_logs ? REG_TASK_DETAILED_MAX_LOGS
                              : REG_TASK_DEFAULT_MAX_LOGS;
  if (limit < 1) limit = 1;
  if (task->log_len >= limit) {
    size_t drop = limit / 4;
    if (drop < 1) drop = 1;
    if (drop > task->log_len) drop = task->log_len;
    memmove(task->logs, task->logs + drop,
            (task->log_len - drop) * sizeof(*task->logs));
    task->log_len -= drop;
  }
  if (task->log_len == task->log_cap) {
    size_t cap = task->log_cap == 0 ? 128 : task->log_cap * 2;
    struct registration_log_entry *next;
    if (cap > limit) cap = limit;
    next = (struct registration_log_entry *) realloc(
        task->logs, cap * sizeof(*next));
    if (next == NULL) return;
    task->logs = next;
    task->log_cap = cap;
  }
  entry = &task->logs[task->log_len++];
  memset(entry, 0, sizeof(*entry));
  entry->seq = ++s_log_seq;
  entry->ts_ms = now_ms();
  mg_snprintf(entry->level, sizeof(entry->level), "%s",
              level ? level : "info");
  mg_snprintf(entry->flow_id, sizeof(entry->flow_id), "%s",
              flow_id ? flow_id : "");
  mg_snprintf(entry->message, sizeof(entry->message), "%s", message);
  task->updated_ms = entry->ts_ms;
}

static void append_logf_locked(struct registration_task *task,
                               const char *flow_id, const char *level,
                               const char *fmt, ...) {
  char message[REG_TASK_LOG_MSG_LEN];
  va_list ap;
  if (fmt == NULL) return;
  va_start(ap, fmt);
  vsnprintf(message, sizeof(message), fmt, ap);
  va_end(ap);
  append_log_locked(task, flow_id, level, message);
}

static void task_log(struct registration_task *task, const char *flow_id,
                     const char *level, const char *fmt, ...) {
  char message[REG_TASK_LOG_MSG_LEN];
  va_list ap;

  if (task == NULL || fmt == NULL) return;
  va_start(ap, fmt);
  vsnprintf(message, sizeof(message), fmt, ap);
  va_end(ap);

  pthread_mutex_lock(&s_tasks_mu);
  append_log_locked(task, flow_id, level, message);
  pthread_mutex_unlock(&s_tasks_mu);
}

static void task_log_account_message(struct registration_task *task,
                                     const char *flow_id, const char *level,
                                     long account_id, const char *message) {
  char wrapped[REG_TASK_LOG_MSG_LEN];

  if (task == NULL || message == NULL) return;
  if (account_id > 0 && strstr(message, "账号 ID=") == NULL &&
      strstr(message, "账号ID=") == NULL) {
    mg_snprintf(wrapped, sizeof(wrapped), "账号 ID=%ld %s", account_id,
                message);
    task_log(task, flow_id, level, "%s", wrapped);
    return;
  }
  task_log(task, flow_id, level, "%s", message);
}

static bool default_log_level_visible(const char *level) {
  return level != NULL &&
         (strcmp(level, "error") == 0 || strcmp(level, "warn") == 0);
}

static bool flow_log_visible(const struct registration_task *task,
                             const char *level) {
  if (task == NULL) return false;
  if (task->detailed_logs) return true;
  return default_log_level_visible(level);
}

static void flow_log_callback(struct flow_context *flow, const char *level,
                              const char *message, void *userdata) {
  struct registration_task *task = (struct registration_task *) userdata;
  if (task == NULL || flow == NULL || message == NULL) return;
  if (!flow_log_visible(task, level)) return;
  task_log_account_message(task, flow->id, level, flow->account_id, message);
}

static void flow_job_log_callback(struct flow_context *flow, const char *level,
                                  const char *message, void *userdata) {
  struct registration_flow_job *job = (struct registration_flow_job *) userdata;
  struct registration_task *task = job ? job->task : NULL;
  if (task == NULL || flow == NULL || message == NULL) return;
  if (!flow_log_visible(task, level)) return;
  task_log_account_message(task, flow->id, level, flow->account_id, message);
}

static void flow_job_event_callback(struct flow_context *flow,
                                    const char *event, void *userdata) {
  struct registration_flow_job *job = (struct registration_flow_job *) userdata;
  if (job == NULL || event == NULL) return;
  if (strcmp(event, FLOW_EVENT_EMAIL_OTP_WAITING) == 0) {
    fastlane_set_job_stage(job, REG_FLOW_STAGE_WAITING_EMAIL,
                           flow ? flow->id : "",
                           "已进入邮箱验证码等待，释放前置启动槽");
  } else if (strcmp(event, FLOW_EVENT_EMAIL_OTP_VALIDATED) == 0) {
    fastlane_set_job_stage(job, REG_FLOW_STAGE_POST_EMAIL_ACTIVE,
                           flow ? flow->id : "",
                           "邮箱验证码已通过，进入后置阶段");
  }
}

static bool flow_job_cancel_callback(struct flow_context *flow,
                                     void *userdata) {
  struct registration_flow_job *job = (struct registration_flow_job *) userdata;
  (void) flow;
  return job != NULL && task_stop_requested(job->task);
}

static int task_target_progress_unlocked(const struct registration_task *task) {
  if (task == NULL) return 0;
  return task->target_metric == REG_TARGET_OAUTH_SUCCESS ? task->oauth_success
                                                         : task->started;
}

static bool task_goal_met_unlocked(const struct registration_task *task) {
  if (task == NULL || task->infinite) return false;
  return task->target_count > 0 &&
         task_target_progress_unlocked(task) >= task->target_count;
}

static void task_refresh_success_unlocked(struct registration_task *task) {
  if (task != NULL) task->success = task_target_progress_unlocked(task);
}

static bool task_should_launch_unlocked(const struct registration_task *task) {
  if (task == NULL || strcmp(task->status, "running") != 0 ||
      task->stop_requested) {
    return false;
  }
  if (task_uses_fastlane_unlocked(task)) {
    if (task->fastlane_pre_email_active >= task->concurrency ||
        task->active >= task->max_inflight) {
      return false;
    }
  } else if (task->active >= task->concurrency) {
    return false;
  }
  if (workflow_is_account_task(task->workflow)) {
    return task->next_account_index < task->account_id_count;
  }
  return task->infinite || !task_goal_met_unlocked(task);
}

static bool task_is_done_unlocked(const struct registration_task *task) {
  if (task == NULL || task->active > 0) return false;
  if (task->stop_requested) return true;
  if (workflow_is_account_task(task->workflow)) {
    return task->next_account_index >= task->account_id_count;
  }
  return !task->infinite && task_goal_met_unlocked(task);
}

static bool task_should_continue(struct registration_task *task) {
  bool keep_running;
  pthread_mutex_lock(&s_tasks_mu);
  keep_running = strcmp(task->status, "running") == 0 ||
                 strcmp(task->status, "stopping") == 0;
  pthread_mutex_unlock(&s_tasks_mu);
  return keep_running;
}

static bool can_launch_more(struct registration_task *task) {
  bool ok;
  pthread_mutex_lock(&s_tasks_mu);
  ok = task_should_launch_unlocked(task);
  pthread_mutex_unlock(&s_tasks_mu);
  return ok;
}

static bool task_is_done(struct registration_task *task) {
  bool done;
  pthread_mutex_lock(&s_tasks_mu);
  done = task_is_done_unlocked(task);
  pthread_mutex_unlock(&s_tasks_mu);
  return done;
}

static bool task_stop_requested(struct registration_task *task) {
  bool stop;
  pthread_mutex_lock(&s_tasks_mu);
  stop = task != NULL &&
         (task->stop_requested || strcmp(task->status, "stopping") == 0 ||
          strcmp(task->status, "stopped") == 0);
  pthread_mutex_unlock(&s_tasks_mu);
  return stop;
}

static void mark_task_running(struct registration_task *task) {
  pthread_mutex_lock(&s_tasks_mu);
  mg_snprintf(task->status, sizeof(task->status),
              task->stop_requested ? "stopping" : "running");
  task->started_ms = now_ms();
  task->updated_ms = task->started_ms;
  if (task->detailed_logs) {
    append_logf_locked(task, "", "info",
                       "任务编排已启动: workflow=%s scheduler=%s register=%s target=%s core=%s%s%s%s 并发=%d%s",
                       workflow_name(task->workflow),
                       scheduler_mode_name(task->scheduler_mode),
                       task_register_label(task),
                       target_metric_name(task->target_metric),
                       request_core_label(task->request_core),
                       task->request_core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE
                           ? " impersonate="
                           : "",
                       task->request_core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE
                           ? task_libcurl_impersonate_target(task)
                           : "",
                       task->infinite ? " infinite" : "",
                       task->concurrency,
                       task_uses_fastlane_unlocked(task) ? " 高速模式" : "");
  } else {
    append_log_locked(task, "", "info", "任务已启动");
  }
  if (task->detailed_logs && task_uses_fastlane_unlocked(task)) {
    append_logf_locked(task, "", "info",
                       "高速模式调度: 前置并发=%d 最大存活=%d，进入邮箱等待后释放启动槽",
                       task->concurrency, task->max_inflight);
  }
  if (task->detailed_logs && !task->infinite) {
    append_logf_locked(task, "", "info", "目标数量: %d", task->target_count);
  }
  if (task->detailed_logs &&
      task->workflow == REG_WORKFLOW_REGISTER_THEN_OAUTH &&
      task->oauth_delay_seconds > 0) {
    append_logf_locked(task, "", "info", "注册完成后延迟 %d 秒再执行 OAuth",
                       task->oauth_delay_seconds);
  }
  if (task->detailed_logs && task->fast_email_otp_resend) {
    append_log_locked(task, "", "info",
                      "快速重发验证码: 10 秒未收到即重发，最多连续 3 次，最后一次等待 30 秒");
  }
  if (task->detailed_logs && task->discard_oauth_failed_accounts) {
    append_log_locked(task, "", "info",
                      "OA 失败账号不保存: OAuth 最终失败时将从账号库移除新注册账号");
  }
  if (task->detailed_logs && workflow_uses_current_session_codex(task->workflow)) {
    append_log_locked(task, "", "info",
                      "当前会话 Codex OAuth: 注册成功后不重新登录，直接复用注册会话授权");
    if (task->current_session_oauth_fallback_mode ==
        REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE) {
      append_log_locked(task, "", "info",
                        "当前会话 Codex OAuth 兜底: 非 phone_binding_required 失败将进入单 OAuth");
    } else if (task->current_session_oauth_fallback_mode ==
               REG_CURRENT_SESSION_OAUTH_FALLBACK_DOUBLE) {
      append_log_locked(task, "", "info",
                        "当前会话 Codex OAuth 兜底: 非 phone_binding_required 失败将进入双 OAuth 抢码");
    } else if (task->current_session_oauth_fallback_mode ==
               REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE_TIMEOUT_RETRY) {
      append_logf_locked(
          task, "", "info",
          "当前会话 Codex OAuth 兜底: 先执行单 OAuth，%d 秒未收到验证码时触发第二次 OA，第二次邮箱超时 30 秒",
          task->current_session_oauth_retry_after_seconds);
    }
  }
  if (task->detailed_logs && task->auto_upload_oauth_success) {
    if (task->auto_upload_service_mode == REG_AUTO_UPLOAD_SERVICE_ALL) {
      append_log_locked(task, "", "info",
                        "OAuth 成功后将自动上传到上传配置中所有已启用的 Aether 服务");
    } else {
      append_logf_locked(task, "", "info",
                         "OAuth 成功后将自动上传到 %s: %s",
                         auto_upload_service_mode_label(
                             task->auto_upload_service_mode),
                         task->auto_upload_service_name[0]
                             ? task->auto_upload_service_name
                             : auto_upload_service_mode_label(
                                   task->auto_upload_service_mode));
    }
  }
  pthread_mutex_unlock(&s_tasks_mu);
}

static void mark_task_failed(struct registration_task *task,
                             const char *message) {
  pthread_mutex_lock(&s_tasks_mu);
  mg_snprintf(task->status, sizeof(task->status), "failed");
  mg_snprintf(task->error, sizeof(task->error), "%s",
              message ? message : "注册任务失败");
  task_refresh_success_unlocked(task);
  task->active = 0;
  task->finished_ms = now_ms();
  task->updated_ms = task->finished_ms;
  append_log_locked(task, "", "error", task->error);
  pthread_mutex_unlock(&s_tasks_mu);
}

static void mark_task_finished(struct registration_task *task) {
  bool goal_met;
  pthread_mutex_lock(&s_tasks_mu);
  task_refresh_success_unlocked(task);
  goal_met = task_goal_met_unlocked(task);
  if (task->stop_requested) {
    mg_snprintf(task->status, sizeof(task->status), "stopped");
  } else if (goal_met || (workflow_is_account_task(task->workflow) &&
                          task->oauth_success == (int) task->account_id_count)) {
    mg_snprintf(task->status, sizeof(task->status), "success");
  } else if (task->success > 0) {
    mg_snprintf(task->status, sizeof(task->status), "partial");
  } else {
    mg_snprintf(task->status, sizeof(task->status), "failed");
  }
  if (strcmp(task->status, "failed") == 0 && task->error[0] == '\0') {
    mg_snprintf(task->error, sizeof(task->error), "任务未达到目标，请查看详细日志");
  }
  task->finished_ms = now_ms();
  task->updated_ms = task->finished_ms;
  append_logf_locked(task, "", strcmp(task->status, "success") == 0 ? "info" : "warn",
                     "任务结束: 注册成功 %d / %s成功 %d / 失败 %d",
                     task->register_success, credential_action_label(task),
                     task->oauth_success, task->failed);
  if (task->auto_upload_oauth_success) {
    append_logf_locked(task, "", "info",
                       "自动上传统计: 成功 %d / 失败 %d / 跳过 %d",
                       task->upload_success, task->upload_failed,
                       task->upload_skipped);
  }
  pthread_mutex_unlock(&s_tasks_mu);
}

static void fastlane_set_job_stage(struct registration_flow_job *job,
                                   enum registration_fastlane_stage next_stage,
                                   const char *flow_id,
                                   const char *reason) {
  struct registration_task *task = job ? job->task : NULL;
  enum registration_fastlane_stage old_stage;

  if (task == NULL || next_stage == REG_FLOW_STAGE_NONE) return;
  pthread_mutex_lock(&s_tasks_mu);
  if (!task_uses_fastlane_unlocked(task) ||
      job->scheduler_stage == REG_FLOW_STAGE_TERMINAL) {
    pthread_mutex_unlock(&s_tasks_mu);
    return;
  }
  old_stage = job->scheduler_stage;
  if (old_stage == next_stage) {
    pthread_mutex_unlock(&s_tasks_mu);
    return;
  }
  adjust_fastlane_stage_count_unlocked(task, old_stage, -1);
  adjust_fastlane_stage_count_unlocked(task, next_stage, 1);
  job->scheduler_stage = next_stage;
  task->updated_ms = now_ms();
  if (task->detailed_logs && reason != NULL && reason[0] != '\0') {
    append_logf_locked(task, flow_id ? flow_id : "", "info",
                       "高速模式阶段切换: %s -> %s，%s",
                       fastlane_stage_label(old_stage),
                       fastlane_stage_label(next_stage), reason);
  }
  pthread_mutex_unlock(&s_tasks_mu);
}

static enum registration_fastlane_stage mark_flow_launch(
    struct registration_task *task) {
  enum registration_fastlane_stage stage = REG_FLOW_STAGE_NONE;
  pthread_mutex_lock(&s_tasks_mu);
  task->started++;
  task->active++;
  if (task_uses_fastlane_unlocked(task)) {
    stage = REG_FLOW_STAGE_PRE_EMAIL_ACTIVE;
    adjust_fastlane_stage_count_unlocked(task, stage, 1);
  }
  task_refresh_success_unlocked(task);
  task->updated_ms = now_ms();
  pthread_mutex_unlock(&s_tasks_mu);
  return stage;
}

static void mark_job_done(struct registration_flow_job *job) {
  struct registration_task *task = job ? job->task : NULL;
  pthread_mutex_lock(&s_tasks_mu);
  if (task != NULL) {
    if (task_uses_fastlane_unlocked(task) &&
        job->scheduler_stage != REG_FLOW_STAGE_TERMINAL) {
      adjust_fastlane_stage_count_unlocked(task, job->scheduler_stage, -1);
      job->scheduler_stage = REG_FLOW_STAGE_TERMINAL;
    }
    if (task->active > 0) task->active--;
    task_refresh_success_unlocked(task);
    task->updated_ms = now_ms();
  }
  pthread_mutex_unlock(&s_tasks_mu);
}

static void mark_flow_launch_failed(struct registration_task *task,
                                    const char *message) {
  pthread_mutex_lock(&s_tasks_mu);
  if (task->active > 0) task->active--;
  if (task_uses_fastlane_unlocked(task)) {
    adjust_fastlane_stage_count_unlocked(task, REG_FLOW_STAGE_PRE_EMAIL_ACTIVE,
                                         -1);
  }
  task->failed++;
  if (workflow_is_account_task(task->workflow)) task->oauth_failed++;
  else task->register_failed++;
  task_refresh_success_unlocked(task);
  if (task->error[0] == '\0') {
    mg_snprintf(task->error, sizeof(task->error), "%s",
                message ? message : "流程启动失败");
  }
  append_log_locked(task, "", "error", message ? message : "流程启动失败");
  pthread_mutex_unlock(&s_tasks_mu);
}

static void mark_account_load_failed(struct registration_task *task, long id) {
  pthread_mutex_lock(&s_tasks_mu);
  task->started++;
  task->failed++;
  task->oauth_failed++;
  task_refresh_success_unlocked(task);
  task->updated_ms = now_ms();
  append_logf_locked(task, "", "error",
                     "账号 ID=%ld 不存在或无法读取，跳过账号任务", id);
  pthread_mutex_unlock(&s_tasks_mu);
}

static void record_register_success(struct registration_task *task,
                                    const struct flow_context *flow) {
  const char *status;
  const char *label;
  pthread_mutex_lock(&s_tasks_mu);
  task->register_success++;
  status = flow && flow->success_account_status[0]
               ? flow->success_account_status
               : "temp";
  if (strcmp(status, "expired") == 0) {
    task->expired_written++;
    label = "过期";
  } else if (strcmp(status, "active") == 0) {
    label = "活跃";
  } else {
    task->temp_written++;
    label = "临时";
  }
  task_refresh_success_unlocked(task);
  task->updated_ms = now_ms();
  if (task->detailed_logs) {
    append_logf_locked(task, flow ? flow->id : "", "info",
                       "注册成功，已写入%s账号 ID=%ld",
                       label, flow ? flow->persisted_account_id : 0);
  }
  pthread_mutex_unlock(&s_tasks_mu);
}

static void record_register_failure(struct registration_task *task,
                                    const struct flow_context *flow,
                                    const char *message) {
  pthread_mutex_lock(&s_tasks_mu);
  task->register_failed++;
  task->failed++;
  task_refresh_success_unlocked(task);
  if (task->error[0] == '\0') {
    mg_snprintf(task->error, sizeof(task->error), "%s",
                message ? message : "注册失败");
  }
  task->updated_ms = now_ms();
  append_logf_locked(task, flow ? flow->id : "", "error", "注册失败: %s",
                     message ? message : "-");
  pthread_mutex_unlock(&s_tasks_mu);
}

static void record_oauth_success(struct registration_task *task,
                                 const struct flow_context *flow,
                                 long account_id) {
  pthread_mutex_lock(&s_tasks_mu);
  task->oauth_success++;
  task_refresh_success_unlocked(task);
  task->updated_ms = now_ms();
  if (task->detailed_logs) {
    append_logf_locked(task, flow ? flow->id : "", "info",
                       "%s成功，账号 ID=%ld 已更新为活跃账号",
                       credential_action_label(task), account_id);
  }
  pthread_mutex_unlock(&s_tasks_mu);
}

static void record_oauth_failure_with_account_note(
    struct registration_task *task, const struct flow_context *flow,
    long account_id, const char *message, const char *account_note) {
  if (task == NULL) return;
  pthread_mutex_lock(&s_tasks_mu);
  task->oauth_failed++;
  task->failed++;
  task_refresh_success_unlocked(task);
  if (task->error[0] == '\0') {
    mg_snprintf(task->error, sizeof(task->error), "%s",
                message ? message : "账号任务失败");
  }
  task->updated_ms = now_ms();
  append_logf_locked(task, flow ? flow->id : "", "error",
                     "%s失败，账号 ID=%ld %s: %s",
                     credential_action_label(task), account_id,
                     account_note && account_note[0] ? account_note
                                                      : "状态保持不变",
                     message ? message : "-");
  pthread_mutex_unlock(&s_tasks_mu);
}

static bool discard_job_oauth_failed_account(
    sqlite3 *db, struct registration_flow_job *job,
    const struct flow_context *flow, long account_id, const char *message) {
  long id = account_id;
  int changed;

  if (db == NULL || job == NULL || account_id <= 0 ||
      !job->discard_oauth_failed_accounts ||
      workflow_is_account_task(job->workflow)) {
    return false;
  }
  changed = account_delete_ids(db, &id, 1);
  if (changed >= 0) {
    job->account_id = 0;
    return true;
  }
  task_log(job->task, flow ? flow->id : "", "warn",
           "不保存 OA 失败账号已开启，但删除账号 ID=%ld 失败: %s",
           account_id, message ? message : "-");
  return false;
}

static void record_job_oauth_failure(sqlite3 *db,
                                     struct registration_flow_job *job,
                                     const struct flow_context *flow,
                                     const char *message) {
  long account_id = job ? job->account_id : 0;
  bool discarded = discard_job_oauth_failed_account(db, job, flow, account_id,
                                                    message);
  record_oauth_failure_with_account_note(
      job ? job->task : NULL, flow, account_id, message,
      discarded ? "已按配置不保存" : "状态保持不变");
}

static const char *auto_upload_pool_label(const char *pool_type) {
  if (pool_type != NULL && strcmp(pool_type, "chatgpt_web") == 0) {
    return "ChatGPT Web";
  }
  return "Codex";
}

static const char *auto_upload_service_mode_name(
    enum registration_auto_upload_service_mode mode) {
  if (mode == REG_AUTO_UPLOAD_SERVICE_RANDOM) return "random";
  if (mode == REG_AUTO_UPLOAD_SERVICE_FIXED) return "fixed";
  return "all";
}

static const char *auto_upload_service_mode_label(
    enum registration_auto_upload_service_mode mode) {
  if (mode == REG_AUTO_UPLOAD_SERVICE_RANDOM) return "随机服务";
  if (mode == REG_AUTO_UPLOAD_SERVICE_FIXED) return "指定服务";
  return "全部启用服务";
}

static const char *auto_upload_service_name(
    const struct registration_flow_job *job) {
  if (job == NULL) return "";
  if (job->auto_upload_service_id <= 0) return "全部启用服务";
  if (job->auto_upload_service_name[0] != '\0') {
    return job->auto_upload_service_name;
  }
  return "指定服务";
}

static void record_auto_upload_result(struct registration_task *task,
                                      const char *flow_id, long account_id,
                                      const char *pool_type, bool ok,
                                      long success_count,
                                      long failed_count, long skipped_count,
                                      const char *error) {
  const char *pool_label = auto_upload_pool_label(pool_type);
  pthread_mutex_lock(&s_tasks_mu);
  if (success_count > 0) task->upload_success += (int) success_count;
  if (failed_count > 0) task->upload_failed += (int) failed_count;
  if (skipped_count > 0) task->upload_skipped += (int) skipped_count;
  if (!ok && success_count == 0 && failed_count == 0 && skipped_count == 0) {
    task->upload_failed++;
  }
  task->updated_ms = now_ms();
  if (ok && success_count > 0) {
    if (!task->detailed_logs) {
      pthread_mutex_unlock(&s_tasks_mu);
      return;
    }
    append_logf_locked(task, flow_id ? flow_id : "", "info",
                       "账号 ID=%ld %s 自动上传完成: 成功 %ld / 失败 %ld / 跳过 %ld",
                       account_id, pool_label, success_count, failed_count,
                       skipped_count);
  } else {
    append_logf_locked(task, flow_id ? flow_id : "", "warn",
                       "账号 ID=%ld %s 自动上传未成功: 成功 %ld / 失败 %ld / 跳过 %ld%s%s",
                       account_id, pool_label, success_count, failed_count,
                       skipped_count,
                       error != NULL && error[0] != '\0' ? "，原因: " : "",
                       error != NULL && error[0] != '\0' ? error : "");
  }
  pthread_mutex_unlock(&s_tasks_mu);
}

static long take_next_account_id(struct registration_task *task) {
  long id = 0;
  pthread_mutex_lock(&s_tasks_mu);
  if (task->next_account_index < task->account_id_count) {
    id = task->account_ids[task->next_account_index++];
  }
  pthread_mutex_unlock(&s_tasks_mu);
  return id;
}

static void detach_flow_snapshot(struct flow_context *flow) {
  if (flow == NULL) return;
  flow->provider_data = NULL;
  flow->log_fn = NULL;
  flow->finish_fn = NULL;
  flow->cancel_fn = NULL;
  flow->event_fn = NULL;
  flow->callback_data = NULL;
}

static int flow_libcurl_run(const struct flow_provider *provider,
                            const struct flow_start_options *options,
                            struct flow_context *snapshot) {
  struct flow_engine_options engine_options;
  struct flow_engine *engine = NULL;
  struct flow_context *live = NULL;
  int rc = -1;

  if (snapshot != NULL) memset(snapshot, 0, sizeof(*snapshot));
  if (provider == NULL || provider->next_request == NULL || options == NULL) {
    return -1;
  }

  memset(&engine_options, 0, sizeof(engine_options));
  engine_options.db = options->db;
  engine_options.max_concurrency = 1;
  if (flow_engine_create(&engine_options, &engine) != 0) {
    if (snapshot != NULL) flow_context_fail(snapshot, "创建 libcurl flow engine 失败");
    return -1;
  }
  if (flow_engine_add(engine, provider, options, &live) != 0) {
    if (live != NULL && snapshot != NULL) {
      *snapshot = *live;
      detach_flow_snapshot(snapshot);
    } else if (snapshot != NULL) {
      flow_context_fail(snapshot, "启动 libcurl 请求流程失败");
    }
    flow_engine_destroy(engine);
    return -1;
  }

  flow_context_log(live, "info", "请求驱动: libcurl");
  rc = flow_engine_run_until_idle(engine, 50);
  if (live != NULL && snapshot != NULL) {
    *snapshot = *live;
    detach_flow_snapshot(snapshot);
  } else if (snapshot != NULL) {
    flow_context_fail(snapshot, "libcurl 请求流程未返回上下文");
  }
  if (rc == 0 && live != NULL && live->status == FLOW_STATUS_SUCCESS) {
    rc = 0;
  } else {
    rc = -1;
  }
  flow_engine_destroy(engine);
  return rc;
}

static int run_flow_with_request_core(enum registration_request_core core,
                                      const struct flow_provider *provider,
                                      const struct flow_start_options *options,
                                      struct flow_context *snapshot) {
  if (core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE) {
    return flow_libcurl_impersonate_run(provider, options, snapshot);
  }
  if (core == REG_REQUEST_CORE_LIBCURL) {
    return flow_libcurl_run(provider, options, snapshot);
  }
  return flow_impersonate_run(provider, options, snapshot);
}

static int run_oauth_flow_impl(
    sqlite3 *db, struct registration_flow_job *job,
    struct flow_context *oauth_flow,
    void (*log_fn)(struct flow_context *flow, const char *level,
                   const char *message, void *userdata),
    bool (*cancel_fn)(struct flow_context *flow, void *userdata),
    void (*event_fn)(struct flow_context *flow, const char *event,
                     void *userdata),
    void *userdata, long oauth_otp_timeout_ms) {
  struct flow_start_options options;
  memset(&options, 0, sizeof(options));
  memset(oauth_flow, 0, sizeof(*oauth_flow));
  options.mode = FLOW_MODE_REGISTER_THEN_OAUTH;
  options.proxy_url = job->proxy_url;
  options.profile = &job->profile;
  options.identity = &job->identity;
  options.workspace_id = job->workspace_id;
  options.impersonate_target = job->libcurl_impersonate_target;
  options.db = db;
  options.persist_on_success = false;
  options.account_id = job->account_id;
  options.deadline_ms = (long) mg_millis() + 180000;
  options.oauth_otp_timeout_ms = oauth_otp_timeout_ms;
  options.fast_email_otp_resend = job->fast_email_otp_resend;
  options.log_fn = log_fn ? log_fn : flow_log_callback;
  options.cancel_fn = cancel_fn;
  options.event_fn = event_fn;
  options.callback_data = userdata ? userdata : job->task;
  return run_flow_with_request_core(job->request_core, oauth_code_provider(),
                                    &options, oauth_flow);
}

static void oauth_race_log_callback(struct flow_context *flow, const char *level,
                                    const char *message, void *userdata) {
  struct oauth_race_runner *runner = (struct oauth_race_runner *) userdata;
  struct registration_task *task = runner ? runner->job.task : NULL;
  if (task == NULL || flow == NULL || message == NULL) return;
  if (!flow_log_visible(task, level)) return;
  task_log_account_message(task, flow->id, level, flow->account_id, message);
}

static bool oauth_race_cancel_callback(struct flow_context *flow,
                                      void *userdata) {
  struct oauth_race_runner *runner = (struct oauth_race_runner *) userdata;
  bool cancel = false;
  if (runner == NULL || runner->race == NULL) return false;
  pthread_mutex_lock(&runner->race->mu);
  cancel = runner->race->cancel[runner->index] ||
           (runner->race->winner_index >= 0 &&
            runner->race->winner_index != runner->index);
  pthread_mutex_unlock(&runner->race->mu);
  if (!cancel && runner->job.task != NULL) {
    cancel = task_stop_requested(runner->job.task);
  }
  (void) flow;
  return cancel;
}

static void oauth_race_event_callback(struct flow_context *flow,
                                      const char *event, void *userdata) {
  struct oauth_race_runner *runner = (struct oauth_race_runner *) userdata;
  bool became_winner = false;
  bool became_loser = false;

  if (runner == NULL || runner->race == NULL || event == NULL || flow == NULL) {
    return;
  }
  if (strcmp(event, FLOW_EVENT_OAUTH_OTP_VALIDATED) != 0) return;
  pthread_mutex_lock(&runner->race->mu);
  if (runner->race->winner_index < 0) {
    runner->race->winner_index = runner->index;
    for (int i = 0; i < OAUTH_RACE_BRANCHES; i++) {
      if (i != runner->index) runner->race->cancel[i] = true;
    }
    became_winner = true;
  } else if (runner->race->winner_index != runner->index) {
    runner->race->cancel[runner->index] = true;
    became_loser = true;
  }
  pthread_mutex_unlock(&runner->race->mu);

  if (became_winner && runner->job.task != NULL &&
      runner->job.task->detailed_logs) {
    task_log(runner->job.task, flow->id, "info",
             "账号 ID=%ld OAuth 抢码分支 %d 已通过验证码校验，取消另一路 OAuth",
             runner->job.account_id, runner->index + 1);
  } else if (became_loser && runner->job.task != NULL) {
    task_log(runner->job.task, flow->id, "warn",
             "账号 ID=%ld OAuth 抢码分支 %d 已取消，验证码校验已由另一路通过",
             runner->job.account_id, runner->index + 1);
  }
}

static void oauth_race_prepare_branch(sqlite3 *db,
                                      struct registration_flow_job *job,
                                      int branch_index) {
  char proxy_url[FLOW_PROXY_LEN] = "";
  char old_proxy[FLOW_PROXY_LEN];
  int proxy_rc = 0;

  if (job == NULL) return;
  if (branch_index <= 0) return;
  mg_snprintf(old_proxy, sizeof(old_proxy), "%s", job->proxy_url);
  browser_profile_generate(&job->profile, NULL, NULL);
  if (job->task != NULL && job->task->mihomo_task_proxy) {
    mg_snprintf(job->proxy_url, sizeof(job->proxy_url), "%s",
                job->task->mihomo_proxy_url);
  } else if (db != NULL) {
    for (int i = 0; i < 5; i++) {
      proxy_rc = proxy_pool_pick_active_url(db, proxy_url, sizeof(proxy_url));
      if (proxy_rc <= 0 || old_proxy[0] == '\0' ||
          strcmp(old_proxy, proxy_url) != 0) {
        break;
      }
    }
    if (proxy_rc > 0) {
      mg_snprintf(job->proxy_url, sizeof(job->proxy_url), "%s", proxy_url);
    }
  }
  if (job->task != NULL && job->task->detailed_logs) {
    task_log(job->task, "", "info",
             "账号 ID=%ld OAuth 备用分支已准备独立环境: proxy=%s profile=%s %s core=%s%s%s",
             job->account_id, job->proxy_url[0] ? job->proxy_url : "direct",
             job->profile.browser[0] ? job->profile.browser : "browser",
             job->profile.browser_version[0] ? job->profile.browser_version : "-",
             request_core_label(job->request_core),
             job->request_core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE
                 ? " impersonate="
                 : "",
             job->request_core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE
                 ? job->libcurl_impersonate_target
                 : "");
  }
}

static void *oauth_race_runner_thread(void *arg) {
  struct oauth_race_runner *runner = (struct oauth_race_runner *) arg;
  sqlite3 *db = NULL;

  if (runner == NULL) return NULL;
  memset(&runner->flow, 0, sizeof(runner->flow));
  runner->rc = -1;
  if (app_db_open("data/app.db", &db) != 0) {
    flow_context_fail(&runner->flow, "流程无法打开 SQLite 数据库");
    goto finish;
  }

  runner->rc = run_oauth_flow_impl(db, &runner->job, &runner->flow,
                                   oauth_race_log_callback,
                                   oauth_race_cancel_callback,
                                   oauth_race_event_callback, runner, 0);

finish:
  if (db != NULL) app_db_close(db);
  runner->flow.log_fn = NULL;
  runner->flow.finish_fn = NULL;
  runner->flow.cancel_fn = NULL;
  runner->flow.event_fn = NULL;
  return NULL;
}

static int run_oauth_flow_race_with_environment_retry(
    sqlite3 *db, struct registration_flow_job *job,
    struct flow_context *oauth_flow) {
  int environment_retry_count = 0;

  for (;;) {
    struct oauth_race_state race;
    struct oauth_race_runner runners[OAUTH_RACE_BRANCHES];
    int winner_index = -1;
    int rc = -1;

    memset(&race, 0, sizeof(race));
    pthread_mutex_init(&race.mu, NULL);
    race.winner_index = -1;
    for (int i = 0; i < OAUTH_RACE_BRANCHES; i++) {
      memset(&runners[i], 0, sizeof(runners[i]));
      runners[i].race = &race;
      runners[i].index = i;
      runners[i].job = *job;
      oauth_race_prepare_branch(db, &runners[i].job, i);
    }

    {
      pthread_attr_t attr;
      pthread_attr_t *attrp =
          init_flow_thread_attr(&attr) == 0 ? &attr : NULL;
      for (int i = 0; i < OAUTH_RACE_BRANCHES; i++) {
        if (pthread_create(&runners[i].thread, attrp,
                           oauth_race_runner_thread, &runners[i]) != 0) {
          runners[i].launched = false;
          runners[i].rc = -1;
          flow_context_fail(&runners[i].flow, "OAuth 线程创建失败");
        } else {
          runners[i].launched = true;
        }
      }
      if (attrp != NULL) pthread_attr_destroy(&attr);
    }

    for (int i = 0; i < OAUTH_RACE_BRANCHES; i++) {
      if (runners[i].launched) pthread_join(runners[i].thread, NULL);
    }

    winner_index = race.winner_index;
    if (winner_index < 0) {
      for (int i = 0; i < OAUTH_RACE_BRANCHES; i++) {
        if (!runners[i].launched) continue;
        if (runners[i].flow.status == FLOW_STATUS_SUCCESS) {
          winner_index = i;
          break;
        }
      }
    }
    if (winner_index < 0) {
      for (int i = 0; i < OAUTH_RACE_BRANCHES; i++) {
        if (!runners[i].launched) continue;
        if (runners[i].flow.status != FLOW_STATUS_CANCELLED) {
          winner_index = i;
          break;
        }
      }
    }
    if (winner_index >= 0) {
      *oauth_flow = runners[winner_index].flow;
      rc = runners[winner_index].rc;
      if (oauth_flow->status == FLOW_STATUS_SUCCESS && rc == 0) {
        oauth_flow->log_fn = NULL;
        oauth_flow->finish_fn = NULL;
        oauth_flow->cancel_fn = NULL;
        oauth_flow->event_fn = NULL;
        oauth_flow->callback_data = NULL;
        pthread_mutex_destroy(&race.mu);
        return 0;
      }
    }
    if (winner_index < 0) {
      *oauth_flow = runners[0].flow;
      rc = runners[0].rc;
    }
    oauth_flow->log_fn = NULL;
    oauth_flow->finish_fn = NULL;
    oauth_flow->cancel_fn = NULL;
    oauth_flow->event_fn = NULL;
    oauth_flow->callback_data = NULL;

    if (oauth_flow->environment_retryable &&
        environment_retry_count < ENVIRONMENT_RETRY_LIMIT &&
        !task_stop_requested(job->task)) {
      environment_retry_count++;
      if (reassign_job_environment(db, job, "OAuth 流程", environment_retry_count,
                                   ENVIRONMENT_RETRY_LIMIT) != 0) {
        flow_context_fail(oauth_flow, "重新分配 OAuth 环境失败");
        pthread_mutex_destroy(&race.mu);
        return -1;
      }
      memset(oauth_flow, 0, sizeof(*oauth_flow));
      pthread_mutex_destroy(&race.mu);
      usleep(250000);
      continue;
    }
    pthread_mutex_destroy(&race.mu);
    return rc;
  }
  return -1;
}

static bool oauth_flow_waiting_code_timeout(const struct flow_context *flow) {
  return flow != NULL && strstr(flow->error, "等待 OAuth 邮箱验证码超时") != NULL;
}

static int run_oauth_flow_single_with_environment_retry(
    sqlite3 *db, struct registration_flow_job *job,
    struct flow_context *oauth_flow, long oauth_otp_timeout_ms) {
  int environment_retry_count = 0;

  for (;;) {
    int rc = run_oauth_flow_impl(db, job, oauth_flow, flow_job_log_callback,
                                 flow_job_cancel_callback, NULL, job,
                                 oauth_otp_timeout_ms);
    if (rc == 0 && oauth_flow->status == FLOW_STATUS_SUCCESS) return 0;
    oauth_flow->log_fn = NULL;
    oauth_flow->finish_fn = NULL;
    oauth_flow->cancel_fn = NULL;
    oauth_flow->event_fn = NULL;
    oauth_flow->callback_data = NULL;

    if (oauth_flow->environment_retryable &&
        environment_retry_count < ENVIRONMENT_RETRY_LIMIT &&
        job != NULL && !task_stop_requested(job->task)) {
      environment_retry_count++;
      if (reassign_job_environment(db, job, "OAuth 流程",
                                   environment_retry_count,
                                   ENVIRONMENT_RETRY_LIMIT) != 0) {
        flow_context_fail(oauth_flow, "重新分配 OAuth 环境失败");
        return -1;
      }
      memset(oauth_flow, 0, sizeof(*oauth_flow));
      usleep(250000);
      continue;
    }
    return rc;
  }
}

static int apply_oauth_success(sqlite3 *db, struct registration_flow_job *job,
                               const struct flow_context *oauth_flow) {
  struct account_success_record record;
  memset(&record, 0, sizeof(record));
  record.email = job->identity.email;
  record.password = job->identity.password;
  record.status = "active";
  record.upload_state = "not_uploaded";
  record.access_token = oauth_flow->access_token;
  record.refresh_token = oauth_flow->refresh_token;
  record.id_token = oauth_flow->id_token;
  record.external_account_id = oauth_flow->external_account_id;
  record.workspace_id = oauth_flow->workspace_id[0] ? oauth_flow->workspace_id
                                                    : job->workspace_id;
  return account_apply_oauth_success(db, job->account_id, &record);
}

static int run_chatgpt_login_flow_impl(
    sqlite3 *db, struct registration_flow_job *job,
    struct flow_context *login_flow,
    void (*log_fn)(struct flow_context *flow, const char *level,
                   const char *message, void *userdata),
    bool (*cancel_fn)(struct flow_context *flow, void *userdata),
    void *userdata) {
  struct flow_start_options options;
  memset(&options, 0, sizeof(options));
  memset(login_flow, 0, sizeof(*login_flow));
  options.mode = FLOW_MODE_REGISTER_ONLY;
  options.proxy_url = job->proxy_url;
  options.profile = &job->profile;
  options.identity = &job->identity;
  options.workspace_id = job->workspace_id;
  options.impersonate_target = job->libcurl_impersonate_target;
  options.db = db;
  options.persist_on_success = false;
  options.account_id = job->account_id;
  options.deadline_ms = (long) mg_millis() + 180000;
  options.fast_email_otp_resend = job->fast_email_otp_resend;
  options.log_fn = log_fn ? log_fn : flow_job_log_callback;
  options.cancel_fn = cancel_fn;
  options.event_fn = flow_job_event_callback;
  options.callback_data = userdata ? userdata : job;
  return run_flow_with_request_core(job->request_core, web_login_provider(),
                                    &options, login_flow);
}

static int run_chatgpt_login_flow_with_environment_retry(
    sqlite3 *db, struct registration_flow_job *job,
    struct flow_context *login_flow) {
  int environment_retry_count = 0;

  for (;;) {
    int rc = run_chatgpt_login_flow_impl(
        db, job, login_flow, flow_job_log_callback,
        flow_job_cancel_callback, job);
    if (rc == 0 && login_flow->status == FLOW_STATUS_SUCCESS) return 0;
    login_flow->log_fn = NULL;
    login_flow->finish_fn = NULL;
    login_flow->cancel_fn = NULL;
    login_flow->event_fn = NULL;
    login_flow->callback_data = NULL;

    if (login_flow->environment_retryable &&
        environment_retry_count < ENVIRONMENT_RETRY_LIMIT &&
        job != NULL && !task_stop_requested(job->task)) {
      environment_retry_count++;
      if (reassign_job_environment(db, job, "ChatGPT 登录流程",
                                   environment_retry_count,
                                   ENVIRONMENT_RETRY_LIMIT) != 0) {
        flow_context_fail(login_flow, "重新分配 ChatGPT 登录环境失败");
        return -1;
      }
      memset(login_flow, 0, sizeof(*login_flow));
      usleep(250000);
      continue;
    }
    return rc;
  }
}

static int apply_chatgpt_login_success(
    sqlite3 *db, struct registration_flow_job *job,
    const struct flow_context *login_flow) {
  struct account_success_record record;
  memset(&record, 0, sizeof(record));
  record.email = job->identity.email;
  record.password = job->identity.password;
  record.status = "active";
  record.upload_state = "not_uploaded";
  record.access_token = login_flow->access_token;
  record.refresh_token = login_flow->refresh_token;
  record.id_token = login_flow->id_token;
  record.session_token = login_flow->session_token;
  record.cookies = login_flow->cookies;
  record.external_account_id = login_flow->external_account_id;
  record.workspace_id = login_flow->workspace_id[0] ? login_flow->workspace_id
                                                    : job->workspace_id;
  return account_apply_chatgpt_login_success(db, job->account_id, &record);
}

static void auto_upload_account_to_pool(sqlite3 *db,
                                        struct registration_flow_job *job,
                                        const struct flow_context *flow,
                                        const char *pool_type) {
  char *json;
  struct mg_str body;
  bool ok = false;
  long success_count = 0;
  long failed_count = 0;
  long skipped_count = 0;
  char *error = NULL;

  if (db == NULL || job == NULL || job->account_id <= 0) {
    return;
  }
  if (task_stop_requested(job->task)) {
    record_auto_upload_result(job->task, flow ? flow->id : "", job->account_id,
                              pool_type, false, 0, 0, 1,
                              "任务已请求停止，跳过自动上传");
    return;
  }

  if (job->task != NULL && job->task->detailed_logs) {
    task_log(job->task, flow ? flow->id : "", "info",
             "账号 ID=%ld 开始自动上传到 %s 号池，服务: %s",
             job->account_id, auto_upload_pool_label(pool_type),
             auto_upload_service_name(job));
  }
  json = aether_upload_accounts_to_service_json(
      db, &job->account_id, 1, pool_type, job->auto_upload_service_id);
  if (json == NULL) {
    record_auto_upload_result(job->task, flow ? flow->id : "", job->account_id,
                              pool_type, false, 0, 1, 0, "Aether 上传失败");
    return;
  }

  body = mg_str(json);
  ok = mg_json_get_long(body, "$.ok", 0) == 1;
  success_count = mg_json_get_long(body, "$.success_count", 0);
  failed_count = mg_json_get_long(body, "$.failed_count", 0);
  skipped_count = mg_json_get_long(body, "$.skipped_count", 0);
  error = mg_json_get_str(body, "$.error");
  record_auto_upload_result(job->task, flow ? flow->id : "", job->account_id,
                            pool_type, ok, success_count, failed_count,
                            skipped_count, error);
  mg_free(error);
  free(json);
}

static void maybe_auto_upload_oauth_success(sqlite3 *db,
                                            struct registration_flow_job *job,
                                            const struct flow_context *flow) {
  if (db == NULL || job == NULL || !job->auto_upload_oauth_success ||
      job->account_id <= 0) {
    return;
  }

  auto_upload_account_to_pool(db, job, flow, "oauth");
  if (aether_has_chatgpt_web_upload_service_id(db, job->auto_upload_service_id)) {
    auto_upload_account_to_pool(db, job, flow, "chatgpt_web");
  } else if (job->task != NULL && job->task->detailed_logs) {
    task_log(job->task, flow ? flow->id : "", "info",
             "未配置 ChatGPT Web 号池，跳过 Access Token 自动上传");
  }
}

static int reassign_job_environment(sqlite3 *db, struct registration_flow_job *job,
                                    const char *phase, int attempt,
                                    int limit) {
  char old_proxy[FLOW_PROXY_LEN];
  char proxy_url[FLOW_PROXY_LEN] = "";
  char scheme[32];
  int proxy_rc = 0;

  if (job == NULL) return -1;
  mg_snprintf(old_proxy, sizeof(old_proxy), "%s", job->proxy_url);
  browser_profile_generate(&job->profile, NULL, NULL);
  if (job->task != NULL && job->task->mihomo_task_proxy) {
    mg_snprintf(proxy_url, sizeof(proxy_url), "%s",
                job->task->mihomo_proxy_url);
    proxy_rc = proxy_url[0] != '\0' ? 1 : 0;
  } else if (db != NULL) {
    for (int i = 0; i < 5; i++) {
      proxy_rc = proxy_pool_pick_active_url(db, proxy_url, sizeof(proxy_url));
      if (proxy_rc <= 0 || old_proxy[0] == '\0' ||
          strcmp(old_proxy, proxy_url) != 0) {
        break;
      }
    }
    if (proxy_rc < 0) return -1;
  }
  if (ensure_non_direct_proxy_available(db, proxy_rc, NULL, 0) == 0) {
    job->proxy_url[0] = '\0';
    if (proxy_rc > 0) {
      mg_snprintf(job->proxy_url, sizeof(job->proxy_url), "%s", proxy_url);
    }
  }
  proxy_scheme_label(job->proxy_url, scheme, sizeof(scheme));
  if (job->account_id > 0) {
    task_log(job->task, "", "warn",
             "账号 ID=%ld %s 触发边缘风控，重新分配环境后重试 %d/%d: proxy=%s profile=%s %s",
             job->account_id, phase ? phase : "流程", attempt, limit,
             scheme[0] ? scheme : "direct",
             job->profile.browser[0] ? job->profile.browser : "browser",
             job->profile.browser_version[0] ? job->profile.browser_version : "-");
  } else {
    task_log(job->task, "", "warn",
             "%s 触发边缘风控，重新分配环境后重试 %d/%d: proxy=%s profile=%s %s",
             phase ? phase : "流程", attempt, limit,
             scheme[0] ? scheme : "direct",
             job->profile.browser[0] ? job->profile.browser : "browser",
             job->profile.browser_version[0] ? job->profile.browser_version : "-");
  }
  return 0;
}

static int reassign_job_identity(sqlite3 *db, struct registration_flow_job *job,
                                 const char *flow_id, int attempt, int limit) {
  char old_email[IDENTITY_EMAIL_LEN];
  char error[REG_TASK_ERROR_LEN] = "";

  if (job == NULL) return -1;
  mg_snprintf(old_email, sizeof(old_email), "%s", job->identity.email);
  if (job->workflow == REG_WORKFLOW_OUTLOOK_DIRECT) {
    // outlook 直注: 同母邮箱换一个新别名(母邮箱单线程锁仍占用中)
    char mother[IDENTITY_EMAIL_LEN];
    outlook_pool_alias_to_mother(old_email, mother, sizeof(mother));
    if (identity_generate_outlook_alias(db, mother, &job->identity, error,
                                        sizeof(error)) != 0) {
      task_log(job->task, flow_id ? flow_id : "", "error",
               "远端提示邮箱已存在，但重新生成 outlook 别名失败: %s",
               error[0] ? error : "身份信息生成失败");
      return -1;
    }
  } else if (identity_generate(db, &job->identity, error, sizeof(error)) != 0) {
    task_log(job->task, flow_id ? flow_id : "", "error",
             "远端提示邮箱已存在，但重新生成邮箱失败: %s",
             error[0] ? error : "身份信息生成失败");
    return -1;
  }
  browser_profile_generate(&job->profile, NULL, NULL);
  task_log(job->task, flow_id ? flow_id : "", "warn",
           "远端提示邮箱已存在，重新生成邮箱后重试 %d/%d: %s -> %s",
           attempt, limit, old_email[0] ? old_email : "-", job->identity.email);
  return 0;
}

static int run_registration_flow_with_environment_retry(
    sqlite3 *db, struct registration_flow_job *job, struct flow_context *reg_flow) {
  const struct flow_provider *provider;
  int environment_retry_count = 0;
  int identity_retry_count = 0;

  if (job == NULL || reg_flow == NULL) return -1;
  if (job->workflow == REG_WORKFLOW_CODEX_CLI_SIMPLIFIED) {
    provider = codex_direct_provider();
  } else if (job->workflow == REG_WORKFLOW_OUTLOOK_DIRECT) {
    // Outlook 直注: 复用 ChatGPT 网页注册主体, 注册后走当前会话 Codex OAuth(独立工作空间)
    provider = web_register_provider();
  } else {
    provider = job->register_provider == REG_REGISTER_PROVIDER_TEMPORARY
                   ? web_register_provider()
                   : platform_register_provider();
  }

  for (;;) {
    struct flow_start_options options;
    int rc;

    memset(reg_flow, 0, sizeof(*reg_flow));
    memset(&options, 0, sizeof(options));
    options.mode =
        job->workflow == REG_WORKFLOW_REGISTER_THEN_OAUTH
            ? FLOW_MODE_REGISTER_THEN_OAUTH
            : (workflow_uses_current_session_codex(job->workflow)
                   ? FLOW_MODE_REGISTER_THEN_CURRENT_CODEX
                   : FLOW_MODE_REGISTER_ONLY);
    options.proxy_url = job->proxy_url;
    options.profile = &job->profile;
    options.identity = &job->identity;
    options.impersonate_target = job->libcurl_impersonate_target;
    options.db = db;
    options.persist_on_success = true;
    options.deadline_ms = job->deadline_ms;
    options.fast_email_otp_resend = job->fast_email_otp_resend;
    options.log_fn = flow_job_log_callback;
    options.cancel_fn = flow_job_cancel_callback;
    options.event_fn = flow_job_event_callback;
    options.callback_data = job;

    rc = run_flow_with_request_core(job->request_core, provider, &options,
                                    reg_flow);
    if (rc == 0 && reg_flow->status == FLOW_STATUS_SUCCESS) return 0;

    if (reg_flow->identity_retryable && !task_stop_requested(job->task)) {
      if (identity_retry_count >= IDENTITY_RETRY_LIMIT) {
        flow_context_fail(reg_flow, "远端邮箱已存在，换邮箱重试次数已用尽");
        return -1;
      }
      identity_retry_count++;
      if (reassign_job_identity(db, job, reg_flow->id, identity_retry_count,
                                IDENTITY_RETRY_LIMIT) != 0) {
        flow_context_fail(reg_flow, "重新生成注册邮箱失败");
        return -1;
      }
      fastlane_set_job_stage(job, REG_FLOW_STAGE_PRE_EMAIL_ACTIVE,
                             reg_flow->id,
                             "远端邮箱已存在，换新邮箱后回到前置阶段");
      usleep(250000);
      continue;
    }

    if (reg_flow->environment_retryable &&
        environment_retry_count < ENVIRONMENT_RETRY_LIMIT &&
        !task_stop_requested(job->task)) {
      environment_retry_count++;
      if (reassign_job_environment(db, job, "注册流程", environment_retry_count,
                                   ENVIRONMENT_RETRY_LIMIT) != 0) {
        flow_context_fail(reg_flow, "重新分配注册环境失败");
        return -1;
      }
      fastlane_set_job_stage(job, REG_FLOW_STAGE_PRE_EMAIL_ACTIVE,
                             reg_flow->id,
                             "注册流程重新分配环境，回到前置阶段");
      usleep(250000);
      continue;
    }
    return rc;
  }
  return -1;
}

static bool wait_before_oauth(struct registration_flow_job *job) {
  int remaining_ms;
  if (job == NULL || job->workflow != REG_WORKFLOW_REGISTER_THEN_OAUTH ||
      job->oauth_delay_seconds <= 0) {
    return true;
  }
  if (job->task != NULL && job->task->detailed_logs) {
    task_log(job->task, "", "info",
             "账号 ID=%ld 注册完成，等待 %d 秒后执行 OAuth",
             job->account_id, job->oauth_delay_seconds);
  }
  remaining_ms = job->oauth_delay_seconds * 1000;
  while (remaining_ms > 0) {
    int chunk_ms = remaining_ms > 250 ? 250 : remaining_ms;
    if (task_stop_requested(job->task)) {
      task_log(job->task, "", "warn",
               "账号 ID=%ld 任务已请求停止，跳过等待中的 OAuth",
               job->account_id);
      return false;
    }
    usleep((useconds_t) chunk_ms * 1000);
    remaining_ms -= chunk_ms;
  }
  if (task_stop_requested(job->task)) {
    task_log(job->task, "", "warn",
             "账号 ID=%ld 任务已请求停止，跳过等待中的 OAuth",
             job->account_id);
    return false;
  }
  if (job->task != NULL && job->task->detailed_logs) {
    task_log(job->task, "", "info",
             "账号 ID=%ld OAuth 延迟等待结束，继续执行",
             job->account_id);
  }
  return true;
}

static bool run_current_session_oauth_fallback(
    sqlite3 *db, struct registration_flow_job *job,
    const struct flow_context *current_flow, const char *message,
    struct flow_context *oauth_flow) {
  const char *reason = message != NULL && message[0] != '\0'
                           ? message
                           : "当前会话 Codex OAuth 失败";
  enum registration_current_session_oauth_fallback_mode mode;
  const char *mode_label;
  const char *fallback_error = "当前会话 Codex OAuth 兜底失败";
  char write_error[128];
  int rc = -1;

  if (db == NULL || job == NULL || oauth_flow == NULL ||
      !workflow_uses_current_session_codex(job->workflow) ||
      job->account_id <= 0 || task_stop_requested(job->task)) {
    return false;
  }
  mode = job->current_session_oauth_fallback_mode;
  if (mode == REG_CURRENT_SESSION_OAUTH_FALLBACK_NONE) return false;
  if (flow_has_phone_binding_required(current_flow, reason)) {
    return false;
  }
  if (current_flow != NULL && current_flow->workspace_id[0] != '\0') {
    mg_snprintf(job->workspace_id, sizeof(job->workspace_id), "%s",
                current_flow->workspace_id);
  }

  mode_label = current_session_fallback_mode_label(mode);
  task_log(job->task, current_flow ? current_flow->id : "", "warn",
           "账号 ID=%ld 当前会话 Codex OAuth 未成功，且不是 phone_binding_required，进入%s: %s",
           job->account_id, mode_label, reason);

  if (mode == REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE) {
    fallback_error = "单 OAuth 兜底失败";
    rc = run_oauth_flow_single_with_environment_retry(db, job, oauth_flow, 0);
  } else if (mode == REG_CURRENT_SESSION_OAUTH_FALLBACK_DOUBLE) {
    fallback_error = "双 OAuth 兜底失败";
    rc = run_oauth_flow_race_with_environment_retry(db, job, oauth_flow);
  } else if (mode == REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE_TIMEOUT_RETRY) {
    int retry_after = job->current_session_oauth_retry_after_seconds;
    long first_timeout_ms = (long) retry_after * 1000L;
    fallback_error = "超时二次 OAuth 兜底失败";
    rc = run_oauth_flow_single_with_environment_retry(db, job, oauth_flow,
                                                      first_timeout_ms);
    if (!(rc == 0 && oauth_flow->status == FLOW_STATUS_SUCCESS) &&
        oauth_flow_waiting_code_timeout(oauth_flow) &&
        !task_stop_requested(job->task)) {
      task_log(job->task, oauth_flow->id, "warn",
               "账号 ID=%ld 单 OAuth %d 秒未收到验证码，立即触发第二次 OA，第二次邮箱超时 30 秒",
               job->account_id, retry_after);
      oauth_race_prepare_branch(db, job, 1);
      memset(oauth_flow, 0, sizeof(*oauth_flow));
      rc = run_oauth_flow_single_with_environment_retry(
          db, job, oauth_flow, CURRENT_SESSION_SECOND_OAUTH_OTP_TIMEOUT_MS);
    }
  }

  if (rc == 0 && oauth_flow->status == FLOW_STATUS_SUCCESS) {
    if (apply_oauth_success(db, job, oauth_flow) == 0) {
      record_oauth_success(job->task, oauth_flow, job->account_id);
      maybe_auto_upload_oauth_success(db, job, oauth_flow);
    } else {
      mg_snprintf(write_error, sizeof(write_error), "%s结果写入账号库失败",
                  mode_label);
      record_job_oauth_failure(db, job, oauth_flow, write_error);
    }
  } else {
    record_job_oauth_failure(db, job, oauth_flow,
                             oauth_flow->error[0] ? oauth_flow->error
                                                  : fallback_error);
  }
  return true;
}

static void *flow_worker(void *arg) {
  struct registration_flow_job *job = (struct registration_flow_job *) arg;
  sqlite3 *db = NULL;
  struct flow_context reg_flow;
  struct flow_context oauth_flow;

  if (job == NULL) return NULL;
  memset(&reg_flow, 0, sizeof(reg_flow));
  memset(&oauth_flow, 0, sizeof(oauth_flow));
  if (app_db_open("data/app.db", &db) != 0) {
    if (workflow_is_account_task(job->workflow)) {
      record_job_oauth_failure(NULL, job, NULL, "流程无法打开 SQLite 数据库");
    } else {
      record_register_failure(job->task, NULL, "流程无法打开 SQLite 数据库");
    }
    mark_job_done(job);
    free(job);
    return NULL;
  }

  if (job->workflow == REG_WORKFLOW_CHATGPT_LOGIN_ONLY) {
    if (run_chatgpt_login_flow_with_environment_retry(db, job, &oauth_flow) == 0 &&
        oauth_flow.status == FLOW_STATUS_SUCCESS) {
      if (apply_chatgpt_login_success(db, job, &oauth_flow) == 0) {
        record_oauth_success(job->task, &oauth_flow, job->account_id);
      } else {
        record_job_oauth_failure(db, job, &oauth_flow,
                                 "ChatGPT 登录结果写入账号库失败");
      }
    } else {
      record_job_oauth_failure(db, job, &oauth_flow,
                               oauth_flow.error[0] ? oauth_flow.error
                                                   : "ChatGPT 登录流程失败");
    }
    mark_job_done(job);
    app_db_close(db);
    free(job);
    return NULL;
  }

  if (job->workflow != REG_WORKFLOW_OAUTH_ONLY) {
    bool reg_flow_ok =
        run_registration_flow_with_environment_retry(db, job, &reg_flow) == 0 &&
        reg_flow.status == FLOW_STATUS_SUCCESS;
    // Outlook 直注: 注册流程(含 workspace 加入)已结束, 释放母邮箱单线程锁
    if (job->workflow == REG_WORKFLOW_OUTLOOK_DIRECT &&
        job->outlook_mailbox_id > 0) {
      outlook_pool_release(db, job->outlook_mailbox_id, reg_flow_ok);
      job->outlook_mailbox_id = -1;
    }
    if (!reg_flow_ok) {
      if (workflow_uses_current_session_codex(job->workflow) &&
          reg_flow.persisted_account_id > 0) {
        const char *message = reg_flow.error[0] ? reg_flow.error
                                                : "当前会话 Codex OAuth 失败";
        job->account_id = reg_flow.persisted_account_id;
        record_register_success(job->task, &reg_flow);
        fastlane_set_job_stage(job, REG_FLOW_STAGE_POST_EMAIL_ACTIVE,
                               reg_flow.id,
                               "注册已入库，当前会话 Codex OAuth 未完成");
        if (!run_current_session_oauth_fallback(db, job, &reg_flow, message,
                                                &oauth_flow)) {
          record_job_oauth_failure(db, job, &reg_flow, message);
        }
        mark_job_done(job);
        app_db_close(db);
        free(job);
        return NULL;
      }
      record_register_failure(job->task, &reg_flow,
                              reg_flow.error[0] ? reg_flow.error
                                                : "注册流程失败");
      mark_job_done(job);
      app_db_close(db);
      free(job);
      return NULL;
    }
    job->account_id = reg_flow.persisted_account_id;
    record_register_success(job->task, &reg_flow);
    fastlane_set_job_stage(job, REG_FLOW_STAGE_POST_EMAIL_ACTIVE,
                           reg_flow.id,
                           "注册已通过邮箱阶段");
    if (job->workflow == REG_WORKFLOW_REGISTER_ONLY) {
      mark_job_done(job);
      app_db_close(db);
      free(job);
      return NULL;
    }
    if (workflow_uses_current_session_codex(job->workflow)) {
      if (reg_flow.access_token[0] != '\0') {
        record_oauth_success(job->task, &reg_flow, job->account_id);
        maybe_auto_upload_oauth_success(db, job, &reg_flow);
      } else {
        const char *message = "当前会话 Codex OAuth 未返回 Access Token";
        if (!run_current_session_oauth_fallback(db, job, &reg_flow, message,
                                                &oauth_flow)) {
          record_job_oauth_failure(db, job, &reg_flow, message);
        }
      }
      mark_job_done(job);
      app_db_close(db);
      free(job);
      return NULL;
    }
    if (!wait_before_oauth(job)) {
      mark_job_done(job);
      app_db_close(db);
      free(job);
      return NULL;
    }
  }

  if (run_oauth_flow_race_with_environment_retry(db, job, &oauth_flow) == 0 &&
      oauth_flow.status == FLOW_STATUS_SUCCESS) {
    if (apply_oauth_success(db, job, &oauth_flow) == 0) {
      record_oauth_success(job->task, &oauth_flow, job->account_id);
      maybe_auto_upload_oauth_success(db, job, &oauth_flow);
    } else {
      record_job_oauth_failure(db, job, &oauth_flow,
                               "OAuth 结果写入账号库失败");
    }
  } else {
    record_job_oauth_failure(db, job, &oauth_flow,
                             oauth_flow.error[0] ? oauth_flow.error
                                                 : "OAuth 流程失败");
  }

  mark_job_done(job);
  app_db_close(db);
  free(job);
  return NULL;
}

static int launch_flow_job(struct registration_task *task,
                           enum registration_workflow workflow,
                           enum registration_register_provider register_provider,
                           const struct identity_result *identity,
                           const struct browser_profile *profile,
                           const char *proxy_url, long account_id,
                           const char *workspace_id, long outlook_mailbox_id,
                           enum registration_fastlane_stage initial_stage) {
  struct registration_flow_job *job;
  pthread_t thread;
  pthread_attr_t attr;
  pthread_attr_t *attrp = NULL;

  job = (struct registration_flow_job *) calloc(1, sizeof(*job));
  if (job == NULL) return -1;
  job->task = task;
  job->workflow = workflow;
  job->register_provider = register_provider;
  job->request_core = task->request_core;
  mg_snprintf(job->libcurl_impersonate_target,
              sizeof(job->libcurl_impersonate_target), "%s",
              task_libcurl_impersonate_target(task));
  job->account_id = account_id;
  job->outlook_mailbox_id = outlook_mailbox_id;
  job->scheduler_stage = initial_stage;
  job->auto_upload_oauth_success = task->auto_upload_oauth_success;
  job->discard_oauth_failed_accounts = task->discard_oauth_failed_accounts;
  job->auto_upload_service_mode = task->auto_upload_service_mode;
  job->auto_upload_service_id = task->auto_upload_service_id;
  mg_snprintf(job->auto_upload_service_name,
              sizeof(job->auto_upload_service_name), "%s",
              task->auto_upload_service_name);
  job->current_session_oauth_fallback = task->current_session_oauth_fallback;
  job->fast_email_otp_resend = task->fast_email_otp_resend;
  job->current_session_oauth_fallback_mode =
      task->current_session_oauth_fallback_mode;
  job->current_session_oauth_retry_after_seconds =
      task->current_session_oauth_retry_after_seconds;
  job->oauth_delay_seconds =
      workflow == REG_WORKFLOW_REGISTER_THEN_OAUTH ? task->oauth_delay_seconds : 0;
  if (identity != NULL) job->identity = *identity;
  if (profile != NULL) job->profile = *profile;
  if (proxy_url != NULL) {
    mg_snprintf(job->proxy_url, sizeof(job->proxy_url), "%s", proxy_url);
  }
  if (workspace_id != NULL) {
    mg_snprintf(job->workspace_id, sizeof(job->workspace_id), "%s",
                workspace_id);
  }
  job->deadline_ms = (long) mg_millis() + 180000;

  if (init_flow_thread_attr(&attr) == 0) attrp = &attr;
  if (pthread_create(&thread, attrp, flow_worker, job) != 0) {
    if (attrp != NULL) pthread_attr_destroy(&attr);
    free(job);
    return -1;
  }
  if (attrp != NULL) pthread_attr_destroy(&attr);
  pthread_detach(thread);
  return 0;
}

static int prepare_oauth_identity(sqlite3 *db, long account_id,
                                  struct identity_result *identity,
                                  char *workspace_id,
                                  size_t workspace_id_len) {
  struct account_oauth_record record;
  if (identity != NULL) memset(identity, 0, sizeof(*identity));
  if (workspace_id != NULL && workspace_id_len > 0) workspace_id[0] = '\0';
  if (account_load_oauth_record(db, account_id, &record) != 0) return -1;
  mg_snprintf(identity->email, sizeof(identity->email), "%s", record.email);
  mg_snprintf(identity->password, sizeof(identity->password), "%s",
              record.password);
  if (workspace_id != NULL && workspace_id_len > 0) {
    mg_snprintf(workspace_id, workspace_id_len, "%s", record.workspace_id);
  }
  return 0;
}

static void *task_worker(void *arg) {
  struct registration_task *task = (struct registration_task *) arg;
  sqlite3 *db = NULL;
  char error[256] = "";
  char impersonate_path[512] = "";
  char libcurl_impersonate_path[512] = "";
  bool fatal = false;

  if (app_db_open("data/app.db", &db) != 0) {
    mark_task_failed(task, "任务无法打开 SQLite 数据库");
    return NULL;
  }

  if (task->request_core == REG_REQUEST_CORE_CURL_IMPERSONATE &&
      flow_impersonate_available(impersonate_path, sizeof(impersonate_path)) != 0) {
    app_db_close(db);
    mark_task_failed(task, "未找到 curl-impersonate，请安装 curl_chrome145 或设置 CURL_IMPERSONATE_BIN");
    return NULL;
  }
  if (task->request_core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE &&
      flow_libcurl_impersonate_available(libcurl_impersonate_path,
                                         sizeof(libcurl_impersonate_path)) != 0) {
    app_db_close(db);
    mark_task_failed(task, "未找到 libcurl-impersonate 动态库，请构建 /opt/curl-impersonate/lib/libcurl-impersonate.so 或设置 LIBCURL_IMPERSONATE_LIB");
    return NULL;
  }

  mark_task_running(task);
  if (task->detailed_logs) {
    if (task->request_core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE) {
      task_log(task, "", "info",
               "执行器: libcurl-impersonate 动态库 %s target=%s",
               libcurl_impersonate_path, task_libcurl_impersonate_target(task));
    } else if (task->request_core == REG_REQUEST_CORE_LIBCURL) {
      task_log(task, "", "info", "执行器: libcurl 内置 flow engine");
    } else {
      task_log(task, "", "info", "执行器: curl-impersonate %s", impersonate_path);
    }
  }
  if (prepare_task_mihomo_proxy(db, task, error, sizeof(error)) != 0) {
    app_db_close(db);
    mark_task_failed(task, error[0] ? error : "准备 Mihomo 任务代理失败");
    mihomo_task_proxy_release(task->id);
    return NULL;
  }
  if (task->detailed_logs) {
    if (workflow_is_account_task(task->workflow)) {
      task_log(task, "", "info", "任务类型: %s", task_register_label(task));
    } else {
      task_log(task, "", "info", "注册方式: %s",
               register_provider_label(task->register_provider));
      task_log(task, "", "info",
               "注册成功但未 OAuth 的账号将按注册方式写入对应状态");
    }
  }

  while (task_should_continue(task)) {
    while (can_launch_more(task)) {
      struct identity_result identity;
      struct browser_profile profile;
      char proxy_url[FLOW_PROXY_LEN] = "";
      char workspace_id[FLOW_WORKSPACE_ID_LEN] = "";
      long account_id = 0;
      long outlook_mailbox_id = -1;
      int proxy_rc;
      enum registration_fastlane_stage initial_stage;

      if (workflow_is_account_task(task->workflow)) {
        account_id = take_next_account_id(task);
        if (account_id <= 0) break;
        if (prepare_oauth_identity(db, account_id, &identity, workspace_id,
                                   sizeof(workspace_id)) != 0) {
          mark_account_load_failed(task, account_id);
          continue;
        }
      } else if (task->workflow == REG_WORKFLOW_OUTLOOK_DIRECT) {
        char mother[IDENTITY_EMAIL_LEN] = "";
        if (outlook_pool_claim(db, mother, sizeof(mother), NULL, 0,
                               &outlook_mailbox_id, error,
                               sizeof(error)) != 0) {
          break;  // 母邮箱都在占用/达上限, 稍后再试(非致命)
        }
        if (identity_generate_outlook_alias(db, mother, &identity, error,
                                            sizeof(error)) != 0) {
          outlook_pool_release(db, outlook_mailbox_id, false);
          mark_task_failed(task,
                           error[0] ? error : "outlook 别名身份生成失败");
          fatal = true;
          break;
        }
      } else if (identity_generate(db, &identity, error, sizeof(error)) != 0) {
        mark_task_failed(task, error[0] ? error : "身份信息生成失败");
        fatal = true;
        break;
      }

      browser_profile_generate(&profile, NULL, NULL);
      if (task->mihomo_task_proxy) {
        mg_snprintf(proxy_url, sizeof(proxy_url), "%s", task->mihomo_proxy_url);
        proxy_rc = proxy_url[0] != '\0' ? 1 : 0;
      } else {
        proxy_rc = proxy_pool_pick_active_url(db, proxy_url, sizeof(proxy_url));
      }
      if (ensure_non_direct_proxy_available(db, proxy_rc, error,
                                            sizeof(error)) != 0) {
        mark_task_failed(task, error[0] ? error : "当前代理模式没有可用代理");
        fatal = true;
        break;
      }

      initial_stage = mark_flow_launch(task);
      if (launch_flow_job(task, task->workflow, task->register_provider,
                          &identity, &profile,
                          proxy_rc > 0 ? proxy_url : "", account_id,
                          workspace_id, outlook_mailbox_id,
                          initial_stage) != 0) {
        // 启动线程失败, 释放已 claim 的母邮箱
        if (outlook_mailbox_id > 0) {
          outlook_pool_release(db, outlook_mailbox_id, false);
        }
        mark_flow_launch_failed(task, "任务流程启动请求线程失败");
      }
    }

    if (fatal || task_is_done(task)) break;
    usleep(50000);
  }

  mihomo_task_proxy_release(task->id);
  app_db_close(db);
  if (!fatal) mark_task_finished(task);
  return NULL;
}

int registration_tasks_start(const struct registration_start_options *options,
                             char *task_id, size_t task_id_len,
                             char *error, size_t error_len) {
  struct registration_task *task;
  int target_count, concurrency, max_inflight;
  enum registration_scheduler_mode scheduler_mode;
  enum registration_request_core request_core;
  enum registration_current_session_oauth_fallback_mode fallback_mode;
  enum registration_auto_upload_service_mode auto_upload_service_mode;
  int retry_after_seconds;
  const char *requested_libcurl_impersonate_target;
  char libcurl_impersonate_target[FLOW_IMPERSONATE_TARGET_LEN];
  char mihomo_node[REG_TASK_MIHOMO_NODE_LEN] = "";
  long auto_upload_service_id = 0;
  char auto_upload_service_name[REG_TASK_UPLOAD_SERVICE_NAME_LEN] = "";

  if (task_id != NULL && task_id_len > 0) task_id[0] = '\0';
  if (options == NULL) {
    set_error(error, error_len, "任务参数为空");
    return -1;
  }
  if (workflow_is_account_task(options->workflow) &&
      (options->account_ids == NULL || options->account_id_count == 0)) {
    set_error(error, error_len, "账号任务缺少账号 ID");
    return -1;
  }

  target_count = options->count <= 0 ? 1 : options->count;
  if (options->infinite && !workflow_is_account_task(options->workflow)) {
    target_count = 0;
  }
  if (workflow_is_account_task(options->workflow)) {
    target_count = (int) options->account_id_count;
  }
  if (target_count > 10000) target_count = 10000;
  concurrency = options->concurrency <= 0 ? 1 : options->concurrency;
  if (!options->infinite && concurrency > target_count) concurrency = target_count;
  if (concurrency > 5000) concurrency = 5000;
  if (concurrency <= 0) concurrency = 1;
  scheduler_mode = options->scheduler_mode == REG_SCHEDULER_FASTLANE &&
                           !workflow_is_account_task(options->workflow)
                       ? REG_SCHEDULER_FASTLANE
                       : REG_SCHEDULER_NORMAL;
  if (scheduler_mode == REG_SCHEDULER_FASTLANE &&
      concurrency > FASTLANE_MAX_INFLIGHT_LIMIT) {
    concurrency = FASTLANE_MAX_INFLIGHT_LIMIT;
  }
  max_inflight = concurrency;
  if (scheduler_mode == REG_SCHEDULER_FASTLANE) {
    if (options->max_inflight > 0) {
      max_inflight = options->max_inflight;
      if (!options->infinite && target_count > 0 && max_inflight > target_count) {
        max_inflight = target_count;
      }
      if (max_inflight < concurrency) max_inflight = concurrency;
    } else {
      max_inflight = concurrency * 3;
      if (max_inflight < FASTLANE_DEFAULT_MAX_INFLIGHT) {
        max_inflight = FASTLANE_DEFAULT_MAX_INFLIGHT;
      }
      if (!options->infinite && target_count > 0 && max_inflight > target_count) {
        max_inflight = target_count;
      }
      if (max_inflight < concurrency) max_inflight = concurrency;
    }
    if (max_inflight > FASTLANE_MAX_INFLIGHT_LIMIT) {
      max_inflight = FASTLANE_MAX_INFLIGHT_LIMIT;
    }
    if (max_inflight <= 0) max_inflight = concurrency;
  }

  request_core =
      options->request_core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE
          ? REG_REQUEST_CORE_LIBCURL_IMPERSONATE
          : (options->request_core == REG_REQUEST_CORE_CURL_IMPERSONATE
                 ? REG_REQUEST_CORE_CURL_IMPERSONATE
                 : (options->request_core == REG_REQUEST_CORE_LIBCURL
                        ? REG_REQUEST_CORE_LIBCURL
                        : REG_REQUEST_CORE_LIBCURL_IMPERSONATE));
  requested_libcurl_impersonate_target =
      options->libcurl_impersonate_target != NULL &&
              options->libcurl_impersonate_target[0] != '\0'
          ? options->libcurl_impersonate_target
          : flow_libcurl_impersonate_default_target();
  if (request_core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE &&
      !flow_libcurl_impersonate_normalize_target(
          requested_libcurl_impersonate_target, libcurl_impersonate_target,
          sizeof(libcurl_impersonate_target))) {
    mg_snprintf(error, error_len, "libcurl-impersonate 指纹版本不支持: %s",
                requested_libcurl_impersonate_target);
    return -1;
  }
  if (request_core != REG_REQUEST_CORE_LIBCURL_IMPERSONATE) {
    mg_snprintf(libcurl_impersonate_target, sizeof(libcurl_impersonate_target),
                "%s", flow_libcurl_impersonate_default_target());
  }
  fallback_mode = options->current_session_oauth_fallback_mode;
  if (options->workflow != REG_WORKFLOW_REGISTER_THEN_CURRENT_CODEX) {
    fallback_mode = REG_CURRENT_SESSION_OAUTH_FALLBACK_NONE;
  } else if (fallback_mode == REG_CURRENT_SESSION_OAUTH_FALLBACK_NONE &&
             options->current_session_oauth_fallback) {
    fallback_mode = REG_CURRENT_SESSION_OAUTH_FALLBACK_DOUBLE;
  }
  retry_after_seconds = options->current_session_oauth_retry_after_seconds;
  if (retry_after_seconds <= 0) {
    retry_after_seconds = CURRENT_SESSION_OAUTH_RETRY_AFTER_DEFAULT_SECONDS;
  }
  if (retry_after_seconds > CURRENT_SESSION_OAUTH_RETRY_AFTER_MAX_SECONDS) {
    retry_after_seconds = CURRENT_SESSION_OAUTH_RETRY_AFTER_MAX_SECONDS;
  }
  if (options->mihomo_node != NULL && options->mihomo_node[0] != '\0') {
    sqlite3 *validation_db = NULL;
    char validation_error[256] = "";
    int validate_rc;
    if (app_db_open("data/app.db", &validation_db) != 0) {
      set_error(error, error_len, "无法打开数据库校验 Mihomo 节点");
      return -1;
    }
    validate_rc = mihomo_task_node_validate(
        validation_db, options->mihomo_node, mihomo_node, sizeof(mihomo_node),
        validation_error, sizeof(validation_error));
    app_db_close(validation_db);
    if (validate_rc < 0) {
      set_error(error, error_len,
                validation_error[0] ? validation_error : "Mihomo 节点不可用");
      return -1;
    }
  }
  auto_upload_service_mode = options->auto_upload_service_mode;
  if (auto_upload_service_mode != REG_AUTO_UPLOAD_SERVICE_RANDOM &&
      auto_upload_service_mode != REG_AUTO_UPLOAD_SERVICE_FIXED) {
    auto_upload_service_mode = REG_AUTO_UPLOAD_SERVICE_ALL;
  }
  if (options->auto_upload_oauth_success &&
      workflow_has_oauth(options->workflow)) {
    sqlite3 *validation_db = NULL;
    char validation_error[256] = "";
    long resolved_service_id = 0;
    char resolved_service_name[REG_TASK_UPLOAD_SERVICE_NAME_LEN] = "";
    int validate_rc;

    if (auto_upload_service_mode == REG_AUTO_UPLOAD_SERVICE_FIXED &&
        options->auto_upload_service_id <= 0) {
      set_error(error, error_len, "请选择用于自动上传的 Aether 服务");
      return -1;
    }
    if (app_db_open("data/app.db", &validation_db) != 0) {
      set_error(error, error_len, "无法打开数据库校验 Aether 上传服务");
      return -1;
    }
    validate_rc = aether_resolve_enabled_upload_service(
        validation_db,
        auto_upload_service_mode == REG_AUTO_UPLOAD_SERVICE_FIXED
            ? options->auto_upload_service_id
            : 0,
        auto_upload_service_mode != REG_AUTO_UPLOAD_SERVICE_FIXED,
        &resolved_service_id, resolved_service_name,
        sizeof(resolved_service_name), validation_error,
        sizeof(validation_error));
    app_db_close(validation_db);
    if (validate_rc != 0) {
      set_error(error, error_len,
                validation_error[0] ? validation_error
                                    : "Aether 上传服务不可用");
      return -1;
    }
    if (auto_upload_service_mode == REG_AUTO_UPLOAD_SERVICE_RANDOM ||
        auto_upload_service_mode == REG_AUTO_UPLOAD_SERVICE_FIXED) {
      auto_upload_service_id = resolved_service_id;
      mg_snprintf(auto_upload_service_name, sizeof(auto_upload_service_name),
                  "%s", resolved_service_name);
    }
  }

  task = (struct registration_task *) calloc(1, sizeof(*task));
  if (task == NULL) {
    set_error(error, error_len, "任务内存分配失败");
    return -1;
  }
  generate_task_id(task->id, sizeof(task->id));
  task->workflow = options->workflow;
  task->scheduler_mode = scheduler_mode;
  task->register_provider =
      options->register_provider == REG_REGISTER_PROVIDER_TEMPORARY
          ? REG_REGISTER_PROVIDER_TEMPORARY
          : REG_REGISTER_PROVIDER_PLATFORM;
  task->request_core = request_core;
  mg_snprintf(task->libcurl_impersonate_target,
              sizeof(task->libcurl_impersonate_target), "%s",
              libcurl_impersonate_target);
  if (mihomo_node[0] != '\0') {
    mg_snprintf(task->mihomo_node, sizeof(task->mihomo_node), "%s",
                mihomo_node);
  }
  task->target_metric = workflow_is_account_task(options->workflow)
                            ? REG_TARGET_OAUTH_SUCCESS
                            : options->target_metric;
  if (task->workflow == REG_WORKFLOW_REGISTER_ONLY) {
    task->target_metric = REG_TARGET_REGISTER_TASK;
  }
  task->target_count = target_count;
  task->concurrency = concurrency;
  task->max_inflight = max_inflight;
  task->oauth_delay_seconds = options->oauth_delay_seconds;
  if (task->oauth_delay_seconds < 0) task->oauth_delay_seconds = 0;
  if (task->oauth_delay_seconds > 3600) task->oauth_delay_seconds = 3600;
  task->detailed_logs = options->detailed_logs;
  task->auto_upload_oauth_success =
      options->auto_upload_oauth_success && workflow_has_oauth(options->workflow);
  task->discard_oauth_failed_accounts =
      options->discard_oauth_failed_accounts &&
      workflow_has_oauth(options->workflow) &&
      !workflow_is_account_task(options->workflow);
  task->auto_upload_service_mode = task->auto_upload_oauth_success
                                       ? auto_upload_service_mode
                                       : REG_AUTO_UPLOAD_SERVICE_ALL;
  task->auto_upload_service_id =
      task->auto_upload_oauth_success ? auto_upload_service_id : 0;
  mg_snprintf(task->auto_upload_service_name,
              sizeof(task->auto_upload_service_name), "%s",
              task->auto_upload_oauth_success ? auto_upload_service_name : "");
  task->fast_email_otp_resend =
      options->fast_email_otp_resend && !workflow_is_account_task(options->workflow);
  task->current_session_oauth_fallback_mode = fallback_mode;
  task->current_session_oauth_fallback =
      task->current_session_oauth_fallback_mode !=
      REG_CURRENT_SESSION_OAUTH_FALLBACK_NONE;
  task->current_session_oauth_retry_after_seconds =
      task->current_session_oauth_fallback_mode ==
              REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE_TIMEOUT_RETRY
          ? retry_after_seconds
          : 0;
  task->infinite = workflow_is_account_task(options->workflow)
                       ? false
                       : options->infinite;
  if (options->account_id_count > 0) {
    task->account_ids = (long *) calloc(options->account_id_count,
                                        sizeof(*task->account_ids));
    if (task->account_ids == NULL) {
      free(task);
      set_error(error, error_len, "账号 ID 列表内存分配失败");
      return -1;
    }
    memcpy(task->account_ids, options->account_ids,
           options->account_id_count * sizeof(*task->account_ids));
    task->account_id_count = options->account_id_count;
  }
  mg_snprintf(task->status, sizeof(task->status), "queued");
  task->created_ms = now_ms();
  task->updated_ms = task->created_ms;

  pthread_mutex_lock(&s_tasks_mu);
  task->next = s_tasks;
  s_tasks = task;
  if (task->detailed_logs) {
    append_logf_locked(task, "", "info",
                       "任务已创建 workflow=%s scheduler=%s register=%s target=%s core=%s%s%s count=%d infinite=%s 并发=%d max_inflight=%d oauth_delay=%d fast_email_otp_resend=%s discard_oauth_failed=%s auto_upload=%s auto_upload_service=%s(%s) current_session_fallback=%s current_session_fallback_mode=%s retry_after=%d mihomo_node=%s",
                       workflow_name(task->workflow),
                       scheduler_mode_name(task->scheduler_mode),
                       task_register_label(task),
                       target_metric_name(task->target_metric),
                       request_core_label(task->request_core),
                       task->request_core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE
                           ? " impersonate="
                           : "",
                       task->request_core == REG_REQUEST_CORE_LIBCURL_IMPERSONATE
                           ? task_libcurl_impersonate_target(task)
                           : "",
                       task->target_count, task->infinite ? "yes" : "no",
                       task->concurrency, task->max_inflight,
                       task->oauth_delay_seconds,
                       task->fast_email_otp_resend ? "yes" : "no",
                       task->discard_oauth_failed_accounts ? "yes" : "no",
                       task->auto_upload_oauth_success ? "yes" : "no",
                       auto_upload_service_mode_name(
                           task->auto_upload_service_mode),
                       task->auto_upload_service_name[0]
                           ? task->auto_upload_service_name
                           : auto_upload_service_mode_label(
                                 task->auto_upload_service_mode),
                       task->current_session_oauth_fallback ? "yes" : "no",
                       current_session_fallback_mode_name(
                           task->current_session_oauth_fallback_mode),
                       task->current_session_oauth_retry_after_seconds,
                       task->mihomo_node[0] ? task->mihomo_node : "auto");
  } else {
    append_logf_locked(task, "", "info",
                       "任务已创建: %s，目标=%s，并发=%d",
                       workflow_name(task->workflow),
                       task->infinite ? "无限" : "有限",
                       task->concurrency);
  }
  pthread_mutex_unlock(&s_tasks_mu);

  if (pthread_create(&task->thread, NULL, task_worker, task) != 0) {
    mark_task_failed(task, "任务线程创建失败");
    set_error(error, error_len, "任务线程创建失败");
    return -1;
  }
  pthread_detach(task->thread);
  mg_snprintf(task_id, task_id_len, "%s", task->id);
  return 0;
}

int registration_tasks_stop(const char *task_id, char *error, size_t error_len) {
  struct registration_task *task;
  int rc = -1;
  pthread_mutex_lock(&s_tasks_mu);
  task = find_task_locked(task_id ? task_id : "");
  if (task == NULL) {
    set_error(error, error_len, "任务不存在");
  } else if (strcmp(task->status, "running") != 0 &&
             strcmp(task->status, "queued") != 0) {
    set_error(error, error_len, "任务当前状态不可停止");
  } else {
    task->stop_requested = true;
    mg_snprintf(task->status, sizeof(task->status), "stopping");
    task->updated_ms = now_ms();
    append_log_locked(task, "", "warn", "已请求停止任务，将等待运行中的流程结束");
    rc = 0;
  }
  pthread_mutex_unlock(&s_tasks_mu);
  return rc;
}

static void append_task_json(struct mg_iobuf *io,
                             const struct registration_task *task) {
  int alive_total = task_fastlane_alive_unlocked(task);
  mg_xprintf(mg_pfn_iobuf, io, "{");
  mg_xprintf(mg_pfn_iobuf, io,
             "%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m",
             MG_ESC("id"), MG_ESC(task->id), MG_ESC("status"),
             MG_ESC(task->status), MG_ESC("mode"),
             MG_ESC(workflow_name(task->workflow)), MG_ESC("workflow"),
             MG_ESC(workflow_name(task->workflow)), MG_ESC("scheduler_mode"),
             MG_ESC(scheduler_mode_name(task->scheduler_mode)),
             MG_ESC("target_metric"),
             MG_ESC(target_metric_name(task->target_metric)),
             MG_ESC("register_provider"),
             MG_ESC(register_provider_name(task->register_provider)),
             MG_ESC("request_core"),
             MG_ESC(request_core_name(task->request_core)),
             MG_ESC("libcurl_impersonate_target"),
             MG_ESC(task_libcurl_impersonate_target(task)));
  mg_xprintf(mg_pfn_iobuf, io,
             ",%m:%m",
             MG_ESC("current_session_oauth_fallback_mode"),
             MG_ESC(current_session_fallback_mode_name(
                 task->current_session_oauth_fallback_mode)));
  mg_xprintf(mg_pfn_iobuf, io,
             ",%m:%m,%m:%m,%m:%d",
             MG_ESC("mihomo_node"), MG_ESC(task->mihomo_node),
             MG_ESC("mihomo_proxy_url"), MG_ESC(task->mihomo_proxy_url),
             MG_ESC("mihomo_task_proxy"), task->mihomo_task_proxy ? 1 : 0);
  mg_xprintf(mg_pfn_iobuf, io,
             ",%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d",
             MG_ESC("count"), task->target_count, MG_ESC("target_count"),
             task->target_count, MG_ESC("concurrency"), task->concurrency,
             MG_ESC("max_inflight"), task->max_inflight,
             MG_ESC("oauth_delay_seconds"), task->oauth_delay_seconds,
             MG_ESC("current_session_oauth_retry_after_seconds"),
             task->current_session_oauth_retry_after_seconds,
             MG_ESC("detailed_logs"), task->detailed_logs ? 1 : 0,
             MG_ESC("fast_email_otp_resend"),
             task->fast_email_otp_resend ? 1 : 0,
             MG_ESC("discard_oauth_failed_accounts"),
             task->discard_oauth_failed_accounts ? 1 : 0,
             MG_ESC("auto_upload_oauth_success"),
             task->auto_upload_oauth_success ? 1 : 0,
             MG_ESC("current_session_oauth_fallback"),
             task->current_session_oauth_fallback ? 1 : 0,
             MG_ESC("infinite"), task->infinite ? 1 : 0,
             MG_ESC("stop_requested"), task->stop_requested ? 1 : 0,
             MG_ESC("started"), task->started);
  mg_xprintf(mg_pfn_iobuf, io,
             ",%m:%m,%m:%ld,%m:%m",
             MG_ESC("auto_upload_service_mode"),
             MG_ESC(auto_upload_service_mode_name(
                 task->auto_upload_service_mode)),
             MG_ESC("auto_upload_service_id"), task->auto_upload_service_id,
             MG_ESC("auto_upload_service_name"),
             MG_ESC(task->auto_upload_service_name));
  mg_xprintf(mg_pfn_iobuf, io,
             ",%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d,%m:%d",
             MG_ESC("active"), task->active, MG_ESC("success"),
             task->success, MG_ESC("failed"), task->failed,
             MG_ESC("register_success"), task->register_success,
             MG_ESC("register_failed"), task->register_failed,
             MG_ESC("oauth_success"), task->oauth_success,
             MG_ESC("oauth_failed"), task->oauth_failed,
             MG_ESC("expired_written"), task->expired_written,
             MG_ESC("temp_written"), task->temp_written);
  mg_xprintf(mg_pfn_iobuf, io,
             ",%m:%d,%m:%d,%m:%d",
             MG_ESC("upload_success"), task->upload_success,
             MG_ESC("upload_failed"), task->upload_failed,
             MG_ESC("upload_skipped"), task->upload_skipped);
  mg_xprintf(mg_pfn_iobuf, io,
             ",%m:%d,%m:%d,%m:%d,%m:%d",
             MG_ESC("fastlane_pre_email_active"),
             task->fastlane_pre_email_active,
             MG_ESC("fastlane_waiting_email"),
             task->fastlane_waiting_email,
             MG_ESC("fastlane_post_email_active"),
             task->fastlane_post_email_active,
             MG_ESC("fastlane_alive_total"), alive_total);
  mg_xprintf(mg_pfn_iobuf, io,
             ",%m:%lu,%m:%lu",
             MG_ESC("log_count"), (unsigned long) task->log_len,
             MG_ESC("log_limit"),
             (unsigned long) (task->detailed_logs
                                  ? REG_TASK_DETAILED_MAX_LOGS
                                  : REG_TASK_DEFAULT_MAX_LOGS));
  mg_xprintf(mg_pfn_iobuf, io,
             ",%m:%llu,%m:%llu,%m:%llu,%m:%llu,%m:%m}",
             MG_ESC("created_ms"), (unsigned long long) task->created_ms,
             MG_ESC("started_ms"), (unsigned long long) task->started_ms,
             MG_ESC("updated_ms"), (unsigned long long) task->updated_ms,
             MG_ESC("finished_ms"), (unsigned long long) task->finished_ms,
             MG_ESC("error"), MG_ESC(task->error));
}

char *registration_tasks_list_json(void) {
  struct mg_iobuf io = {0, 0, 0, 1024};
  bool first = true;

  pthread_mutex_lock(&s_tasks_mu);
  purge_expired_tasks_locked();
  mg_xprintf(mg_pfn_iobuf, &io, "{%m:[", MG_ESC("items"));
  for (struct registration_task *task = s_tasks; task != NULL; task = task->next) {
    if (!first) mg_xprintf(mg_pfn_iobuf, &io, ",");
    first = false;
    append_task_json(&io, task);
  }
  mg_xprintf(mg_pfn_iobuf, &io, "]}");
  pthread_mutex_unlock(&s_tasks_mu);
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

static void append_logs_json(struct mg_iobuf *io,
                             const struct registration_task *task,
                             uint64_t since_seq, uint64_t *last_seq,
                             size_t max_count) {
  bool first = true;
  size_t match_count = 0;
  size_t skip_count = 0;
  mg_xprintf(mg_pfn_iobuf, io, "[");
  for (size_t i = 0; i < task->log_len; i++) {
    if (task->logs[i].seq > since_seq) match_count++;
  }
  if (max_count > 0 && match_count > max_count) {
    skip_count = match_count - max_count;
  }
  for (size_t i = 0; i < task->log_len; i++) {
    const struct registration_log_entry *log = &task->logs[i];
    if (log->seq <= since_seq) continue;
    if (skip_count > 0) {
      skip_count--;
      continue;
    }
    if (!first) mg_xprintf(mg_pfn_iobuf, io, ",");
    first = false;
    if (last_seq != NULL && log->seq > *last_seq) *last_seq = log->seq;
    mg_xprintf(mg_pfn_iobuf, io,
               "{%m:%llu,%m:%llu,%m:%m,%m:%m,%m:%m}",
               MG_ESC("seq"), (unsigned long long) log->seq,
               MG_ESC("ts_ms"), (unsigned long long) log->ts_ms,
               MG_ESC("level"), MG_ESC(log->level), MG_ESC("flow_id"),
               MG_ESC(log->flow_id), MG_ESC("message"), MG_ESC(log->message));
  }
  mg_xprintf(mg_pfn_iobuf, io, "]");
}

static uint64_t registration_task_latest_log_seq_locked(
    const struct registration_task *task) {
  if (task == NULL || task->log_len == 0) return 0;
  return task->logs[task->log_len - 1].seq;
}

static uint64_t registration_task_latest_log_seq(const char *task_id) {
  struct registration_task *task;
  uint64_t seq = 0;
  pthread_mutex_lock(&s_tasks_mu);
  purge_expired_tasks_locked();
  task = find_task_locked(task_id ? task_id : "");
  seq = registration_task_latest_log_seq_locked(task);
  pthread_mutex_unlock(&s_tasks_mu);
  return seq;
}

char *registration_task_detail_json(const char *task_id, bool include_logs,
                                    size_t log_limit) {
  struct mg_iobuf io = {0, 0, 0, 2048};
  struct registration_task *task;

  pthread_mutex_lock(&s_tasks_mu);
  purge_expired_tasks_locked();
  task = find_task_locked(task_id ? task_id : "");
  if (task == NULL) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("任务不存在"));
  } else {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:", MG_ESC("ok"), 1,
               MG_ESC("task"));
    append_task_json(&io, task);
    if (include_logs) {
      mg_xprintf(mg_pfn_iobuf, &io, ",%m:", MG_ESC("logs"));
      if (log_limit == 0) {
        mg_xprintf(mg_pfn_iobuf, &io, "[]");
      } else {
        append_logs_json(&io, task, 0, NULL, log_limit);
      }
    }
    mg_xprintf(mg_pfn_iobuf, &io, "}");
  }
  pthread_mutex_unlock(&s_tasks_mu);
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

void registration_tasks_counts(int *active_tasks, int *active_flows,
                               int *queued_flows) {
  int tasks = 0, active = 0, queued = 0;
  pthread_mutex_lock(&s_tasks_mu);
  purge_expired_tasks_locked();
  for (struct registration_task *task = s_tasks; task != NULL; task = task->next) {
    if (strcmp(task->status, "running") == 0 ||
        strcmp(task->status, "queued") == 0 ||
        strcmp(task->status, "stopping") == 0) {
      tasks++;
      active += task->active;
      if (workflow_is_account_task(task->workflow)) {
        queued += (int) (task->account_id_count - task->next_account_index);
      } else if (!task->infinite) {
        int remain = task->target_count - task_target_progress_unlocked(task);
        queued += remain > 0 ? remain : 0;
      }
    }
  }
  pthread_mutex_unlock(&s_tasks_mu);
  if (active_tasks != NULL) *active_tasks = tasks;
  if (active_flows != NULL) *active_flows = active;
  if (queued_flows != NULL) *queued_flows = queued < 0 ? 0 : queued;
}

static unsigned ws_count_connections(struct mg_mgr *mgr) {
  unsigned count = 0;
  if (mgr == NULL) return 0;
  for (struct mg_connection *c = mgr->conns; c != NULL; c = c->next) count++;
  return count;
}

static uint64_t clamp_system_interval(long interval_ms) {
  if (interval_ms <= 0) return 3000;
  if (interval_ms < 1000) return 1000;
  if (interval_ms > 60000) return 60000;
  return (uint64_t) interval_ms;
}

static void send_system_status(struct mg_connection *c, sqlite3 *db,
                               uint64_t started_ms) {
  char *json;
  uint64_t current_ms = mg_millis();
  uint64_t uptime = current_ms >= started_ms ? current_ms - started_ms : 0;
  if (c == NULL || !c->is_websocket) return;
  json = system_monitor_status_json(db, uptime, ws_count_connections(c->mgr));
  mg_ws_printf(c, WEBSOCKET_OP_TEXT, "{%m:%m,%m:%s}",
               MG_ESC("type"), MG_ESC("system_status"),
               MG_ESC("payload"), json ? json : "{}");
  free(json);
}

static char *logs_since_json(const char *task_id, uint64_t since_seq,
                             uint64_t *last_seq, bool *has_logs) {
  struct mg_iobuf io = {0, 0, 0, 2048};
  struct registration_task *task;
  uint64_t before = last_seq != NULL ? *last_seq : since_seq;

  if (has_logs != NULL) *has_logs = false;
  pthread_mutex_lock(&s_tasks_mu);
  purge_expired_tasks_locked();
  task = find_task_locked(task_id ? task_id : "");
  if (task == NULL) {
    mg_xprintf(mg_pfn_iobuf, &io, "[]");
  } else {
    if (last_seq != NULL && *last_seq < since_seq) *last_seq = since_seq;
    append_logs_json(&io, task, since_seq, last_seq,
                     REG_TASK_WS_LOG_BATCH_LIMIT);
    if (has_logs != NULL && last_seq != NULL && *last_seq > before) {
      *has_logs = true;
    }
  }
  pthread_mutex_unlock(&s_tasks_mu);
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

void registration_ws_open(struct mg_connection *c) {
  struct registration_ws_state *state;
  if (c == NULL) return;
  state = (struct registration_ws_state *) calloc(1, sizeof(*state));
  c->fn_data = state;
}

void registration_ws_close(struct mg_connection *c) {
  if (c == NULL) return;
  free(c->fn_data);
  c->fn_data = NULL;
}

bool registration_ws_handle_message(struct mg_connection *c, struct mg_str data,
                                    sqlite3 *db, uint64_t started_ms) {
  struct registration_ws_state *state;
  char *type;
  char *task_id;

  if (c == NULL || !c->is_websocket) return false;
  state = (struct registration_ws_state *) c->fn_data;
  if (state == NULL) return false;

  type = mg_json_get_str(data, "$.type");
  task_id = mg_json_get_str(data, "$.task_id");
  if (type != NULL && strcmp(type, "system_subscribe") == 0) {
    long interval_ms = mg_json_get_long(data, "$.interval_ms", 3000);
    state->system_subscribed = true;
    state->system_interval_ms = clamp_system_interval(interval_ms);
    state->last_system_status_ms = 0;
    mg_ws_printf(c, WEBSOCKET_OP_TEXT,
                 "{%m:%m,%m:%llu}", MG_ESC("type"),
                 MG_ESC("system_subscribed"), MG_ESC("interval_ms"),
                 (unsigned long long) state->system_interval_ms);
    send_system_status(c, db, started_ms);
    state->last_system_status_ms = now_ms();
  } else if (type != NULL && strcmp(type, "system_unsubscribe") == 0) {
    state->system_subscribed = false;
    mg_ws_printf(c, WEBSOCKET_OP_TEXT,
                 "{%m:%m}", MG_ESC("type"), MG_ESC("system_unsubscribed"));
  } else if (type != NULL &&
      (strcmp(type, "registration_subscribe") == 0 ||
       strcmp(type, "subscribe_registration") == 0 ||
       strcmp(type, "subscribe") == 0) &&
      task_id != NULL && task_id[0] != '\0') {
    char *detail;
    long last_seq = mg_json_get_long(data, "$.last_seq", -1);
    mg_snprintf(state->task_id, sizeof(state->task_id), "%s", task_id);
    state->last_seq = last_seq > 0 ? (uint64_t) last_seq
                                   : registration_task_latest_log_seq(
                                         state->task_id);
    state->last_status_ms = 0;
    mg_ws_printf(c, WEBSOCKET_OP_TEXT,
                 "{%m:%m,%m:%m}", MG_ESC("type"),
                 MG_ESC("registration_subscribed"), MG_ESC("task_id"),
                 MG_ESC(state->task_id));
    detail = registration_task_detail_json(state->task_id, false, 0);
    mg_ws_printf(c, WEBSOCKET_OP_TEXT,
                 "{%m:%m,%m:%s}", MG_ESC("type"),
                 MG_ESC("registration_task"), MG_ESC("payload"),
                 detail ? detail : "{}");
    free(detail);
  } else {
    mg_ws_printf(c, WEBSOCKET_OP_TEXT,
                 "{%m:%m,%m:%m}", MG_ESC("type"), MG_ESC("echo"),
                 MG_ESC("status"), MG_ESC("ok"));
  }
  mg_free(type);
  mg_free(task_id);
  return true;
}

void registration_ws_poll(struct mg_mgr *mgr, sqlite3 *db, uint64_t started_ms) {
  static uint64_t s_last_poll_ms;
  uint64_t now = now_ms();
  if (mgr == NULL) return;
  if (now - s_last_poll_ms < 200) return;
  s_last_poll_ms = now;
  for (struct mg_connection *c = mgr->conns; c != NULL; c = c->next) {
    struct registration_ws_state *state =
        (struct registration_ws_state *) c->fn_data;
    if (!c->is_websocket || state == NULL) continue;

    if (state->system_subscribed &&
        now - state->last_system_status_ms >= state->system_interval_ms) {
      send_system_status(c, db, started_ms);
      state->last_system_status_ms = now;
    }

    if (state->task_id[0] == '\0') continue;

    bool has_logs = false;
    uint64_t last_seq = state->last_seq;
    char *logs = logs_since_json(state->task_id, state->last_seq, &last_seq,
                                 &has_logs);
    if (has_logs) {
      mg_ws_printf(c, WEBSOCKET_OP_TEXT,
                   "{%m:%m,%m:%m,%m:%s}", MG_ESC("type"),
                   MG_ESC("registration_logs"), MG_ESC("task_id"),
                   MG_ESC(state->task_id), MG_ESC("logs"), logs ? logs : "[]");
      state->last_seq = last_seq;
    }
    free(logs);

    if (now - state->last_status_ms >= 1000) {
      char *detail = registration_task_detail_json(state->task_id, false, 0);
      mg_ws_printf(c, WEBSOCKET_OP_TEXT,
                   "{%m:%m,%m:%s}", MG_ESC("type"),
                   MG_ESC("registration_task"), MG_ESC("payload"),
                   detail ? detail : "{}");
      free(detail);
      state->last_status_ms = now;
    }
  }
}
