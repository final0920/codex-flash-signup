#ifndef APP_REGISTRATION_TASKS_H
#define APP_REGISTRATION_TASKS_H

#include "flow/flow_engine.h"
#include "mongoose.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

#define REG_TASK_ID_LEN 32

enum registration_workflow {
  REG_WORKFLOW_REGISTER_ONLY = 0,
  REG_WORKFLOW_REGISTER_THEN_OAUTH,
  REG_WORKFLOW_REGISTER_THEN_CURRENT_CODEX,
  REG_WORKFLOW_OAUTH_ONLY,
  REG_WORKFLOW_CHATGPT_LOGIN_ONLY,
  REG_WORKFLOW_CODEX_CLI_SIMPLIFIED,
  REG_WORKFLOW_OUTLOOK_DIRECT
};

enum registration_scheduler_mode {
  REG_SCHEDULER_NORMAL = 0,
  REG_SCHEDULER_FASTLANE
};

enum registration_target_metric {
  REG_TARGET_REGISTER_TASK = 0,
  REG_TARGET_OAUTH_SUCCESS
};

enum registration_register_provider {
  REG_REGISTER_PROVIDER_PLATFORM = 0,
  REG_REGISTER_PROVIDER_TEMPORARY
};

enum registration_request_core {
  REG_REQUEST_CORE_LIBCURL_IMPERSONATE = 0,
  REG_REQUEST_CORE_CURL_IMPERSONATE,
  REG_REQUEST_CORE_LIBCURL
};

enum registration_current_session_oauth_fallback_mode {
  REG_CURRENT_SESSION_OAUTH_FALLBACK_NONE = 0,
  REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE,
  REG_CURRENT_SESSION_OAUTH_FALLBACK_DOUBLE,
  REG_CURRENT_SESSION_OAUTH_FALLBACK_SINGLE_TIMEOUT_RETRY
};

enum registration_auto_upload_service_mode {
  REG_AUTO_UPLOAD_SERVICE_ALL = 0,
  REG_AUTO_UPLOAD_SERVICE_RANDOM,
  REG_AUTO_UPLOAD_SERVICE_FIXED
};

struct registration_start_options {
  enum registration_workflow workflow;
  enum registration_scheduler_mode scheduler_mode;
  enum registration_target_metric target_metric;
  enum registration_register_provider register_provider;
  enum registration_request_core request_core;
  enum registration_current_session_oauth_fallback_mode
      current_session_oauth_fallback_mode;
  enum registration_auto_upload_service_mode auto_upload_service_mode;
  const char *libcurl_impersonate_target;
  const char *mihomo_node;
  long auto_upload_service_id;
  int count;
  int concurrency;
  int max_inflight;
  int oauth_delay_seconds;
  int current_session_oauth_retry_after_seconds;
  bool detailed_logs;
  bool infinite;
  bool auto_upload_oauth_success;
  bool current_session_oauth_fallback;
  bool discard_oauth_failed_accounts;
  bool fast_email_otp_resend;
  const long *account_ids;
  size_t account_id_count;
};

int registration_tasks_start(const struct registration_start_options *options,
                             char *task_id, size_t task_id_len,
                             char *error, size_t error_len);
char *registration_tasks_list_json(void);
char *registration_task_detail_json(const char *task_id, bool include_logs,
                                    size_t log_limit);
void registration_tasks_counts(int *active_tasks, int *active_flows,
                               int *queued_flows);
int registration_tasks_stop(const char *task_id, char *error, size_t error_len);

void registration_ws_open(struct mg_connection *c);
void registration_ws_close(struct mg_connection *c);
bool registration_ws_handle_message(struct mg_connection *c,
                                    struct mg_str data, sqlite3 *db,
                                    uint64_t started_ms);
void registration_ws_poll(struct mg_mgr *mgr, sqlite3 *db, uint64_t started_ms);

#endif
