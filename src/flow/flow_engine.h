#ifndef APP_FLOW_ENGINE_H
#define APP_FLOW_ENGINE_H

#include "http_client/browser_profile.h"
#include "identity/identity_generator.h"

#include <stdbool.h>
#include <stddef.h>
#include <sqlite3.h>

#define FLOW_ID_LEN 48
#define FLOW_PROXY_LEN 512
#define FLOW_ERROR_LEN 256
#define FLOW_TOKEN_LEN 4096
#define FLOW_CODE_LEN 2048
#define FLOW_PKCE_VERIFIER_LEN 160
#define FLOW_EXTERNAL_ID_LEN 160
#define FLOW_WORKSPACE_ID_LEN 160
#define FLOW_IMPERSONATE_TARGET_LEN 64
#define FLOW_URL_LEN 8192
#define FLOW_LOG_LEN 1024
#define FLOW_COOKIE_LEN 8192
#define FLOW_DEFAULT_CONNECT_TIMEOUT_MS 8000L
#define FLOW_EVENT_EMAIL_OTP_WAITING "email_otp_waiting"
#define FLOW_EVENT_EMAIL_OTP_VALIDATED "email_otp_validated"
#define FLOW_EVENT_OAUTH_OTP_VALIDATED "oauth_otp_validated"

enum flow_mode {
  FLOW_MODE_REGISTER_ONLY = 0,
  FLOW_MODE_REGISTER_THEN_OAUTH,
  FLOW_MODE_REGISTER_THEN_CURRENT_CODEX
};

enum flow_status {
  FLOW_STATUS_PENDING = 0,
  FLOW_STATUS_RUNNING,
  FLOW_STATUS_SUCCESS,
  FLOW_STATUS_FAILED,
  FLOW_STATUS_CANCELLED
};

enum flow_provider_action {
  FLOW_PROVIDER_FAILED = -1,
  FLOW_PROVIDER_WAIT = 0,
  FLOW_PROVIDER_REQUEST = 1,
  FLOW_PROVIDER_DONE = 2
};

struct flow_http_header {
  const char *name;
  const char *value;
};

struct flow_http_request {
  const char *method;
  const char *url;
  const char *body;
  size_t body_len;
  long timeout_ms;
  long connect_timeout_ms;
  bool follow_location;
  const struct flow_http_header *headers;
  size_t num_headers;
};

static inline long flow_http_effective_connect_timeout_ms(
    const struct flow_http_request *request) {
  long timeout_ms = request != NULL ? request->timeout_ms : 0;
  long connect_ms = request != NULL ? request->connect_timeout_ms : 0;
  if (connect_ms <= 0) connect_ms = FLOW_DEFAULT_CONNECT_TIMEOUT_MS;
  if (timeout_ms > 0 && connect_ms > timeout_ms) connect_ms = timeout_ms;
  return connect_ms > 0 ? connect_ms : timeout_ms;
}

struct flow_http_response {
  long status_code;
  char *body;
  size_t body_len;
  char effective_url[FLOW_URL_LEN];
  char location[FLOW_URL_LEN];
  char device_id[80];
  char primary_ip[128];
  char content_type[160];
  char server[80];
  char cf_mitigated[80];
  char cf_ray[160];
  char auth_session_cookie[FLOW_COOKIE_LEN];
  char auth_info_cookie[FLOW_COOKIE_LEN];
  char chatgpt_session_token[FLOW_COOKIE_LEN];
  char cookie_header[FLOW_COOKIE_LEN];
  char error[FLOW_ERROR_LEN];
};

struct flow_context {
  char id[FLOW_ID_LEN];
  enum flow_mode mode;
  enum flow_status status;
  int step;
  int retry_count;
  long deadline_ms;
  long next_retry_ms;
  sqlite3 *db;
  char proxy_url[FLOW_PROXY_LEN];
  struct browser_profile profile;
  struct identity_result identity;
  char access_token[FLOW_TOKEN_LEN];
  char refresh_token[FLOW_TOKEN_LEN];
  char id_token[FLOW_TOKEN_LEN];
  char session_token[FLOW_COOKIE_LEN];
  char cookies[FLOW_COOKIE_LEN];
  char authorization_code[FLOW_CODE_LEN];
  char pkce_code_verifier[FLOW_PKCE_VERIFIER_LEN];
  char external_account_id[FLOW_EXTERNAL_ID_LEN];
  char workspace_id[FLOW_WORKSPACE_ID_LEN];
  char impersonate_target[FLOW_IMPERSONATE_TARGET_LEN];
  char success_account_status[24];
  char success_auth_source[32];
  bool persist_on_success;
  bool environment_retryable;
  bool identity_retryable;
  long account_id;
  long persisted_account_id;
  long oauth_otp_timeout_ms;
  bool fast_email_otp_resend;
  char error[FLOW_ERROR_LEN];
  void *provider_data;
  void (*log_fn)(struct flow_context *flow, const char *level,
                 const char *message, void *userdata);
  void (*finish_fn)(struct flow_context *flow, void *userdata);
  bool (*cancel_fn)(struct flow_context *flow, void *userdata);
  void (*event_fn)(struct flow_context *flow, const char *event,
                   void *userdata);
  void *callback_data;
};

struct flow_provider {
  const char *name;
  int (*start)(struct flow_context *flow);
  enum flow_provider_action (*next_request)(struct flow_context *flow,
                                            struct flow_http_request *request);
  int (*on_response)(struct flow_context *flow,
                     const struct flow_http_response *response);
  void (*cleanup)(struct flow_context *flow);
};

struct flow_engine;

struct flow_engine_options {
  sqlite3 *db;
  size_t max_concurrency;
};

struct flow_start_options {
  enum flow_mode mode;
  const char *proxy_url;
  const struct browser_profile *profile;
  const struct identity_result *identity;
  const char *workspace_id;
  const char *impersonate_target;
  sqlite3 *db;
  bool persist_on_success;
  long account_id;
  long deadline_ms;
  long oauth_otp_timeout_ms;
  bool fast_email_otp_resend;
  void (*log_fn)(struct flow_context *flow, const char *level,
                 const char *message, void *userdata);
  void (*finish_fn)(struct flow_context *flow, void *userdata);
  bool (*cancel_fn)(struct flow_context *flow, void *userdata);
  void (*event_fn)(struct flow_context *flow, const char *event,
                   void *userdata);
  void *callback_data;
};

int flow_engine_create(const struct flow_engine_options *options,
                       struct flow_engine **out);
void flow_engine_destroy(struct flow_engine *engine);
int flow_engine_add(struct flow_engine *engine, const struct flow_provider *provider,
                    const struct flow_start_options *options,
                    struct flow_context **out_flow);
int flow_engine_run_once(struct flow_engine *engine, long timeout_ms);
int flow_engine_run_until_idle(struct flow_engine *engine, long timeout_ms);
size_t flow_engine_active_count(const struct flow_engine *engine);
size_t flow_engine_total_count(const struct flow_engine *engine);

const char *flow_status_name(enum flow_status status);
void flow_context_fail(struct flow_context *flow, const char *message);
void flow_context_cancel(struct flow_context *flow, const char *message);
bool flow_context_cancel_requested(struct flow_context *flow);
void flow_context_mark_environment_retry(struct flow_context *flow,
                                         const char *message);
void flow_context_mark_identity_retry(struct flow_context *flow,
                                      const char *message);
void flow_context_log(struct flow_context *flow, const char *level,
                      const char *fmt, ...);
void flow_context_emit_event(struct flow_context *flow, const char *event);
bool flow_response_is_edge_block(const struct flow_http_response *response);
bool flow_response_is_email_already_registered(
    const struct flow_http_response *response);
bool flow_response_is_invalid_auth_step(
    const struct flow_http_response *response);

#endif
