#include "registration/web_register_provider.h"

#include "mail/rapid_inbox.h"
#include "mongoose.h"
#include "oauth/codex_session_oauth.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define APP_BASE_URL "https://chatgpt.com"
#define AUTH_BASE_URL "https://auth.openai.com"
#define OAUTH_CLIENT_ID "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"
#define OAUTH_SCOPE "openid%20email%20profile%20offline_access%20model.request%20model.read%20organization.read%20organization.write"
#define OAUTH_SCOPE_CALLBACK "openid+email+profile+offline_access+model.request+model.read+organization.read+organization.write"
#define OAUTH_AUDIENCE "https%3A%2F%2Fapi.openai.com%2Fv1"
#define OAUTH_REDIRECT_URI "https%3A%2F%2Fchatgpt.com%2Fapi%2Fauth%2Fcallback%2Fopenai"
#define EMAIL_OTP_POLL_INTERVAL_MS 1500L
#define EMAIL_OTP_ERROR_POLL_INTERVAL_MS 2500L
#define EMAIL_OTP_FAST_RESEND_WAIT_MS 10000L
#define EMAIL_OTP_FAST_RESEND_FINAL_TIMEOUT_MS 30000L
#define EMAIL_OTP_FAST_RESEND_MAX_COUNT 3

enum register_step {
  STEP_PROVIDERS = 0,
  STEP_CSRF,
  STEP_SIGNIN,
  STEP_AUTHORIZE,
  STEP_EMAIL_VERIFICATION,
  STEP_OTP_RESEND,
  STEP_OTP_VALIDATE,
  STEP_SESSION_DUMP,
  STEP_CREATE_ACCOUNT,
  STEP_CONTINUE,
  STEP_CALLBACK,
  STEP_ME,
  STEP_ACCOUNT_CHECK,
  STEP_SESSION,
  STEP_TOKEN_EXCHANGE,
  STEP_CODEX_OAUTH,
  STEP_DONE
};

struct web_register_state {
  char device_id[48];
  char logging_id[48];
  char csrf[160];
  char authorize_url[FLOW_URL_LEN];
  char email_verification_url[FLOW_URL_LEN];
  char continue_url[FLOW_URL_LEN];
  char callback_url[FLOW_URL_LEN];
  char state[256];
  char session_token[FLOW_COOKIE_LEN];
  char cookies[FLOW_COOKIE_LEN];
  char otp_code[64];
  char body[1024];
  char url[FLOW_URL_LEN];
  struct codex_current_session_state codex;
  int otp_attempts;
  int otp_resend_count;
  int redirect_attempts;
  long otp_last_request_ms;
  long otp_last_request_after_epoch;
  bool login_only;
};

static const struct flow_http_header s_ofoco_api_headers[] = {
    {"Accept", "*/*"},
    {"Content-Type", "application/json"},
    {"Referer", APP_BASE_URL "/"},
    {"Sec-Fetch-Dest", "empty"},
    {"Sec-Fetch-Mode", "cors"},
    {"Sec-Fetch-Site", "same-origin"},
};

static const struct flow_http_header s_signin_headers[] = {
    {"Accept", "*/*"},
    {"Content-Type", "application/x-www-form-urlencoded"},
    {"Origin", APP_BASE_URL},
    {"Referer", APP_BASE_URL "/"},
    {"Sec-Fetch-Dest", "empty"},
    {"Sec-Fetch-Mode", "cors"},
    {"Sec-Fetch-Site", "same-origin"},
};

static const struct flow_http_header s_auth_nav_headers[] = {
    {"Accept",
     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
     "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
    {"Referer", APP_BASE_URL "/"},
    {"Sec-Fetch-Dest", "document"},
    {"Sec-Fetch-Mode", "navigate"},
    {"Sec-Fetch-Site", "cross-site"},
    {"Sec-Fetch-User", "?1"},
    {"Upgrade-Insecure-Requests", "1"},
};

static const struct flow_http_header s_auth_json_headers[] = {
    {"Accept", "application/json"},
    {"Content-Type", "application/json"},
    {"Origin", AUTH_BASE_URL},
    {"Referer", AUTH_BASE_URL "/email-verification"},
    {"Sec-Fetch-Dest", "empty"},
    {"Sec-Fetch-Mode", "cors"},
    {"Sec-Fetch-Site", "same-origin"},
};

static const struct flow_http_header s_auth_resend_headers[] = {
    {"Accept", "*/*"},
    {"Origin", AUTH_BASE_URL},
    {"Referer", AUTH_BASE_URL "/email-verification"},
    {"Sec-Fetch-Dest", "empty"},
    {"Sec-Fetch-Mode", "cors"},
    {"Sec-Fetch-Site", "same-origin"},
};

static const struct flow_http_header s_create_account_headers[] = {
    {"Accept", "application/json"},
    {"Content-Type", "application/json"},
    {"Origin", AUTH_BASE_URL},
    {"Referer", AUTH_BASE_URL "/about-you"},
    {"Sec-Fetch-Dest", "empty"},
    {"Sec-Fetch-Mode", "cors"},
    {"Sec-Fetch-Site", "same-origin"},
};

static const struct flow_http_header s_callback_headers[] = {
    {"Accept",
     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
     "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
    {"Referer", AUTH_BASE_URL "/"},
    {"Sec-Fetch-Dest", "document"},
    {"Sec-Fetch-Mode", "navigate"},
    {"Sec-Fetch-Site", "cross-site"},
    {"Sec-Fetch-User", "?1"},
    {"Upgrade-Insecure-Requests", "1"},
};

static const struct flow_http_header s_me_headers[] = {
    {"Accept", "*/*"},
    {"Referer", APP_BASE_URL "/"},
    {"Sec-Fetch-Dest", "empty"},
    {"Sec-Fetch-Mode", "cors"},
    {"Sec-Fetch-Site", "same-origin"},
};

static const struct flow_http_header s_session_headers[] = {
    {"Accept", "application/json"},
    {"Referer", APP_BASE_URL "/"},
    {"Sec-Fetch-Dest", "empty"},
    {"Sec-Fetch-Mode", "cors"},
    {"Sec-Fetch-Site", "same-origin"},
};

static const struct flow_http_header s_token_exchange_headers[] = {
    {"Accept", "*/*"},
    {"Content-Type", "application/json"},
    {"Origin", APP_BASE_URL},
    {"Referer", APP_BASE_URL "/"},
    {"Sec-Fetch-Dest", "empty"},
    {"Sec-Fetch-Mode", "cors"},
    {"Sec-Fetch-Site", "same-site"},
};

static void random_uuid_like(char *out, size_t out_len) {
  uint8_t bytes[16];
  if (out_len == 0) return;
  if (!mg_random(bytes, sizeof(bytes))) {
    for (size_t i = 0; i < sizeof(bytes); i++) bytes[i] = (uint8_t) rand();
  }
  bytes[6] = (uint8_t) ((bytes[6] & 0x0f) | 0x40);
  bytes[8] = (uint8_t) ((bytes[8] & 0x3f) | 0x80);
  mg_snprintf(out, out_len,
              "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
              "%02x%02x%02x%02x%02x%02x",
              bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
              bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
              bytes[12], bytes[13], bytes[14], bytes[15]);
}

static bool copy_json_path(const char *json, const char *path, char *out,
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

static void proxy_scheme_label(const char *proxy_url, char *out, size_t out_len) {
  const char *p;
  size_t len;
  if (out_len == 0) return;
  out[0] = '\0';
  if (proxy_url == NULL || proxy_url[0] == '\0') return;
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

static bool copy_json_string_key(const char *json, const char *key, char *out,
                                 size_t out_len) {
  const char *p, *value, *end;
  char needle[128];

  if (json == NULL || key == NULL || out == NULL || out_len == 0) return false;
  mg_snprintf(needle, sizeof(needle), "\"%s\"", key);
  p = strstr(json, needle);
  if (p == NULL) return false;
  p += strlen(needle);
  while (*p && isspace((unsigned char) *p)) p++;
  if (*p != ':') return false;
  p++;
  while (*p && isspace((unsigned char) *p)) p++;
  if (*p != '"') return false;
  value = ++p;
  while (*p && (*p != '"' || p[-1] == '\\')) p++;
  end = p;
  if (end <= value) return false;
  mg_snprintf(out, out_len, "%.*s", (int) (end - value), value);
  return true;
}

static bool copy_first_url(const char *body, char *out, size_t out_len,
                           const char *must_contain) {
  const char *p = body;
  if (body == NULL || out == NULL || out_len == 0) return false;
  while ((p = strstr(p, "https://")) != NULL) {
    const char *end = p;
    size_t len;
    while (*end && *end != '"' && *end != '\'' && !isspace((unsigned char) *end) &&
           *end != '<' && *end != '\\') {
      end++;
    }
    len = (size_t) (end - p);
    if (must_contain == NULL || must_contain[0] == '\0' ||
        (len > 0 && strstr(p, must_contain) != NULL)) {
      if (len >= out_len) len = out_len - 1;
      memcpy(out, p, len);
      out[len] = '\0';
      return true;
    }
    p = end;
  }
  return false;
}

static bool copy_any_redirect_url(const char *body, char *out, size_t out_len,
                                  const char *must_contain) {
  return copy_json_path(body, "$.url", out, out_len) ||
         copy_json_path(body, "$.continue_url", out, out_len) ||
         copy_json_path(body, "$.continueUrl", out, out_len) ||
         copy_json_path(body, "$.redirectUrl", out, out_len) ||
         copy_json_path(body, "$.redirect_url", out, out_len) ||
         copy_json_path(body, "$.callbackUrl", out, out_len) ||
         copy_json_path(body, "$.authorizationUrl", out, out_len) ||
         copy_json_path(body, "$.authorization_url", out, out_len) ||
         copy_first_url(body, out, out_len, must_contain);
}

static bool is_chatgpt_callback_url(const char *url) {
  return url != NULL && strstr(url, "/api/auth/callback/openai") != NULL;
}

static void make_absolute_url(const char *base, const char *location,
                              char *out, size_t out_len) {
  const char *scheme_end;
  const char *host_start;
  const char *path_start;
  size_t origin_len;

  if (out_len == 0) return;
  out[0] = '\0';
  if (location == NULL || location[0] == '\0') return;
  if (strncmp(location, "https://", 8) == 0 ||
      strncmp(location, "http://", 7) == 0) {
    mg_snprintf(out, out_len, "%s", location);
    return;
  }
  if (base == NULL || base[0] == '\0') {
    mg_snprintf(out, out_len, "%s", location);
    return;
  }
  scheme_end = strstr(base, "://");
  if (scheme_end == NULL) {
    mg_snprintf(out, out_len, "%s", location);
    return;
  }
  host_start = scheme_end + 3;
  path_start = strchr(host_start, '/');
  origin_len = path_start == NULL ? strlen(base) : (size_t) (path_start - base);
  if (location[0] == '/') {
    mg_snprintf(out, out_len, "%.*s%s", (int) origin_len, base, location);
    return;
  }
  if (origin_len + 1 + strlen(location) < out_len) {
    mg_snprintf(out, out_len, "%.*s/%s", (int) origin_len, base, location);
  } else {
    mg_snprintf(out, out_len, "%s", location);
  }
}

static void query_value_from_url(const char *url, const char *name, char *out,
                                 size_t out_len) {
  const char *q;
  char buf[512];
  if (out_len == 0) return;
  out[0] = '\0';
  if (url == NULL || name == NULL) return;
  q = strchr(url, '?');
  if (q == NULL) return;
  struct mg_str query = mg_str_n((char *) q + 1, strlen(q + 1));
  if (mg_http_get_var(&query, name, buf, sizeof(buf)) > 0) {
    mg_snprintf(out, out_len, "%s", buf);
  }
}

static void request_get(struct flow_http_request *request, const char *url,
                        const struct flow_http_header *headers,
                        size_t num_headers) {
  request->method = "GET";
  request->url = url;
  request->timeout_ms = 30000;
  request->follow_location = false;
  request->headers = headers;
  request->num_headers = num_headers;
}

static void request_post(struct flow_http_request *request, const char *url,
                         const char *body,
                         const struct flow_http_header *headers,
                         size_t num_headers) {
  request->method = "POST";
  request->url = url;
  request->body = body;
  request->body_len = body == NULL ? 0 : strlen(body);
  request->timeout_ms = 30000;
  request->follow_location = false;
  request->headers = headers;
  request->num_headers = num_headers;
}

static void request_post_no_body(struct flow_http_request *request, const char *url,
                                 const struct flow_http_header *headers,
                                 size_t num_headers) {
  request->method = "POST";
  request->url = url;
  request->body = NULL;
  request->body_len = 0;
  request->timeout_ms = 30000;
  request->follow_location = false;
  request->headers = headers;
  request->num_headers = num_headers;
}

static const char *step_label(enum register_step step) {
  switch (step) {
    case STEP_PROVIDERS: return "auth providers";
    case STEP_CSRF: return "csrf";
    case STEP_SIGNIN: return "signin";
    case STEP_AUTHORIZE: return "authorize";
    case STEP_EMAIL_VERIFICATION: return "email verification";
    case STEP_OTP_RESEND: return "email otp resend";
    case STEP_OTP_VALIDATE: return "email otp";
    case STEP_SESSION_DUMP: return "session dump";
    case STEP_CREATE_ACCOUNT: return "create account";
    case STEP_CONTINUE: return "continue";
    case STEP_CALLBACK: return "callback";
    case STEP_ME: return "backend me";
    case STEP_ACCOUNT_CHECK: return "account check";
    case STEP_SESSION: return "site session";
    case STEP_TOKEN_EXCHANGE: return "token exchange";
    case STEP_CODEX_OAUTH: return "current session codex oauth";
    case STEP_DONE: return "done";
    default: return "unknown";
  }
}

static void response_summary(const struct flow_http_response *response,
                             char *out, size_t out_len) {
  if (out_len == 0) return;
  out[0] = '\0';
  if (response == NULL) return;
  if (response->status_code >= 200 && response->status_code < 300) {
    mg_snprintf(out, out_len,
                "HTTP %ld url=%s body=%luB ip=%s ct=%s server=%s location=%s",
                response->status_code,
                response->effective_url[0] ? response->effective_url : "-",
                (unsigned long) response->body_len,
                response->primary_ip[0] ? response->primary_ip : "-",
                response->content_type[0] ? response->content_type : "-",
                response->server[0] ? response->server : "-",
                response->location[0] ? response->location : "-");
    return;
  }
  mg_snprintf(out, out_len,
              "HTTP %ld url=%s body=%luB ip=%s ct=%s server=%s cf=%s ray=%s location=%s",
              response->status_code,
              response->effective_url[0] ? response->effective_url : "-",
              (unsigned long) response->body_len,
              response->primary_ip[0] ? response->primary_ip : "-",
              response->content_type[0] ? response->content_type : "-",
              response->server[0] ? response->server : "-",
              response->cf_mitigated[0] ? response->cf_mitigated : "-",
              response->cf_ray[0] ? response->cf_ray : "-",
              response->location[0] ? response->location : "-");
}

static void body_preview(const struct flow_http_response *response, char *out,
                         size_t out_len) {
  size_t i, n = 0;
  if (out_len == 0) return;
  out[0] = '\0';
  if (response == NULL || response->body == NULL || response->body_len == 0) return;
  for (i = 0; i < response->body_len && n + 1 < out_len; i++) {
    unsigned char ch = (unsigned char) response->body[i];
    if (ch == '\r' || ch == '\n' || ch == '\t') {
      if (n > 0 && out[n - 1] != ' ') out[n++] = ' ';
    } else if (isprint(ch)) {
      out[n++] = (char) ch;
    } else if (n > 0 && out[n - 1] != ' ') {
      out[n++] = ' ';
    }
    if (n >= 160) break;
  }
  while (n > 0 && out[n - 1] == ' ') n--;
  out[n] = '\0';
}

static void copy_response_credentials(struct web_register_state *state,
                                      struct flow_context *flow,
                                      const struct flow_http_response *response) {
  if (state == NULL || flow == NULL || response == NULL) return;
  if (response->chatgpt_session_token[0] != '\0') {
    mg_snprintf(state->session_token, sizeof(state->session_token), "%s",
                response->chatgpt_session_token);
    mg_snprintf(flow->session_token, sizeof(flow->session_token), "%s",
                response->chatgpt_session_token);
  }
  if (response->cookie_header[0] != '\0') {
    mg_snprintf(state->cookies, sizeof(state->cookies), "%s",
                response->cookie_header);
    mg_snprintf(flow->cookies, sizeof(flow->cookies), "%s",
                response->cookie_header);
  }
}

static int provider_start_impl(struct flow_context *flow, bool login_only) {
  struct web_register_state *state;

  state = (struct web_register_state *) calloc(1, sizeof(*state));
  if (state == NULL) return -1;
  state->login_only = login_only;
  random_uuid_like(state->device_id, sizeof(state->device_id));
  random_uuid_like(state->logging_id, sizeof(state->logging_id));
  flow->provider_data = state;
  flow->step = STEP_PROVIDERS;
  if (flow->deadline_ms <= 0) flow->deadline_ms = (long) mg_millis() + 180000;
  flow_context_log(flow, "info", "准备%s邮箱 %s",
                   login_only ? "ChatGPT 登录" : "注册",
                   flow->identity.email);
  if (flow->mode == FLOW_MODE_REGISTER_THEN_CURRENT_CODEX) {
    flow_context_log(flow, "info",
                     "注册完成后将复用当前登录会话继续 Codex OAuth");
  }
  if (flow->proxy_url[0] != '\0') {
    char scheme[24];
    proxy_scheme_label(flow->proxy_url, scheme, sizeof(scheme));
    flow_context_log(flow, "info", "流程代理已锚定: %s",
                     scheme[0] ? scheme : "proxy");
  } else {
    flow_context_log(flow, "info", "未分配代理，当前流程使用直连");
  }
  return 0;
}

static int provider_start(struct flow_context *flow) {
  return provider_start_impl(flow, false);
}

static int provider_login_start(struct flow_context *flow) {
  return provider_start_impl(flow, true);
}

static bool fast_otp_resend_enabled(const struct flow_context *flow) {
  return flow != NULL && flow->fast_email_otp_resend;
}

static void mark_otp_request_sent(struct web_register_state *state) {
  if (state == NULL) return;
  state->otp_last_request_ms = (long) mg_millis();
  state->otp_last_request_after_epoch = (long) time(NULL);
  state->otp_attempts = 0;
  state->otp_code[0] = '\0';
}

static long next_otp_policy_boundary_ms(const struct flow_context *flow,
                                        const struct web_register_state *state) {
  if (!fast_otp_resend_enabled(flow) || state == NULL ||
      state->otp_last_request_ms <= 0) {
    return 0;
  }
  if (state->otp_resend_count >= EMAIL_OTP_FAST_RESEND_MAX_COUNT) {
    return state->otp_last_request_ms + EMAIL_OTP_FAST_RESEND_FINAL_TIMEOUT_MS;
  }
  return state->otp_last_request_ms + EMAIL_OTP_FAST_RESEND_WAIT_MS;
}

static void schedule_otp_poll(struct flow_context *flow,
                              const struct web_register_state *state,
                              long now, long interval_ms) {
  long next = now + interval_ms;
  long cap = next_otp_policy_boundary_ms(flow, state);
  if (cap > 0 && next > cap) next = cap;
  flow->next_retry_ms = next;
}

static bool fast_resend_wait_timed_out(const struct flow_context *flow,
                                       const struct web_register_state *state,
                                       long now) {
  return fast_otp_resend_enabled(flow) && state != NULL &&
         state->otp_resend_count >= EMAIL_OTP_FAST_RESEND_MAX_COUNT &&
         state->otp_last_request_ms > 0 &&
         now - state->otp_last_request_ms >=
             EMAIL_OTP_FAST_RESEND_FINAL_TIMEOUT_MS;
}

static bool should_fast_resend_otp(const struct flow_context *flow,
                                   const struct web_register_state *state,
                                   long now) {
  return fast_otp_resend_enabled(flow) && state != NULL &&
         state->otp_resend_count < EMAIL_OTP_FAST_RESEND_MAX_COUNT &&
         state->otp_last_request_ms > 0 &&
         now - state->otp_last_request_ms >= EMAIL_OTP_FAST_RESEND_WAIT_MS;
}

static void fail_fast_resend_timeout(struct flow_context *flow) {
  flow_context_fail(flow, "快速重发后 30 秒内未收到邮箱验证码");
  flow_context_log(flow, "warn",
                   "验证码已连续快速重发 3 次，最后一次 30 秒内仍未送达，放弃当前注册流程，email=%s",
                   flow->identity.email);
}

static enum flow_provider_action request_otp_resend(
    struct flow_context *flow, struct flow_http_request *request,
    struct web_register_state *state) {
  state->otp_resend_count++;
  mark_otp_request_sent(state);
  // email-otp/resend 仅接受 application/json; 发空 json body, 避免底层
  // libcurl-impersonate 默认填 application/x-www-form-urlencoded 被 OpenAI 拒(4xx)
  mg_snprintf(state->body, sizeof(state->body), "{}");
  request_post(request, AUTH_BASE_URL "/api/accounts/email-otp/resend",
               state->body, s_auth_json_headers,
               sizeof(s_auth_json_headers) / sizeof(s_auth_json_headers[0]));
  flow->step = STEP_OTP_RESEND;
  if (fast_otp_resend_enabled(flow)) {
    flow_context_log(flow, "info", "步骤 %s: 触发验证码邮件重发 %d/%d，email=%s",
                     step_label(flow->step), state->otp_resend_count,
                     EMAIL_OTP_FAST_RESEND_MAX_COUNT, flow->identity.email);
  } else {
    flow_context_log(flow, "info", "步骤 %s: 触发验证码邮件重发，email=%s",
                     step_label(flow->step), flow->identity.email);
  }
  return FLOW_PROVIDER_REQUEST;
}

static enum flow_provider_action next_otp_request(struct flow_context *flow,
                                                  struct flow_http_request *request) {
  struct web_register_state *state =
      (struct web_register_state *) flow->provider_data;
  char error[256] = "";
  int rc;
  long now = (long) mg_millis();

  if (fast_resend_wait_timed_out(flow, state, now)) {
    fail_fast_resend_timeout(flow);
    return FLOW_PROVIDER_FAILED;
  }
  if (now > flow->deadline_ms) {
    flow_context_fail(flow, "等待邮箱验证码超时");
    return FLOW_PROVIDER_FAILED;
  }
  if (now < flow->next_retry_ms) return FLOW_PROVIDER_WAIT;

  state->otp_attempts++;
  if (state->otp_last_request_after_epoch > 0) {
    rc = rapid_inbox_fetch_latest_code_since(
        flow->db, flow->identity.email, state->otp_last_request_after_epoch,
        state->otp_code, sizeof(state->otp_code), error, sizeof(error));
  } else {
    rc = rapid_inbox_fetch_latest_code(flow->db, flow->identity.email,
                                       state->otp_code, sizeof(state->otp_code),
                                       error, sizeof(error));
  }
  now = (long) mg_millis();
  if (rc == 0) {
    if (fast_resend_wait_timed_out(flow, state, now)) {
      flow_context_log(flow, "warn", "验证码读取未命中后超时: email=%s，reason=%s",
                       flow->identity.email,
                       error[0] ? error : "邮件服务未返回验证码");
      fail_fast_resend_timeout(flow);
      return FLOW_PROVIDER_FAILED;
    }
    if (should_fast_resend_otp(flow, state, now)) {
      flow_context_log(flow, "warn", "验证码读取未命中: email=%s，reason=%s",
                       flow->identity.email,
                       error[0] ? error : "邮件服务未返回验证码");
      return request_otp_resend(flow, request, state);
    }
    flow_context_log(flow, "debug",
                     "等待邮箱验证码，第 %d 次轮询，email=%s，reason=%s",
                     state->otp_attempts, flow->identity.email,
                     error[0] ? error : "邮件服务未返回验证码");
    schedule_otp_poll(flow, state, now, EMAIL_OTP_POLL_INTERVAL_MS);
    return FLOW_PROVIDER_WAIT;
  }
  if (rc < 0) {
    if (fast_resend_wait_timed_out(flow, state, now)) {
      flow_context_log(flow, "warn", "验证码读取失败后超时: email=%s，reason=%s",
                       flow->identity.email, error[0] ? error : "unknown");
      fail_fast_resend_timeout(flow);
      return FLOW_PROVIDER_FAILED;
    }
    if (should_fast_resend_otp(flow, state, now)) {
      flow_context_log(flow, "warn", "验证码读取失败: email=%s，reason=%s",
                       flow->identity.email, error[0] ? error : "unknown");
      return request_otp_resend(flow, request, state);
    }
    flow_context_log(flow, "warn", "读取验证码失败: email=%s，reason=%s",
                     flow->identity.email, error[0] ? error : "unknown");
    schedule_otp_poll(flow, state, now, EMAIL_OTP_ERROR_POLL_INTERVAL_MS);
    return FLOW_PROVIDER_WAIT;
  }

  mg_snprintf(state->body, sizeof(state->body), "{\"code\":\"%s\"}",
              state->otp_code);
  request_post(request, AUTH_BASE_URL "/api/accounts/email-otp/validate",
               state->body, s_auth_json_headers,
               sizeof(s_auth_json_headers) / sizeof(s_auth_json_headers[0]));
  flow_context_log(flow, "info", "验证码已获取，提交邮箱验证");
  return FLOW_PROVIDER_REQUEST;
}

static enum flow_provider_action provider_next(struct flow_context *flow,
                                               struct flow_http_request *request) {
  struct web_register_state *state =
      (struct web_register_state *) flow->provider_data;
  char email_enc[512];
  char csrf_enc[256];

  if (state == NULL || request == NULL) {
    flow_context_fail(flow, "注册 provider 状态丢失");
    return FLOW_PROVIDER_FAILED;
  }

  switch (flow->step) {
    case STEP_PROVIDERS:
      request_get(request, APP_BASE_URL "/api/auth/providers",
                  s_ofoco_api_headers,
                  sizeof(s_ofoco_api_headers) / sizeof(s_ofoco_api_headers[0]));
      flow_context_log(flow, "info", "步骤 %s: 请求 %s", step_label(flow->step),
                       request->url);
      return FLOW_PROVIDER_REQUEST;
    case STEP_CSRF:
      request_get(request, APP_BASE_URL "/api/auth/csrf", s_ofoco_api_headers,
                  sizeof(s_ofoco_api_headers) / sizeof(s_ofoco_api_headers[0]));
      flow_context_log(flow, "info", "步骤 %s: 请求 %s", step_label(flow->step),
                       request->url);
      return FLOW_PROVIDER_REQUEST;
    case STEP_SIGNIN:
      if (mg_url_encode(flow->identity.email, strlen(flow->identity.email),
                        email_enc, sizeof(email_enc)) >= sizeof(email_enc) ||
          mg_url_encode(state->csrf, strlen(state->csrf), csrf_enc,
                        sizeof(csrf_enc)) >= sizeof(csrf_enc)) {
        flow_context_fail(flow, "注册邮箱或 CSRF 编码失败");
        return FLOW_PROVIDER_FAILED;
      }
      mg_snprintf(state->url, sizeof(state->url),
                  APP_BASE_URL
                  "/api/auth/signin/openai?prompt=login&ext-oai-did=%s&"
                  "auth_session_logging_id=%s&"
                  "ext-passkey-client-capabilities=1111&"
                  "screen_hint=login_or_signup&login_hint=%s",
                  state->device_id, state->logging_id, email_enc);
      mg_snprintf(state->body, sizeof(state->body),
                  "callbackUrl=https%%3A%%2F%%2Fchatgpt.com%%2F&csrfToken=%s&"
                  "json=true",
                  csrf_enc);
      request_post(request, state->url, state->body, s_signin_headers,
                   sizeof(s_signin_headers) / sizeof(s_signin_headers[0]));
      flow_context_log(flow, "info", "步骤 %s: 提交%s入口 %s",
                       step_label(flow->step),
                       state->login_only ? "ChatGPT 登录" : "注册",
                       flow->identity.email);
      return FLOW_PROVIDER_REQUEST;
    case STEP_AUTHORIZE:
      request_get(request, state->authorize_url, s_auth_nav_headers,
                  sizeof(s_auth_nav_headers) / sizeof(s_auth_nav_headers[0]));
      flow_context_log(flow, "info", "步骤 %s: 打开授权入口 %s",
                       step_label(flow->step), request->url);
      return FLOW_PROVIDER_REQUEST;
    case STEP_EMAIL_VERIFICATION:
      if (state->email_verification_url[0] == '\0') {
        mg_snprintf(state->email_verification_url,
                    sizeof(state->email_verification_url), "%s",
                    AUTH_BASE_URL "/email-verification");
      }
      request_get(request, state->email_verification_url, s_auth_nav_headers,
                  sizeof(s_auth_nav_headers) / sizeof(s_auth_nav_headers[0]));
      flow_context_log(flow, "info", "步骤 %s: 打开邮箱验证页面 %s",
                       step_label(flow->step), request->url);
      return FLOW_PROVIDER_REQUEST;
    case STEP_OTP_RESEND:
      return request_otp_resend(flow, request, state);
    case STEP_OTP_VALIDATE:
      return next_otp_request(flow, request);
    case STEP_SESSION_DUMP:
      request_get(request, AUTH_BASE_URL "/api/accounts/client_auth_session_dump",
                  s_auth_json_headers,
                  sizeof(s_auth_json_headers) / sizeof(s_auth_json_headers[0]));
      flow_context_log(flow, "info", "步骤 %s: 读取 client auth session",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_CREATE_ACCOUNT:
      mg_snprintf(state->body, sizeof(state->body),
                  "{\"name\":\"%s\",\"birthdate\":\"%s\"}",
                  flow->identity.full_name, flow->identity.birthdate);
      request_post(request, AUTH_BASE_URL "/api/accounts/create_account",
                   state->body, s_create_account_headers,
                   sizeof(s_create_account_headers) /
                       sizeof(s_create_account_headers[0]));
      flow_context_log(flow, "info", "步骤 %s: 创建账号资料 %s / %s",
                       step_label(flow->step),
                       flow->identity.full_name, flow->identity.birthdate);
      return FLOW_PROVIDER_REQUEST;
    case STEP_CONTINUE:
      if (state->continue_url[0] == '\0') {
        mg_snprintf(state->continue_url, sizeof(state->continue_url), "%s",
                    state->authorize_url);
      }
      request_get(request, state->continue_url, s_auth_nav_headers,
                  sizeof(s_auth_nav_headers) / sizeof(s_auth_nav_headers[0]));
      flow_context_log(flow, "info", "步骤 %s: 跟随登录继续地址 %s",
                       step_label(flow->step), request->url);
      return FLOW_PROVIDER_REQUEST;
    case STEP_CALLBACK:
      request_get(request, state->callback_url, s_callback_headers,
                  sizeof(s_callback_headers) / sizeof(s_callback_headers[0]));
      flow_context_log(flow, "info", "步骤 %s: 回调站点 %s",
                       step_label(flow->step), request->url);
      return FLOW_PROVIDER_REQUEST;
    case STEP_ME:
      request_get(request, APP_BASE_URL "/backend-api/me", s_me_headers,
                  sizeof(s_me_headers) / sizeof(s_me_headers[0]));
      flow_context_log(flow, "info", "步骤 %s: 读取用户信息", step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_ACCOUNT_CHECK:
      request_get(request,
                  APP_BASE_URL
                  "/backend-api/accounts/check/v4-2023-04-27?"
                  "timezone_offset_min=-480",
                  s_me_headers, sizeof(s_me_headers) / sizeof(s_me_headers[0]));
      flow_context_log(flow, "info", "步骤 %s: 读取账号检查信息",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_SESSION:
      request_get(request, APP_BASE_URL "/api/auth/session", s_session_headers,
                  sizeof(s_session_headers) / sizeof(s_session_headers[0]));
      flow_context_log(flow, "info", "步骤 %s: 读取 ChatGPT session",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_TOKEN_EXCHANGE: {
      char code[FLOW_CODE_LEN] = "";
      query_value_from_url(state->callback_url, "code", code, sizeof(code));
      if (code[0] == '\0') {
        flow_context_log(flow, "debug",
                         "ChatGPT callback 未携带 code，跳过 token exchange");
        flow->step = STEP_DONE;
        return FLOW_PROVIDER_DONE;
      }
      mg_snprintf(state->body, sizeof(state->body),
                  "{\"client_id\":\"%s\",\"grant_type\":\"authorization_code\","
                  "\"code\":\"%s\",\"redirect_uri\":\"https://chatgpt.com/\"}",
                  OAUTH_CLIENT_ID, code);
      request_post(request, AUTH_BASE_URL "/api/accounts/oauth/token",
                   state->body, s_token_exchange_headers,
                   sizeof(s_token_exchange_headers) /
                       sizeof(s_token_exchange_headers[0]));
      flow_context_log(flow, "info",
                       "步骤 %s: 尝试补全 refresh/id token",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    }
    case STEP_CODEX_OAUTH:
      return codex_current_session_next(flow, &state->codex, request);
    case STEP_DONE:
      return FLOW_PROVIDER_DONE;
    default:
      flow_context_fail(flow, "未知注册步骤");
      return FLOW_PROVIDER_FAILED;
  }
}

static bool expect_success(struct flow_context *flow,
                           const struct flow_http_response *response,
                           const char *label) {
  if (response->status_code >= 200 && response->status_code < 400) return true;
  if (flow_response_is_email_already_registered(response)) {
    flow_context_mark_identity_retry(flow,
                                     "邮箱已被远端注册，需要重新生成邮箱重试");
  } else if (flow_response_is_edge_block(response)) {
    flow_context_mark_environment_retry(flow,
                                        "边缘风控拦截，需要重新分配环境重试");
  } else {
    flow_context_fail(flow, "注册请求返回非成功状态");
  }
  {
    char summary[FLOW_LOG_LEN];
    char preview[FLOW_LOG_LEN];
    response_summary(response, summary, sizeof(summary));
    body_preview(response, preview, sizeof(preview));
    flow_context_log(flow, "error", "%s 失败: %s", label, summary);
    if (flow->environment_retryable) {
      flow_context_log(flow, "warn", "%s 触发边缘风控，当前环境将被丢弃并重试",
                       label);
    } else if (flow->identity_retryable) {
      flow_context_log(flow, "warn",
                       "%s 返回邮箱已存在，当前邮箱将被丢弃并换新邮箱重试",
                       label);
    }
    if (preview[0] != '\0') {
      flow_context_log(flow, "warn", "%s 响应片段: %s", label, preview);
    }
  }
  return false;
}

static int provider_response(struct flow_context *flow,
                             const struct flow_http_response *response) {
  struct web_register_state *state =
      (struct web_register_state *) flow->provider_data;

  if (state == NULL || response == NULL) {
    flow_context_fail(flow, "注册响应状态丢失");
    return -1;
  }

  switch (flow->step) {
    case STEP_PROVIDERS:
      if (!expect_success(flow, response, "auth providers")) return -1;
      flow_context_log(flow, "info", "步骤 %s 完成", step_label(flow->step));
      flow->step = STEP_CSRF;
      return 0;
    case STEP_CSRF:
      if (!expect_success(flow, response, "csrf")) return -1;
      if (!copy_json_path(response->body, "$.csrfToken", state->csrf,
                          sizeof(state->csrf))) {
        flow_context_fail(flow, "CSRF token 解析失败");
        return -1;
      }
      flow_context_log(flow, "info", "步骤 %s 完成，csrf=%s",
                       step_label(flow->step), state->csrf);
      flow->step = STEP_SIGNIN;
      return 0;
    case STEP_SIGNIN:
      if (!expect_success(flow, response, "signin")) return -1;
      if (response->location[0] != '\0') {
        mg_snprintf(state->authorize_url, sizeof(state->authorize_url), "%s",
                    response->location);
      } else if (!copy_any_redirect_url(response->body, state->authorize_url,
                                        sizeof(state->authorize_url),
                                        "/api/accounts/authorize")) {
        flow_context_fail(flow, "signin 响应中未找到 authorize URL");
        return -1;
      }
      query_value_from_url(state->authorize_url, "state", state->state,
                           sizeof(state->state));
      flow_context_log(flow, "info", "步骤 %s 完成，authorize=%s state=%s",
                       step_label(flow->step), state->authorize_url,
                       state->state[0] ? state->state : "-");
      flow->step = STEP_AUTHORIZE;
      return 0;
    case STEP_AUTHORIZE:
      if (!expect_success(flow, response, "authorize")) return -1;
      if (response->location[0] != '\0') {
        mg_snprintf(state->email_verification_url,
                    sizeof(state->email_verification_url), "%s",
                    response->location);
      } else {
        mg_snprintf(state->email_verification_url,
                    sizeof(state->email_verification_url), "%s",
                    AUTH_BASE_URL "/email-verification");
      }
      flow_context_log(flow, "info", "步骤 %s 完成，email_verification=%s",
                       step_label(flow->step), state->email_verification_url);
      flow->step = STEP_EMAIL_VERIFICATION;
      return 0;
    case STEP_EMAIL_VERIFICATION:
      if (!expect_success(flow, response, "email verification")) return -1;
      flow_context_log(flow, "info", "步骤 %s 完成，已触发邮箱验证页面",
                       step_label(flow->step));
      if (state->login_only) {
        flow->step = STEP_OTP_VALIDATE;
        flow->next_retry_ms = 0;
        if (fast_otp_resend_enabled(flow)) {
          mark_otp_request_sent(state);
        }
        flow_context_emit_event(flow, FLOW_EVENT_EMAIL_OTP_WAITING);
        return 0;
      }
      state->otp_resend_count = 0;
      flow->step = STEP_OTP_RESEND;
      return 0;
    case STEP_OTP_RESEND:
      if (!expect_success(flow, response, "email otp resend")) return -1;
      {
        char preview[FLOW_LOG_LEN];
        body_preview(response, preview, sizeof(preview));
        if (preview[0] != '\0') {
          flow_context_log(flow, "debug", "步骤 %s 响应片段: %s",
                           step_label(flow->step), preview);
        }
      }
      flow_context_log(flow, "info", "步骤 %s 完成，已请求验证码重发",
                       step_label(flow->step));
      flow->step = STEP_OTP_VALIDATE;
      flow->next_retry_ms = 0;
      flow_context_emit_event(flow, FLOW_EVENT_EMAIL_OTP_WAITING);
      return 0;
    case STEP_OTP_VALIDATE:
      if (!expect_success(flow, response, "email otp")) return -1;
      flow_context_emit_event(flow, FLOW_EVENT_EMAIL_OTP_VALIDATED);
      flow_context_log(flow, "info", "步骤 %s 完成，验证码已验证", step_label(flow->step));
      if (state->login_only) {
        char next_url[FLOW_URL_LEN] = "";
        char absolute[FLOW_URL_LEN] = "";
        if (response->location[0] != '\0') {
          mg_snprintf(next_url, sizeof(next_url), "%s", response->location);
        } else {
          copy_any_redirect_url(response->body, next_url, sizeof(next_url),
                                NULL);
        }
        if (next_url[0] != '\0') {
          make_absolute_url(state->authorize_url, next_url, absolute,
                            sizeof(absolute));
          if (is_chatgpt_callback_url(absolute)) {
            mg_snprintf(state->callback_url, sizeof(state->callback_url), "%s",
                        absolute);
            flow_context_log(flow, "info",
                             "验证码响应已返回 ChatGPT callback");
            flow->step = STEP_CALLBACK;
            return 0;
          }
          mg_snprintf(state->continue_url, sizeof(state->continue_url), "%s",
                      absolute);
        } else {
          mg_snprintf(state->continue_url, sizeof(state->continue_url), "%s",
                      state->authorize_url);
        }
        flow->step = STEP_CONTINUE;
        return 0;
      }
      flow->step = STEP_SESSION_DUMP;
      return 0;
    case STEP_SESSION_DUMP:
      if (!expect_success(flow, response, "session dump")) return -1;
      flow_context_log(flow, "info", "步骤 %s 完成", step_label(flow->step));
      flow->step = STEP_CREATE_ACCOUNT;
      return 0;
    case STEP_CREATE_ACCOUNT:
      if (!expect_success(flow, response, "create account")) return -1;
      if (response->location[0] != '\0') {
        mg_snprintf(state->callback_url, sizeof(state->callback_url), "%s",
                    response->location);
      } else if (!copy_any_redirect_url(response->body, state->callback_url,
                                        sizeof(state->callback_url),
                                        "/api/auth/callback/openai")) {
        char code[256] = "";
        if (copy_json_path(response->body, "$.code", code, sizeof(code)) &&
            state->state[0] != '\0') {
          mg_snprintf(state->callback_url, sizeof(state->callback_url),
                      APP_BASE_URL
                      "/api/auth/callback/openai?code=%s&scope=%s&state=%s",
                      code, OAUTH_SCOPE_CALLBACK, state->state);
        }
      }
      if (state->callback_url[0] == '\0') {
        flow_context_fail(flow, "create_account 响应中未找到 callback URL");
        return -1;
      }
      flow_context_log(flow, "info", "步骤 %s 完成，callback=%s",
                       step_label(flow->step), state->callback_url);
      flow->step = STEP_CALLBACK;
      return 0;
    case STEP_CONTINUE: {
      char next_url[FLOW_URL_LEN] = "";
      char absolute[FLOW_URL_LEN] = "";
      if (!expect_success(flow, response, "login continue")) return -1;
      state->redirect_attempts++;
      if (response->location[0] != '\0') {
        mg_snprintf(next_url, sizeof(next_url), "%s", response->location);
      } else {
        copy_any_redirect_url(response->body, next_url, sizeof(next_url),
                              NULL);
      }
      if (next_url[0] == '\0') {
        flow_context_fail(flow, "ChatGPT 登录继续流程未返回 callback");
        return -1;
      }
      make_absolute_url(state->continue_url[0] ? state->continue_url
                                               : state->authorize_url,
                        next_url, absolute, sizeof(absolute));
      if (is_chatgpt_callback_url(absolute)) {
        mg_snprintf(state->callback_url, sizeof(state->callback_url), "%s",
                    absolute);
        flow_context_log(flow, "info", "步骤 %s 完成，callback=%s",
                         step_label(flow->step), state->callback_url);
        flow->step = STEP_CALLBACK;
        return 0;
      }
      if (state->redirect_attempts > 6) {
        flow_context_fail(flow, "ChatGPT 登录继续跳转次数过多");
        return -1;
      }
      mg_snprintf(state->continue_url, sizeof(state->continue_url), "%s",
                  absolute);
      flow_context_log(flow, "debug", "继续跟随登录跳转: %s",
                       state->continue_url);
      flow->step = STEP_CONTINUE;
      return 0;
    }
    case STEP_CALLBACK:
      if (!expect_success(flow, response, "callback")) return -1;
      copy_response_credentials(state, flow, response);
      flow_context_log(flow, "info", "步骤 %s 完成", step_label(flow->step));
      flow->step = STEP_ME;
      return 0;
    case STEP_ME:
      if (!expect_success(flow, response, "me")) return -1;
      copy_json_path(response->body, "$.orgs.data[0].id", flow->workspace_id,
                     sizeof(flow->workspace_id));
      if (flow->workspace_id[0] == '\0') {
        copy_json_string_key(response->body, "organization_id",
                             flow->workspace_id, sizeof(flow->workspace_id));
      }
      flow_context_log(flow, "info", "步骤 %s 完成，workspace=%s",
                       step_label(flow->step),
                       flow->workspace_id[0] ? flow->workspace_id : "-");
      flow->step = STEP_ACCOUNT_CHECK;
      return 0;
    case STEP_ACCOUNT_CHECK:
      if (!expect_success(flow, response, "account check")) return -1;
      copy_json_string_key(response->body, "account_id",
                           flow->external_account_id,
                           sizeof(flow->external_account_id));
      if (flow->workspace_id[0] == '\0') {
        copy_json_string_key(response->body, "organization_id",
                             flow->workspace_id, sizeof(flow->workspace_id));
      }
      flow_context_log(flow, "info", "%s成功，Account ID=%s Workspace ID=%s",
                       state->login_only ? "ChatGPT 登录" : "注册",
                       flow->external_account_id[0] ? flow->external_account_id
                                                    : "-",
                       flow->workspace_id[0] ? flow->workspace_id : "-");
      if (state->login_only) {
        flow->step = STEP_SESSION;
        return 0;
      }
      if (flow->mode == FLOW_MODE_REGISTER_THEN_CURRENT_CODEX) {
        if (codex_current_session_persist_baseline(flow, "temp") != 0) {
          return -1;
        }
        if (codex_current_session_start(flow, &state->codex) != 0) {
          flow_context_fail(flow, "当前会话 Codex OAuth 初始化失败");
          return -1;
        }
        flow_context_log(flow, "info",
                         "ChatGPT 注册成功，继续当前会话 Codex OAuth");
        flow->step = STEP_CODEX_OAUTH;
        return 0;
      }
      flow->step = STEP_DONE;
      return 0;
    case STEP_SESSION: {
      if (!expect_success(flow, response, "site session")) return -1;
      copy_response_credentials(state, flow, response);
      if (!copy_json_path(response->body, "$.accessToken", flow->access_token,
                          sizeof(flow->access_token))) {
        copy_json_path(response->body, "$.access_token", flow->access_token,
                       sizeof(flow->access_token));
      }
      if (flow->session_token[0] == '\0' && state->session_token[0] != '\0') {
        mg_snprintf(flow->session_token, sizeof(flow->session_token), "%s",
                    state->session_token);
      }
      if (flow->cookies[0] == '\0' && state->cookies[0] != '\0') {
        mg_snprintf(flow->cookies, sizeof(flow->cookies), "%s",
                    state->cookies);
      }
      if (flow->access_token[0] == '\0') {
        flow_context_fail(flow, "ChatGPT session 未返回 accessToken");
        return -1;
      }
      flow_context_log(flow, "info",
                       "ChatGPT session 已获取 Access Token%s%s",
                       flow->session_token[0] ? "，Session Token=yes" : "",
                       flow->cookies[0] ? "，Cookies=yes" : "");
      flow->step = STEP_TOKEN_EXCHANGE;
      return 0;
    }
    case STEP_TOKEN_EXCHANGE:
      if (response->status_code >= 200 && response->status_code < 300) {
        char *access_token = mg_json_get_str(
            mg_str(response->body ? response->body : ""), "$.access_token");
        char *refresh_token = mg_json_get_str(
            mg_str(response->body ? response->body : ""), "$.refresh_token");
        char *id_token = mg_json_get_str(
            mg_str(response->body ? response->body : ""), "$.id_token");
        if (flow->access_token[0] == '\0' && access_token != NULL &&
            access_token[0] != '\0') {
          mg_snprintf(flow->access_token, sizeof(flow->access_token), "%s",
                      access_token);
        }
        if (refresh_token != NULL && refresh_token[0] != '\0') {
          mg_snprintf(flow->refresh_token, sizeof(flow->refresh_token), "%s",
                      refresh_token);
        }
        if (id_token != NULL && id_token[0] != '\0') {
          mg_snprintf(flow->id_token, sizeof(flow->id_token), "%s",
                      id_token);
        }
        flow_context_log(flow, "info",
                         "ChatGPT token exchange 完成，refresh=%s id_token=%s",
                         flow->refresh_token[0] ? "yes" : "no",
                         flow->id_token[0] ? "yes" : "no");
        mg_free(access_token);
        mg_free(refresh_token);
        mg_free(id_token);
      } else {
        char summary[FLOW_LOG_LEN];
        response_summary(response, summary, sizeof(summary));
        flow_context_log(flow, "warn",
                         "ChatGPT token exchange 未成功，保留 session accessToken: %s",
                         summary);
      }
      flow->step = STEP_DONE;
      return 0;
    case STEP_CODEX_OAUTH:
      if (codex_current_session_on_response(flow, &state->codex, response) != 0) {
        return -1;
      }
      if (codex_current_session_is_done(&state->codex)) {
        flow_context_log(flow, "info", "当前会话 Codex OAuth 完成");
      }
      return 0;
    default:
      flow_context_fail(flow, "收到未知步骤响应");
      return -1;
  }
}

static void provider_cleanup(struct flow_context *flow) {
  if (flow == NULL) return;
  free(flow->provider_data);
  flow->provider_data = NULL;
}

static const struct flow_provider s_provider = {
    "web-register-har",
    provider_start,
    provider_next,
    provider_response,
    provider_cleanup,
};

static const struct flow_provider s_login_provider = {
    "web-login-har",
    provider_login_start,
    provider_next,
    provider_response,
    provider_cleanup,
};

const struct flow_provider *web_register_provider(void) {
  return &s_provider;
}

const struct flow_provider *web_login_provider(void) {
  return &s_login_provider;
}
