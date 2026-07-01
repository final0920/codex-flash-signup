#include "oauth/oauth_provider.h"

#include "mail/rapid_inbox.h"
#include "mongoose.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OAUTH_AUTH_BASE_URL "https://auth.openai.com"
#define OAUTH_AUTHORIZE_URL OAUTH_AUTH_BASE_URL "/oauth/authorize"
#define OAUTH_TOKEN_URL OAUTH_AUTH_BASE_URL "/oauth/token"
#define OAUTH_SENTINEL_URL "https://sentinel.openai.com/backend-api/sentinel/req"
#define OAUTH_SENTINEL_ORIGIN "https://sentinel.openai.com"
#define OAUTH_SENTINEL_REFERER \
  "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6"
#define OAUTH_CLIENT_ID "app_EMoamEEZ73f0CkXaXp7hrann"
#define OAUTH_REDIRECT_URI "http://localhost:1455/auth/callback"
#define OAUTH_SCOPE \
  "openid profile email offline_access api.connectors.read api.connectors.invoke"
#define OAUTH_ORIGINATOR "codex_vscode"
#define OAUTH_OTP_WAIT_TIMEOUT_MS 60000
#define OAUTH_OTP_POLL_INTERVAL_MS 1500L
#define OAUTH_OTP_ERROR_POLL_INTERVAL_MS 2500L

enum oauth_step {
  STEP_OAUTH_AUTHORIZE = 0,
  STEP_OAUTH_AUTH,
  STEP_ACCOUNT_LOGIN,
  STEP_LOGIN_PAGE,
  STEP_SENTINEL_AUTHORIZE_CONTINUE,
  STEP_AUTHORIZE_CONTINUE,
  STEP_SENTINEL_PASSWORD_VERIFY,
  STEP_PASSWORDLESS_SEND_OTP,
  STEP_OTP_VALIDATE,
  STEP_CLIENT_AUTH_SESSION_DUMP,
  STEP_CONSENT_PAGE,
  STEP_WORKSPACE_SELECT,
  STEP_OAUTH_AFTER_LOGIN,
  STEP_CONSENT,
  STEP_OAUTH_AFTER_CONSENT,
  STEP_FOLLOW_REDIRECT,
  STEP_TOKEN_EXCHANGE,
  STEP_DONE
};

struct oauth_state {
  char state[128];
  char code_verifier[160];
  char code_challenge[96];
  char authorize_url[FLOW_URL_LEN];
  char oauth_auth_url[FLOW_URL_LEN];
  char login_url[FLOW_URL_LEN];
  char password_url[FLOW_URL_LEN];
  char email_verification_url[FLOW_URL_LEN];
  char consent_url[FLOW_URL_LEN];
  char callback_url[FLOW_URL_LEN];
  char redirect_url[FLOW_URL_LEN];
  char login_verifier[512];
  char consent_verifier[512];
  char device_id[80];
  char sentinel_authorize_token[4096];
  char workspace_id[FLOW_WORKSPACE_ID_LEN];
  char otp_code[64];
  char body[8192];
  char header_origin[96];
  char header_referer[FLOW_URL_LEN];
  char header_content_type[96];
  char header_accept[256];
  char header_sentinel_token[4608];
  struct flow_http_header headers[16];
  size_t num_headers;
  int otp_attempts;
  int otp_validation_retries;
  int redirect_count;
  long otp_sent_after_epoch;
  long otp_send_requested_ms;
  bool workspace_select_enabled;
};

static long oauth_otp_wait_timeout_ms(const struct flow_context *flow) {
  return flow != NULL && flow->oauth_otp_timeout_ms > 0
             ? flow->oauth_otp_timeout_ms
             : OAUTH_OTP_WAIT_TIMEOUT_MS;
}

static long oauth_otp_wait_timeout_seconds(const struct flow_context *flow) {
  long timeout_ms = oauth_otp_wait_timeout_ms(flow);
  return (timeout_ms + 999) / 1000;
}

static uint64_t random_u64(void) {
  uint64_t value = 0;
  if (!mg_random(&value, sizeof(value))) {
    value = ((uint64_t) rand() << 32) ^ (uint64_t) rand();
  }
  return value;
}

static void random_urlsafe(char *out, size_t out_len, size_t chars) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  size_t n = 0;
  if (out_len == 0) return;
  while (n < chars && n + 1 < out_len) {
    out[n++] = alphabet[random_u64() % (sizeof(alphabet) - 1)];
  }
  out[n] = '\0';
}

static void base64url_no_padding(char *s) {
  if (s == NULL) return;
  for (size_t i = 0; s[i] != '\0'; i++) {
    if (s[i] == '+') s[i] = '-';
    else if (s[i] == '/') s[i] = '_';
    else if (s[i] == '=') {
      s[i] = '\0';
      break;
    }
  }
}

static void make_code_challenge(const char *verifier, char *out,
                                size_t out_len) {
  uint8_t digest[32];
  if (out_len == 0) return;
  out[0] = '\0';
  if (verifier == NULL) return;
  mg_sha256(digest, (uint8_t *) verifier, strlen(verifier));
  mg_base64_encode(digest, sizeof(digest), out, out_len);
  base64url_no_padding(out);
}

static void set_header(struct oauth_state *state, const char *name,
                       const char *value) {
  if (state == NULL || state->num_headers >=
                           sizeof(state->headers) / sizeof(state->headers[0])) {
    return;
  }
  if (name == NULL || value == NULL || value[0] == '\0') return;
  state->headers[state->num_headers].name = name;
  state->headers[state->num_headers].value = value;
  state->num_headers++;
}

static void set_nav_headers(struct oauth_state *state, const char *referer,
                            const char *site) {
  state->num_headers = 0;
  mg_snprintf(state->header_accept, sizeof(state->header_accept),
              "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8,"
              "application/signed-exchange;v=b3;q=0.7");
  mg_snprintf(state->header_referer, sizeof(state->header_referer), "%s",
              referer ? referer : "");
  set_header(state, "Accept", state->header_accept);
  set_header(state, "Referer", state->header_referer);
  set_header(state, "Sec-Fetch-Dest", "document");
  set_header(state, "Sec-Fetch-Mode", "navigate");
  set_header(state, "Sec-Fetch-Site", site ? site : "same-origin");
  set_header(state, "Sec-Fetch-User", "?1");
  set_header(state, "Upgrade-Insecure-Requests", "1");
}

static void set_json_headers(struct oauth_state *state, const char *referer) {
  state->num_headers = 0;
  mg_snprintf(state->header_origin, sizeof(state->header_origin), "%s",
              OAUTH_AUTH_BASE_URL);
  mg_snprintf(state->header_referer, sizeof(state->header_referer), "%s",
              referer ? referer : OAUTH_AUTH_BASE_URL "/log-in");
  mg_snprintf(state->header_content_type, sizeof(state->header_content_type),
              "application/json");
  set_header(state, "Accept", "application/json");
  set_header(state, "Content-Type", state->header_content_type);
  set_header(state, "Origin", state->header_origin);
  set_header(state, "Referer", state->header_referer);
  set_header(state, "Sec-Fetch-Dest", "empty");
  set_header(state, "Sec-Fetch-Mode", "cors");
  set_header(state, "Sec-Fetch-Site", "same-origin");
}

static void request_get(struct oauth_state *state,
                        struct flow_http_request *request, const char *url,
                        const char *referer, const char *site) {
  set_nav_headers(state, referer, site);
  request->method = "GET";
  request->url = url;
  request->timeout_ms = 30000;
  request->follow_location = false;
  request->headers = state->headers;
  request->num_headers = state->num_headers;
}

static void request_post_json(struct oauth_state *state,
                              struct flow_http_request *request,
                              const char *url, const char *body,
                              const char *referer) {
  set_json_headers(state, referer);
  request->method = "POST";
  request->url = url;
  request->body = body;
  request->body_len = body == NULL ? 0 : strlen(body);
  request->timeout_ms = 30000;
  request->follow_location = false;
  request->headers = state->headers;
  request->num_headers = state->num_headers;
}

static void request_post_sentinel(struct oauth_state *state,
                                  struct flow_http_request *request,
                                  const char *flow_name) {
  state->num_headers = 0;
  mg_snprintf(state->header_origin, sizeof(state->header_origin), "%s",
              OAUTH_SENTINEL_ORIGIN);
  mg_snprintf(state->header_referer, sizeof(state->header_referer), "%s",
              OAUTH_SENTINEL_REFERER);
  mg_snprintf(state->header_content_type, sizeof(state->header_content_type),
              "text/plain;charset=UTF-8");
  mg_snprintf(state->body, sizeof(state->body),
              "{\"p\":\"\",\"id\":\"%s\",\"flow\":\"%s\"}",
              state->device_id, flow_name ? flow_name : "authorize_continue");
  set_header(state, "Accept", "*/*");
  set_header(state, "Content-Type", state->header_content_type);
  set_header(state, "Origin", state->header_origin);
  set_header(state, "Referer", state->header_referer);
  set_header(state, "Sec-Fetch-Dest", "empty");
  set_header(state, "Sec-Fetch-Mode", "cors");
  set_header(state, "Sec-Fetch-Site", "same-origin");
  request->method = "POST";
  request->url = OAUTH_SENTINEL_URL;
  request->body = state->body;
  request->body_len = strlen(state->body);
  request->timeout_ms = 30000;
  request->follow_location = false;
  request->headers = state->headers;
  request->num_headers = state->num_headers;
}

static void request_post_form(struct oauth_state *state,
                              struct flow_http_request *request,
                              const char *url, const char *body,
                              const char *referer) {
  state->num_headers = 0;
  mg_snprintf(state->header_origin, sizeof(state->header_origin), "%s",
              OAUTH_AUTH_BASE_URL);
  mg_snprintf(state->header_referer, sizeof(state->header_referer), "%s",
              referer ? referer : OAUTH_AUTH_BASE_URL "/");
  mg_snprintf(state->header_content_type, sizeof(state->header_content_type),
              "application/x-www-form-urlencoded");
  set_header(state, "Accept", "application/json");
  set_header(state, "Content-Type", state->header_content_type);
  set_header(state, "Origin", state->header_origin);
  set_header(state, "Referer", state->header_referer);
  set_header(state, "Sec-Fetch-Dest", "empty");
  set_header(state, "Sec-Fetch-Mode", "cors");
  set_header(state, "Sec-Fetch-Site", "same-origin");
  request->method = "POST";
  request->url = url;
  request->body = body;
  request->body_len = body == NULL ? 0 : strlen(body);
  request->timeout_ms = 30000;
  request->follow_location = false;
  request->headers = state->headers;
  request->num_headers = state->num_headers;
}

static void make_absolute_url(const char *location, char *out, size_t out_len) {
  char location_copy[FLOW_URL_LEN];
  if (out_len == 0) return;
  if (location == out && location != NULL) {
    mg_snprintf(location_copy, sizeof(location_copy), "%s", location);
    location = location_copy;
  }
  out[0] = '\0';
  if (location == NULL || location[0] == '\0') return;
  if (strncmp(location, "http://", 7) == 0 ||
      strncmp(location, "https://", 8) == 0) {
    mg_snprintf(out, out_len, "%s", location);
  } else if (location[0] == '/') {
    mg_snprintf(out, out_len, "%s%s", OAUTH_AUTH_BASE_URL, location);
  } else {
    mg_snprintf(out, out_len, "%s/%s", OAUTH_AUTH_BASE_URL, location);
  }
}

static bool copy_query_value_from_url(const char *url, const char *name,
                                      char *out, size_t out_len);

static void append_query_param(char *url, size_t url_len, const char *key,
                               const char *value) {
  char value_enc[256];
  const char *sep;
  size_t need;

  if (url == NULL || url_len == 0 || key == NULL || key[0] == '\0' ||
      value == NULL || value[0] == '\0') {
    return;
  }
  mg_url_encode(value, strlen(value), value_enc, sizeof(value_enc));
  sep = strchr(url, '?') == NULL ? "?" : "&";
  need = strlen(url) + strlen(sep) + strlen(key) + strlen(value_enc) + 2;
  if (need >= url_len) return;
  strncat(url, sep, url_len - strlen(url) - 1);
  strncat(url, key, url_len - strlen(url) - 1);
  strncat(url, "=", url_len - strlen(url) - 1);
  strncat(url, value_enc, url_len - strlen(url) - 1);
}

static void ensure_codex_originator(char *url, size_t url_len) {
  char originator[96] = "";
  if (url == NULL || url[0] == '\0') return;
  if (!copy_query_value_from_url(url, "originator", originator,
                                 sizeof(originator))) {
    append_query_param(url, url_len, "originator", OAUTH_ORIGINATOR);
  }
}

static bool copy_query_value_from_url(const char *url, const char *name,
                                      char *out, size_t out_len) {
  const char *q;
  size_t name_len;
  char decoded[FLOW_URL_LEN];
  if (out == NULL || out_len == 0) return false;
  if (url == NULL || name == NULL) return false;
  q = strchr(url, '?');
  if (q == NULL) return false;
  q++;
  name_len = strlen(name);
  while (*q) {
    const char *key = q;
    const char *eq = strchr(key, '=');
    const char *amp = strchr(key, '&');
    if (eq == NULL || (amp != NULL && amp < eq)) break;
    if ((size_t) (eq - key) == name_len && strncmp(key, name, name_len) == 0) {
      size_t value_len = amp == NULL ? strlen(eq + 1) : (size_t) (amp - eq - 1);
      int n = mg_url_decode(eq + 1, value_len, decoded, sizeof(decoded), 1);
      if (n <= 0) return false;
      mg_snprintf(out, out_len, "%s", decoded);
      return true;
    }
    if (amp == NULL) break;
    q = amp + 1;
  }
  return false;
}

static bool contains_casefold(const char *s, const char *needle) {
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

static bool response_has_phone_marker(const struct flow_http_response *response) {
  if (response == NULL) return false;
  return contains_casefold(response->location, "add-phone") ||
         contains_casefold(response->effective_url, "add-phone") ||
         contains_casefold(response->location, "phone-verification") ||
         contains_casefold(response->effective_url, "phone-verification") ||
         contains_casefold(response->body, "add-phone") ||
         contains_casefold(response->body, "phone-verification");
}

static bool copy_json_string(struct mg_str json, const char *path, char *out,
                             size_t out_len) {
  char *value;
  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  value = mg_json_get_str(json, path);
  if (value == NULL) return false;
  mg_snprintf(out, out_len, "%s", value);
  mg_free(value);
  return out[0] != '\0';
}

static bool copy_json_string_from_response(
    const struct flow_http_response *response, const char *path, char *out,
    size_t out_len) {
  if (response == NULL || response->body == NULL || response->body_len == 0) {
    if (out != NULL && out_len > 0) out[0] = '\0';
    return false;
  }
  return copy_json_string(mg_str_n(response->body, response->body_len), path,
                          out, out_len);
}

static void add_authorize_sentinel_header(struct oauth_state *state) {
  if (state == NULL || state->sentinel_authorize_token[0] == '\0' ||
      state->device_id[0] == '\0') {
    return;
  }
  mg_snprintf(state->header_sentinel_token,
              sizeof(state->header_sentinel_token),
              "{\"p\":\"\",\"t\":\"\",\"c\":\"%s\",\"id\":\"%s\","
              "\"flow\":\"authorize_continue\"}",
              state->sentinel_authorize_token, state->device_id);
  set_header(state, "OpenAI-Sentinel-Token", state->header_sentinel_token);
}

static bool copy_json_key_string(const char *json, const char *key, char *out,
                                 size_t out_len) {
  char pattern[160];
  const char *p;
  const char *colon;
  const char *value;
  size_t n = 0;

  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (json == NULL || key == NULL || key[0] == '\0') return false;
  mg_snprintf(pattern, sizeof(pattern), "\"%s\"", key);
  p = strstr(json, pattern);
  if (p == NULL) return false;
  colon = strchr(p + strlen(pattern), ':');
  if (colon == NULL) return false;
  value = colon + 1;
  while (*value && isspace((unsigned char) *value)) value++;
  if (*value != '"') return false;
  value++;
  while (*value && *value != '"' && n + 1 < out_len) {
    if (*value == '\\' && value[1] != '\0') value++;
    out[n++] = *value++;
  }
  out[n] = '\0';
  return n > 0;
}

static bool copy_json_string_after_key_ptr(const char *key_ptr, char *out,
                                           size_t out_len) {
  const char *colon;
  const char *value;
  size_t n = 0;

  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (key_ptr == NULL) return false;
  colon = strchr(key_ptr, ':');
  if (colon == NULL) return false;
  value = colon + 1;
  while (*value && isspace((unsigned char) *value)) value++;
  if (*value != '"') return false;
  value++;
  while (*value && *value != '"' && n + 1 < out_len) {
    if (*value == '\\' && value[1] != '\0') value++;
    out[n++] = *value++;
  }
  out[n] = '\0';
  return n > 0;
}

static bool copy_object_id_after_json_key(const char *text, const char *key,
                                          char *out, size_t out_len) {
  char pattern[160];
  const char *p;

  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (text == NULL || key == NULL || key[0] == '\0') return false;
  mg_snprintf(pattern, sizeof(pattern), "\"%s\"", key);
  p = strstr(text, pattern);
  while (p != NULL) {
    const char *scope_start = strchr(p + strlen(pattern), '{');
    const char *array_start = strchr(p + strlen(pattern), '[');
    const char *scope_end = NULL;
    const char *id;

    if (array_start != NULL && (scope_start == NULL || array_start < scope_start)) {
      scope_start = array_start;
      scope_end = strchr(scope_start, ']');
    } else if (scope_start != NULL) {
      scope_end = strchr(scope_start, '}');
    }
    if (scope_start != NULL && scope_end != NULL) {
      id = strstr(scope_start, "\"id\"");
      if (id != NULL && id < scope_end &&
          copy_json_string_after_key_ptr(id, out, out_len)) {
        return true;
      }
    }
    p = strstr(p + strlen(pattern), pattern);
  }
  return false;
}

static bool copy_workspace_id_from_text(const char *text, char *out,
                                        size_t out_len) {
  static const char *keys[] = {
      "workspace_id",
      "workspaceId",
      "default_workspace_id",
      "defaultWorkspaceId",
      "active_workspace_id",
      "activeWorkspaceId",
  };
  const char *workspace;

  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (text == NULL || text[0] == '\0') return false;
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
    if (copy_json_key_string(text, keys[i], out, out_len)) return true;
  }

  if (copy_object_id_after_json_key(text, "workspaces", out, out_len)) {
    return true;
  }
  if (copy_object_id_after_json_key(text, "workspace", out, out_len) ||
      copy_object_id_after_json_key(text, "default_workspace", out, out_len) ||
      copy_object_id_after_json_key(text, "active_workspace", out, out_len) ||
      copy_object_id_after_json_key(text, "defaultWorkspace", out, out_len) ||
      copy_object_id_after_json_key(text, "activeWorkspace", out, out_len)) {
    return true;
  }

  workspace = strstr(text, "\"workspace\"");
  while (workspace != NULL) {
    const char *brace = strchr(workspace, '{');
    const char *next = strstr(workspace + 1, "\"workspace\"");
    const char *id;
    if (brace != NULL && (next == NULL || brace < next)) {
      id = strstr(brace, "\"id\"");
      if (id != NULL && (next == NULL || id < next)) {
        const char *colon = strchr(id + 4, ':');
        const char *value = colon == NULL ? NULL : colon + 1;
        size_t n = 0;
        while (value != NULL && *value && isspace((unsigned char) *value)) value++;
        if (value != NULL && *value == '"') {
          value++;
          while (*value && *value != '"' && n + 1 < out_len) {
            if (*value == '\\' && value[1] != '\0') value++;
            out[n++] = *value++;
          }
          out[n] = '\0';
          if (n > 0) return true;
        }
      }
    }
    workspace = next;
  }
  return false;
}

static bool copy_workspace_id_from_url(const char *url, char *out,
                                       size_t out_len) {
  static const char *keys[] = {
      "workspace_id",
      "workspaceId",
      "default_workspace_id",
      "active_workspace_id",
  };
  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
    if (copy_query_value_from_url(url, keys[i], out, out_len)) return true;
  }
  return false;
}

static bool copy_workspace_id_from_auth_cookie(const char *cookie, char *out,
                                               size_t out_len) {
  const char *candidate;
  char b64[FLOW_COOKIE_LEN + 8];
  char decoded[FLOW_COOKIE_LEN];

  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (cookie == NULL || cookie[0] == '\0') return false;

  candidate = cookie;
  for (;;) {
    const char *dot = strchr(candidate, '.');
    size_t len = dot == NULL ? strlen(candidate) : (size_t) (dot - candidate);
    size_t padded_len = len;

    if (len > 0 && len + 4 < sizeof(b64)) {
      memcpy(b64, candidate, len);
      for (size_t i = 0; i < len; i++) {
        if (b64[i] == '-') b64[i] = '+';
        else if (b64[i] == '_') b64[i] = '/';
      }
      while (padded_len % 4 != 0) b64[padded_len++] = '=';
      b64[padded_len] = '\0';
      {
        size_t decoded_len =
            mg_base64_decode(b64, padded_len, decoded, sizeof(decoded) - 1);
        if (decoded_len > 0) {
          decoded[decoded_len] = '\0';
          if (copy_workspace_id_from_text(decoded, out, out_len)) return true;
        }
      }
    }

    if (dot == NULL) break;
    candidate = dot + 1;
  }

  return false;
}

static bool copy_workspace_id_from_response(
    const struct flow_http_response *response, char *out, size_t out_len) {
  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (response == NULL) return false;
  if (copy_workspace_id_from_text(response->body, out, out_len)) return true;
  if (copy_workspace_id_from_auth_cookie(response->auth_session_cookie, out,
                                         out_len)) {
    return true;
  }
  if (copy_workspace_id_from_auth_cookie(response->auth_info_cookie, out,
                                         out_len)) {
    return true;
  }
  if (copy_workspace_id_from_url(response->effective_url, out, out_len)) return true;
  if (copy_workspace_id_from_url(response->location, out, out_len)) return true;
  return false;
}

static bool oauth_try_callback_url(struct flow_context *flow,
                                   struct oauth_state *state,
                                   const char *url) {
  char returned_state[128] = "";
  char oauth_error[160] = "";
  char error_description[256] = "";
  if (flow == NULL || state == NULL || url == NULL || url[0] == '\0') {
    return false;
  }
  if (copy_query_value_from_url(url, "error", oauth_error,
                                sizeof(oauth_error))) {
    char message[FLOW_ERROR_LEN];
    copy_query_value_from_url(url, "error_description", error_description,
                              sizeof(error_description));
    mg_snprintf(message, sizeof(message), "OAuth 重定向返回错误: %s%s%s",
                oauth_error,
                error_description[0] ? ": " : "",
                error_description);
    flow_context_fail(flow, message);
    return true;
  }
  if (!copy_query_value_from_url(url, "code", flow->authorization_code,
                                 sizeof(flow->authorization_code))) {
    return false;
  }
  copy_query_value_from_url(url, "state", returned_state,
                            sizeof(returned_state));
  if (strcmp(returned_state, state->state) != 0) {
    flow_context_fail(flow, "OAuth callback state 不匹配");
    return true;
  }
  mg_snprintf(state->callback_url, sizeof(state->callback_url), "%s", url);
  flow_context_log(flow, "info", "OAuth 已返回授权码");
  flow->step = STEP_TOKEN_EXCHANGE;
  return true;
}

static bool decode_jwt_payload(const char *token, char *out, size_t out_len) {
  const char *p1;
  const char *p2;
  char b64[4096];
  size_t len;

  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (token == NULL) return false;
  p1 = strchr(token, '.');
  if (p1 == NULL) return false;
  p2 = strchr(p1 + 1, '.');
  if (p2 == NULL || p2 <= p1 + 1) return false;
  len = (size_t) (p2 - p1 - 1);
  if (len + 4 >= sizeof(b64)) return false;
  memcpy(b64, p1 + 1, len);
  for (size_t i = 0; i < len; i++) {
    if (b64[i] == '-') b64[i] = '+';
    else if (b64[i] == '_') b64[i] = '/';
  }
  while (len % 4 != 0) b64[len++] = '=';
  b64[len] = '\0';
  len = mg_base64_decode(b64, len, out, out_len - 1);
  if (len == 0) return false;
  out[len] = '\0';
  return true;
}

static void sanitized_url(const char *url, char *out, size_t out_len) {
  const char *q;
  size_t len;
  if (out_len == 0) return;
  out[0] = '\0';
  if (url == NULL) return;
  q = strchr(url, '?');
  len = q == NULL ? strlen(url) : (size_t) (q - url);
  if (len >= out_len) len = out_len - 1;
  memcpy(out, url, len);
  out[len] = '\0';
  if (q != NULL && len + 4 < out_len) {
    strncat(out, "?...", out_len - strlen(out) - 1);
  }
}

static void body_preview(const struct flow_http_response *response, char *out,
                         size_t out_len) {
  size_t n = 0;
  if (out_len == 0) return;
  out[0] = '\0';
  if (response == NULL || response->body == NULL || response->body_len == 0) {
    return;
  }
  for (size_t i = 0; i < response->body_len && n + 1 < out_len; i++) {
    unsigned char ch = (unsigned char) response->body[i];
    if (ch == '\r' || ch == '\n' || ch == '\t') {
      if (n > 0 && out[n - 1] != ' ') out[n++] = ' ';
    } else if (isprint(ch)) {
      out[n++] = (char) ch;
    } else if (n > 0 && out[n - 1] != ' ') {
      out[n++] = ' ';
    }
    if (n >= 180) break;
  }
  while (n > 0 && out[n - 1] == ' ') n--;
  out[n] = '\0';
}

static const char *step_label(enum oauth_step step) {
  switch (step) {
    case STEP_OAUTH_AUTHORIZE: return "oauth authorize";
    case STEP_OAUTH_AUTH: return "oauth auth";
    case STEP_ACCOUNT_LOGIN: return "account login";
    case STEP_LOGIN_PAGE: return "login page";
    case STEP_SENTINEL_AUTHORIZE_CONTINUE: return "sentinel authorize";
    case STEP_AUTHORIZE_CONTINUE: return "authorize continue";
    case STEP_SENTINEL_PASSWORD_VERIFY: return "sentinel password";
    case STEP_PASSWORDLESS_SEND_OTP: return "passwordless send otp";
    case STEP_OTP_VALIDATE: return "email otp validate";
    case STEP_CLIENT_AUTH_SESSION_DUMP: return "client auth session dump";
    case STEP_CONSENT_PAGE: return "consent page";
    case STEP_WORKSPACE_SELECT: return "workspace select";
    case STEP_OAUTH_AFTER_LOGIN: return "oauth after login";
    case STEP_CONSENT: return "consent";
    case STEP_OAUTH_AFTER_CONSENT: return "oauth after consent";
    case STEP_FOLLOW_REDIRECT: return "follow redirect";
    case STEP_TOKEN_EXCHANGE: return "token exchange";
    case STEP_DONE: return "done";
    default: return "unknown";
  }
}

static bool expect_success(struct flow_context *flow,
                           const struct flow_http_response *response,
                           const char *label) {
  if (response->status_code >= 200 && response->status_code < 400) return true;
  if (flow_response_is_edge_block(response)) {
    flow_context_mark_environment_retry(flow,
                                        "边缘风控拦截，需要重新分配环境重试");
  } else {
    flow_context_fail(flow, "OAuth 请求返回非成功状态");
  }
  {
    char preview[FLOW_LOG_LEN];
    body_preview(response, preview, sizeof(preview));
    flow_context_log(flow, "error",
                     "%s 失败: HTTP %ld body=%luB ip=%s server=%s cf=%s ray=%s location=%s",
                     label, response->status_code,
                     (unsigned long) response->body_len,
                     response->primary_ip[0] ? response->primary_ip : "-",
                     response->server[0] ? response->server : "-",
                     response->cf_mitigated[0] ? response->cf_mitigated : "-",
                     response->cf_ray[0] ? response->cf_ray : "-",
                     response->location[0] ? response->location : "-");
    if (flow->environment_retryable) {
      flow_context_log(flow, "warn", "%s 触发边缘风控，当前环境将被丢弃并重试",
                       label);
    }
    if (preview[0] != '\0') {
      flow_context_log(flow, "warn", "%s 响应片段: %s", label, preview);
    }
  }
  return false;
}

static void build_authorize_url(struct oauth_state *state) {
  char redirect_enc[256];
  char scope_enc[512];
  mg_url_encode(OAUTH_REDIRECT_URI, strlen(OAUTH_REDIRECT_URI),
                redirect_enc, sizeof(redirect_enc));
  mg_url_encode(OAUTH_SCOPE, strlen(OAUTH_SCOPE), scope_enc,
                sizeof(scope_enc));
  mg_snprintf(state->authorize_url, sizeof(state->authorize_url),
              OAUTH_AUTHORIZE_URL
              "?response_type=code&client_id=%s"
              "&redirect_uri=%s&state=%s&scope=%s&code_challenge=%s"
              "&code_challenge_method=S256&prompt=login"
              "&id_token_add_organizations=true&codex_cli_simplified_flow=true"
              "&originator=%s",
              OAUTH_CLIENT_ID, redirect_enc, state->state, scope_enc,
              state->code_challenge, OAUTH_ORIGINATOR);
}

static void build_oauth_auth_url(struct oauth_state *state, const char *extra_key,
                                 const char *extra_value) {
  char redirect_enc[256];
  char scope_enc[512];
  char extra_enc[768];
  mg_url_encode(OAUTH_REDIRECT_URI, strlen(OAUTH_REDIRECT_URI),
                redirect_enc, sizeof(redirect_enc));
  mg_url_encode(OAUTH_SCOPE, strlen(OAUTH_SCOPE), scope_enc,
                sizeof(scope_enc));
  mg_snprintf(state->oauth_auth_url, sizeof(state->oauth_auth_url),
              OAUTH_AUTH_BASE_URL
              "/api/oauth/oauth2/auth?client_id=%s&code_challenge=%s"
              "&code_challenge_method=S256&codex_cli_simplified_flow=true"
              "&id_token_add_organizations=true&prompt=login&redirect_uri=%s"
              "&response_type=code&scope=%s&state=%s&originator=%s",
              OAUTH_CLIENT_ID, state->code_challenge, redirect_enc,
              scope_enc, state->state, OAUTH_ORIGINATOR);
  extra_enc[0] = '\0';
  if (extra_key != NULL && extra_value != NULL && extra_value[0] != '\0') {
    mg_url_encode(extra_value, strlen(extra_value), extra_enc,
                  sizeof(extra_enc));
  }
  if (extra_key != NULL && extra_enc[0] != '\0' &&
      strlen(state->oauth_auth_url) + strlen(extra_key) + strlen(extra_enc) +
              3 <
          sizeof(state->oauth_auth_url)) {
    strncat(state->oauth_auth_url, "&",
            sizeof(state->oauth_auth_url) - strlen(state->oauth_auth_url) - 1);
    strncat(state->oauth_auth_url, extra_key,
            sizeof(state->oauth_auth_url) - strlen(state->oauth_auth_url) - 1);
    strncat(state->oauth_auth_url, "=",
            sizeof(state->oauth_auth_url) - strlen(state->oauth_auth_url) - 1);
    strncat(state->oauth_auth_url, extra_enc,
            sizeof(state->oauth_auth_url) - strlen(state->oauth_auth_url) - 1);
  }
}

static int provider_start(struct flow_context *flow) {
  struct oauth_state *state;

  state = (struct oauth_state *) calloc(1, sizeof(*state));
  if (state == NULL) return -1;
  random_urlsafe(state->state, sizeof(state->state), 64);
  random_urlsafe(state->code_verifier, sizeof(state->code_verifier), 64);
  make_code_challenge(state->code_verifier, state->code_challenge,
                      sizeof(state->code_challenge));
  mg_snprintf(flow->pkce_code_verifier, sizeof(flow->pkce_code_verifier), "%s",
              state->code_verifier);
  if (flow->workspace_id[0] != '\0') {
    mg_snprintf(state->workspace_id, sizeof(state->workspace_id), "%s",
                flow->workspace_id);
    state->workspace_select_enabled = true;
  }
  build_authorize_url(state);
  flow->provider_data = state;
  flow->step = STEP_OAUTH_AUTHORIZE;
  if (flow->deadline_ms <= 0) flow->deadline_ms = (long) mg_millis() + 180000;
  mg_snprintf(flow->success_account_status, sizeof(flow->success_account_status),
              "active");
  flow_context_log(flow, "info", "OAuth 架构路径准备账号 %s",
                   flow->identity.email);
  flow_context_log(flow, "info",
                   "OAuth 默认域名=%s，使用 Codex OAuth 参数并在 callback 后换取 Token",
                   OAUTH_AUTH_BASE_URL);
  return 0;
}

static enum flow_provider_action next_otp_request(struct flow_context *flow,
                                                  struct flow_http_request *request) {
  struct oauth_state *state = (struct oauth_state *) flow->provider_data;
  char error[256] = "";
  int rc;
  long now;
  long otp_timeout_ms;
  long otp_timeout_seconds;

  now = (long) mg_millis();
  otp_timeout_ms = oauth_otp_wait_timeout_ms(flow);
  otp_timeout_seconds = oauth_otp_wait_timeout_seconds(flow);
  if (now > flow->deadline_ms) {
    flow_context_fail(flow, "等待 OAuth 邮箱验证码超时");
    return FLOW_PROVIDER_FAILED;
  }
  if (now < flow->next_retry_ms) return FLOW_PROVIDER_WAIT;

  state->otp_attempts++;
  rc = rapid_inbox_fetch_latest_code_since(
      flow->db, flow->identity.email, state->otp_sent_after_epoch,
      state->otp_code, sizeof(state->otp_code), error, sizeof(error));
  now = (long) mg_millis();
  if (rc == 0) {
    if (state->otp_send_requested_ms > 0 &&
        now - state->otp_send_requested_ms >= otp_timeout_ms) {
      flow_context_fail(flow, "等待 OAuth 邮箱验证码超时");
      flow_context_log(flow, "warn",
                       "OAuth 验证码 %ld 秒内未送达，当前链接超时，email=%s，reason=%s",
                       otp_timeout_seconds, flow->identity.email,
                       error[0] ? error : "邮件服务未返回验证码");
      return FLOW_PROVIDER_FAILED;
    }
    flow_context_log(flow, "debug",
                     "等待 OAuth 邮箱验证码，第 %d 次轮询，email=%s，reason=%s",
                     state->otp_attempts, flow->identity.email,
                     error[0] ? error : "邮件服务未返回验证码");
    flow->next_retry_ms = (long) mg_millis() + OAUTH_OTP_POLL_INTERVAL_MS;
    return FLOW_PROVIDER_WAIT;
  }
  if (rc < 0) {
    if (state->otp_send_requested_ms > 0 &&
        now - state->otp_send_requested_ms >= otp_timeout_ms) {
      flow_context_fail(flow, "等待 OAuth 邮箱验证码超时");
      flow_context_log(flow, "warn",
                       "OAuth 验证码读取失败且已超过 %ld 秒，当前链接超时，email=%s，reason=%s",
                       otp_timeout_seconds, flow->identity.email,
                       error[0] ? error : "unknown");
      return FLOW_PROVIDER_FAILED;
    }
    flow_context_log(flow, "warn", "读取 OAuth 验证码失败: email=%s，reason=%s",
                     flow->identity.email, error[0] ? error : "unknown");
    flow->next_retry_ms =
        (long) mg_millis() + OAUTH_OTP_ERROR_POLL_INTERVAL_MS;
    return FLOW_PROVIDER_WAIT;
  }

  flow_context_log(flow, "info", "已获取发送时间后的 OAuth 邮箱验证码");
  mg_snprintf(state->body, sizeof(state->body), "{\"code\":\"%s\"}",
              state->otp_code);
  request_post_json(state, request,
                    OAUTH_AUTH_BASE_URL "/api/accounts/email-otp/validate",
                    state->body,
                    state->email_verification_url[0]
                        ? state->email_verification_url
                        : OAUTH_AUTH_BASE_URL "/email-verification");
  flow_context_log(flow, "info", "OAuth 验证码已获取，提交邮箱验证");
  return FLOW_PROVIDER_REQUEST;
}

static enum flow_provider_action next_token_exchange(struct flow_context *flow,
                                                     struct flow_http_request *request) {
  struct oauth_state *state = (struct oauth_state *) flow->provider_data;
  char code_enc[3072];
  char redirect_enc[256];
  char verifier_enc[256];

  if (flow->authorization_code[0] == '\0') {
    flow_context_fail(flow, "OAuth token exchange 缺少授权码");
    return FLOW_PROVIDER_FAILED;
  }
  mg_url_encode(flow->authorization_code, strlen(flow->authorization_code),
                code_enc, sizeof(code_enc));
  mg_url_encode(OAUTH_REDIRECT_URI, strlen(OAUTH_REDIRECT_URI),
                redirect_enc, sizeof(redirect_enc));
  mg_url_encode(flow->pkce_code_verifier, strlen(flow->pkce_code_verifier),
                verifier_enc, sizeof(verifier_enc));
  mg_snprintf(state->body, sizeof(state->body),
              "grant_type=authorization_code&client_id=%s&code=%s"
              "&redirect_uri=%s&code_verifier=%s",
              OAUTH_CLIENT_ID, code_enc, redirect_enc, verifier_enc);
  request_post_form(state, request, OAUTH_TOKEN_URL, state->body,
                    OAUTH_AUTH_BASE_URL "/oauth/authorize");
  flow_context_log(flow, "info", "步骤 %s: 使用授权码换取 Token",
                   step_label(flow->step));
  return FLOW_PROVIDER_REQUEST;
}

static enum flow_provider_action provider_next(struct flow_context *flow,
                                               struct flow_http_request *request) {
  struct oauth_state *state = (struct oauth_state *) flow->provider_data;

  if (state == NULL || request == NULL) {
    flow_context_fail(flow, "OAuth provider 状态丢失");
    return FLOW_PROVIDER_FAILED;
  }

  switch (flow->step) {
    case STEP_OAUTH_AUTHORIZE:
      request_get(state, request, state->authorize_url, NULL, "none");
      flow_context_log(flow, "info", "步骤 %s: 打开 OAuth 入口",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_OAUTH_AUTH:
      request_get(state, request, state->oauth_auth_url, state->authorize_url,
                  "same-origin");
      flow_context_log(flow, "info", "步骤 %s: 打开 OAuth auth",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_ACCOUNT_LOGIN:
      request_get(state, request, state->login_url, state->oauth_auth_url,
                  "same-origin");
      flow_context_log(flow, "info", "步骤 %s: 打开账号登录挑战",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_LOGIN_PAGE:
      if (state->login_url[0] == '\0') {
        mg_snprintf(state->login_url, sizeof(state->login_url), "%s/log-in",
                    OAUTH_AUTH_BASE_URL);
      }
      request_get(state, request, state->login_url, state->oauth_auth_url,
                  "same-origin");
      flow_context_log(flow, "info", "步骤 %s: 打开登录页",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_SENTINEL_AUTHORIZE_CONTINUE:
      if (state->device_id[0] == '\0') {
        flow_context_log(flow, "warn", "未获得 oai-did，跳过 authorize Sentinel");
        flow->step = STEP_AUTHORIZE_CONTINUE;
        return FLOW_PROVIDER_WAIT;
      }
      request_post_sentinel(state, request, "authorize_continue");
      flow_context_log(flow, "info", "步骤 %s: 请求 Sentinel Token",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_AUTHORIZE_CONTINUE:
      mg_snprintf(state->body, sizeof(state->body),
                  "{\"username\":{\"kind\":\"email\",\"value\":\"%s\"}}",
                  flow->identity.email);
      request_post_json(state, request,
                        OAUTH_AUTH_BASE_URL "/api/accounts/authorize/continue",
                        state->body, OAUTH_AUTH_BASE_URL "/log-in");
      add_authorize_sentinel_header(state);
      request->num_headers = state->num_headers;
      flow_context_log(flow, "info", "步骤 %s: 提交账号邮箱",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_SENTINEL_PASSWORD_VERIFY:
      if (state->device_id[0] == '\0') {
        flow_context_log(flow, "warn", "未获得 oai-did，跳过 password Sentinel");
        flow->step = STEP_PASSWORDLESS_SEND_OTP;
        return FLOW_PROVIDER_WAIT;
      }
      request_post_sentinel(state, request, "password_verify");
      flow_context_log(flow, "info", "步骤 %s: 刷新 Sentinel 校验",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_PASSWORDLESS_SEND_OTP:
      state->otp_sent_after_epoch = (long) time(NULL);
      state->otp_send_requested_ms = (long) mg_millis();
      state->otp_code[0] = '\0';
      request_post_json(state, request,
                        OAUTH_AUTH_BASE_URL
                        "/api/accounts/passwordless/send-otp",
                        "", state->password_url[0] ? state->password_url :
                             OAUTH_AUTH_BASE_URL "/log-in/password");
      request->body_len = 0;
      flow_context_log(flow, "info", "步骤 %s: 触发 OAuth 邮箱验证码",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_OTP_VALIDATE:
      return next_otp_request(flow, request);
    case STEP_CLIENT_AUTH_SESSION_DUMP:
      request_get(state, request,
                  OAUTH_AUTH_BASE_URL
                  "/api/accounts/client_auth_session_dump",
                  OAUTH_AUTH_BASE_URL "/log-in", "same-origin");
      state->num_headers = 0;
      set_header(state, "Accept", "application/json");
      set_header(state, "Referer", OAUTH_AUTH_BASE_URL "/log-in");
      set_header(state, "Origin", OAUTH_AUTH_BASE_URL);
      set_header(state, "Sec-Fetch-Dest", "empty");
      set_header(state, "Sec-Fetch-Mode", "cors");
      set_header(state, "Sec-Fetch-Site", "same-origin");
      request->headers = state->headers;
      request->num_headers = state->num_headers;
      flow_context_log(flow, "info", "步骤 %s: 读取授权会话摘要",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_CONSENT_PAGE:
      if (state->consent_url[0] == '\0') {
        build_oauth_auth_url(state, state->login_verifier[0] ? "login_verifier" : NULL,
                             state->login_verifier);
        mg_snprintf(state->consent_url, sizeof(state->consent_url), "%s",
                    state->oauth_auth_url);
      }
      request_get(state, request, state->consent_url,
                  OAUTH_AUTH_BASE_URL "/email-verification", "same-origin");
      flow_context_log(flow, "info", "步骤 %s: 请求 consent/授权态页面",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_WORKSPACE_SELECT:
      if (!state->workspace_select_enabled || state->workspace_id[0] == '\0') {
        flow->step = STEP_CONSENT_PAGE;
        return FLOW_PROVIDER_WAIT;
      }
      mg_snprintf(state->body, sizeof(state->body), "{\"workspace_id\":\"%s\"}",
                  state->workspace_id);
      request_post_json(state, request,
                        OAUTH_AUTH_BASE_URL "/api/accounts/workspace/select",
                        state->body,
                        OAUTH_AUTH_BASE_URL "/sign-in-with-chatgpt/codex/consent");
      flow_context_log(flow, "info", "步骤 %s: 选择 workspace %s",
                       step_label(flow->step), state->workspace_id);
      return FLOW_PROVIDER_REQUEST;
    case STEP_OAUTH_AFTER_LOGIN:
      request_get(state, request, state->oauth_auth_url,
                  OAUTH_AUTH_BASE_URL "/sign-in-with-chatgpt/codex/consent",
                  "same-origin");
      flow_context_log(flow, "info", "步骤 %s: 登录后继续 OAuth",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_CONSENT:
      request_get(state, request, state->consent_url,
                  OAUTH_AUTH_BASE_URL "/sign-in-with-chatgpt/codex/consent",
                  "same-origin");
      flow_context_log(flow, "info", "步骤 %s: 打开 OAuth consent",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_OAUTH_AFTER_CONSENT:
      request_get(state, request, state->oauth_auth_url,
                  OAUTH_AUTH_BASE_URL "/sign-in-with-chatgpt/codex/consent",
                  "same-origin");
      flow_context_log(flow, "info", "步骤 %s: consent 后继续 OAuth",
                       step_label(flow->step));
      return FLOW_PROVIDER_REQUEST;
    case STEP_FOLLOW_REDIRECT:
      if (state->redirect_url[0] == '\0') {
        flow_context_fail(flow, "OAuth 重定向链缺少下一跳");
        return FLOW_PROVIDER_FAILED;
      }
      if (oauth_try_callback_url(flow, state, state->redirect_url)) {
        return flow->status == FLOW_STATUS_FAILED ? FLOW_PROVIDER_FAILED
                                                  : FLOW_PROVIDER_WAIT;
      }
      request_get(state, request, state->redirect_url,
                  OAUTH_AUTH_BASE_URL "/sign-in-with-chatgpt/codex/consent",
                  "same-origin");
      flow_context_log(flow, "info", "步骤 %s: 跟随 OAuth 重定向 %d/8",
                       step_label(flow->step), state->redirect_count + 1);
      return FLOW_PROVIDER_REQUEST;
    case STEP_TOKEN_EXCHANGE:
      return next_token_exchange(flow, request);
    case STEP_DONE:
      return FLOW_PROVIDER_DONE;
    default:
      flow_context_fail(flow, "未知 OAuth 步骤");
      return FLOW_PROVIDER_FAILED;
  }
}

static void maybe_copy_login_verifier(struct oauth_state *state,
                                      const char *url) {
  if (state->login_verifier[0] == '\0') {
    copy_query_value_from_url(url, "login_verifier", state->login_verifier,
                              sizeof(state->login_verifier));
  }
}

static int handle_token_exchange_response(
    struct flow_context *flow, const struct flow_http_response *response) {
  struct mg_str json;
  char *access_token = NULL;
  char *refresh_token = NULL;
  char *id_token = NULL;
  char payload[8192];

  if (!expect_success(flow, response, "token exchange")) return -1;
  json = mg_str_n(response->body ? response->body : "", response->body_len);
  access_token = mg_json_get_str(json, "$.access_token");
  refresh_token = mg_json_get_str(json, "$.refresh_token");
  id_token = mg_json_get_str(json, "$.id_token");
  if (access_token == NULL || access_token[0] == '\0') {
    flow_context_fail(flow, "OAuth token exchange 未返回 access_token");
    goto fail;
  }
  mg_snprintf(flow->access_token, sizeof(flow->access_token), "%s",
              access_token);
  mg_snprintf(flow->refresh_token, sizeof(flow->refresh_token), "%s",
              refresh_token ? refresh_token : "");
  mg_snprintf(flow->id_token, sizeof(flow->id_token), "%s",
              id_token ? id_token : "");

  if (id_token != NULL && decode_jwt_payload(id_token, payload,
                                             sizeof(payload))) {
    struct mg_str claims = mg_str(payload);
    if (flow->identity.email[0] == '\0') {
      copy_json_string(claims, "$.email", flow->identity.email,
                       sizeof(flow->identity.email));
    }
    if (flow->external_account_id[0] == '\0') {
      copy_json_key_string(payload, "chatgpt_account_id",
                           flow->external_account_id,
                           sizeof(flow->external_account_id));
    }
    if (flow->workspace_id[0] == '\0') {
      if (!copy_json_key_string(payload, "chatgpt_workspace_id",
                                flow->workspace_id,
                                sizeof(flow->workspace_id))) {
        copy_json_key_string(payload, "workspace_id", flow->workspace_id,
                             sizeof(flow->workspace_id));
      }
    }
  }

  flow_context_log(flow, "info",
                   "OAuth Token 获取完成，account=%s workspace=%s",
                   flow->external_account_id[0] ? flow->external_account_id
                                                : "-",
                   flow->workspace_id[0] ? flow->workspace_id : "-");
  mg_free(access_token);
  mg_free(refresh_token);
  mg_free(id_token);
  flow->step = STEP_DONE;
  return 0;

fail:
  mg_free(access_token);
  mg_free(refresh_token);
  mg_free(id_token);
  return -1;
}

static int provider_response(struct flow_context *flow,
                             const struct flow_http_response *response) {
  struct oauth_state *state = (struct oauth_state *) flow->provider_data;
  char short_url[FLOW_URL_LEN];

  if (state == NULL || response == NULL) {
    flow_context_fail(flow, "OAuth 响应状态丢失");
    return -1;
  }
  if (response_has_phone_marker(response)) {
    flow_context_fail(flow, "检测到手机号验证，OAuth 失败");
    flow_context_log(flow, "warn",
                     "OAuth 命中手机号验证标记，当前账号不再重试");
    return -1;
  }

  switch (flow->step) {
    case STEP_OAUTH_AUTHORIZE:
      if (!expect_success(flow, response, "oauth authorize")) return -1;
      if (response->location[0] != '\0') {
        make_absolute_url(response->location, state->oauth_auth_url,
                          sizeof(state->oauth_auth_url));
      } else {
        build_oauth_auth_url(state, NULL, NULL);
      }
      sanitized_url(state->oauth_auth_url, short_url, sizeof(short_url));
      flow_context_log(flow, "info", "步骤 %s 完成，next=%s",
                       step_label(flow->step), short_url);
      flow->step = STEP_OAUTH_AUTH;
      return 0;
    case STEP_OAUTH_AUTH:
      if (!expect_success(flow, response, "oauth auth")) return -1;
      if (response->location[0] == '\0') {
        flow_context_fail(flow, "oauth auth 响应未返回登录挑战地址");
        return -1;
      }
      make_absolute_url(response->location, state->login_url,
                        sizeof(state->login_url));
      flow_context_log(flow, "info", "步骤 %s 完成，进入登录挑战",
                       step_label(flow->step));
      flow->step = STEP_ACCOUNT_LOGIN;
      return 0;
    case STEP_ACCOUNT_LOGIN:
      if (!expect_success(flow, response, "account login")) return -1;
      if (response->location[0] != '\0') {
        make_absolute_url(response->location, state->login_url,
                          sizeof(state->login_url));
      } else {
        mg_snprintf(state->login_url, sizeof(state->login_url), "%s/log-in",
                    OAUTH_AUTH_BASE_URL);
      }
      flow_context_log(flow, "info", "步骤 %s 完成，打开登录页",
                       step_label(flow->step));
      flow->step = STEP_LOGIN_PAGE;
      return 0;
    case STEP_LOGIN_PAGE:
      if (!expect_success(flow, response, "login page")) return -1;
      if (response->device_id[0] != '\0') {
        mg_snprintf(state->device_id, sizeof(state->device_id), "%s",
                    response->device_id);
        flow_context_log(flow, "debug", "已同步 oai-did=%s",
                         state->device_id);
      }
      flow_context_log(flow, "info", "步骤 %s 完成",
                       step_label(flow->step));
      flow->step = STEP_SENTINEL_AUTHORIZE_CONTINUE;
      return 0;
    case STEP_SENTINEL_AUTHORIZE_CONTINUE:
      if (response->status_code >= 200 && response->status_code < 400) {
        if (copy_json_string_from_response(response, "$.token",
                                           state->sentinel_authorize_token,
                                           sizeof(state->sentinel_authorize_token))) {
          flow_context_log(flow, "info", "步骤 %s 完成，已获得 Sentinel Token",
                           step_label(flow->step));
        } else {
          flow_context_log(flow, "warn", "Sentinel 响应未返回 token，继续尝试");
        }
      } else {
        flow_context_log(flow, "warn", "Sentinel 请求失败 HTTP %ld，继续尝试",
                         response->status_code);
      }
      flow->step = STEP_AUTHORIZE_CONTINUE;
      return 0;
    case STEP_AUTHORIZE_CONTINUE:
      if (!expect_success(flow, response, "authorize continue")) return -1;
      maybe_copy_login_verifier(state, response->location);
      if (!copy_json_string_from_response(response, "$.continue_url",
                                          state->password_url,
                                          sizeof(state->password_url))) {
        mg_snprintf(state->password_url, sizeof(state->password_url),
                    "%s/log-in/password", OAUTH_AUTH_BASE_URL);
      }
      {
        char page_type[96] = "";
        copy_json_string_from_response(response, "$.page.type", page_type,
                                       sizeof(page_type));
        flow_context_log(flow, "info", "步骤 %s 完成，page=%s%s",
                         step_label(flow->step),
                         page_type[0] ? page_type : "unknown",
                         state->login_verifier[0] ? "，已获得 login_verifier" :
                                                    "");
      }
      flow->step = STEP_SENTINEL_PASSWORD_VERIFY;
      return 0;
    case STEP_SENTINEL_PASSWORD_VERIFY:
      if (response->status_code >= 200 && response->status_code < 400) {
        flow_context_log(flow, "info", "步骤 %s 完成",
                         step_label(flow->step));
      } else {
        flow_context_log(flow, "warn",
                         "password Sentinel 请求失败 HTTP %ld，继续尝试",
                         response->status_code);
      }
      flow->step = STEP_PASSWORDLESS_SEND_OTP;
      return 0;
    case STEP_PASSWORDLESS_SEND_OTP:
      if (!expect_success(flow, response, "passwordless send otp")) return -1;
      if (!copy_json_string_from_response(response, "$.continue_url",
                                          state->email_verification_url,
                                          sizeof(state->email_verification_url))) {
        mg_snprintf(state->email_verification_url,
                    sizeof(state->email_verification_url),
                    "%s/email-verification", OAUTH_AUTH_BASE_URL);
      }
      {
        char page_type[96] = "";
        copy_json_string_from_response(response, "$.page.type", page_type,
                                       sizeof(page_type));
        flow_context_log(flow, "info", "步骤 %s 完成，page=%s",
                         step_label(flow->step),
                         page_type[0] ? page_type : "unknown");
      }
      flow->step = STEP_OTP_VALIDATE;
      flow->next_retry_ms = 0;
      return 0;
    case STEP_OTP_VALIDATE:
      if (response->status_code < 200 || response->status_code >= 400) {
        char preview[FLOW_LOG_LEN];
        body_preview(response, preview, sizeof(preview));
        if (flow_response_is_edge_block(response)) {
          flow_context_mark_environment_retry(
              flow, "边缘风控拦截，需要重新分配环境重试");
        }
        flow_context_log(flow, "warn",
                         "email otp validate 失败: HTTP %ld body=%luB ip=%s server=%s cf=%s ray=%s location=%s",
                         response->status_code,
                         (unsigned long) response->body_len,
                         response->primary_ip[0] ? response->primary_ip : "-",
                         response->server[0] ? response->server : "-",
                         response->cf_mitigated[0] ? response->cf_mitigated : "-",
                         response->cf_ray[0] ? response->cf_ray : "-",
                         response->location[0] ? response->location : "-");
        if (flow->environment_retryable) {
          flow_context_log(flow, "warn",
                           "email otp validate 触发边缘风控，当前环境将被丢弃并重试");
        }
        if (preview[0] != '\0') {
          flow_context_log(flow, "warn",
                           "email otp validate 响应片段: %s", preview);
        }
        if (flow->environment_retryable) return -1;
        if (state->otp_validation_retries < 1 &&
            (response->status_code == 400 || response->status_code == 401 ||
             response->status_code == 409)) {
          state->otp_validation_retries++;
          state->otp_attempts = 0;
          state->otp_code[0] = '\0';
          flow_context_log(flow, "warn",
                           "验证码校验失败，重新触发 OAuth 邮箱验证码后重试一次");
          flow->step = STEP_PASSWORDLESS_SEND_OTP;
          flow->next_retry_ms = (long) mg_millis() + 1000;
          return 0;
        }
        flow_context_fail(flow, "OAuth 请求返回非成功状态");
        return -1;
      }
      flow_context_emit_event(flow, FLOW_EVENT_OAUTH_OTP_VALIDATED);
      if (flow_context_cancel_requested(flow)) {
        flow_context_cancel(flow, "OAuth 验证码校验分支已取消");
        return -1;
      }
      maybe_copy_login_verifier(state, response->location);
      if (copy_json_string_from_response(response, "$.continue_url",
                                         state->consent_url,
                                         sizeof(state->consent_url))) {
        make_absolute_url(state->consent_url, state->consent_url,
                          sizeof(state->consent_url));
        if (oauth_try_callback_url(flow, state, state->consent_url)) {
          return flow->status == FLOW_STATUS_FAILED ? -1 : 0;
        }
      }
      if (copy_workspace_id_from_response(response, state->workspace_id,
                                          sizeof(state->workspace_id))) {
        state->workspace_select_enabled = true;
        flow_context_log(flow, "info",
                         "步骤 %s 完成，已从验证码响应提取 Workspace ID=%s",
                         step_label(flow->step), state->workspace_id);
        flow->step = STEP_WORKSPACE_SELECT;
        return 0;
      }
      flow_context_log(flow, "info", "步骤 %s 完成",
                       step_label(flow->step));
      flow->step = STEP_CLIENT_AUTH_SESSION_DUMP;
      return 0;
    case STEP_CLIENT_AUTH_SESSION_DUMP:
      if (response->status_code >= 200 && response->status_code < 400) {
        if (copy_workspace_id_from_response(response, state->workspace_id,
                                            sizeof(state->workspace_id))) {
          state->workspace_select_enabled = true;
          flow_context_log(flow, "info", "步骤 %s 完成，Workspace ID=%s",
                           step_label(flow->step), state->workspace_id);
          flow->step = STEP_WORKSPACE_SELECT;
          return 0;
        }
        flow_context_log(flow, "warn",
                         "授权会话摘要中未提取到 Workspace ID，继续请求 consent 页面");
      } else {
        flow_context_log(flow, "warn",
                         "授权会话摘要读取失败 HTTP %ld，继续请求 consent 页面",
                         response->status_code);
      }
      flow->step = STEP_CONSENT_PAGE;
      return 0;
    case STEP_CONSENT_PAGE:
      if (!expect_success(flow, response, "consent page")) return -1;
      if (response->location[0] != '\0') {
        char next_url[FLOW_URL_LEN];
        make_absolute_url(response->location, next_url, sizeof(next_url));
        if (oauth_try_callback_url(flow, state, next_url)) {
          return flow->status == FLOW_STATUS_FAILED ? -1 : 0;
        }
        mg_snprintf(state->consent_url, sizeof(state->consent_url), "%s",
                    next_url);
      }
      if (copy_workspace_id_from_response(response, state->workspace_id,
                                          sizeof(state->workspace_id))) {
        state->workspace_select_enabled = true;
        flow_context_log(flow, "info", "步骤 %s 完成，Workspace ID=%s",
                         step_label(flow->step), state->workspace_id);
        flow->step = STEP_WORKSPACE_SELECT;
        return 0;
      }
      if (copy_query_value_from_url(state->consent_url, "consent_challenge",
                                    state->consent_verifier,
                                    sizeof(state->consent_verifier)) ||
          copy_query_value_from_url(state->consent_url, "consent_verifier",
                                    state->consent_verifier,
                                    sizeof(state->consent_verifier))) {
        flow_context_log(flow, "info", "步骤 %s 完成，进入 consent",
                         step_label(flow->step));
        flow->step = STEP_CONSENT;
        return 0;
      }
      flow_context_fail(flow, "consent 页面未返回 Workspace、consent 或授权码");
      return -1;
    case STEP_WORKSPACE_SELECT:
      if (!expect_success(flow, response, "workspace select")) return -1;
      if (!copy_json_string_from_response(response, "$.continue_url",
                                          state->redirect_url,
                                          sizeof(state->redirect_url)) ||
          state->redirect_url[0] == '\0') {
        flow_context_fail(flow, "workspace/select 响应里缺少 continue_url");
        return -1;
      }
      make_absolute_url(state->redirect_url, state->redirect_url,
                        sizeof(state->redirect_url));
      ensure_codex_originator(state->redirect_url, sizeof(state->redirect_url));
      state->redirect_count = 0;
      {
        char redirect_uri[256] = "";
        char originator[96] = "";
        copy_query_value_from_url(state->redirect_url, "redirect_uri",
                                  redirect_uri, sizeof(redirect_uri));
        copy_query_value_from_url(state->redirect_url, "originator",
                                  originator, sizeof(originator));
        flow_context_log(flow, "debug",
                         "workspace/select continue_url len=%lu redirect_uri=%s originator=%s",
                         (unsigned long) strlen(state->redirect_url),
                         redirect_uri[0] ? redirect_uri : "-",
                         originator[0] ? originator : "-");
      }
      flow_context_log(flow, "info", "步骤 %s 完成，继续 OAuth 重定向链",
                       step_label(flow->step));
      flow->step = STEP_FOLLOW_REDIRECT;
      return 0;
    case STEP_OAUTH_AFTER_LOGIN:
      if (!expect_success(flow, response, "oauth after login")) return -1;
      if (response->location[0] != '\0') {
        make_absolute_url(response->location, state->consent_url,
                          sizeof(state->consent_url));
      }
      if (oauth_try_callback_url(flow, state, state->consent_url)) {
        return flow->status == FLOW_STATUS_FAILED ? -1 : 0;
      }
      if (copy_workspace_id_from_response(response, state->workspace_id,
                                          sizeof(state->workspace_id))) {
        state->workspace_select_enabled = true;
        flow_context_log(flow, "info", "步骤 %s 完成，Workspace ID=%s",
                         step_label(flow->step), state->workspace_id);
        flow->step = STEP_WORKSPACE_SELECT;
        return 0;
      }
      if (state->consent_url[0] == '\0' ||
          !copy_query_value_from_url(state->consent_url, "consent_challenge",
                                     state->consent_verifier,
                                     sizeof(state->consent_verifier))) {
        flow_context_fail(flow, "oauth after login 未返回 Workspace、consent 或授权码");
        return -1;
      }
      flow_context_log(flow, "info", "步骤 %s 完成，进入 consent",
                       step_label(flow->step));
      flow->step = STEP_CONSENT;
      return 0;
    case STEP_CONSENT:
      if (!expect_success(flow, response, "consent")) return -1;
      if (response->location[0] == '\0') {
        flow_context_fail(flow, "consent 响应未返回 OAuth 继续地址");
        return -1;
      }
      make_absolute_url(response->location, state->oauth_auth_url,
                        sizeof(state->oauth_auth_url));
      copy_query_value_from_url(state->oauth_auth_url, "consent_verifier",
                                state->consent_verifier,
                                sizeof(state->consent_verifier));
      flow_context_log(flow, "info", "步骤 %s 完成，继续 OAuth",
                       step_label(flow->step));
      flow->step = STEP_OAUTH_AFTER_CONSENT;
      return 0;
    case STEP_OAUTH_AFTER_CONSENT:
      if (!expect_success(flow, response, "oauth after consent")) return -1;
      if (response->location[0] != '\0') {
        make_absolute_url(response->location, state->callback_url,
                          sizeof(state->callback_url));
      }
      if (!copy_query_value_from_url(state->callback_url, "code",
                                     flow->authorization_code,
                                     sizeof(flow->authorization_code))) {
        flow_context_fail(flow, "OAuth callback 中未找到授权码");
        return -1;
      }
      {
        char returned_state[128] = "";
        copy_query_value_from_url(state->callback_url, "state", returned_state,
                                  sizeof(returned_state));
        if (strcmp(returned_state, state->state) != 0) {
          flow_context_fail(flow, "OAuth callback state 不匹配");
          return -1;
        }
      }
      flow_context_log(flow, "info", "OAuth 授权码获取完成，准备 token exchange");
      flow->step = STEP_TOKEN_EXCHANGE;
      return 0;
    case STEP_FOLLOW_REDIRECT:
      if (!expect_success(flow, response, "follow redirect")) return -1;
      if (response->location[0] == '\0') {
        if (oauth_try_callback_url(flow, state, response->effective_url)) {
          return flow->status == FLOW_STATUS_FAILED ? -1 : 0;
        }
        flow_context_fail(flow, "OAuth 重定向链未返回下一跳");
        return -1;
      }
      make_absolute_url(response->location, state->redirect_url,
                        sizeof(state->redirect_url));
      if (oauth_try_callback_url(flow, state, state->redirect_url)) {
        return flow->status == FLOW_STATUS_FAILED ? -1 : 0;
      }
      state->redirect_count++;
      if (state->redirect_count >= 8) {
        flow_context_fail(flow, "OAuth 重定向链超过上限");
        return -1;
      }
      flow_context_log(flow, "info", "OAuth 重定向下一跳已更新");
      flow->step = STEP_FOLLOW_REDIRECT;
      return 0;
    case STEP_TOKEN_EXCHANGE:
      return handle_token_exchange_response(flow, response);
    default:
      flow_context_fail(flow, "收到未知 OAuth 步骤响应");
      return -1;
  }
}

static void provider_cleanup(struct flow_context *flow) {
  if (flow == NULL) return;
  free(flow->provider_data);
  flow->provider_data = NULL;
}

static const struct flow_provider s_provider = {
    "oauth-code-har",
    provider_start,
    provider_next,
    provider_response,
    provider_cleanup,
};

const struct flow_provider *oauth_code_provider(void) {
  return &s_provider;
}
