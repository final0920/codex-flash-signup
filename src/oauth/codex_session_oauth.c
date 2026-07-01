#include "oauth/codex_session_oauth.h"

#include "account/account_store.h"
#include "mongoose.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CODEX_AUTH_BASE_URL "https://auth.openai.com"
#define CODEX_AUTHORIZE_URL CODEX_AUTH_BASE_URL "/oauth/authorize"
#define CODEX_TOKEN_URL CODEX_AUTH_BASE_URL "/oauth/token"
#define CODEX_CHOOSE_ACCOUNT_URL CODEX_AUTH_BASE_URL "/choose-an-account"
#define CODEX_SESSION_SELECT_URL CODEX_AUTH_BASE_URL "/api/accounts/session/select"
#define CODEX_CONSENT_DATA_URL \
  CODEX_AUTH_BASE_URL \
  "/sign-in-with-chatgpt/codex/consent.data?_routes=SIGN_IN_WITH_CHATGPT_CODEX_CONSENT"
#define CODEX_CLIENT_ID "app_EMoamEEZ73f0CkXaXp7hrann"
#define CODEX_REDIRECT_URI "http://localhost:1455/auth/callback"
#define CODEX_SCOPE "openid email profile offline_access"

static bool decode_jwt_payload(const char *token, char *out, size_t out_len);
static void make_absolute_url(const char *location, char *out, size_t out_len);

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

static void set_header(struct codex_current_session_state *state,
                       const char *name, const char *value) {
  if (state == NULL ||
      state->num_headers >= sizeof(state->headers) / sizeof(state->headers[0])) {
    return;
  }
  if (name == NULL || value == NULL || value[0] == '\0') return;
  state->headers[state->num_headers].name = name;
  state->headers[state->num_headers].value = value;
  state->num_headers++;
}

static void set_nav_headers(struct codex_current_session_state *state,
                            const char *referer, const char *site) {
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

static void set_json_headers(struct codex_current_session_state *state,
                             const char *referer) {
  state->num_headers = 0;
  mg_snprintf(state->header_origin, sizeof(state->header_origin), "%s",
              CODEX_AUTH_BASE_URL);
  mg_snprintf(state->header_referer, sizeof(state->header_referer), "%s",
              referer ? referer : CODEX_AUTH_BASE_URL "/");
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

static void request_get(struct codex_current_session_state *state,
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

static void request_post_json(struct codex_current_session_state *state,
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

static void request_get_fetch(struct codex_current_session_state *state,
                              struct flow_http_request *request,
                              const char *url, const char *referer) {
  state->num_headers = 0;
  mg_snprintf(state->header_referer, sizeof(state->header_referer), "%s",
              referer ? referer : CODEX_CHOOSE_ACCOUNT_URL);
  set_header(state, "Accept", "*/*");
  set_header(state, "Referer", state->header_referer);
  set_header(state, "Sec-Fetch-Dest", "empty");
  set_header(state, "Sec-Fetch-Mode", "cors");
  set_header(state, "Sec-Fetch-Site", "same-origin");
  request->method = "GET";
  request->url = url;
  request->timeout_ms = 30000;
  request->follow_location = false;
  request->headers = state->headers;
  request->num_headers = state->num_headers;
}

static void request_post_form(struct codex_current_session_state *state,
                              struct flow_http_request *request,
                              const char *url, const char *body,
                              const char *referer) {
  state->num_headers = 0;
  mg_snprintf(state->header_origin, sizeof(state->header_origin), "%s",
              CODEX_AUTH_BASE_URL);
  mg_snprintf(state->header_referer, sizeof(state->header_referer), "%s",
              referer ? referer : CODEX_AUTHORIZE_URL);
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

static void start_follow_redirect(struct codex_current_session_state *state,
                                  const char *url, const char *referer,
                                  const char *site) {
  if (state == NULL) return;
  make_absolute_url(url, state->redirect_url, sizeof(state->redirect_url));
  mg_snprintf(state->redirect_referer, sizeof(state->redirect_referer), "%s",
              referer ? referer : "");
  mg_snprintf(state->redirect_site, sizeof(state->redirect_site), "%s",
              site ? site : "same-origin");
  state->redirect_count = 0;
  state->step = CODEX_CURRENT_SESSION_FOLLOW_REDIRECT;
}

static void start_follow_redirect_from_step(
    struct codex_current_session_state *state, const char *url,
    const char *effective_url) {
  const char *referer = NULL;
  const char *site = "same-origin";

  if (state == NULL) return;
  switch (state->step) {
    case CODEX_CURRENT_SESSION_AUTHORIZE:
      site = "none";
      referer = NULL;
      break;
    case CODEX_CURRENT_SESSION_SESSION_SELECT:
      referer = CODEX_CHOOSE_ACCOUNT_URL;
      break;
    case CODEX_CURRENT_SESSION_CONSENT_PAGE:
      referer = effective_url != NULL && effective_url[0] != '\0'
                    ? effective_url
                    : (state->consent_url[0] ? state->consent_url
                                             : CODEX_CHOOSE_ACCOUNT_URL);
      break;
    case CODEX_CURRENT_SESSION_WORKSPACE_SELECT:
      referer = CODEX_AUTH_BASE_URL "/sign-in-with-chatgpt/codex/consent";
      break;
    default:
      referer = effective_url;
      break;
  }
  start_follow_redirect(state, url, referer, site);
}

static void make_absolute_url(const char *location, char *out, size_t out_len) {
  char copy[FLOW_URL_LEN];
  if (out_len == 0) return;
  if (location == out && location != NULL) {
    mg_snprintf(copy, sizeof(copy), "%s", location);
    location = copy;
  }
  out[0] = '\0';
  if (location == NULL || location[0] == '\0') return;
  if (strncmp(location, "http://", 7) == 0 ||
      strncmp(location, "https://", 8) == 0) {
    mg_snprintf(out, out_len, "%s", location);
  } else if (location[0] == '/') {
    mg_snprintf(out, out_len, "%s%s", CODEX_AUTH_BASE_URL, location);
  } else {
    mg_snprintf(out, out_len, "%s/%s", CODEX_AUTH_BASE_URL, location);
  }
}

static bool copy_query_value_from_url(const char *url, const char *name,
                                      char *out, size_t out_len) {
  const char *q;
  size_t name_len;
  char decoded[FLOW_URL_LEN];
  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
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

static bool response_has_consent_marker(
    const struct flow_http_response *response) {
  if (response == NULL) return false;
  return contains_casefold(response->location,
                           "sign-in-with-chatgpt/codex/consent") ||
         contains_casefold(response->effective_url,
                           "sign-in-with-chatgpt/codex/consent") ||
         contains_casefold(response->location, "/api/accounts/consent") ||
         contains_casefold(response->effective_url, "/api/accounts/consent") ||
         contains_casefold(response->body, "workspace/select") ||
         contains_casefold(response->body, "consent_verifier");
}

static bool response_has_choose_account_marker(
    const struct flow_http_response *response) {
  if (response == NULL || response_has_consent_marker(response)) return false;
  return contains_casefold(response->location, "choose-an-account") ||
         contains_casefold(response->effective_url, "choose-an-account") ||
         contains_casefold(response->body, "choose-an-account") ||
         contains_casefold(response->body, "choose an account");
}

static bool response_has_phone_marker(
    const struct flow_http_response *response) {
  if (response == NULL || response_has_consent_marker(response)) return false;
  return contains_casefold(response->location, "add-phone") ||
         contains_casefold(response->effective_url, "add-phone") ||
         contains_casefold(response->location, "add_phone") ||
         contains_casefold(response->effective_url, "add_phone") ||
         contains_casefold(response->location, "phone-verification") ||
         contains_casefold(response->effective_url, "phone-verification") ||
         contains_casefold(response->body, "add-phone") ||
         contains_casefold(response->body, "add_phone") ||
         contains_casefold(response->body, "phone-verification");
}

static bool response_has_login_marker(
    const struct flow_http_response *response) {
  if (response == NULL) return false;
  if (response_has_consent_marker(response)) return false;
  if (response_has_choose_account_marker(response)) return false;
  return contains_casefold(response->location, "/log-in") ||
         contains_casefold(response->effective_url, "/log-in") ||
         contains_casefold(response->body, "action=\"/log-in\"") ||
         contains_casefold(response->body, "action='/log-in'") ||
         contains_casefold(response->body, "name=\"username\"") ||
         contains_casefold(response->body, "authorize/continue");
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
    if (*value == '\\' && value[1] != '\0') {
      value++;
      if (*value == '/') {
        out[n++] = '/';
        value++;
        continue;
      }
    }
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

    if (array_start != NULL &&
        (scope_start == NULL || array_start < scope_start)) {
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

static bool is_unified_session_id(const char *value) {
  return value != NULL && strncmp(value, "us_", 3) == 0;
}

static bool copy_unified_session_candidate(const char *candidate, char *out,
                                           size_t out_len) {
  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (!is_unified_session_id(candidate)) return false;
  mg_snprintf(out, out_len, "%s", candidate);
  return out[0] != '\0';
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
        while (value != NULL && *value && isspace((unsigned char) *value)) {
          value++;
        }
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

static bool copy_session_select_id_from_text(const char *text, char *out,
                                             size_t out_len,
                                             bool allow_top_level) {
  char candidate[160];
  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (text == NULL || text[0] == '\0') return false;
  if ((copy_object_id_after_json_key(text, "unified_sessions", candidate,
                                     sizeof(candidate)) ||
       copy_object_id_after_json_key(text, "account_sessions", candidate,
                                     sizeof(candidate)) ||
       copy_object_id_after_json_key(text, "sessions", candidate,
                                     sizeof(candidate)) ||
       copy_object_id_after_json_key(text, "session", candidate,
                                     sizeof(candidate))) &&
      copy_unified_session_candidate(candidate, out, out_len)) {
    return true;
  }
  if (!allow_top_level) return false;
  if ((copy_json_key_string(text, "selected_session_id", candidate,
                            sizeof(candidate)) ||
       copy_json_key_string(text, "selectedSessionId", candidate,
                            sizeof(candidate)) ||
       copy_json_key_string(text, "account_session_id", candidate,
                            sizeof(candidate)) ||
       copy_json_key_string(text, "accountSessionId", candidate,
                            sizeof(candidate)) ||
       copy_json_key_string(text, "session_id", candidate,
                            sizeof(candidate)) ||
       copy_json_key_string(text, "sessionId", candidate,
                            sizeof(candidate))) &&
      copy_unified_session_candidate(candidate, out, out_len)) {
    return true;
  }
  return false;
}

static bool copy_session_select_id_from_auth_cookie(const char *cookie,
                                                    char *out,
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
          if (copy_session_select_id_from_text(decoded, out, out_len, false)) {
            return true;
          }
        }
      }
    }

    if (dot == NULL) break;
    candidate = dot + 1;
  }
  return false;
}

static bool copy_unified_session_id_from_cookie_value(const char *value,
                                                      size_t value_len,
                                                      char *out,
                                                      size_t out_len) {
  char token[FLOW_COOKIE_LEN];
  char payload[FLOW_COOKIE_LEN];

  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (value == NULL || value_len == 0 || value_len >= sizeof(token)) {
    return false;
  }
  memcpy(token, value, value_len);
  token[value_len] = '\0';
  if (!decode_jwt_payload(token, payload, sizeof(payload))) return false;
  {
    char candidate[160];
    if (copy_object_id_after_json_key(payload, "unified_sessions", candidate,
                                      sizeof(candidate)) &&
        copy_unified_session_candidate(candidate, out, out_len)) {
      return true;
    }
  }
  if ((copy_json_key_string(payload, "encrypted_authenticated_data", out,
                            out_len) ||
       copy_json_key_string(payload, "session_id", out, out_len) ||
       copy_json_key_string(payload, "sessionId", out, out_len)) &&
      is_unified_session_id(out)) {
    return true;
  }
  out[0] = '\0';
  return false;
}

static bool copy_unified_session_id_from_cookie_header(const char *cookie_header,
                                                       char *out,
                                                       size_t out_len) {
  const char *p;

  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (cookie_header == NULL || cookie_header[0] == '\0') return false;
  p = cookie_header;
  while (*p != '\0') {
    const char *name;
    const char *eq;
    const char *end;
    size_t name_len;
    while (*p == ';' || *p == ' ' || *p == '\t') p++;
    if (*p == '\0') break;
    name = p;
    end = strchr(p, ';');
    if (end == NULL) end = p + strlen(p);
    eq = memchr(name, '=', (size_t) (end - name));
    if (eq != NULL) {
      name_len = (size_t) (eq - name);
      if (name_len > 4 && strncmp(name, "usc_", 4) == 0 &&
          copy_unified_session_id_from_cookie_value(
              eq + 1, (size_t) (end - eq - 1), out, out_len)) {
        return true;
      }
    }
    p = end;
  }
  return false;
}

static bool copy_session_select_id_from_response(
    const struct flow_http_response *response, char *out, size_t out_len) {
  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (response == NULL) return false;
  if (copy_unified_session_id_from_cookie_header(response->cookie_header, out,
                                                out_len)) {
    return true;
  }
  if (copy_session_select_id_from_text(response->body, out, out_len, true)) {
    return true;
  }
  if (copy_session_select_id_from_auth_cookie(response->auth_session_cookie,
                                             out, out_len)) {
    return true;
  }
  if (copy_session_select_id_from_auth_cookie(response->auth_info_cookie, out,
                                             out_len)) {
    return true;
  }
  return false;
}

static bool copy_url_token(const char *start, char *out, size_t out_len,
                           bool encoded) {
  char tmp[FLOW_URL_LEN];
  size_t n = 0;
  const char *p = start;
  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (start == NULL) return false;
  while (*p && n + 1 < sizeof(tmp)) {
    unsigned char ch = (unsigned char) *p;
    if (isspace(ch) || ch == '"' || ch == '\'' || ch == '<' || ch == '>' ||
        ch == ')' || ch == ']') {
      break;
    }
    if (p[0] == '\\' && p[1] == '/') {
      tmp[n++] = '/';
      p += 2;
      continue;
    }
    if (strncmp(p, "\\u0026", 6) == 0) {
      tmp[n++] = '&';
      p += 6;
      continue;
    }
    tmp[n++] = *p++;
  }
  tmp[n] = '\0';
  if (encoded) {
    char decoded[FLOW_URL_LEN];
    int decoded_len = mg_url_decode(tmp, strlen(tmp), decoded,
                                    sizeof(decoded), 0);
    if (decoded_len <= 0) return false;
    mg_snprintf(out, out_len, "%s", decoded);
  } else {
    char *amp;
    while ((amp = strstr(tmp, "&amp;")) != NULL) {
      memmove(amp + 1, amp + 5, strlen(amp + 5) + 1);
      amp[0] = '&';
    }
    mg_snprintf(out, out_len, "%s", tmp);
  }
  return out[0] != '\0';
}

static bool copy_callback_url_from_text(const char *text, char *out,
                                        size_t out_len) {
  const char *p;
  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (text == NULL || text[0] == '\0') return false;
  p = strstr(text, CODEX_REDIRECT_URI);
  if (p != NULL && copy_url_token(p, out, out_len, false)) return true;
  p = strstr(text, "http:\\/\\/localhost:1455\\/auth\\/callback");
  if (p != NULL && copy_url_token(p, out, out_len, false)) return true;
  p = strstr(text, "http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback");
  if (p != NULL && copy_url_token(p, out, out_len, true)) return true;
  p = strstr(text, "http%3a%2f%2flocalhost%3a1455%2fauth%2fcallback");
  if (p != NULL && copy_url_token(p, out, out_len, true)) return true;
  return false;
}

static bool copy_continue_url_from_response(
    const struct flow_http_response *response, char *out, size_t out_len) {
  static const char *paths[] = {
      "$.continue_url",
      "$.continueUrl",
      "$.redirect_url",
      "$.redirectUrl",
      "$.next_url",
      "$.nextUrl",
      "$.login_url",
      "$.loginUrl",
      "$.no_auth_url",
      "$.noAuthUrl",
      "$.callback_url",
      "$.callbackUrl",
      "$.auth_url",
      "$.authUrl",
      "$.authorize_url",
      "$.authorizeUrl",
      "$.url",
  };
  static const char *keys[] = {
      "continue_url",
      "continueUrl",
      "redirect_url",
      "redirectUrl",
      "next_url",
      "nextUrl",
      "login_url",
      "loginUrl",
      "no_auth_url",
      "noAuthUrl",
      "callback_url",
      "callbackUrl",
      "auth_url",
      "authUrl",
      "authorize_url",
      "authorizeUrl",
      "url",
  };
  char value[FLOW_URL_LEN];
  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (response == NULL) return false;
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    if (copy_json_string_from_response(response, paths[i], value,
                                       sizeof(value))) {
      make_absolute_url(value, out, out_len);
      return out[0] != '\0';
    }
  }
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
    if (copy_json_key_string(response->body, keys[i], value, sizeof(value))) {
      make_absolute_url(value, out, out_len);
      return out[0] != '\0';
    }
  }
  return false;
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

static void log_cookie_debug(struct flow_context *flow,
                             const struct flow_http_response *response,
                             const char *label) {
  char unified_id[160];
  bool has_auth_session;
  bool has_auth_info;
  bool has_usc;
  bool has_login_session;
  bool has_auth_provider;
  bool body_unified;
  bool auth_cookie_unified;

  if (flow == NULL || response == NULL) return;
  has_auth_session = response->auth_session_cookie[0] != '\0';
  has_auth_info = response->auth_info_cookie[0] != '\0';
  has_usc = contains_casefold(response->cookie_header, "usc_");
  has_login_session = contains_casefold(response->cookie_header,
                                        "login_session=");
  has_auth_provider = contains_casefold(response->cookie_header,
                                        "auth_provider=");
  body_unified = contains_casefold(response->body, "unified_sessions");
  auth_cookie_unified =
      copy_session_select_id_from_auth_cookie(response->auth_session_cookie,
                                              unified_id,
                                              sizeof(unified_id));
  if (!auth_cookie_unified) {
    unified_id[0] = '\0';
    copy_unified_session_id_from_cookie_header(response->cookie_header,
                                               unified_id,
                                               sizeof(unified_id));
  }
  flow_context_log(
      flow, "debug",
      "%s 会话诊断: auth_session=%s auth_info=%s usc=%s login_session=%s auth_provider=%s body_unified=%s unified=%s choose=%s login=%s phone=%s",
      label != NULL ? label : "Codex OAuth",
      has_auth_session ? "yes" : "no",
      has_auth_info ? "yes" : "no",
      has_usc ? "yes" : "no",
      has_login_session ? "yes" : "no",
      has_auth_provider ? "yes" : "no",
      body_unified ? "yes" : "no",
      unified_id[0] ? unified_id : "-",
      response_has_choose_account_marker(response) ? "yes" : "no",
      response_has_login_marker(response) ? "yes" : "no",
      response_has_phone_marker(response) ? "yes" : "no");
}

static bool expect_success(struct flow_context *flow,
                           const struct flow_http_response *response,
                           const char *label) {
  if (response->status_code >= 200 && response->status_code < 400) return true;
  if (flow_response_is_edge_block(response)) {
    flow_context_mark_environment_retry(flow,
                                        "边缘风控拦截，需要重新分配环境重试");
  } else {
    flow_context_fail(flow, "当前会话 Codex OAuth 请求返回非成功状态");
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

static bool try_callback_url(struct flow_context *flow,
                             struct codex_current_session_state *state,
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
    mg_snprintf(message, sizeof(message), "Codex OAuth 重定向返回错误: %s%s%s",
                oauth_error, error_description[0] ? ": " : "",
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
    flow_context_fail(flow, "Codex OAuth callback state 不匹配");
    return true;
  }
  mg_snprintf(state->callback_url, sizeof(state->callback_url), "%s", url);
  flow_context_log(flow, "info", "当前会话 Codex OAuth 已返回授权码");
  state->step = CODEX_CURRENT_SESSION_TOKEN_EXCHANGE;
  return true;
}

static bool try_callback_response(
    struct flow_context *flow, struct codex_current_session_state *state,
    const struct flow_http_response *response) {
  char candidate[FLOW_URL_LEN];
  if (response == NULL) return false;
  if (response->location[0] != '\0') {
    make_absolute_url(response->location, candidate, sizeof(candidate));
    if (try_callback_url(flow, state, candidate)) return true;
  }
  if (try_callback_url(flow, state, response->effective_url)) return true;
  if (copy_callback_url_from_text(response->body, candidate,
                                  sizeof(candidate))) {
    return try_callback_url(flow, state, candidate);
  }
  return false;
}

static void build_authorize_url(struct flow_context *flow,
                                struct codex_current_session_state *state,
                                bool prompt_login,
                                const char *login_hint) {
  char redirect_enc[256];
  char scope_enc[512];
  char login_hint_enc[256];
  (void) flow;
  mg_url_encode(CODEX_REDIRECT_URI, strlen(CODEX_REDIRECT_URI), redirect_enc,
                sizeof(redirect_enc));
  mg_url_encode(CODEX_SCOPE, strlen(CODEX_SCOPE), scope_enc,
                sizeof(scope_enc));
  if (login_hint != NULL && login_hint[0] != '\0') {
    mg_url_encode(login_hint, strlen(login_hint), login_hint_enc,
                  sizeof(login_hint_enc));
  } else {
    login_hint_enc[0] = '\0';
  }
  mg_snprintf(state->authorize_url, sizeof(state->authorize_url),
              CODEX_AUTHORIZE_URL
              "?response_type=code&client_id=%s&redirect_uri=%s&state=%s"
              "&scope=%s&code_challenge=%s&code_challenge_method=S256",
              CODEX_CLIENT_ID, redirect_enc, state->state, scope_enc,
              state->code_challenge);
  if (prompt_login) {
    strncat(state->authorize_url, "&prompt=login",
            sizeof(state->authorize_url) - strlen(state->authorize_url) - 1);
  }
  if (login_hint_enc[0] != '\0') {
    strncat(state->authorize_url, "&login_hint=",
            sizeof(state->authorize_url) - strlen(state->authorize_url) - 1);
    strncat(state->authorize_url, login_hint_enc,
            sizeof(state->authorize_url) - strlen(state->authorize_url) - 1);
  }
  strncat(state->authorize_url, "&id_token_add_organizations=true",
          sizeof(state->authorize_url) - strlen(state->authorize_url) - 1);
  strncat(state->authorize_url, "&codex_cli_simplified_flow=true",
          sizeof(state->authorize_url) - strlen(state->authorize_url) - 1);
}

static bool retry_authorize_without_prompt(
    struct flow_context *flow, struct codex_current_session_state *state,
    const char *reason) {
  bool with_login_hint;

  if (flow == NULL || state == NULL) return false;
  if (state->authorize_retry_count >= 2) return false;
  state->authorize_retry_count++;
  with_login_hint = state->authorize_retry_count >= 2 &&
                    flow->identity.email[0] != '\0';

  random_urlsafe(state->state, sizeof(state->state), 32);
  random_urlsafe(state->code_verifier, sizeof(state->code_verifier), 64);
  make_code_challenge(state->code_verifier, state->code_challenge,
                      sizeof(state->code_challenge));
  mg_snprintf(flow->pkce_code_verifier, sizeof(flow->pkce_code_verifier), "%s",
              state->code_verifier);
  flow->authorization_code[0] = '\0';
  state->consent_url[0] = '\0';
  state->redirect_url[0] = '\0';
  state->redirect_referer[0] = '\0';
  state->redirect_site[0] = '\0';
  state->callback_url[0] = '\0';
  state->session_id[0] = '\0';
  state->workspace_id[0] = '\0';
  state->redirect_count = 0;
  build_authorize_url(flow, state, false,
                      with_login_hint ? flow->identity.email : NULL);
  state->step = CODEX_CURRENT_SESSION_AUTHORIZE;
  flow_context_log(
      flow, "warn",
      "%s，重开 Codex authorize（无 prompt%s，第 %d/2 次）",
      reason ? reason : "当前会话 Codex OAuth 未进入可复用授权态",
      with_login_hint ? " + login_hint" : "", state->authorize_retry_count);
  return true;
}

static enum flow_provider_action next_token_exchange(
    struct flow_context *flow, struct codex_current_session_state *state,
    struct flow_http_request *request) {
  char code_enc[3072];
  char redirect_enc[256];
  char verifier_enc[256];

  if (flow->authorization_code[0] == '\0') {
    flow_context_fail(flow, "Codex OAuth token exchange 缺少授权码");
    return FLOW_PROVIDER_FAILED;
  }
  mg_url_encode(flow->authorization_code, strlen(flow->authorization_code),
                code_enc, sizeof(code_enc));
  mg_url_encode(CODEX_REDIRECT_URI, strlen(CODEX_REDIRECT_URI), redirect_enc,
                sizeof(redirect_enc));
  mg_url_encode(flow->pkce_code_verifier, strlen(flow->pkce_code_verifier),
                verifier_enc, sizeof(verifier_enc));
  mg_snprintf(state->body, sizeof(state->body),
              "grant_type=authorization_code&client_id=%s&code=%s"
              "&redirect_uri=%s&code_verifier=%s",
              CODEX_CLIENT_ID, code_enc, redirect_enc, verifier_enc);
  request_post_form(state, request, CODEX_TOKEN_URL, state->body,
                    CODEX_AUTHORIZE_URL);
  flow_context_log(flow, "info", "当前会话 Codex OAuth: 使用授权码换取 Token");
  return FLOW_PROVIDER_REQUEST;
}

static int apply_token_success(struct flow_context *flow) {
  struct account_success_record record;
  if (flow == NULL || flow->persisted_account_id <= 0) return 0;
  memset(&record, 0, sizeof(record));
  record.email = flow->identity.email;
  record.password = flow->identity.password;
  record.status = "active";
  record.upload_state = "not_uploaded";
  record.access_token = flow->access_token;
  record.refresh_token = flow->refresh_token;
  record.id_token = flow->id_token;
  record.external_account_id = flow->external_account_id;
  record.workspace_id = flow->workspace_id;
  if (account_apply_oauth_success(flow->db, flow->persisted_account_id,
                                  &record) != 0) {
    flow_context_fail(flow, "当前会话 Codex OAuth 结果写入账号库失败");
    return -1;
  }
  return 0;
}

static int handle_token_exchange_response(
    struct flow_context *flow, struct codex_current_session_state *state,
    const struct flow_http_response *response) {
  struct mg_str json;
  char *access_token = NULL;
  char *refresh_token = NULL;
  char *id_token = NULL;
  char payload[8192];

  if (!expect_success(flow, response, "codex token exchange")) return -1;
  json = mg_str_n(response->body ? response->body : "", response->body_len);
  access_token = mg_json_get_str(json, "$.access_token");
  refresh_token = mg_json_get_str(json, "$.refresh_token");
  id_token = mg_json_get_str(json, "$.id_token");
  if (access_token == NULL || access_token[0] == '\0') {
    flow_context_fail(flow, "Codex OAuth token exchange 未返回 access_token");
    goto fail;
  }
  mg_snprintf(flow->access_token, sizeof(flow->access_token), "%s",
              access_token);
  mg_snprintf(flow->refresh_token, sizeof(flow->refresh_token), "%s",
              refresh_token ? refresh_token : "");
  mg_snprintf(flow->id_token, sizeof(flow->id_token), "%s",
              id_token ? id_token : "");
  if (flow->external_account_id[0] == '\0') {
    copy_json_string(json, "$.account_id", flow->external_account_id,
                     sizeof(flow->external_account_id));
  }
  if (flow->workspace_id[0] == '\0') {
    copy_json_string(json, "$.workspace_id", flow->workspace_id,
                     sizeof(flow->workspace_id));
  }
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
  if (flow->workspace_id[0] == '\0' && state->workspace_id[0] != '\0') {
    mg_snprintf(flow->workspace_id, sizeof(flow->workspace_id), "%s",
                state->workspace_id);
  }
  if (apply_token_success(flow) != 0) goto fail;
  mg_snprintf(flow->success_account_status, sizeof(flow->success_account_status),
              "active");
  flow_context_log(flow, "info",
                   "当前会话 Codex OAuth Token 获取完成，account=%s workspace=%s",
                   flow->external_account_id[0] ? flow->external_account_id
                                                : "-",
                   flow->workspace_id[0] ? flow->workspace_id : "-");
  mg_free(access_token);
  mg_free(refresh_token);
  mg_free(id_token);
  state->step = CODEX_CURRENT_SESSION_DONE;
  return 0;

fail:
  mg_free(access_token);
  mg_free(refresh_token);
  mg_free(id_token);
  return -1;
}

static bool begin_session_select_from_response(
    struct flow_context *flow, struct codex_current_session_state *state,
    const struct flow_http_response *response) {
  char session_id[sizeof(state->session_id)];

  if (flow == NULL || state == NULL || response == NULL) return false;
  if (!copy_session_select_id_from_response(response, session_id,
                                            sizeof(session_id))) {
    return false;
  }
  mg_snprintf(state->session_id, sizeof(state->session_id), "%s", session_id);
  state->step = CODEX_CURRENT_SESSION_SESSION_SELECT;
  flow_context_log(flow, "info",
                   "当前会话 Codex OAuth 提取到可复用 unified session");
  return true;
}

static int move_to_workspace_or_consent(
    struct flow_context *flow, struct codex_current_session_state *state,
    const struct flow_http_response *response) {
  char workspace_id[FLOW_WORKSPACE_ID_LEN];
  char continue_url[FLOW_URL_LEN];

  if (try_callback_response(flow, state, response)) {
    return flow->status == FLOW_STATUS_FAILED ? -1 : 0;
  }
  if (response_has_phone_marker(response)) {
    flow_context_fail(flow, "phone_binding_required: 当前注册会话需要绑定手机号");
    return -1;
  }
  if (response_has_choose_account_marker(response)) {
    if (!begin_session_select_from_response(flow, state, response)) {
      flow_context_fail(flow,
                        "codex_session_select_required: choose-an-account 缺少可选登录会话");
      return -1;
    }
    return 0;
  }
  if (response_has_login_marker(response)) {
    flow_context_fail(flow, "codex_login_required: 当前注册会话无法直接完成 Codex OAuth");
    return -1;
  }
  if (copy_workspace_id_from_response(response, workspace_id,
                                      sizeof(workspace_id))) {
    mg_snprintf(state->workspace_id, sizeof(state->workspace_id), "%s",
                workspace_id);
    flow_context_log(flow, "info",
                     "当前会话 Codex OAuth 提取到 Workspace ID=%s",
                     state->workspace_id);
    state->step = CODEX_CURRENT_SESSION_WORKSPACE_SELECT;
    return 0;
  }
  if (copy_continue_url_from_response(response, continue_url,
                                      sizeof(continue_url))) {
    start_follow_redirect_from_step(state, continue_url,
                                    response->effective_url);
    return 0;
  }
  if (response_has_consent_marker(response)) {
    if (response->effective_url[0] != '\0') {
      mg_snprintf(state->consent_url, sizeof(state->consent_url), "%s",
                  response->effective_url);
    } else {
      mg_snprintf(state->consent_url, sizeof(state->consent_url), "%s",
                  state->authorize_url);
    }
    state->step = CODEX_CURRENT_SESSION_SESSION_DUMP;
    return 0;
  }
  state->step = CODEX_CURRENT_SESSION_SESSION_DUMP;
  return 0;
}

int codex_current_session_persist_baseline(struct flow_context *flow,
                                           const char *status) {
  struct account_success_record record;
  if (flow == NULL) return -1;
  if (flow->persisted_account_id > 0) return 0;
  if (flow->db == NULL || !flow->persist_on_success) return 0;
  memset(&record, 0, sizeof(record));
  record.email = flow->identity.email;
  record.password = flow->identity.password;
  record.status = status != NULL && status[0] != '\0' ? status : "temp";
  record.upload_state = "not_uploaded";
  record.external_account_id = flow->external_account_id;
  record.workspace_id = flow->workspace_id;
  if (account_insert_success(flow->db, &record, &flow->persisted_account_id) !=
      0) {
    flow_context_fail(flow, "注册账号写入账号库失败");
    return -1;
  }
  mg_snprintf(flow->success_account_status, sizeof(flow->success_account_status),
              "%s", record.status);
  flow->persist_on_success = false;
  flow_context_log(flow, "info",
                   "已先保留注册账号 ID=%ld，继续复用当前会话做 Codex OAuth",
                   flow->persisted_account_id);
  return 0;
}

int codex_current_session_start(struct flow_context *flow,
                                struct codex_current_session_state *state) {
  if (flow == NULL || state == NULL) return -1;
  memset(state, 0, sizeof(*state));
  random_urlsafe(state->state, sizeof(state->state), 32);
  random_urlsafe(state->code_verifier, sizeof(state->code_verifier), 64);
  make_code_challenge(state->code_verifier, state->code_challenge,
                      sizeof(state->code_challenge));
  mg_snprintf(flow->pkce_code_verifier, sizeof(flow->pkce_code_verifier), "%s",
              state->code_verifier);
  build_authorize_url(flow, state, true, NULL);
  state->step = CODEX_CURRENT_SESSION_AUTHORIZE;
  flow_context_log(flow, "info",
                   "当前会话 Codex OAuth 准备完成: 带 prompt=login，按已登录会话选择账号");
  return 0;
}

enum flow_provider_action codex_current_session_next(
    struct flow_context *flow, struct codex_current_session_state *state,
    struct flow_http_request *request) {
  if (flow == NULL || state == NULL || request == NULL) {
    if (flow != NULL) flow_context_fail(flow, "Codex OAuth provider 状态丢失");
    return FLOW_PROVIDER_FAILED;
  }

  switch (state->step) {
    case CODEX_CURRENT_SESSION_AUTHORIZE:
      request_get(state, request, state->authorize_url, NULL, "none");
      flow_context_log(flow, "info", "当前会话 Codex OAuth: 打开 authorize");
      return FLOW_PROVIDER_REQUEST;
    case CODEX_CURRENT_SESSION_SESSION_SELECT:
      if (state->session_id[0] == '\0') {
        flow_context_fail(flow, "Codex OAuth session/select 缺少 session_id");
        return FLOW_PROVIDER_FAILED;
      }
      mg_snprintf(state->body, sizeof(state->body),
                  "{\"session_id\":\"%s\"}", state->session_id);
      request_post_json(state, request, CODEX_SESSION_SELECT_URL, state->body,
                        CODEX_CHOOSE_ACCOUNT_URL);
      flow_context_log(flow, "info",
                       "当前会话 Codex OAuth: 选择登录会话");
      return FLOW_PROVIDER_REQUEST;
    case CODEX_CURRENT_SESSION_SESSION_DUMP:
      request_get(state, request,
                  CODEX_AUTH_BASE_URL
                  "/api/accounts/client_auth_session_dump",
                  state->consent_url[0] ? state->consent_url
                                        : CODEX_AUTH_BASE_URL "/",
                  "same-origin");
      state->num_headers = 0;
      set_header(state, "Accept", "application/json");
      set_header(state, "Referer",
                 state->consent_url[0] ? state->consent_url
                                       : CODEX_AUTH_BASE_URL "/");
      set_header(state, "Origin", CODEX_AUTH_BASE_URL);
      set_header(state, "Sec-Fetch-Dest", "empty");
      set_header(state, "Sec-Fetch-Mode", "cors");
      set_header(state, "Sec-Fetch-Site", "same-origin");
      request->headers = state->headers;
      request->num_headers = state->num_headers;
      flow_context_log(flow, "info",
                       "当前会话 Codex OAuth: 读取授权会话摘要");
      return FLOW_PROVIDER_REQUEST;
    case CODEX_CURRENT_SESSION_CONSENT_PAGE:
      if (state->consent_url[0] == '\0') {
        mg_snprintf(state->consent_url, sizeof(state->consent_url), "%s",
                    state->authorize_url);
      }
      if (strstr(state->consent_url, ".data") != NULL) {
        request_get_fetch(state, request, state->consent_url,
                          CODEX_CHOOSE_ACCOUNT_URL);
      } else {
        request_get(state, request, state->consent_url, CODEX_AUTHORIZE_URL,
                    "same-origin");
      }
      flow_context_log(flow, "info",
                       "当前会话 Codex OAuth: 请求 consent/授权态页面");
      return FLOW_PROVIDER_REQUEST;
    case CODEX_CURRENT_SESSION_WORKSPACE_SELECT:
      if (state->workspace_id[0] == '\0') {
        state->step = CODEX_CURRENT_SESSION_CONSENT_PAGE;
        return FLOW_PROVIDER_WAIT;
      }
      mg_snprintf(state->body, sizeof(state->body),
                  "{\"workspace_id\":\"%s\"}", state->workspace_id);
      request_post_json(state, request,
                        CODEX_AUTH_BASE_URL "/api/accounts/workspace/select",
                        state->body,
                        CODEX_AUTH_BASE_URL
                        "/sign-in-with-chatgpt/codex/consent");
      flow_context_log(flow, "info",
                       "当前会话 Codex OAuth: 选择 workspace %s",
                       state->workspace_id);
      return FLOW_PROVIDER_REQUEST;
    case CODEX_CURRENT_SESSION_FOLLOW_REDIRECT:
      if (state->redirect_url[0] == '\0') {
        flow_context_fail(flow, "Codex OAuth 重定向链缺少下一跳");
        return FLOW_PROVIDER_FAILED;
      }
      if (try_callback_url(flow, state, state->redirect_url)) {
        return flow->status == FLOW_STATUS_FAILED ? FLOW_PROVIDER_FAILED
                                                  : FLOW_PROVIDER_WAIT;
      }
      request_get(state, request, state->redirect_url,
                  state->redirect_referer[0] ? state->redirect_referer : NULL,
                  state->redirect_site[0] ? state->redirect_site
                                          : "same-origin");
      flow_context_log(flow, "info",
                       "当前会话 Codex OAuth: 跟随重定向 %d/8",
                       state->redirect_count + 1);
      flow_context_log(flow, "debug",
                       "当前会话 Codex OAuth 重定向请求头: referer=%s site=%s",
                       state->redirect_referer[0] ? state->redirect_referer
                                                  : "-",
                       state->redirect_site[0] ? state->redirect_site : "-");
      return FLOW_PROVIDER_REQUEST;
    case CODEX_CURRENT_SESSION_TOKEN_EXCHANGE:
      return next_token_exchange(flow, state, request);
    case CODEX_CURRENT_SESSION_DONE:
      return FLOW_PROVIDER_DONE;
    case CODEX_CURRENT_SESSION_IDLE:
    default:
      flow_context_fail(flow, "当前会话 Codex OAuth 尚未启动");
      return FLOW_PROVIDER_FAILED;
  }
}

int codex_current_session_on_response(
    struct flow_context *flow, struct codex_current_session_state *state,
    const struct flow_http_response *response) {
  char next_url[FLOW_URL_LEN];
  char workspace_id[FLOW_WORKSPACE_ID_LEN];

  if (flow == NULL || state == NULL || response == NULL) return -1;
  log_cookie_debug(flow, response,
                   codex_current_session_step_label(state->step));
  if (response_has_phone_marker(response)) {
    char preview[FLOW_LOG_LEN];
    body_preview(response, preview, sizeof(preview));
    flow_context_log(flow, "warn",
                     "当前会话 Codex OAuth 命中手机号绑定态: HTTP %ld location=%s",
                     response->status_code,
                     response->location[0] ? response->location : "-");
    if (preview[0] != '\0') {
      flow_context_log(flow, "warn",
                       "当前会话 Codex OAuth 手机号响应片段: %s", preview);
    }
    flow_context_fail(flow, "phone_binding_required: 当前注册会话需要绑定手机号");
    return -1;
  }
  if (state->step != CODEX_CURRENT_SESSION_TOKEN_EXCHANGE &&
      response_has_login_marker(response)) {
    if ((state->step == CODEX_CURRENT_SESSION_AUTHORIZE ||
         state->step == CODEX_CURRENT_SESSION_FOLLOW_REDIRECT) &&
        retry_authorize_without_prompt(
            flow, state,
            "当前会话 Codex OAuth 被导向登录页，尝试保留会话改走无 prompt 授权")) {
      return 0;
    }
    flow_context_fail(flow,
                      "codex_login_required: 当前注册会话无法直接完成 Codex OAuth");
    return -1;
  }

  switch (state->step) {
    case CODEX_CURRENT_SESSION_AUTHORIZE:
      if (!expect_success(flow, response, "codex authorize")) return -1;
      if (try_callback_response(flow, state, response)) {
        return flow->status == FLOW_STATUS_FAILED ? -1 : 0;
      }
      if (response_has_choose_account_marker(response) &&
          begin_session_select_from_response(flow, state, response)) {
        return 0;
      }
      if (response->location[0] != '\0') {
        start_follow_redirect_from_step(state, response->location,
                                        response->effective_url);
        return 0;
      }
      return move_to_workspace_or_consent(flow, state, response);
    case CODEX_CURRENT_SESSION_SESSION_SELECT:
      if (!expect_success(flow, response, "codex session select")) return -1;
      if (try_callback_response(flow, state, response)) {
        return flow->status == FLOW_STATUS_FAILED ? -1 : 0;
      }
      if (response->location[0] != '\0') {
        start_follow_redirect_from_step(state, response->location,
                                        response->effective_url);
        return 0;
      }
      if (copy_workspace_id_from_response(response, workspace_id,
                                          sizeof(workspace_id))) {
        mg_snprintf(state->workspace_id, sizeof(state->workspace_id), "%s",
                    workspace_id);
        flow_context_log(flow, "info",
                         "当前会话 Codex OAuth session/select 返回 Workspace ID=%s",
                         state->workspace_id);
        state->step = CODEX_CURRENT_SESSION_WORKSPACE_SELECT;
        return 0;
      }
      if (copy_continue_url_from_response(response, next_url,
                                          sizeof(next_url))) {
        start_follow_redirect_from_step(state, next_url,
                                        response->effective_url);
        return 0;
      }
      mg_snprintf(state->consent_url, sizeof(state->consent_url), "%s",
                  CODEX_CONSENT_DATA_URL);
      state->step = CODEX_CURRENT_SESSION_CONSENT_PAGE;
      return 0;
    case CODEX_CURRENT_SESSION_SESSION_DUMP:
      if (response->status_code >= 200 && response->status_code < 400 &&
          copy_workspace_id_from_response(response, workspace_id,
                                          sizeof(workspace_id))) {
        mg_snprintf(state->workspace_id, sizeof(state->workspace_id), "%s",
                    workspace_id);
        flow_context_log(flow, "info",
                         "当前会话 Codex OAuth 会话摘要返回 Workspace ID=%s",
                         state->workspace_id);
        state->step = CODEX_CURRENT_SESSION_WORKSPACE_SELECT;
        return 0;
      }
      flow_context_log(flow, "warn",
                       "当前会话 Codex OAuth 会话摘要未返回 Workspace，继续 consent 页面");
      state->step = CODEX_CURRENT_SESSION_CONSENT_PAGE;
      return 0;
    case CODEX_CURRENT_SESSION_CONSENT_PAGE:
      if (!expect_success(flow, response, "codex consent page")) return -1;
      if (try_callback_response(flow, state, response)) {
        return flow->status == FLOW_STATUS_FAILED ? -1 : 0;
      }
      if (response->location[0] != '\0') {
        start_follow_redirect_from_step(state, response->location,
                                        response->effective_url);
        return 0;
      }
      return move_to_workspace_or_consent(flow, state, response);
    case CODEX_CURRENT_SESSION_WORKSPACE_SELECT:
      if (!expect_success(flow, response, "codex workspace select")) return -1;
      if (try_callback_response(flow, state, response)) {
        return flow->status == FLOW_STATUS_FAILED ? -1 : 0;
      }
      if (response->location[0] != '\0') {
        start_follow_redirect_from_step(state, response->location,
                                        response->effective_url);
      } else if (copy_continue_url_from_response(response, next_url,
                                                 sizeof(next_url))) {
        start_follow_redirect_from_step(state, next_url,
                                        response->effective_url);
      } else {
        flow_context_fail(flow,
                          "Codex OAuth workspace/select 响应里缺少 continue_url");
        return -1;
      }
      return 0;
    case CODEX_CURRENT_SESSION_FOLLOW_REDIRECT:
      if (!expect_success(flow, response, "codex follow redirect")) return -1;
      if (try_callback_response(flow, state, response)) {
        return flow->status == FLOW_STATUS_FAILED ? -1 : 0;
      }
      if (response_has_choose_account_marker(response)) {
        if (begin_session_select_from_response(flow, state, response)) {
          return 0;
        }
        if (response->location[0] != '\0') {
          make_absolute_url(response->location, state->redirect_url,
                            sizeof(state->redirect_url));
          state->redirect_count++;
          if (state->redirect_count >= 8) {
            flow_context_fail(flow, "Codex OAuth 重定向链超过上限");
            return -1;
          }
          return 0;
        }
        return move_to_workspace_or_consent(flow, state, response);
      }
      if (copy_continue_url_from_response(response, next_url,
                                          sizeof(next_url))) {
        mg_snprintf(state->redirect_url, sizeof(state->redirect_url), "%s",
                    next_url);
      } else if (copy_workspace_id_from_response(response, workspace_id,
                                                 sizeof(workspace_id))) {
        mg_snprintf(state->workspace_id, sizeof(state->workspace_id), "%s",
                    workspace_id);
        state->step = CODEX_CURRENT_SESSION_WORKSPACE_SELECT;
        return 0;
      } else if (response->location[0] != '\0') {
        make_absolute_url(response->location, state->redirect_url,
                          sizeof(state->redirect_url));
      } else {
        flow_context_fail(flow, "Codex OAuth 重定向链未返回下一跳");
        return -1;
      }
      state->redirect_count++;
      if (state->redirect_count >= 8) {
        flow_context_fail(flow, "Codex OAuth 重定向链超过上限");
        return -1;
      }
      return 0;
    case CODEX_CURRENT_SESSION_TOKEN_EXCHANGE:
      return handle_token_exchange_response(flow, state, response);
    case CODEX_CURRENT_SESSION_DONE:
      return 0;
    case CODEX_CURRENT_SESSION_IDLE:
    default:
      flow_context_fail(flow, "收到未知当前会话 Codex OAuth 响应");
      return -1;
  }
}

const char *codex_current_session_step_label(
    enum codex_current_session_step step) {
  switch (step) {
    case CODEX_CURRENT_SESSION_AUTHORIZE: return "codex authorize";
    case CODEX_CURRENT_SESSION_SESSION_SELECT: return "codex session select";
    case CODEX_CURRENT_SESSION_SESSION_DUMP: return "codex session dump";
    case CODEX_CURRENT_SESSION_CONSENT_PAGE: return "codex consent page";
    case CODEX_CURRENT_SESSION_WORKSPACE_SELECT: return "codex workspace select";
    case CODEX_CURRENT_SESSION_FOLLOW_REDIRECT: return "codex follow redirect";
    case CODEX_CURRENT_SESSION_TOKEN_EXCHANGE: return "codex token exchange";
    case CODEX_CURRENT_SESSION_DONE: return "codex done";
    case CODEX_CURRENT_SESSION_IDLE:
    default: return "codex idle";
  }
}

bool codex_current_session_is_done(
    const struct codex_current_session_state *state) {
  return state != NULL && state->step == CODEX_CURRENT_SESSION_DONE;
}
