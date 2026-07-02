#include "flow/flow_libcurl_impersonate.h"

#include "account/account_store.h"
#include "mongoose.h"

#include <ctype.h>
#include <curl/curl.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define CI_LIB_PATH_LEN 512
#define CI_REQUEST_MAX_RETRIES 3
#define CI_DEFAULT_TARGET "chrome145"

static const char *const CI_TARGETS[] = {
    "chrome99",       "chrome99_android", "chrome100",        "chrome101",
    "chrome104",      "chrome107",        "chrome110",        "chrome116",
    "chrome119",      "chrome120",        "chrome123",        "chrome124",
    "chrome131",      "chrome131_android", "chrome133a",      "chrome136",
    "chrome142",      "chrome145",        "chrome146",        "edge99",
    "edge101",        "firefox133",       "firefox135",       "firefox144",
    "firefox147",     "safari153",        "safari15_3",       "safari155",
    "safari15_5",     "safari170",        "safari17_0",       "safari172_ios",
    "safari17_2_ios", "safari180",        "safari18_0",       "safari180_ios",
    "safari18_0_ios", "safari184",        "safari18_4",       "safari184_ios",
    "safari18_4_ios", "safari260",        "safari26_0",       "safari2601",
    "safari26_0_1",   "safari260_ios",    "safari26_0_ios",
};

typedef CURLcode (*ci_curl_global_init_fn)(long flags);
typedef CURL *(*ci_curl_easy_init_fn)(void);
typedef void (*ci_curl_easy_cleanup_fn)(CURL *curl);
typedef CURLcode (*ci_curl_easy_setopt_fn)(CURL *curl, CURLoption option, ...);
typedef CURLcode (*ci_curl_easy_getinfo_fn)(CURL *curl, CURLINFO info, ...);
typedef CURLcode (*ci_curl_easy_perform_fn)(CURL *curl);
typedef void (*ci_curl_easy_reset_fn)(CURL *curl);
typedef const char *(*ci_curl_easy_strerror_fn)(CURLcode code);
typedef struct curl_slist *(*ci_curl_slist_append_fn)(
    struct curl_slist *list, const char *string);
typedef void (*ci_curl_slist_free_all_fn)(struct curl_slist *list);
typedef CURLcode (*ci_curl_easy_impersonate_fn)(CURL *curl,
                                                const char *target,
                                                int default_headers);

struct ci_api {
  void *handle;
  char path[CI_LIB_PATH_LEN];
  char error[FLOW_ERROR_LEN];
  ci_curl_global_init_fn global_init;
  ci_curl_easy_init_fn easy_init;
  ci_curl_easy_cleanup_fn easy_cleanup;
  ci_curl_easy_setopt_fn easy_setopt;
  ci_curl_easy_getinfo_fn easy_getinfo;
  ci_curl_easy_perform_fn easy_perform;
  ci_curl_easy_reset_fn easy_reset;
  ci_curl_easy_strerror_fn easy_strerror;
  ci_curl_slist_append_fn slist_append;
  ci_curl_slist_free_all_fn slist_free_all;
  ci_curl_easy_impersonate_fn easy_impersonate;
  bool loaded;
};

struct response_buffer {
  char *data;
  size_t len;
  size_t cap;
};

struct ci_request_state {
  struct response_buffer body;
  char location[FLOW_URL_LEN];
  char content_type[160];
  char server[80];
  char cf_mitigated[80];
  char cf_ray[160];
  char device_id[80];
  char auth_session_cookie[FLOW_COOKIE_LEN];
  char auth_info_cookie[FLOW_COOKIE_LEN];
  char chatgpt_session_token[FLOW_COOKIE_LEN];
};

static struct ci_api s_api;
static pthread_mutex_t s_api_mu = PTHREAD_MUTEX_INITIALIZER;

static void compact_target_token(const char *src, char *out, size_t out_len) {
  size_t n = 0;
  if (out_len == 0) return;
  out[0] = '\0';
  if (src == NULL) return;
  for (; *src != '\0' && n + 1 < out_len; src++) {
    unsigned char c = (unsigned char) *src;
    if (isalnum(c)) {
      out[n++] = (char) tolower(c);
    }
  }
  out[n] = '\0';
}

static bool target_equals_fuzzy(const char *input, const char *target) {
  char input_buf[FLOW_IMPERSONATE_TARGET_LEN];
  char target_buf[FLOW_IMPERSONATE_TARGET_LEN];
  compact_target_token(input, input_buf, sizeof(input_buf));
  compact_target_token(target, target_buf, sizeof(target_buf));
  return input_buf[0] != '\0' && strcmp(input_buf, target_buf) == 0;
}

const char *flow_libcurl_impersonate_default_target(void) {
  return CI_DEFAULT_TARGET;
}

bool flow_libcurl_impersonate_normalize_target(const char *target, char *out,
                                               size_t out_len) {
  const char *candidate =
      target != NULL && target[0] != '\0' ? target : CI_DEFAULT_TARGET;
  if (out != NULL && out_len > 0) out[0] = '\0';
  for (size_t i = 0; i < sizeof(CI_TARGETS) / sizeof(CI_TARGETS[0]); i++) {
    if (strcmp(candidate, CI_TARGETS[i]) == 0 ||
        target_equals_fuzzy(candidate, CI_TARGETS[i])) {
      if (out != NULL && out_len > 0) {
        mg_snprintf(out, out_len, "%s", CI_TARGETS[i]);
      }
      return true;
    }
  }
  return false;
}

bool flow_libcurl_impersonate_target_supported(const char *target) {
  return flow_libcurl_impersonate_normalize_target(target, NULL, 0);
}

static void generate_flow_id(char *out, size_t out_len) {
  uint64_t seed = 0;
  if (out_len == 0) return;
  if (!mg_random(&seed, sizeof(seed))) seed = (uint64_t) time(NULL);
  mg_snprintf(out, out_len, "flow-%llx", (unsigned long long) seed);
}

static void sanitized_url(const char *url, char *out, size_t out_len) {
  const char *q;
  size_t len;
  if (out_len == 0) return;
  out[0] = '\0';
  if (url == NULL || url[0] == '\0') return;
  q = strchr(url, '?');
  len = q == NULL ? strlen(url) : (size_t) (q - url);
  if (len >= out_len) len = out_len - 1;
  memcpy(out, url, len);
  out[len] = '\0';
  if (q != NULL && len + 4 < out_len) {
    strncat(out, "?...", out_len - strlen(out) - 1);
  }
}

static void proxy_scheme_label(const char *proxy_url, char *out,
                               size_t out_len) {
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

static const char *http_version_name(long version) {
  switch (version) {
    case CURL_HTTP_VERSION_1_0: return "1.0";
    case CURL_HTTP_VERSION_1_1: return "1.1";
    case CURL_HTTP_VERSION_2_0: return "2";
    case CURL_HTTP_VERSION_3: return "3";
    default: return "unknown";
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
}

static void copy_set_cookie_value(const char *line, size_t len,
                                  const char *name, char *out,
                                  size_t out_len) {
  const char *value;
  const char *end;
  size_t name_len;
  if (line == NULL || name == NULL || out == NULL || out_len == 0) return;
  if (len < 11 || strncasecmp(line, "Set-Cookie:", 11) != 0) return;
  value = line + 11;
  while ((size_t) (value - line) < len && (*value == ' ' || *value == '\t')) {
    value++;
  }
  name_len = strlen(name);
  if ((size_t) (line + len - value) <= name_len ||
      strncasecmp(value, name, name_len) != 0 || value[name_len] != '=') {
    return;
  }
  value += name_len + 1;
  end = memchr(value, ';', (size_t) (line + len - value));
  if (end == NULL) end = line + len;
  while (end > value && (end[-1] == '\r' || end[-1] == '\n')) end--;
  if ((size_t) (end - value) >= out_len) end = value + out_len - 1;
  mg_snprintf(out, out_len, "%.*s", (int) (end - value), value);
  trim_line(out);
}

static void append_nextauth_session_cookie(const char *line, size_t len,
                                           char *out, size_t out_len) {
  static const char *name = "__Secure-next-auth.session-token";
  const char *value;
  const char *end;
  size_t name_len = strlen(name);
  size_t current;

  if (line == NULL || out == NULL || out_len == 0) return;
  if (len <= 11 || strncasecmp(line, "Set-Cookie:", 11) != 0) return;
  value = line + 11;
  while ((size_t) (value - line) < len && (*value == ' ' || *value == '\t')) {
    value++;
  }
  if ((size_t) (value - line) + name_len + 1 > len ||
      strncasecmp(value, name, name_len) != 0) {
    return;
  }
  if (value[name_len] == '=') {
    value += name_len + 1;
    out[0] = '\0';
  } else if (value[name_len] == '.' &&
             (size_t) (value - line) + name_len + 3 <= len &&
             value[name_len + 2] == '=') {
    value += name_len + 3;
  } else {
    return;
  }
  end = memchr(value, ';', len - (size_t) (value - line));
  if (end == NULL) end = line + len;
  while (end > value && (end[-1] == '\r' || end[-1] == '\n')) end--;
  current = strlen(out);
  if (current >= out_len - 1) return;
  if ((size_t) (end - value) >= out_len - current) {
    end = value + (out_len - current - 1);
  }
  strncat(out, value, (size_t) (end - value));
}

static void copy_header_value(const char *line, size_t len, const char *name,
                              char *out, size_t out_len) {
  const char *value;
  size_t name_len = strlen(name);
  size_t vlen;
  if (line == NULL || out == NULL || out_len == 0) return;
  if (len <= name_len || strncasecmp(line, name, name_len) != 0 ||
      line[name_len] != ':') {
    return;
  }
  value = line + name_len + 1;
  vlen = len - name_len - 1;
  while (vlen > 0 && (*value == ' ' || *value == '\t')) {
    value++;
    vlen--;
  }
  while (vlen > 0 && (value[vlen - 1] == '\r' || value[vlen - 1] == '\n')) {
    vlen--;
  }
  mg_snprintf(out, out_len, "%.*s", (int) vlen, value);
}

static size_t write_body(char *ptr, size_t size, size_t nmemb, void *userdata) {
  struct response_buffer *buffer = (struct response_buffer *) userdata;
  size_t len = size * nmemb;
  char *next;

  if (len == 0) return 0;
  if (buffer->len + len + 1 > buffer->cap) {
    size_t cap = buffer->cap == 0 ? 4096 : buffer->cap;
    while (cap < buffer->len + len + 1) cap *= 2;
    next = (char *) realloc(buffer->data, cap);
    if (next == NULL) return 0;
    buffer->data = next;
    buffer->cap = cap;
  }
  memcpy(buffer->data + buffer->len, ptr, len);
  buffer->len += len;
  buffer->data[buffer->len] = '\0';
  return len;
}

static size_t write_header(char *ptr, size_t size, size_t nmemb,
                           void *userdata) {
  struct ci_request_state *state = (struct ci_request_state *) userdata;
  size_t len = size * nmemb;
  if (state == NULL || len == 0) return len;
  if (len >= 5 && strncasecmp(ptr, "HTTP/", 5) == 0) {
    state->location[0] = '\0';
    state->content_type[0] = '\0';
    state->server[0] = '\0';
    state->cf_mitigated[0] = '\0';
    state->cf_ray[0] = '\0';
    return len;
  }
  copy_header_value(ptr, len, "Location", state->location,
                    sizeof(state->location));
  copy_header_value(ptr, len, "Content-Type", state->content_type,
                    sizeof(state->content_type));
  copy_header_value(ptr, len, "Server", state->server, sizeof(state->server));
  copy_header_value(ptr, len, "CF-Mitigated", state->cf_mitigated,
                    sizeof(state->cf_mitigated));
  copy_header_value(ptr, len, "CF-Ray", state->cf_ray, sizeof(state->cf_ray));
  if (len > 11 && strncasecmp(ptr, "Set-Cookie:", 11) == 0) {
    copy_set_cookie_value(ptr, len, "oai-did", state->device_id,
                          sizeof(state->device_id));
    copy_set_cookie_value(ptr, len, "oai-client-auth-session",
                          state->auth_session_cookie,
                          sizeof(state->auth_session_cookie));
    copy_set_cookie_value(ptr, len, "oai_client_auth_session",
                          state->auth_session_cookie,
                          sizeof(state->auth_session_cookie));
    copy_set_cookie_value(ptr, len, "oai-client-auth-info",
                          state->auth_info_cookie,
                          sizeof(state->auth_info_cookie));
    copy_set_cookie_value(ptr, len, "oai_client_auth_info",
                          state->auth_info_cookie,
                          sizeof(state->auth_info_cookie));
    append_nextauth_session_cookie(ptr, len, state->chatgpt_session_token,
                                   sizeof(state->chatgpt_session_token));
  }
  return len;
}

static void response_buffer_reset(struct response_buffer *buffer) {
  if (buffer == NULL) return;
  buffer->len = 0;
  if (buffer->data != NULL) buffer->data[0] = '\0';
}

static void request_state_reset(struct ci_request_state *state) {
  if (state == NULL) return;
  response_buffer_reset(&state->body);
  state->location[0] = '\0';
  state->content_type[0] = '\0';
  state->server[0] = '\0';
  state->cf_mitigated[0] = '\0';
  state->cf_ray[0] = '\0';
  state->device_id[0] = '\0';
  state->auth_session_cookie[0] = '\0';
  state->auth_info_cookie[0] = '\0';
  state->chatgpt_session_token[0] = '\0';
}

static void response_buffer_free(struct response_buffer *buffer) {
  if (buffer == NULL) return;
  free(buffer->data);
  memset(buffer, 0, sizeof(*buffer));
}

static int persist_success(sqlite3 *db, struct flow_context *flow) {
  struct account_success_record record;
  if (db == NULL || flow == NULL || !flow->persist_on_success) return 0;
  memset(&record, 0, sizeof(record));
  record.email = flow->identity.email;
  record.password = flow->identity.password;
  record.status = flow->success_account_status[0] ? flow->success_account_status
                                                  : "temp";
  record.upload_state = "not_uploaded";
  record.access_token = flow->access_token;
  record.refresh_token = flow->refresh_token;
  record.id_token = flow->id_token;
  record.session_token = flow->session_token;
  record.cookies = flow->cookies;
  record.external_account_id = flow->external_account_id;
  record.workspace_id = flow->workspace_id;
  record.auth_source =
      flow->success_auth_source[0] ? flow->success_auth_source : NULL;
  if (account_insert_success(db, &record, &flow->persisted_account_id) != 0) {
    flow_context_fail(flow, "成功结果写入账号库失败");
    return -1;
  }
  return 0;
}

static bool sleep_until(struct flow_context *flow, long next_retry_ms) {
  long now = (long) mg_millis();
  long wait_ms = next_retry_ms > now ? next_retry_ms - now : 250;
  if (wait_ms < 50) wait_ms = 50;
  if (wait_ms > 1000) wait_ms = 1000;
  while (wait_ms > 0) {
    long chunk_ms = wait_ms > 50 ? 50 : wait_ms;
    if (flow_context_cancel_requested(flow)) {
      flow_context_cancel(flow, "流程已取消");
      return false;
    }
    usleep((useconds_t) chunk_ms * 1000);
    wait_ms -= chunk_ms;
  }
  if (flow_context_cancel_requested(flow)) {
    flow_context_cancel(flow, "流程已取消");
    return false;
  }
  return true;
}

static int ci_dlopen_flags(void) {
  int flags = RTLD_NOW | RTLD_LOCAL;
#ifdef RTLD_DEEPBIND
  flags |= RTLD_DEEPBIND;
#endif
  return flags;
}

static int load_symbol(void *handle, const char *name, void **out,
                       char *error, size_t error_len) {
  dlerror();
  *out = dlsym(handle, name);
  if (*out == NULL) {
    const char *dlerr = dlerror();
    mg_snprintf(error, error_len, "libcurl-impersonate 缺少符号 %s%s%s",
                name, dlerr ? ": " : "", dlerr ? dlerr : "");
    return -1;
  }
  return 0;
}

static int try_load_api_path(struct ci_api *api, const char *path,
                             char *error, size_t error_len) {
  void *handle;
  CURLcode code;
  memset(api, 0, sizeof(*api));
  handle = dlopen(path, ci_dlopen_flags());
  if (handle == NULL) {
    mg_snprintf(error, error_len, "%s", dlerror() ? dlerror() : "dlopen failed");
    return -1;
  }

#define LOAD_CI_SYMBOL(field, symbol)                                          \
  do {                                                                         \
    if (load_symbol(handle, symbol, (void **) &api->field, error,              \
                    error_len) != 0) {                                         \
      dlclose(handle);                                                         \
      return -1;                                                               \
    }                                                                          \
  } while (0)

  LOAD_CI_SYMBOL(global_init, "curl_global_init");
  LOAD_CI_SYMBOL(easy_init, "curl_easy_init");
  LOAD_CI_SYMBOL(easy_cleanup, "curl_easy_cleanup");
  LOAD_CI_SYMBOL(easy_setopt, "curl_easy_setopt");
  LOAD_CI_SYMBOL(easy_getinfo, "curl_easy_getinfo");
  LOAD_CI_SYMBOL(easy_perform, "curl_easy_perform");
  LOAD_CI_SYMBOL(easy_reset, "curl_easy_reset");
  LOAD_CI_SYMBOL(easy_strerror, "curl_easy_strerror");
  LOAD_CI_SYMBOL(slist_append, "curl_slist_append");
  LOAD_CI_SYMBOL(slist_free_all, "curl_slist_free_all");
  LOAD_CI_SYMBOL(easy_impersonate, "curl_easy_impersonate");

#undef LOAD_CI_SYMBOL

  code = api->global_init(CURL_GLOBAL_DEFAULT);
  if (code != CURLE_OK) {
    mg_snprintf(error, error_len, "curl_global_init failed: %d", (int) code);
    dlclose(handle);
    memset(api, 0, sizeof(*api));
    return -1;
  }
  api->handle = handle;
  api->loaded = true;
  mg_snprintf(api->path, sizeof(api->path), "%s", path);
  return 0;
}

static int load_api(struct ci_api **out) {
  const char *env = getenv("LIBCURL_IMPERSONATE_LIB");
  static const char *candidates[] = {
      "/opt/curl-impersonate/lib/libcurl-impersonate.so",
      "/opt/curl-impersonate/lib/libcurl-impersonate.so.4",
      "/usr/local/lib/libcurl-impersonate.so",
      "/usr/local/lib64/libcurl-impersonate.so",
      "libcurl-impersonate.so",
  };
  char error[FLOW_ERROR_LEN] = "";
  pthread_mutex_lock(&s_api_mu);
  if (s_api.loaded) {
    if (out != NULL) *out = &s_api;
    pthread_mutex_unlock(&s_api_mu);
    return 0;
  }
  if (env != NULL && env[0] != '\0' &&
      try_load_api_path(&s_api, env, error, sizeof(error)) == 0) {
    if (out != NULL) *out = &s_api;
    pthread_mutex_unlock(&s_api_mu);
    return 0;
  }
  for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
    const char *path = candidates[i];
    if (strchr(path, '/') != NULL && access(path, R_OK) != 0) continue;
    if (try_load_api_path(&s_api, path, error, sizeof(error)) == 0) {
      if (out != NULL) *out = &s_api;
      pthread_mutex_unlock(&s_api_mu);
      return 0;
    }
  }
  mg_snprintf(s_api.error, sizeof(s_api.error), "%s",
              error[0] ? error : "未找到 libcurl-impersonate.so");
  pthread_mutex_unlock(&s_api_mu);
  return -1;
}

int flow_libcurl_impersonate_available(char *path, size_t path_len) {
  struct ci_api *api = NULL;
  if (path != NULL && path_len > 0) path[0] = '\0';
  if (load_api(&api) != 0 || api == NULL) return -1;
  if (path != NULL && path_len > 0) {
    mg_snprintf(path, path_len, "%s", api->path);
  }
  return 0;
}

static int append_header(struct ci_api *api, struct curl_slist **headers,
                         const char *name, const char *value) {
  char line[4096];
  struct curl_slist *next;
  int n;
  if (api == NULL || headers == NULL || name == NULL || name[0] == '\0') {
    return -1;
  }
  n = snprintf(line, sizeof(line), "%s: %s", name, value ? value : "");
  if (n < 0 || (size_t) n >= sizeof(line)) return -1;
  next = api->slist_append(*headers, line);
  if (next == NULL) return -1;
  *headers = next;
  return 0;
}

static const char *default_ca_bundle(void) {
  static const char *candidates[] = {
      "/etc/ssl/certs/ca-certificates.crt",
      "/etc/pki/tls/certs/ca-bundle.crt",
      "/etc/ssl/ca-bundle.pem",
  };
  for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
    if (access(candidates[i], R_OK) == 0) return candidates[i];
  }
  return NULL;
}

static const char *default_ca_path(void) {
  return access("/etc/ssl/certs", R_OK) == 0 ? "/etc/ssl/certs" : NULL;
}

static void append_cookie_list_line(char *out, size_t out_len,
                                    const char *line) {
  const char *fields[7] = {0};
  size_t lens[7] = {0};
  const char *p = line;
  size_t idx = 0;
  size_t current;

  if (out == NULL || out_len == 0 || line == NULL || line[0] == '\0') return;
  while (idx < 7 && p != NULL) {
    const char *tab = strchr(p, '\t');
    fields[idx] = p;
    lens[idx] = tab ? (size_t) (tab - p) : strlen(p);
    idx++;
    p = tab ? tab + 1 : NULL;
  }
  if (idx < 7 || lens[5] == 0) return;
  current = strlen(out);
  if (current >= out_len - 1) return;
  mg_snprintf(out + current, out_len - current, "%s%.*s=%.*s",
              current > 0 ? "; " : "", (int) lens[5], fields[5],
              (int) lens[6], fields[6]);
}

static void fill_cookie_header_from_easy(struct ci_api *api, CURL *easy,
                                         char *out, size_t out_len) {
#ifdef CURLINFO_COOKIELIST
  struct curl_slist *cookies = NULL;
  if (out == NULL || out_len == 0 || api == NULL || easy == NULL) return;
  out[0] = '\0';
  if (api->easy_getinfo(easy, CURLINFO_COOKIELIST, &cookies) != CURLE_OK) {
    return;
  }
  for (struct curl_slist *item = cookies; item != NULL; item = item->next) {
    append_cookie_list_line(out, out_len, item->data);
  }
  if (cookies != NULL) api->slist_free_all(cookies);
#else
  (void) api;
  (void) easy;
  if (out != NULL && out_len > 0) out[0] = '\0';
#endif
}

static void fill_response_from_state(struct ci_api *api, CURL *easy,
                                     const char *fallback_url,
                                     struct ci_request_state *state,
                                     struct flow_http_response *response) {
  char *effective_url = NULL;
  char *primary_ip = NULL;
  api->easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response->status_code);
  api->easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &effective_url);
  api->easy_getinfo(easy, CURLINFO_PRIMARY_IP, &primary_ip);
  sanitized_url(effective_url ? effective_url : fallback_url,
                response->effective_url, sizeof(response->effective_url));
  mg_snprintf(response->primary_ip, sizeof(response->primary_ip), "%s",
              primary_ip ? primary_ip : "");
  mg_snprintf(response->location, sizeof(response->location), "%s",
              state->location);
  mg_snprintf(response->content_type, sizeof(response->content_type), "%s",
              state->content_type);
  mg_snprintf(response->server, sizeof(response->server), "%s",
              state->server);
  mg_snprintf(response->cf_mitigated, sizeof(response->cf_mitigated), "%s",
              state->cf_mitigated);
  mg_snprintf(response->cf_ray, sizeof(response->cf_ray), "%s",
              state->cf_ray);
  mg_snprintf(response->device_id, sizeof(response->device_id), "%s",
              state->device_id);
  mg_snprintf(response->auth_session_cookie,
              sizeof(response->auth_session_cookie), "%s",
              state->auth_session_cookie);
  mg_snprintf(response->auth_info_cookie, sizeof(response->auth_info_cookie),
              "%s", state->auth_info_cookie);
  mg_snprintf(response->chatgpt_session_token,
              sizeof(response->chatgpt_session_token), "%s",
              state->chatgpt_session_token);
  fill_cookie_header_from_easy(api, easy, response->cookie_header,
                               sizeof(response->cookie_header));
  response->body = state->body.data;
  response->body_len = state->body.len;
  state->body.data = NULL;
  state->body.len = 0;
  state->body.cap = 0;
}

static int configure_easy_for_request(struct ci_api *api, CURL *easy,
                                      struct flow_context *flow,
                                      const struct flow_http_request *request,
                                      const char *method,
                                      struct ci_request_state *state,
                                      struct curl_slist **headers,
                                      char *error, size_t error_len) {
  CURLcode code;
  const char *target =
      flow->impersonate_target[0] ? flow->impersonate_target : CI_DEFAULT_TARGET;
  api->easy_reset(easy);

#define CI_SETOPT(option, value)                                               \
  do {                                                                         \
    code = api->easy_setopt(easy, option, value);                              \
    if (code != CURLE_OK) {                                                    \
      mg_snprintf(error, error_len, "%s: %s", #option,                        \
                  api->easy_strerror(code));                                   \
      return -1;                                                               \
    }                                                                          \
  } while (0)

  CI_SETOPT(CURLOPT_HTTP_VERSION, (long) CURL_HTTP_VERSION_2TLS);
  code = api->easy_impersonate(easy, target, 1);
  if (code != CURLE_OK) {
    mg_snprintf(error, error_len, "curl_easy_impersonate(%s): %s", target,
                api->easy_strerror(code));
    return -1;
  }
  CI_SETOPT(CURLOPT_URL, request->url);
  CI_SETOPT(CURLOPT_NOSIGNAL, 1L);
  CI_SETOPT(CURLOPT_PATH_AS_IS, 1L);
  CI_SETOPT(CURLOPT_FOLLOWLOCATION, request->follow_location ? 1L : 0L);
  CI_SETOPT(CURLOPT_WRITEFUNCTION, write_body);
  CI_SETOPT(CURLOPT_WRITEDATA, &state->body);
  CI_SETOPT(CURLOPT_HEADERFUNCTION, write_header);
  CI_SETOPT(CURLOPT_HEADERDATA, state);
  CI_SETOPT(CURLOPT_ERRORBUFFER, flow->error);
  CI_SETOPT(CURLOPT_ACCEPT_ENCODING, "");
  CI_SETOPT(CURLOPT_COOKIEFILE, "");
  CI_SETOPT(CURLOPT_FORBID_REUSE, 0L);
  CI_SETOPT(CURLOPT_FRESH_CONNECT, 0L);
  CI_SETOPT(CURLOPT_MAXCONNECTS, 64L);
  CI_SETOPT(CURLOPT_DNS_CACHE_TIMEOUT, 300L);
  CI_SETOPT(CURLOPT_TCP_KEEPALIVE, 1L);
#ifdef CURLOPT_PIPEWAIT
  CI_SETOPT(CURLOPT_PIPEWAIT, 1L);
#endif
  {
    const char *ca_bundle = default_ca_bundle();
    const char *ca_path = default_ca_path();
    if (ca_bundle != NULL) CI_SETOPT(CURLOPT_CAINFO, ca_bundle);
    if (ca_path != NULL) CI_SETOPT(CURLOPT_CAPATH, ca_path);
  }
  if (request->timeout_ms > 0) {
    CI_SETOPT(CURLOPT_TIMEOUT_MS, request->timeout_ms);
    CI_SETOPT(CURLOPT_CONNECTTIMEOUT_MS,
              flow_http_effective_connect_timeout_ms(request));
  }
  if (flow->proxy_url[0] != '\0') {
    CI_SETOPT(CURLOPT_PROXY, flow->proxy_url);
  }
  for (size_t i = 0; i < request->num_headers; i++) {
    if (append_header(api, headers, request->headers[i].name,
                      request->headers[i].value) != 0) {
      mg_snprintf(error, error_len, "追加 libcurl-impersonate 请求头失败");
      return -1;
    }
  }
  if (flow->profile.accept_language[0] != '\0' &&
      append_header(api, headers, "Accept-Language",
                    flow->profile.accept_language) != 0) {
    mg_snprintf(error, error_len, "追加 Accept-Language 请求头失败");
    return -1;
  }
  if (*headers != NULL) CI_SETOPT(CURLOPT_HTTPHEADER, *headers);

  if (strcmp(method, "POST") == 0) {
    CI_SETOPT(CURLOPT_POST, 1L);
    CI_SETOPT(CURLOPT_POSTFIELDS, request->body ? request->body : "");
    CI_SETOPT(CURLOPT_POSTFIELDSIZE, (long) request->body_len);
  } else if (strcmp(method, "GET") != 0) {
    CI_SETOPT(CURLOPT_CUSTOMREQUEST, method);
    if (request->body != NULL) {
      CI_SETOPT(CURLOPT_POSTFIELDS, request->body);
      CI_SETOPT(CURLOPT_POSTFIELDSIZE, (long) request->body_len);
    }
  } else {
    CI_SETOPT(CURLOPT_HTTPGET, 1L);
  }

#undef CI_SETOPT
  return 0;
}

static int execute_request(struct ci_api *api, CURL *easy,
                           struct flow_context *flow,
                           const struct flow_http_request *request,
                           struct flow_http_response *response) {
  struct ci_request_state state;
  char method[16];
  char request_url[FLOW_URL_LEN];
  char scheme[24];
  long connect_timeout_ms;
  int rc = -1;
  long used_http_version = 0;
  long num_connects = 0;
  double connect_time = 0.0;
  double appconnect_time = 0.0;
  double total_time = 0.0;

  if (api == NULL || easy == NULL || flow == NULL || request == NULL ||
      request->url == NULL || request->url[0] == '\0' || response == NULL) {
    flow_context_fail(flow, "libcurl-impersonate 请求参数无效");
    return -1;
  }
  memset(&state, 0, sizeof(state));
  memset(response, 0, sizeof(*response));
  mg_snprintf(method, sizeof(method), "%s",
              request->method != NULL && request->method[0] != '\0'
                  ? request->method
                  : "GET");
  sanitized_url(request->url, request_url, sizeof(request_url));
  proxy_scheme_label(flow->proxy_url, scheme, sizeof(scheme));
  connect_timeout_ms = flow_http_effective_connect_timeout_ms(request);
  flow_context_log(flow, "debug",
                   "libcurl-impersonate 请求: %s %s target=%s timeout=%ldms connect=%ldms proxy=%s body=%luB",
                   method, request_url,
                   flow->impersonate_target[0] ? flow->impersonate_target
                                                : CI_DEFAULT_TARGET,
                   request->timeout_ms, connect_timeout_ms, scheme,
                   (unsigned long) request->body_len);

  for (int attempt = 0; attempt <= CI_REQUEST_MAX_RETRIES; attempt++) {
    CURLcode code;
    struct curl_slist *headers = NULL;
    char error[FLOW_ERROR_LEN] = "";

    free(response->body);
    memset(response, 0, sizeof(*response));
    request_state_reset(&state);
    flow->error[0] = '\0';

    if (configure_easy_for_request(api, easy, flow, request, method, &state,
                                   &headers, error, sizeof(error)) != 0) {
      if (headers != NULL) api->slist_free_all(headers);
      flow_context_fail(flow, error[0] ? error : "配置 libcurl-impersonate 请求失败");
      rc = -1;
      goto finish;
    }

    code = api->easy_perform(easy);
    fill_response_from_state(api, easy, request_url, &state, response);
    api->easy_getinfo(easy, CURLINFO_HTTP_VERSION, &used_http_version);
    api->easy_getinfo(easy, CURLINFO_NUM_CONNECTS, &num_connects);
    api->easy_getinfo(easy, CURLINFO_CONNECT_TIME, &connect_time);
    api->easy_getinfo(easy, CURLINFO_APPCONNECT_TIME, &appconnect_time);
    api->easy_getinfo(easy, CURLINFO_TOTAL_TIME, &total_time);
    if (headers != NULL) {
      api->easy_setopt(easy, CURLOPT_HTTPHEADER, NULL);
      api->slist_free_all(headers);
    }
    if (code == CURLE_OK) {
      rc = 0;
      break;
    }
    if (flow_context_cancel_requested(flow)) {
      flow_context_cancel(flow, "流程已取消");
      rc = -1;
      goto finish;
    }
    {
      const char *message =
          flow->error[0] ? flow->error : api->easy_strerror(code);
      if (attempt < CI_REQUEST_MAX_RETRIES) {
        flow_context_log(flow, "warn",
                         "libcurl-impersonate 请求失败，将重试 %d/%d: %s %s error=%s proxy=%s",
                         attempt + 1, CI_REQUEST_MAX_RETRIES, method,
                         request_url, message, scheme);
        usleep((useconds_t) (300000 * (attempt + 1)));
        continue;
      }
      mg_snprintf(response->error, sizeof(response->error), "%s", message);
    }
    flow_context_fail(flow, response->error);
    flow_context_log(flow, "error",
                     "libcurl-impersonate 失败: %s %s error=%s proxy=%s retries=%d",
                     method, request_url, response->error, scheme,
                     CI_REQUEST_MAX_RETRIES);
    rc = -1;
    goto finish;
  }

  flow_context_log(flow, "debug",
                   "libcurl-impersonate 响应: %s %s -> %ld body=%luB ip=%s http=%s connects=%ld tcp=%.1fms tls=%.1fms total=%.1fms server=%s cf=%s ray=%s location=%s",
                   method, response->effective_url, response->status_code,
                   (unsigned long) response->body_len,
                   response->primary_ip[0] ? response->primary_ip : "-",
                   http_version_name(used_http_version), num_connects,
                   connect_time * 1000.0, appconnect_time * 1000.0,
                   total_time * 1000.0,
                   response->server[0] ? response->server : "-",
                   response->cf_mitigated[0] ? response->cf_mitigated : "-",
                   response->cf_ray[0] ? response->cf_ray : "-",
                   response->location[0] ? response->location : "-");

finish:
  response_buffer_free(&state.body);
  return rc;
}

int flow_libcurl_impersonate_perform(const struct flow_http_request *request,
                                     const char *proxy_url,
                                     const struct browser_profile *profile,
                                     struct flow_http_response *response,
                                     char *error, size_t error_len) {
  struct ci_api *api = NULL;
  struct flow_context flow;
  CURL *easy = NULL;
  int rc = -1;

  if (error != NULL && error_len > 0) error[0] = '\0';
  if (response != NULL) memset(response, 0, sizeof(*response));
  memset(&flow, 0, sizeof(flow));

  if (request == NULL || response == NULL) {
    if (error != NULL && error_len > 0) {
      mg_snprintf(error, error_len, "libcurl-impersonate 请求参数无效");
    }
    return -1;
  }
  if (load_api(&api) != 0 || api == NULL) {
    if (error != NULL && error_len > 0) {
      mg_snprintf(error, error_len, "%s",
                  s_api.error[0] ? s_api.error
                                 : "未找到 libcurl-impersonate.so");
    }
    return -1;
  }
  easy = api->easy_init();
  if (easy == NULL) {
    if (error != NULL && error_len > 0) {
      mg_snprintf(error, error_len,
                  "curl_easy_init(libcurl-impersonate) 失败");
    }
    return -1;
  }

  flow.status = FLOW_STATUS_RUNNING;
  generate_flow_id(flow.id, sizeof(flow.id));
  if (proxy_url != NULL) {
    mg_snprintf(flow.proxy_url, sizeof(flow.proxy_url), "%s", proxy_url);
  }
  if (profile != NULL) flow.profile = *profile;

  rc = execute_request(api, easy, &flow, request, response);
  if (rc != 0 && error != NULL && error_len > 0) {
    mg_snprintf(error, error_len, "%s",
                response->error[0] ? response->error
                                   : (flow.error[0] ? flow.error
                                                    : "libcurl-impersonate 请求失败"));
  }
  api->easy_cleanup(easy);
  return rc;
}

int flow_libcurl_impersonate_run(const struct flow_provider *provider,
                                 const struct flow_start_options *options,
                                 struct flow_context *snapshot) {
  struct ci_api *api = NULL;
  struct flow_context flow;
  CURL *easy = NULL;
  int result = -1;

  if (snapshot != NULL) memset(snapshot, 0, sizeof(*snapshot));
  memset(&flow, 0, sizeof(flow));
  if (provider == NULL || provider->next_request == NULL || options == NULL) {
    return -1;
  }
  if (load_api(&api) != 0 || api == NULL) {
    flow_context_fail(&flow, s_api.error[0] ? s_api.error
                                            : "未找到 libcurl-impersonate.so");
    goto finish;
  }
  easy = api->easy_init();
  if (easy == NULL) {
    flow_context_fail(&flow, "curl_easy_init(libcurl-impersonate) 失败");
    goto finish;
  }

  flow.status = FLOW_STATUS_PENDING;
  flow.mode = options->mode;
  flow.persist_on_success = options->persist_on_success;
  flow.account_id = options->account_id;
  flow.deadline_ms = options->deadline_ms;
  flow.oauth_otp_timeout_ms = options->oauth_otp_timeout_ms;
  flow.fast_email_otp_resend = options->fast_email_otp_resend;
  flow.db = options->db;
  flow.log_fn = options->log_fn;
  flow.finish_fn = options->finish_fn;
  flow.cancel_fn = options->cancel_fn;
  flow.event_fn = options->event_fn;
  flow.callback_data = options->callback_data;
  generate_flow_id(flow.id, sizeof(flow.id));
  if (options->proxy_url != NULL) {
    mg_snprintf(flow.proxy_url, sizeof(flow.proxy_url), "%s",
                options->proxy_url);
  }
  if (options->profile != NULL) flow.profile = *options->profile;
  if (options->identity != NULL) flow.identity = *options->identity;
  if (options->workspace_id != NULL) {
    mg_snprintf(flow.workspace_id, sizeof(flow.workspace_id), "%s",
                options->workspace_id);
  }
  if (options->impersonate_target != NULL) {
    mg_snprintf(flow.impersonate_target, sizeof(flow.impersonate_target), "%s",
                options->impersonate_target);
  }

  flow_context_log(&flow, "info",
                   "请求驱动: libcurl-impersonate 动态库 (%s) target=%s",
                   api->path,
                   flow.impersonate_target[0] ? flow.impersonate_target
                                               : CI_DEFAULT_TARGET);
  if (provider->start != NULL && provider->start(&flow) != 0) {
    if (flow.error[0] == '\0') flow_context_fail(&flow, "provider start failed");
    goto finish;
  }
  flow.status = FLOW_STATUS_RUNNING;

  while (flow.status == FLOW_STATUS_RUNNING ||
         flow.status == FLOW_STATUS_PENDING) {
    struct flow_http_request request;
    struct flow_http_response response;
    enum flow_provider_action action;

    if (flow_context_cancel_requested(&flow)) {
      flow_context_cancel(&flow, "流程已取消");
      break;
    }
    memset(&request, 0, sizeof(request));
    action = provider->next_request(&flow, &request);
    if (action == FLOW_PROVIDER_WAIT) {
      if (!sleep_until(&flow, flow.next_retry_ms)) break;
      continue;
    }
    if (action == FLOW_PROVIDER_FAILED) {
      if (flow.error[0] == '\0') flow_context_fail(&flow, "provider failed");
      break;
    }
    if (action == FLOW_PROVIDER_DONE) {
      flow.status = FLOW_STATUS_SUCCESS;
      if (persist_success(flow.db, &flow) != 0) break;
      result = 0;
      break;
    }
    if (action != FLOW_PROVIDER_REQUEST) {
      flow_context_fail(&flow, "未知 flow provider 动作");
      break;
    }

    memset(&response, 0, sizeof(response));
    if (execute_request(api, easy, &flow, &request, &response) != 0) {
      free(response.body);
      break;
    }
    if (provider->on_response != NULL &&
        provider->on_response(&flow, &response) != 0) {
      free(response.body);
      if (flow.error[0] == '\0') {
        flow_context_fail(&flow, "provider response handling failed");
      }
      break;
    }
    free(response.body);
  }

finish:
  if (flow.status != FLOW_STATUS_SUCCESS &&
      flow.status != FLOW_STATUS_CANCELLED) {
    if (flow.error[0] == '\0') flow_context_fail(&flow, "流程失败");
    result = -1;
  }
  if (flow.finish_fn != NULL) flow.finish_fn(&flow, flow.callback_data);
  if (provider != NULL && provider->cleanup != NULL) provider->cleanup(&flow);
  if (snapshot != NULL) *snapshot = flow;
  if (easy != NULL && api != NULL) api->easy_cleanup(easy);
  return result;
}
