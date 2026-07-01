#include "flow/flow_engine.h"

#include "account/account_store.h"
#include "mongoose.h"

#include <curl/curl.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define FLOW_LIBCURL_REQUEST_MAX_RETRIES 3
#define FLOW_REQWEST_USER_AGENT                                                \
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "        \
  "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
#define FLOW_REQWEST_ACCEPT_LANGUAGE "zh-CN,zh;q=0.9"
#define FLOW_REQWEST_SEC_CH_UA                                                 \
  "\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", "                   \
  "\"Not/A)Brand\";v=\"99\""
#define FLOW_REQWEST_SEC_CH_UA_MOBILE "?0"
#define FLOW_REQWEST_SEC_CH_UA_PLATFORM "\"macOS\""

struct response_buffer {
  char *data;
  size_t len;
  size_t cap;
};

struct stored_cookie {
  char *name;
  char *value;
  char *domain;
  char *path;
  bool host_only;
  bool secure;
};

struct flow_slot {
  struct flow_context flow;
  const struct flow_provider *provider;
  CURL *easy;
  struct curl_slist *headers;
  struct stored_cookie *cookies;
  size_t cookie_len;
  size_t cookie_cap;
  struct response_buffer response;
  char location[FLOW_URL_LEN];
  char content_type[160];
  char server[80];
  char cf_mitigated[80];
  char cf_ray[160];
  char device_id[80];
  char auth_session_cookie[FLOW_COOKIE_LEN];
  char auth_info_cookie[FLOW_COOKIE_LEN];
  char chatgpt_session_token[FLOW_COOKIE_LEN];
  char request_url[FLOW_URL_LEN];
  char request_full_url[FLOW_URL_LEN];
  char request_method[16];
  int transport_retry_count;
  bool in_multi;
  bool finished;
};

struct flow_engine {
  CURLM *multi;
  sqlite3 *db;
  size_t max_concurrency;
  struct flow_slot **slots;
  size_t len;
  size_t cap;
};

static void copy_set_cookie_value(const char *line, size_t len,
                                  const char *name, char *out,
                                  size_t out_len);
static void append_nextauth_session_cookie(const char *line, size_t len,
                                           char *out, size_t out_len);
static void store_set_cookie_header(struct flow_slot *slot, const char *line,
                                    size_t len);
static bool parse_url_parts(const char *url, char *scheme, size_t scheme_len,
                            char *host, size_t host_len, char *path,
                            size_t path_len);

static bool proxy_url_has_scheme(const char *url, const char *scheme) {
  size_t len;
  if (url == NULL || scheme == NULL) return false;
  len = strlen(scheme);
  return strncasecmp(url, scheme, len) == 0 && strncmp(url + len, "://", 3) == 0;
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
  struct flow_slot *slot = (struct flow_slot *) userdata;
  size_t len = size * nmemb;
  if (slot == NULL || len == 0) return len;
  if (len > 10 && strncasecmp(ptr, "Location:", 9) == 0) {
    const char *value = ptr + 9;
    size_t vlen = len - 9;
    while (vlen > 0 && (*value == ' ' || *value == '\t')) {
      value++;
      vlen--;
    }
    while (vlen > 0 && (value[vlen - 1] == '\r' || value[vlen - 1] == '\n')) {
      vlen--;
    }
    mg_snprintf(slot->location, sizeof(slot->location), "%.*s",
                (int) vlen, value);
  } else if (len > 14 && strncasecmp(ptr, "Content-Type:", 13) == 0) {
    const char *value = ptr + 13;
    size_t vlen = len - 13;
    while (vlen > 0 && (*value == ' ' || *value == '\t')) {
      value++;
      vlen--;
    }
    while (vlen > 0 && (value[vlen - 1] == '\r' || value[vlen - 1] == '\n')) {
      vlen--;
    }
    mg_snprintf(slot->content_type, sizeof(slot->content_type), "%.*s",
                (int) vlen, value);
  } else if (len > 8 && strncasecmp(ptr, "Server:", 7) == 0) {
    const char *value = ptr + 7;
    size_t vlen = len - 7;
    while (vlen > 0 && (*value == ' ' || *value == '\t')) {
      value++;
      vlen--;
    }
    while (vlen > 0 && (value[vlen - 1] == '\r' || value[vlen - 1] == '\n')) {
      vlen--;
    }
    mg_snprintf(slot->server, sizeof(slot->server), "%.*s", (int) vlen,
                value);
  } else if (len > 14 && strncasecmp(ptr, "CF-Mitigated:", 13) == 0) {
    const char *value = ptr + 13;
    size_t vlen = len - 13;
    while (vlen > 0 && (*value == ' ' || *value == '\t')) {
      value++;
      vlen--;
    }
    while (vlen > 0 && (value[vlen - 1] == '\r' || value[vlen - 1] == '\n')) {
      vlen--;
    }
    mg_snprintf(slot->cf_mitigated, sizeof(slot->cf_mitigated), "%.*s",
                (int) vlen, value);
  } else if (len > 8 && strncasecmp(ptr, "CF-Ray:", 7) == 0) {
    const char *value = ptr + 7;
    size_t vlen = len - 7;
    while (vlen > 0 && (*value == ' ' || *value == '\t')) {
      value++;
      vlen--;
    }
    while (vlen > 0 && (value[vlen - 1] == '\r' || value[vlen - 1] == '\n')) {
      vlen--;
    }
    mg_snprintf(slot->cf_ray, sizeof(slot->cf_ray), "%.*s", (int) vlen,
                value);
  } else if (len > 11 && strncasecmp(ptr, "Set-Cookie:", 11) == 0) {
    copy_set_cookie_value(ptr, len, "oai-did", slot->device_id,
                          sizeof(slot->device_id));
    copy_set_cookie_value(ptr, len, "oai-client-auth-session",
                          slot->auth_session_cookie,
                          sizeof(slot->auth_session_cookie));
    copy_set_cookie_value(ptr, len, "oai_client_auth_session",
                          slot->auth_session_cookie,
                          sizeof(slot->auth_session_cookie));
    copy_set_cookie_value(ptr, len, "oai-client-auth-info",
                          slot->auth_info_cookie,
                          sizeof(slot->auth_info_cookie));
    copy_set_cookie_value(ptr, len, "oai_client_auth_info",
                          slot->auth_info_cookie,
                          sizeof(slot->auth_info_cookie));
    append_nextauth_session_cookie(ptr, len, slot->chatgpt_session_token,
                                   sizeof(slot->chatgpt_session_token));
    store_set_cookie_header(slot, ptr, len);
  }
  return size * nmemb;
}

static void response_buffer_reset(struct response_buffer *buffer) {
  if (buffer == NULL) return;
  buffer->len = 0;
  if (buffer->data != NULL) buffer->data[0] = '\0';
}

static void response_buffer_clear_location(struct flow_slot *slot) {
  if (slot == NULL) return;
  slot->location[0] = '\0';
  slot->content_type[0] = '\0';
  slot->server[0] = '\0';
  slot->cf_mitigated[0] = '\0';
  slot->cf_ray[0] = '\0';
  slot->device_id[0] = '\0';
  slot->auth_session_cookie[0] = '\0';
  slot->auth_info_cookie[0] = '\0';
  slot->chatgpt_session_token[0] = '\0';
}

static void response_buffer_free(struct response_buffer *buffer) {
  if (buffer == NULL) return;
  free(buffer->data);
  memset(buffer, 0, sizeof(*buffer));
}

static struct curl_slist *append_header(struct curl_slist *headers,
                                        const char *name,
                                        const char *value) {
  char *line;
  size_t need;
  struct curl_slist *next;
  if (name == NULL || value == NULL || value[0] == '\0') return headers;
  need = strlen(name) + strlen(value) + 3;
  line = (char *) malloc(need);
  if (line == NULL) return headers;
  snprintf(line, need, "%s: %s", name, value);
  next = curl_slist_append(headers, line);
  free(line);
  return next != NULL ? next : headers;
}

static bool request_has_header(const struct flow_http_request *request,
                               const char *name) {
  if (request == NULL || name == NULL || name[0] == '\0') return false;
  if (request->headers == NULL) return false;
  for (size_t i = 0; i < request->num_headers; i++) {
    if (request->headers[i].name != NULL &&
        strcasecmp(request->headers[i].name, name) == 0) {
      return true;
    }
  }
  return false;
}

static bool request_header_equals(const struct flow_http_request *request,
                                  const char *name, const char *value) {
  if (request == NULL || request->headers == NULL || name == NULL ||
      value == NULL) {
    return false;
  }
  for (size_t i = 0; i < request->num_headers; i++) {
    if (request->headers[i].name != NULL && request->headers[i].value != NULL &&
        strcasecmp(request->headers[i].name, name) == 0 &&
        strcasecmp(request->headers[i].value, value) == 0) {
      return true;
    }
  }
  return false;
}

static uint64_t nonzero_random_u64(void) {
  uint64_t value = 0;
  while (value == 0) {
    if (!mg_random(&value, sizeof(value))) {
      value = ((uint64_t) rand() << 32) ^ (uint64_t) rand();
    }
  }
  return value;
}

static struct curl_slist *append_reqwest_browser_headers(
    struct curl_slist *headers, const struct flow_http_request *request) {
  if (!request_has_header(request, "Accept-Language")) {
    headers = append_header(headers, "Accept-Language",
                            FLOW_REQWEST_ACCEPT_LANGUAGE);
  }
  if (!request_has_header(request, "Sec-CH-UA")) {
    headers = append_header(headers, "Sec-CH-UA", FLOW_REQWEST_SEC_CH_UA);
  }
  if (!request_has_header(request, "Sec-CH-UA-Platform")) {
    headers = append_header(headers, "Sec-CH-UA-Platform",
                            FLOW_REQWEST_SEC_CH_UA_PLATFORM);
  }
  if (!request_has_header(request, "Sec-CH-UA-Mobile")) {
    headers = append_header(headers, "Sec-CH-UA-Mobile",
                            FLOW_REQWEST_SEC_CH_UA_MOBILE);
  }
  return headers;
}

static struct curl_slist *append_reqwest_trace_headers(
    struct curl_slist *headers, const struct flow_http_request *request) {
  char scheme[16], host[256], path[FLOW_URL_LEN];
  uint64_t trace_id_low, span_id;
  char traceparent[80];
  char trace_id_decimal[32];
  char span_id_decimal[32];

  if (request == NULL || request->url == NULL ||
      !request_header_equals(request, "Sec-Fetch-Mode", "cors") ||
      !request_header_equals(request, "Sec-Fetch-Site", "same-origin") ||
      !parse_url_parts(request->url, scheme, sizeof(scheme), host,
                       sizeof(host), path, sizeof(path)) ||
      strcmp(host, "auth.openai.com") != 0) {
    return headers;
  }
  if (!request_has_header(request, "Priority")) {
    headers = append_header(headers, "Priority", "u=1, i");
  }
  trace_id_low = nonzero_random_u64();
  span_id = nonzero_random_u64();
  mg_snprintf(traceparent, sizeof(traceparent), "00-%016llx%016llx-%016llx-01",
              0ULL, (unsigned long long) trace_id_low,
              (unsigned long long) span_id);
  mg_snprintf(trace_id_decimal, sizeof(trace_id_decimal), "%llu",
              (unsigned long long) trace_id_low);
  mg_snprintf(span_id_decimal, sizeof(span_id_decimal), "%llu",
              (unsigned long long) span_id);
  if (!request_has_header(request, "Traceparent")) {
    headers = append_header(headers, "Traceparent", traceparent);
  }
  if (!request_has_header(request, "Tracestate")) {
    headers = append_header(headers, "Tracestate", "dd=s:1;o:rum");
  }
  if (!request_has_header(request, "X-Datadog-Origin")) {
    headers = append_header(headers, "X-Datadog-Origin", "rum");
  }
  if (!request_has_header(request, "X-Datadog-Parent-Id")) {
    headers = append_header(headers, "X-Datadog-Parent-Id", span_id_decimal);
  }
  if (!request_has_header(request, "X-Datadog-Sampling-Priority")) {
    headers = append_header(headers, "X-Datadog-Sampling-Priority", "1");
  }
  if (!request_has_header(request, "X-Datadog-Trace-Id")) {
    headers = append_header(headers, "X-Datadog-Trace-Id", trace_id_decimal);
  }
  return headers;
}

static void copy_set_cookie_value(const char *line, size_t len,
                                  const char *name, char *out,
                                  size_t out_len) {
  const char *value;
  const char *end;
  size_t name_len;
  if (line == NULL || name == NULL || out == NULL || out_len == 0) return;
  if (len <= 11 || strncasecmp(line, "Set-Cookie:", 11) != 0) return;
  value = line + 11;
  while ((size_t) (value - line) < len && (*value == ' ' || *value == '\t')) {
    value++;
  }
  name_len = strlen(name);
  if ((size_t) (value - line) + name_len + 1 > len ||
      strncasecmp(value, name, name_len) != 0 || value[name_len] != '=') {
    return;
  }
  value += name_len + 1;
  end = memchr(value, ';', len - (size_t) (value - line));
  if (end == NULL) end = line + len;
  while (end > value && (end[-1] == '\r' || end[-1] == '\n')) end--;
  if ((size_t) (end - value) >= out_len) end = value + out_len - 1;
  mg_snprintf(out, out_len, "%.*s", (int) (end - value), value);
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

static char *xstrndup(const char *s, size_t len) {
  char *out;
  if (s == NULL) return NULL;
  out = (char *) calloc(1, len + 1);
  if (out == NULL) return NULL;
  memcpy(out, s, len);
  out[len] = '\0';
  return out;
}

static void trim_ascii_span(const char **start, size_t *len) {
  const char *s;
  size_t n;
  if (start == NULL || len == NULL || *start == NULL) return;
  s = *start;
  n = *len;
  while (n > 0 && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')) {
    s++;
    n--;
  }
  while (n > 0 &&
         (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' ||
          s[n - 1] == '\n')) {
    n--;
  }
  *start = s;
  *len = n;
}

static void lowercase_ascii(char *s) {
  if (s == NULL) return;
  for (; *s != '\0'; s++) {
    if (*s >= 'A' && *s <= 'Z') *s = (char) (*s - 'A' + 'a');
  }
}

static char *canonical_cookie_domain_copy(const char *s, size_t len) {
  const char *start = s;
  char *out;
  trim_ascii_span(&start, &len);
  while (len > 0 && *start == '.') {
    start++;
    len--;
  }
  while (len > 0 && start[len - 1] == '.') len--;
  out = xstrndup(start, len);
  lowercase_ascii(out);
  return out;
}

static bool parse_url_parts(const char *url, char *scheme, size_t scheme_len,
                            char *host, size_t host_len, char *path,
                            size_t path_len) {
  const char *scheme_end;
  const char *host_start;
  const char *host_end;
  const char *path_start;
  size_t n;
  bool bracketed_host = false;

  if (scheme_len > 0) scheme[0] = '\0';
  if (host_len > 0) host[0] = '\0';
  if (path_len > 0) path[0] = '\0';
  if (url == NULL || scheme == NULL || host == NULL || path == NULL ||
      scheme_len == 0 || host_len == 0 || path_len == 0) {
    return false;
  }

  scheme_end = strstr(url, "://");
  if (scheme_end == NULL || scheme_end == url) return false;
  n = (size_t) (scheme_end - url);
  if (n >= scheme_len) n = scheme_len - 1;
  memcpy(scheme, url, n);
  scheme[n] = '\0';
  lowercase_ascii(scheme);

  host_start = scheme_end + 3;
  if (*host_start == '[') {
    bracketed_host = true;
    host_end = strchr(host_start, ']');
    if (host_end == NULL) return false;
    host_start++;
  } else {
    host_end = host_start;
    while (*host_end != '\0' && *host_end != '/' && *host_end != '?' &&
           *host_end != '#') {
      host_end++;
    }
  }
  n = (size_t) (host_end - host_start);
  if (!bracketed_host) {
    const char *colon = memchr(host_start, ':', n);
    if (colon != NULL) n = (size_t) (colon - host_start);
  }
  while (n > 0 && host_start[n - 1] == '.') n--;
  if (n == 0) return false;
  if (n >= host_len) n = host_len - 1;
  memcpy(host, host_start, n);
  host[n] = '\0';
  lowercase_ascii(host);

  path_start = *host_end == ']' ? host_end + 1 : host_end;
  if (*path_start == ':') {
    while (*path_start != '\0' && *path_start != '/' && *path_start != '?' &&
           *path_start != '#') {
      path_start++;
    }
  }
  if (*path_start != '/') {
    mg_snprintf(path, path_len, "/");
    return true;
  }
  n = 0;
  while (path_start[n] != '\0' && path_start[n] != '?' &&
         path_start[n] != '#') {
    n++;
  }
  if (n == 0) {
    mg_snprintf(path, path_len, "/");
  } else {
    if (n >= path_len) n = path_len - 1;
    memcpy(path, path_start, n);
    path[n] = '\0';
  }
  return true;
}

static char *default_cookie_path_copy(const char *request_path) {
  const char *last;
  size_t len;
  if (request_path == NULL || request_path[0] != '/') return strdup("/");
  last = strrchr(request_path, '/');
  if (last == NULL || last == request_path) return strdup("/");
  len = (size_t) (last - request_path);
  return xstrndup(request_path, len);
}

static bool domain_matches(const char *host, const char *domain) {
  size_t hlen, dlen;
  if (host == NULL || domain == NULL) return false;
  hlen = strlen(host);
  dlen = strlen(domain);
  if (hlen == 0 || dlen == 0) return false;
  if (hlen == dlen && strcasecmp(host, domain) == 0) return true;
  if (hlen <= dlen || strcasecmp(host + hlen - dlen, domain) != 0) {
    return false;
  }
  return host[hlen - dlen - 1] == '.';
}

static bool cookie_matches_host(const struct stored_cookie *cookie,
                                const char *host) {
  if (cookie == NULL || host == NULL || cookie->domain == NULL) return false;
  if (cookie->host_only) return strcasecmp(host, cookie->domain) == 0;
  return domain_matches(host, cookie->domain);
}

static bool path_matches(const char *cookie_path, const char *request_path) {
  size_t len;
  const char *remaining;
  if (cookie_path == NULL || request_path == NULL) return false;
  if (strcmp(cookie_path, "/") == 0 || strcmp(request_path, cookie_path) == 0) {
    return true;
  }
  len = strlen(cookie_path);
  if (strncmp(request_path, cookie_path, len) != 0) return false;
  remaining = request_path + len;
  return cookie_path[len - 1] == '/' || *remaining == '/';
}

static bool contains_casefold_n(const char *s, size_t len, const char *needle) {
  size_t nlen;
  if (s == NULL || needle == NULL) return false;
  nlen = strlen(needle);
  if (nlen == 0) return true;
  if (len < nlen) return false;
  for (size_t i = 0; i + nlen <= len; i++) {
    if (strncasecmp(s + i, needle, nlen) == 0) return true;
  }
  return false;
}

static bool is_cookie_delete_header(const char *raw, size_t len) {
  return contains_casefold_n(raw, len, "max-age=0") ||
         contains_casefold_n(raw, len, "max-age=-") ||
         contains_casefold_n(raw, len, "expires=thu, 01 jan 1970");
}

static bool attr_name_eq(const char *s, size_t len, const char *name) {
  size_t nlen = name == NULL ? 0 : strlen(name);
  return nlen == len && strncasecmp(s, name, len) == 0;
}

static bool attr_name_value_eq(const char *s, size_t len, const char *name,
                               const char **value, size_t *value_len) {
  const char *eq;
  size_t name_len;
  if (value != NULL) *value = NULL;
  if (value_len != NULL) *value_len = 0;
  if (s == NULL || name == NULL) return false;
  eq = memchr(s, '=', len);
  if (eq == NULL) return false;
  name_len = (size_t) (eq - s);
  if (name_len != strlen(name) || strncasecmp(s, name, name_len) != 0) {
    return false;
  }
  if (value != NULL) *value = eq + 1;
  if (value_len != NULL) *value_len = len - name_len - 1;
  return true;
}

static void free_cookie(struct stored_cookie *cookie) {
  if (cookie == NULL) return;
  free(cookie->name);
  free(cookie->value);
  free(cookie->domain);
  free(cookie->path);
  memset(cookie, 0, sizeof(*cookie));
}

static void remove_cookie_at(struct flow_slot *slot, size_t index) {
  if (slot == NULL || index >= slot->cookie_len) return;
  free_cookie(&slot->cookies[index]);
  if (index + 1 < slot->cookie_len) {
    memmove(&slot->cookies[index], &slot->cookies[index + 1],
            (slot->cookie_len - index - 1) * sizeof(slot->cookies[0]));
  }
  slot->cookie_len--;
}

static int append_cookie(struct flow_slot *slot, struct stored_cookie *cookie) {
  struct stored_cookie *next;
  if (slot == NULL || cookie == NULL) return -1;
  if (slot->cookie_len == slot->cookie_cap) {
    size_t cap = slot->cookie_cap == 0 ? 16 : slot->cookie_cap * 2;
    next = (struct stored_cookie *) realloc(slot->cookies, cap * sizeof(*next));
    if (next == NULL) return -1;
    slot->cookies = next;
    slot->cookie_cap = cap;
  }
  slot->cookies[slot->cookie_len++] = *cookie;
  memset(cookie, 0, sizeof(*cookie));
  return 0;
}

static void store_set_cookie_header(struct flow_slot *slot, const char *line,
                                    size_t len) {
  char scheme[16], host[256], request_path[FLOW_URL_LEN];
  const char *raw;
  size_t raw_len;
  const char *first_end;
  const char *eq;
  struct stored_cookie cookie;
  bool delete_cookie;

  if (slot == NULL || line == NULL || len <= 11 ||
      strncasecmp(line, "Set-Cookie:", 11) != 0) {
    return;
  }
  if (!parse_url_parts(slot->request_full_url, scheme, sizeof(scheme), host,
                       sizeof(host), request_path, sizeof(request_path))) {
    return;
  }
  memset(&cookie, 0, sizeof(cookie));
  raw = line + 11;
  raw_len = len - 11;
  trim_ascii_span(&raw, &raw_len);
  if (raw_len == 0) return;
  delete_cookie = is_cookie_delete_header(raw, raw_len);

  first_end = memchr(raw, ';', raw_len);
  if (first_end == NULL) first_end = raw + raw_len;
  {
    const char *pair = raw;
    size_t pair_len = (size_t) (first_end - raw);
    trim_ascii_span(&pair, &pair_len);
    eq = memchr(pair, '=', pair_len);
    if (eq == NULL || eq == pair) return;
    cookie.name = xstrndup(pair, (size_t) (eq - pair));
    cookie.value = xstrndup(eq + 1, pair_len - (size_t) (eq - pair) - 1);
    if (cookie.name == NULL || cookie.value == NULL) goto cleanup;
  }

  for (const char *p = first_end; p < raw + raw_len;) {
    const char *attr;
    const char *attr_end;
    size_t attr_len;
    const char *value = NULL;
    size_t value_len = 0;

    if (*p == ';') p++;
    attr = p;
    while (p < raw + raw_len && *p != ';') p++;
    attr_end = p;
    attr_len = (size_t) (attr_end - attr);
    trim_ascii_span(&attr, &attr_len);
    if (attr_len == 0) continue;

    if (attr_name_value_eq(attr, attr_len, "Domain", &value, &value_len)) {
      char *domain = canonical_cookie_domain_copy(value, value_len);
      if (domain == NULL) goto cleanup;
      if (domain[0] == '\0' || !domain_matches(host, domain)) {
        free(domain);
        goto cleanup;
      }
      free(cookie.domain);
      cookie.domain = domain;
      cookie.host_only = false;
    } else if (attr_name_value_eq(attr, attr_len, "Path", &value,
                                  &value_len)) {
      const char *path_value = value;
      trim_ascii_span(&path_value, &value_len);
      if (value_len > 0 && path_value[0] == '/') {
        free(cookie.path);
        cookie.path = xstrndup(path_value, value_len);
        if (cookie.path == NULL) goto cleanup;
      }
    } else if (attr_name_eq(attr, attr_len, "Secure")) {
      cookie.secure = true;
    }
  }

  if (cookie.domain == NULL) {
    cookie.domain = strdup(host);
    cookie.host_only = true;
    if (cookie.domain == NULL) goto cleanup;
  }
  if (cookie.path == NULL) {
    cookie.path = default_cookie_path_copy(request_path);
    if (cookie.path == NULL) goto cleanup;
  }

  for (size_t i = 0; i < slot->cookie_len;) {
    struct stored_cookie *stored = &slot->cookies[i];
    if (strcmp(stored->name, cookie.name) == 0 &&
        strcmp(stored->domain, cookie.domain) == 0 &&
        strcmp(stored->path, cookie.path) == 0) {
      remove_cookie_at(slot, i);
    } else {
      i++;
    }
  }
  if (!delete_cookie && append_cookie(slot, &cookie) != 0) goto cleanup;

cleanup:
  free_cookie(&cookie);
}

static char *build_cookie_header_for_url(const struct flow_slot *slot,
                                         const char *url) {
  char scheme[16], host[256], request_path[FLOW_URL_LEN];
  bool secure_request;
  size_t *matches = NULL;
  size_t match_len = 0, match_cap = 0;
  size_t total = 1;
  char *out = NULL;
  size_t offset = 0;

  if (slot == NULL || url == NULL ||
      !parse_url_parts(url, scheme, sizeof(scheme), host, sizeof(host),
                       request_path, sizeof(request_path))) {
    return NULL;
  }
  secure_request = strcasecmp(scheme, "https") == 0;
  for (size_t i = 0; i < slot->cookie_len; i++) {
    const struct stored_cookie *cookie = &slot->cookies[i];
    if ((cookie->secure && !secure_request) ||
        !cookie_matches_host(cookie, host) ||
        !path_matches(cookie->path, request_path)) {
      continue;
    }
    if (match_len == match_cap) {
      size_t cap = match_cap == 0 ? 8 : match_cap * 2;
      size_t *next = (size_t *) realloc(matches, cap * sizeof(*next));
      if (next == NULL) {
        free(matches);
        return NULL;
      }
      matches = next;
      match_cap = cap;
    }
    {
      size_t pos = match_len;
      size_t path_len = strlen(cookie->path);
      while (pos > 0 &&
             strlen(slot->cookies[matches[pos - 1]].path) < path_len) {
        matches[pos] = matches[pos - 1];
        pos--;
      }
      matches[pos] = i;
      match_len++;
    }
  }
  if (match_len == 0) {
    free(matches);
    return NULL;
  }
  for (size_t i = 0; i < match_len; i++) {
    const struct stored_cookie *cookie = &slot->cookies[matches[i]];
    total += strlen(cookie->name) + strlen(cookie->value) + 1;
    if (i > 0) total += 2;
  }
  out = (char *) calloc(1, total);
  if (out == NULL) {
    free(matches);
    return NULL;
  }
  for (size_t i = 0; i < match_len; i++) {
    const struct stored_cookie *cookie = &slot->cookies[matches[i]];
    int n = snprintf(out + offset, total - offset, "%s%s=%s",
                     i > 0 ? "; " : "", cookie->name, cookie->value);
    if (n < 0 || (size_t) n >= total - offset) break;
    offset += (size_t) n;
  }
  free(matches);
  return out;
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
  if (q != NULL && len + 4 < out_len) strncat(out, "?...", out_len - strlen(out) - 1);
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

static void free_slot(struct flow_slot *slot) {
  if (slot == NULL) return;
  if (slot->provider != NULL && slot->provider->cleanup != NULL) {
    slot->provider->cleanup(&slot->flow);
  }
  for (size_t i = 0; i < slot->cookie_len; i++) {
    free_cookie(&slot->cookies[i]);
  }
  free(slot->cookies);
  if (slot->headers != NULL) curl_slist_free_all(slot->headers);
  if (slot->easy != NULL) curl_easy_cleanup(slot->easy);
  response_buffer_free(&slot->response);
  free(slot);
}

static void generate_flow_id(char *out, size_t out_len) {
  uint64_t seed = 0;
  if (out_len == 0) return;
  if (!mg_random(&seed, sizeof(seed))) seed = (uint64_t) rand();
  mg_snprintf(out, out_len, "flow-%llx",
              (unsigned long long) seed);
}

const char *flow_status_name(enum flow_status status) {
  switch (status) {
    case FLOW_STATUS_PENDING:
      return "pending";
    case FLOW_STATUS_RUNNING:
      return "running";
    case FLOW_STATUS_SUCCESS:
      return "success";
    case FLOW_STATUS_FAILED:
      return "failed";
    case FLOW_STATUS_CANCELLED:
      return "cancelled";
    default:
      return "unknown";
  }
}

void flow_context_fail(struct flow_context *flow, const char *message) {
  if (flow == NULL) return;
  flow->status = FLOW_STATUS_FAILED;
  mg_snprintf(flow->error, sizeof(flow->error), "%s",
              message ? message : "flow failed");
}

void flow_context_cancel(struct flow_context *flow, const char *message) {
  if (flow == NULL) return;
  flow->status = FLOW_STATUS_CANCELLED;
  mg_snprintf(flow->error, sizeof(flow->error), "%s",
              message ? message : "流程已取消");
}

bool flow_context_cancel_requested(struct flow_context *flow) {
  if (flow == NULL) return false;
  if (flow->status == FLOW_STATUS_CANCELLED) return true;
  if (flow->cancel_fn == NULL) return false;
  return flow->cancel_fn(flow, flow->callback_data);
}

void flow_context_mark_environment_retry(struct flow_context *flow,
                                         const char *message) {
  if (flow == NULL) return;
  flow->environment_retryable = true;
  flow_context_fail(flow, message ? message : "需要重新分配环境重试");
}

void flow_context_mark_identity_retry(struct flow_context *flow,
                                      const char *message) {
  if (flow == NULL) return;
  flow->identity_retryable = true;
  flow_context_fail(flow, message ? message : "需要重新生成邮箱重试");
}

static bool contains_case(const char *s, const char *needle) {
  size_t nlen;
  if (s == NULL || needle == NULL || needle[0] == '\0') return false;
  nlen = strlen(needle);
  for (; *s != '\0'; s++) {
    if (strncasecmp(s, needle, nlen) == 0) return true;
  }
  return false;
}

bool flow_response_is_email_already_registered(
    const struct flow_http_response *response) {
  const char *body;
  if (response == NULL || response->status_code < 400) return false;
  body = response->body;
  if (body == NULL || body[0] == '\0') return false;
  if (contains_case(body, "An account already exists for this email address")) {
    return true;
  }
  if (contains_case(body, "email_already_exists") ||
      contains_case(body, "email already exists") ||
      contains_case(body, "email is already registered")) {
    return true;
  }
  return (contains_case(body, "account already exists") &&
          contains_case(body, "email")) ||
         (contains_case(body, "already exists") &&
          contains_case(body, "email address"));
}

bool flow_response_is_invalid_auth_step(
    const struct flow_http_response *response) {
  const char *body;
  if (response == NULL || response->status_code < 400) return false;
  body = response->body;
  if (body == NULL || body[0] == '\0') return false;
  return contains_case(body, "invalid_auth_step") ||
         contains_case(body, "Invalid authorization step");
}

bool flow_response_is_edge_block(const struct flow_http_response *response) {
  bool edge_signal, html_signal;
  if (response == NULL) return false;
  if (response->status_code != 403 && response->status_code != 429) return false;
  edge_signal = contains_case(response->server, "cloudflare") ||
                response->cf_ray[0] != '\0' ||
                response->cf_mitigated[0] != '\0' ||
                contains_case(response->body, "cloudflare");
  if (!edge_signal) return false;
  html_signal = contains_case(response->content_type, "text/html") ||
                contains_case(response->body, "<html") ||
                contains_case(response->body, "<!doctype html") ||
                contains_case(response->body, "challenge") ||
                contains_case(response->body, "blocked");
  return html_signal;
}

void flow_context_log(struct flow_context *flow, const char *level,
                      const char *fmt, ...) {
  char message[FLOW_LOG_LEN];
  va_list ap;

  if (flow == NULL || flow->log_fn == NULL || fmt == NULL) return;
  va_start(ap, fmt);
  vsnprintf(message, sizeof(message), fmt, ap);
  va_end(ap);
  flow->log_fn(flow, level != NULL && level[0] != '\0' ? level : "info",
               message, flow->callback_data);
}

void flow_context_emit_event(struct flow_context *flow, const char *event) {
  if (flow == NULL || flow->event_fn == NULL || event == NULL) return;
  flow->event_fn(flow, event, flow->callback_data);
}

int flow_engine_create(const struct flow_engine_options *options,
                       struct flow_engine **out) {
  struct flow_engine *engine;
  long max_connections;
  if (out == NULL) return -1;
  *out = NULL;
  engine = (struct flow_engine *) calloc(1, sizeof(*engine));
  if (engine == NULL) return -1;
  engine->multi = curl_multi_init();
  if (engine->multi == NULL) {
    free(engine);
    return -1;
  }
  engine->db = options ? options->db : NULL;
  engine->max_concurrency =
      options != NULL && options->max_concurrency > 0 ? options->max_concurrency
                                                      : 512;
  max_connections = (long) engine->max_concurrency;
  if (max_connections < 4) max_connections = 4;
  if (max_connections > 512) max_connections = 512;
#ifdef CURLMOPT_PIPELINING
#ifdef CURLPIPE_MULTIPLEX
  curl_multi_setopt(engine->multi, CURLMOPT_PIPELINING,
                    (long) CURLPIPE_MULTIPLEX);
#endif
#endif
#ifdef CURLMOPT_MAX_HOST_CONNECTIONS
  curl_multi_setopt(engine->multi, CURLMOPT_MAX_HOST_CONNECTIONS, 4L);
#endif
#ifdef CURLMOPT_MAX_TOTAL_CONNECTIONS
  curl_multi_setopt(engine->multi, CURLMOPT_MAX_TOTAL_CONNECTIONS,
                    max_connections);
#endif
  *out = engine;
  return 0;
}

void flow_engine_destroy(struct flow_engine *engine) {
  if (engine == NULL) return;
  for (size_t i = 0; i < engine->len; i++) free_slot(engine->slots[i]);
  free(engine->slots);
  if (engine->multi != NULL) curl_multi_cleanup(engine->multi);
  free(engine);
}

static int append_slot(struct flow_engine *engine, struct flow_slot *slot) {
  struct flow_slot **next;
  if (engine->len == engine->cap) {
    size_t cap = engine->cap == 0 ? 16 : engine->cap * 2;
    next = (struct flow_slot **) realloc(engine->slots, cap * sizeof(*next));
    if (next == NULL) return -1;
    engine->slots = next;
    engine->cap = cap;
  }
  engine->slots[engine->len++] = slot;
  return 0;
}

static size_t live_slot_count(const struct flow_engine *engine) {
  size_t live = 0;
  if (engine == NULL) return 0;
  for (size_t i = 0; i < engine->len; i++) {
    if (engine->slots[i] != NULL && !engine->slots[i]->finished) live++;
  }
  return live;
}

static int persist_success(struct flow_engine *engine, struct flow_context *flow) {
  struct account_success_record record;
  if (engine == NULL || engine->db == NULL || flow == NULL ||
      !flow->persist_on_success) {
    return 0;
  }
  memset(&record, 0, sizeof(record));
  record.email = flow->identity.email;
  record.password = flow->identity.password;
  record.status = flow->success_account_status[0] ? flow->success_account_status : "temp";
  record.upload_state = "not_uploaded";
  record.access_token = flow->access_token;
  record.refresh_token = flow->refresh_token;
  record.id_token = flow->id_token;
  record.session_token = flow->session_token;
  record.cookies = flow->cookies;
  record.external_account_id = flow->external_account_id;
  record.workspace_id = flow->workspace_id;
  if (account_insert_success(engine->db, &record,
                             &flow->persisted_account_id) != 0) {
    flow_context_fail(flow, "成功结果写入账号库失败");
    return -1;
  }
  return 0;
}

static int configure_request(struct flow_slot *slot,
                             const struct flow_http_request *request) {
  CURL *easy = slot->easy;
  const char *method;

  if (easy == NULL || request == NULL || request->url == NULL ||
      request->url[0] == '\0') {
    flow_context_fail(&slot->flow, "请求未配置 URL");
    return -1;
  }
  response_buffer_reset(&slot->response);
  response_buffer_clear_location(slot);
  if (slot->headers != NULL) {
    curl_slist_free_all(slot->headers);
    slot->headers = NULL;
  }
  curl_easy_reset(easy);
  slot->transport_retry_count = 0;
  method = request->method != NULL && request->method[0] != '\0'
               ? request->method
               : "GET";
  mg_snprintf(slot->request_method, sizeof(slot->request_method), "%s", method);
  mg_snprintf(slot->request_full_url, sizeof(slot->request_full_url), "%s",
              request->url);
  sanitized_url(request->url, slot->request_url, sizeof(slot->request_url));

  curl_easy_setopt(easy, CURLOPT_URL, request->url);
  curl_easy_setopt(easy, CURLOPT_PRIVATE, slot);
  curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION,
                   request->follow_location ? 1L : 0L);
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_body);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, &slot->response);
  curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, write_header);
  curl_easy_setopt(easy, CURLOPT_HEADERDATA, slot);
  curl_easy_setopt(easy, CURLOPT_ERRORBUFFER, slot->flow.error);
  curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
  curl_easy_setopt(easy, CURLOPT_FORBID_REUSE, 0L);
  curl_easy_setopt(easy, CURLOPT_FRESH_CONNECT, 0L);
  curl_easy_setopt(easy, CURLOPT_MAXCONNECTS, 64L);
  curl_easy_setopt(easy, CURLOPT_DNS_CACHE_TIMEOUT, 300L);
  curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE, 1L);
#ifdef CURLOPT_PIPEWAIT
  curl_easy_setopt(easy, CURLOPT_PIPEWAIT, 1L);
#endif
  if (request->timeout_ms > 0) {
    curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, request->timeout_ms);
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS,
                     flow_http_effective_connect_timeout_ms(request));
  }
  if (slot->flow.proxy_url[0] != '\0') {
    curl_easy_setopt(easy, CURLOPT_PROXY, slot->flow.proxy_url);
    if (proxy_url_has_scheme(slot->flow.proxy_url, "socks5")) {
      curl_easy_setopt(easy, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
#if LIBCURL_VERSION_NUM >= 0x073E00
      curl_easy_setopt(easy, CURLOPT_DOH_URL, "https://1.1.1.1/dns-query");
#endif
    }
  }
  curl_easy_setopt(easy, CURLOPT_USERAGENT, FLOW_REQWEST_USER_AGENT);
  curl_easy_setopt(easy, CURLOPT_ACCEPT_ENCODING, "");
  slot->headers = append_reqwest_browser_headers(slot->headers, request);
  slot->headers = append_reqwest_trace_headers(slot->headers, request);
  {
    char *cookie_header = build_cookie_header_for_url(slot, request->url);
    bool manual_cookie = cookie_header != NULL && cookie_header[0] != '\0';
    if (manual_cookie) {
      slot->headers = append_header(slot->headers, "Cookie", cookie_header);
    }
    for (size_t i = 0; request->headers != NULL && i < request->num_headers;
         i++) {
      if (manual_cookie && request->headers[i].name != NULL &&
          strcasecmp(request->headers[i].name, "Cookie") == 0) {
        continue;
      }
      slot->headers = append_header(slot->headers, request->headers[i].name,
                                    request->headers[i].value);
    }
    free(cookie_header);
  }
  if (slot->headers != NULL) curl_easy_setopt(easy, CURLOPT_HTTPHEADER,
                                              slot->headers);

  if (strcmp(method, "POST") == 0) {
    curl_easy_setopt(easy, CURLOPT_POST, 1L);
    curl_easy_setopt(easy, CURLOPT_POSTFIELDS,
                     request->body != NULL ? request->body : "");
    curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long) request->body_len);
  } else if (strcmp(method, "GET") != 0) {
    curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, method);
    if (request->body != NULL) {
      curl_easy_setopt(easy, CURLOPT_POSTFIELDS, request->body);
      curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long) request->body_len);
    }
  }
  {
    char scheme[24];
    long connect_timeout_ms = flow_http_effective_connect_timeout_ms(request);
    proxy_scheme_label(slot->flow.proxy_url, scheme, sizeof(scheme));
    flow_context_log(&slot->flow, "debug",
                     "HTTP 请求: %s %s timeout=%ldms connect=%ldms proxy=%s body=%zuB",
                     method, slot->request_url, request->timeout_ms,
                     connect_timeout_ms, scheme, request->body_len);
  }
  return 0;
}

static int schedule_next(struct flow_engine *engine, struct flow_slot *slot) {
  struct flow_http_request request;
  enum flow_provider_action action;

  if (slot == NULL || slot->provider == NULL ||
      slot->provider->next_request == NULL || slot->finished) {
    return 0;
  }
  if (flow_context_cancel_requested(&slot->flow)) {
    flow_context_cancel(&slot->flow, "流程已取消");
    slot->finished = true;
    if (slot->flow.finish_fn != NULL) {
      slot->flow.finish_fn(&slot->flow, slot->flow.callback_data);
    }
    return -1;
  }
  if (slot->flow.status == FLOW_STATUS_PENDING) {
    slot->flow.status = FLOW_STATUS_RUNNING;
  }
  memset(&request, 0, sizeof(request));
  action = slot->provider->next_request(&slot->flow, &request);
  if (action == FLOW_PROVIDER_DONE) {
    slot->flow.status = FLOW_STATUS_SUCCESS;
    if (persist_success(engine, &slot->flow) != 0) {
      slot->finished = true;
      if (slot->flow.finish_fn != NULL) {
        slot->flow.finish_fn(&slot->flow, slot->flow.callback_data);
      }
      return -1;
    }
    slot->finished = true;
    if (slot->flow.finish_fn != NULL) {
      slot->flow.finish_fn(&slot->flow, slot->flow.callback_data);
    }
    return 0;
  }
  if (action == FLOW_PROVIDER_WAIT) return 0;
  if (action == FLOW_PROVIDER_FAILED) {
    if (slot->flow.error[0] == '\0') {
      flow_context_fail(&slot->flow, "provider failed");
    }
    slot->finished = true;
    if (slot->flow.finish_fn != NULL) {
      slot->flow.finish_fn(&slot->flow, slot->flow.callback_data);
    }
    return -1;
  }
  if (configure_request(slot, &request) != 0) {
    slot->finished = true;
    if (slot->flow.finish_fn != NULL) {
      slot->flow.finish_fn(&slot->flow, slot->flow.callback_data);
    }
    return -1;
  }
  if (curl_multi_add_handle(engine->multi, slot->easy) != CURLM_OK) {
    flow_context_fail(&slot->flow, "curl_multi_add_handle failed");
    slot->finished = true;
    if (slot->flow.finish_fn != NULL) {
      slot->flow.finish_fn(&slot->flow, slot->flow.callback_data);
    }
    return -1;
  }
  slot->in_multi = true;
  slot->flow.status = FLOW_STATUS_RUNNING;
  return 0;
}

int flow_engine_add(struct flow_engine *engine, const struct flow_provider *provider,
                    const struct flow_start_options *options,
                    struct flow_context **out_flow) {
  struct flow_slot *slot;
  if (out_flow != NULL) *out_flow = NULL;
  if (engine == NULL || provider == NULL) return -1;
  if (live_slot_count(engine) >= engine->max_concurrency) return -1;

  slot = (struct flow_slot *) calloc(1, sizeof(*slot));
  if (slot == NULL) return -1;
  slot->easy = curl_easy_init();
  if (slot->easy == NULL) {
    free(slot);
    return -1;
  }
  slot->provider = provider;
  slot->flow.status = FLOW_STATUS_PENDING;
  slot->flow.mode = options ? options->mode : FLOW_MODE_REGISTER_ONLY;
  slot->flow.persist_on_success = options ? options->persist_on_success : false;
  slot->flow.account_id = options ? options->account_id : 0;
  slot->flow.deadline_ms = options ? options->deadline_ms : 0;
  slot->flow.oauth_otp_timeout_ms = options ? options->oauth_otp_timeout_ms : 0;
  slot->flow.fast_email_otp_resend =
      options ? options->fast_email_otp_resend : false;
  slot->flow.db = options ? options->db : NULL;
  slot->flow.log_fn = options ? options->log_fn : NULL;
  slot->flow.finish_fn = options ? options->finish_fn : NULL;
  slot->flow.cancel_fn = options ? options->cancel_fn : NULL;
  slot->flow.event_fn = options ? options->event_fn : NULL;
  slot->flow.callback_data = options ? options->callback_data : NULL;
  generate_flow_id(slot->flow.id, sizeof(slot->flow.id));
  if (options != NULL && options->proxy_url != NULL) {
    mg_snprintf(slot->flow.proxy_url, sizeof(slot->flow.proxy_url), "%s",
                options->proxy_url);
  }
  if (options != NULL && options->profile != NULL) {
    slot->flow.profile = *options->profile;
  }
  if (options != NULL && options->identity != NULL) {
    slot->flow.identity = *options->identity;
  }
  if (options != NULL && options->workspace_id != NULL) {
    mg_snprintf(slot->flow.workspace_id, sizeof(slot->flow.workspace_id), "%s",
                options->workspace_id);
  }
  if (options != NULL && options->impersonate_target != NULL) {
    mg_snprintf(slot->flow.impersonate_target,
                sizeof(slot->flow.impersonate_target), "%s",
                options->impersonate_target);
  }
  if (provider->start != NULL && provider->start(&slot->flow) != 0) {
    free_slot(slot);
    return -1;
  }
  if (append_slot(engine, slot) != 0) {
    free_slot(slot);
    return -1;
  }
  if (out_flow != NULL) *out_flow = &slot->flow;
  return schedule_next(engine, slot);
}

static void schedule_waiting(struct flow_engine *engine) {
  for (size_t i = 0; i < engine->len; i++) {
    if (engine->slots[i] == NULL) continue;
    if (!engine->slots[i]->finished && !engine->slots[i]->in_multi) {
      (void) schedule_next(engine, engine->slots[i]);
    }
  }
}

static void complete_easy(struct flow_engine *engine, CURLMsg *msg) {
  struct flow_slot *slot = NULL;
  struct flow_http_response response;
  CURLcode result = msg->data.result;
  long used_http_version = 0;
  long num_connects = 0;
  double connect_time = 0.0;
  double appconnect_time = 0.0;
  double total_time = 0.0;

  curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &slot);
  if (slot == NULL) return;
  curl_multi_remove_handle(engine->multi, msg->easy_handle);
  slot->in_multi = false;
  memset(&response, 0, sizeof(response));
  curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE,
                    &response.status_code);
  curl_easy_getinfo(msg->easy_handle, CURLINFO_HTTP_VERSION,
                    &used_http_version);
  curl_easy_getinfo(msg->easy_handle, CURLINFO_NUM_CONNECTS, &num_connects);
  curl_easy_getinfo(msg->easy_handle, CURLINFO_CONNECT_TIME, &connect_time);
  curl_easy_getinfo(msg->easy_handle, CURLINFO_APPCONNECT_TIME,
                    &appconnect_time);
  curl_easy_getinfo(msg->easy_handle, CURLINFO_TOTAL_TIME, &total_time);
  {
    char *effective_url = NULL;
    char *primary_ip = NULL;
    curl_easy_getinfo(msg->easy_handle, CURLINFO_EFFECTIVE_URL, &effective_url);
    curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIMARY_IP, &primary_ip);
    sanitized_url(effective_url ? effective_url : slot->request_url,
                  response.effective_url, sizeof(response.effective_url));
    mg_snprintf(response.primary_ip, sizeof(response.primary_ip), "%s",
                primary_ip ? primary_ip : "");
  }
  if (slot->location[0] != '\0') {
    mg_snprintf(response.location, sizeof(response.location), "%s",
                slot->location);
  }
  mg_snprintf(response.content_type, sizeof(response.content_type), "%s",
              slot->content_type);
  mg_snprintf(response.server, sizeof(response.server), "%s", slot->server);
  mg_snprintf(response.cf_mitigated, sizeof(response.cf_mitigated), "%s",
              slot->cf_mitigated);
  mg_snprintf(response.cf_ray, sizeof(response.cf_ray), "%s", slot->cf_ray);
  mg_snprintf(response.device_id, sizeof(response.device_id), "%s",
              slot->device_id);
  mg_snprintf(response.auth_session_cookie,
              sizeof(response.auth_session_cookie), "%s",
              slot->auth_session_cookie);
  mg_snprintf(response.auth_info_cookie, sizeof(response.auth_info_cookie),
              "%s", slot->auth_info_cookie);
  mg_snprintf(response.chatgpt_session_token,
              sizeof(response.chatgpt_session_token), "%s",
              slot->chatgpt_session_token);
  {
    char *cookie_header =
        build_cookie_header_for_url(slot, slot->request_full_url);
    if (cookie_header != NULL) {
      mg_snprintf(response.cookie_header, sizeof(response.cookie_header), "%s",
                  cookie_header);
      free(cookie_header);
    }
  }
  response.body = slot->response.data;
  response.body_len = slot->response.len;
  if (result != CURLE_OK) {
    mg_snprintf(response.error, sizeof(response.error), "%s",
                slot->flow.error[0] != '\0' ? slot->flow.error
                                            : curl_easy_strerror(result));
    if (!flow_context_cancel_requested(&slot->flow) &&
        slot->transport_retry_count < FLOW_LIBCURL_REQUEST_MAX_RETRIES) {
      char scheme[24];
      slot->transport_retry_count++;
      proxy_scheme_label(slot->flow.proxy_url, scheme, sizeof(scheme));
      flow_context_log(&slot->flow, "warn",
                       "libcurl 请求失败，将重试 %d/%d: %s %s error=%s proxy=%s",
                       slot->transport_retry_count,
                       FLOW_LIBCURL_REQUEST_MAX_RETRIES,
                       slot->request_method, slot->request_url,
                       response.error, scheme);
      response_buffer_reset(&slot->response);
      response_buffer_clear_location(slot);
      slot->flow.error[0] = '\0';
      usleep((useconds_t) slot->transport_retry_count * 300000);
      if (curl_multi_add_handle(engine->multi, slot->easy) != CURLM_OK) {
        flow_context_fail(&slot->flow, "curl_multi_add_handle retry failed");
        slot->finished = true;
        if (slot->flow.finish_fn != NULL) {
          slot->flow.finish_fn(&slot->flow, slot->flow.callback_data);
        }
        return;
      }
      slot->in_multi = true;
      return;
    }
    if (flow_context_cancel_requested(&slot->flow)) {
      flow_context_cancel(&slot->flow, "流程已取消");
      slot->finished = true;
      if (slot->flow.finish_fn != NULL) {
        slot->flow.finish_fn(&slot->flow, slot->flow.callback_data);
      }
      return;
    }
    flow_context_fail(&slot->flow, response.error);
    {
      char scheme[24];
      proxy_scheme_label(slot->flow.proxy_url, scheme, sizeof(scheme));
      flow_context_log(&slot->flow, "error",
                       "HTTP 失败: %s %s error=%s proxy=%s",
                       slot->request_method, slot->request_url, response.error,
                       scheme);
    }
    slot->finished = true;
    if (slot->flow.finish_fn != NULL) {
      slot->flow.finish_fn(&slot->flow, slot->flow.callback_data);
    }
    return;
  }
  flow_context_log(&slot->flow, "debug",
                   "HTTP 响应: %s %s -> %ld body=%zuB ip=%s http=%s connects=%ld tcp=%.1fms tls=%.1fms total=%.1fms server=%s cf=%s ray=%s location=%s",
                   slot->request_method, response.effective_url,
                   response.status_code, response.body_len,
                   response.primary_ip[0] ? response.primary_ip : "-",
                   http_version_name(used_http_version), num_connects,
                   connect_time * 1000.0, appconnect_time * 1000.0,
                   total_time * 1000.0,
                   response.server[0] ? response.server : "-",
                   response.cf_mitigated[0] ? response.cf_mitigated : "-",
                   response.cf_ray[0] ? response.cf_ray : "-",
                   response.location[0] ? response.location : "-");
  if (slot->provider != NULL && slot->provider->on_response != NULL &&
      slot->provider->on_response(&slot->flow, &response) != 0) {
    if (slot->flow.error[0] == '\0') {
      flow_context_fail(&slot->flow, "provider response handling failed");
    }
    slot->finished = true;
    if (slot->flow.finish_fn != NULL) {
      slot->flow.finish_fn(&slot->flow, slot->flow.callback_data);
    }
    return;
  }
  schedule_next(engine, slot);
}

int flow_engine_run_once(struct flow_engine *engine, long timeout_ms) {
  int running = 0;
  int msgs_left = 0;
  CURLMsg *msg;
  if (engine == NULL || engine->multi == NULL) return -1;

  schedule_waiting(engine);
  curl_multi_perform(engine->multi, &running);
  curl_multi_wait(engine->multi, NULL, 0, timeout_ms > 0 ? timeout_ms : 10,
                  NULL);
  schedule_waiting(engine);
  curl_multi_perform(engine->multi, &running);
  while ((msg = curl_multi_info_read(engine->multi, &msgs_left)) != NULL) {
    if (msg->msg == CURLMSG_DONE) complete_easy(engine, msg);
  }
  schedule_waiting(engine);
  return 0;
}

int flow_engine_run_until_idle(struct flow_engine *engine, long timeout_ms) {
  while (flow_engine_active_count(engine) > 0) {
    if (flow_engine_run_once(engine, timeout_ms) != 0) return -1;
  }
  return 0;
}

size_t flow_engine_active_count(const struct flow_engine *engine) {
  size_t active = 0;
  if (engine == NULL) return 0;
  for (size_t i = 0; i < engine->len; i++) {
    if (engine->slots[i] != NULL && !engine->slots[i]->finished) active++;
  }
  return active;
}

size_t flow_engine_total_count(const struct flow_engine *engine) {
  return engine == NULL ? 0 : engine->len;
}
