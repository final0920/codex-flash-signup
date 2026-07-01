#include "http_client/http_client.h"

#include <curl/curl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HTTP_CLIENT_DEFAULT_CONNECT_TIMEOUT_MS 8000L

struct response_buffer {
  char *data;
  size_t len;
  size_t cap;
};

static long effective_connect_timeout_ms(
    const struct http_client_request *request) {
  long timeout_ms = request != NULL ? request->timeout_ms : 0;
  long connect_ms = request != NULL ? request->connect_timeout_ms : 0;
  if (connect_ms <= 0) connect_ms = HTTP_CLIENT_DEFAULT_CONNECT_TIMEOUT_MS;
  if (timeout_ms > 0 && connect_ms > timeout_ms) connect_ms = timeout_ms;
  return connect_ms > 0 ? connect_ms : timeout_ms;
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

static struct curl_slist *append_header(struct curl_slist *headers,
                                        const char *name,
                                        const char *value) {
  char line[512];
  if (name == NULL || value == NULL || value[0] == '\0') return headers;
  snprintf(line, sizeof(line), "%s: %s", name, value);
  return curl_slist_append(headers, line);
}

static struct curl_slist *append_profile_headers(
    struct curl_slist *headers, const struct browser_profile *profile) {
  if (profile == NULL) return headers;

  headers = append_header(headers, "Accept", profile->accept);
  headers = append_header(headers, "Accept-Language", profile->accept_language);
  headers = append_header(headers, "Sec-CH-UA", profile->sec_ch_ua);
  headers = append_header(headers, "Sec-CH-UA-Platform",
                          profile->sec_ch_ua_platform);
  headers = append_header(headers, "Sec-CH-UA-Mobile",
                          profile->sec_ch_ua_mobile);
  headers = append_header(headers, "Upgrade-Insecure-Requests", "1");
  headers = append_header(headers, "Sec-Fetch-Site", "none");
  headers = append_header(headers, "Sec-Fetch-Mode", "navigate");
  headers = append_header(headers, "Sec-Fetch-User", "?1");
  headers = append_header(headers, "Sec-Fetch-Dest", "document");
  return headers;
}

int http_client_global_init(void) {
  return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK ? 0 : -1;
}

void http_client_global_cleanup(void) {
  curl_global_cleanup();
}

int http_client_perform(const struct http_client_request *request,
                        struct http_client_response *response) {
  CURL *curl;
  CURLcode rc;
  struct curl_slist *headers = NULL;
  struct response_buffer buffer = {0};

  if (request == NULL || response == NULL || request->url == NULL) return -1;
  memset(response, 0, sizeof(*response));

  curl = curl_easy_init();
  if (curl == NULL) {
    snprintf(response->error, sizeof(response->error), "curl_easy_init failed");
    return -1;
  }

  curl_easy_setopt(curl, CURLOPT_URL, request->url);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, response->error);
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);

  if (request->timeout_ms > 0) {
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, request->timeout_ms);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS,
                     effective_connect_timeout_ms(request));
  }
  if (request->ip_resolve == HTTP_CLIENT_IPRESOLVE_V4) {
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
  } else if (request->ip_resolve == HTTP_CLIENT_IPRESOLVE_V6) {
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
  }
  if (request->proxy_url != NULL && request->proxy_url[0] != '\0') {
    curl_easy_setopt(curl, CURLOPT_PROXY, request->proxy_url);
  }
#if LIBCURL_VERSION_NUM >= 0x073E00
  if (request->doh_url != NULL && request->doh_url[0] != '\0') {
    curl_easy_setopt(curl, CURLOPT_DOH_URL, request->doh_url);
  }
#endif
  if (request->profile != NULL) {
    curl_easy_setopt(curl, CURLOPT_USERAGENT, request->profile->user_agent);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING,
                     request->profile->accept_encoding);
    headers = append_profile_headers(headers, request->profile);
  } else {
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
  }
  for (size_t i = 0; i < request->num_headers; i++) {
    headers = append_header(headers, request->headers[i].name,
                            request->headers[i].value);
  }
  if (headers != NULL) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  if (request->method != NULL && strcmp(request->method, "POST") == 0) {
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request->body ? request->body : "");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                     (long) request->body_len);
  } else if (request->method != NULL && strcmp(request->method, "GET") != 0) {
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, request->method);
    if (request->body != NULL) {
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request->body);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                       (long) request->body_len);
    }
  }

  rc = curl_easy_perform(curl);
  if (rc != CURLE_OK) {
    if (response->error[0] == '\0') {
      snprintf(response->error, sizeof(response->error), "%s",
               curl_easy_strerror(rc));
    }
    free(buffer.data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return -1;
  }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status_code);
  response->body = buffer.data;
  response->body_len = buffer.len;

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  return 0;
}

void http_client_response_free(struct http_client_response *response) {
  if (response == NULL) return;
  free(response->body);
  response->body = NULL;
  response->body_len = 0;
}
