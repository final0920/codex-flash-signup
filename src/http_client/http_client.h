#ifndef APP_HTTP_CLIENT_H
#define APP_HTTP_CLIENT_H

#include "http_client/browser_profile.h"

#include <stddef.h>

struct http_client_header {
  const char *name;
  const char *value;
};

enum http_client_ip_resolve {
  HTTP_CLIENT_IPRESOLVE_DEFAULT = 0,
  HTTP_CLIENT_IPRESOLVE_V4,
  HTTP_CLIENT_IPRESOLVE_V6
};

struct http_client_request {
  const char *method;
  const char *url;
  const char *proxy_url;
  const char *doh_url;
  const char *body;
  size_t body_len;
  long timeout_ms;
  long connect_timeout_ms;
  enum http_client_ip_resolve ip_resolve;
  const struct browser_profile *profile;
  const struct http_client_header *headers;
  size_t num_headers;
};

struct http_client_response {
  long status_code;
  char *body;
  size_t body_len;
  char error[256];
};

int http_client_global_init(void);
void http_client_global_cleanup(void);
int http_client_perform(const struct http_client_request *request,
                        struct http_client_response *response);
void http_client_response_free(struct http_client_response *response);

#endif
