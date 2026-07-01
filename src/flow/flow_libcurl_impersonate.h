#ifndef APP_FLOW_LIBCURL_IMPERSONATE_H
#define APP_FLOW_LIBCURL_IMPERSONATE_H

#include "flow/flow_engine.h"

#include <stdbool.h>
#include <stddef.h>

int flow_libcurl_impersonate_available(char *path, size_t path_len);
const char *flow_libcurl_impersonate_default_target(void);
bool flow_libcurl_impersonate_normalize_target(const char *target, char *out,
                                               size_t out_len);
bool flow_libcurl_impersonate_target_supported(const char *target);
int flow_libcurl_impersonate_perform(const struct flow_http_request *request,
                                     const char *proxy_url,
                                     const struct browser_profile *profile,
                                     struct flow_http_response *response,
                                     char *error, size_t error_len);
int flow_libcurl_impersonate_run(const struct flow_provider *provider,
                                 const struct flow_start_options *options,
                                 struct flow_context *snapshot);

#endif
