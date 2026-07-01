#ifndef APP_FLOW_IMPERSONATE_H
#define APP_FLOW_IMPERSONATE_H

#include "flow/flow_engine.h"

#include <stddef.h>

int flow_impersonate_available(char *path, size_t path_len);
int flow_impersonate_run(const struct flow_provider *provider,
                         const struct flow_start_options *options,
                         struct flow_context *snapshot);

#endif
