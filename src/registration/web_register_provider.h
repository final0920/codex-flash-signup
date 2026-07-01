#ifndef APP_WEB_REGISTER_PROVIDER_H
#define APP_WEB_REGISTER_PROVIDER_H

#include "flow/flow_engine.h"

const struct flow_provider *web_register_provider(void);
const struct flow_provider *web_login_provider(void);

#endif
