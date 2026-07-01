#ifndef APP_CHATGPT2API_REGISTER_PROVIDER_H
#define APP_CHATGPT2API_REGISTER_PROVIDER_H

#include "flow/flow_engine.h"

/* chatgpt2api platform-register signup provider.
 * Faithfully mirrors the chatgpt2api project's platform authorize flow natively:
 *   authorize -> authorize/continue(signup) -> create-pwd-page -> user/register
 *   -> email-otp send/validate -> create_account -> follow consent/workspace
 *   -> workspace/select -> oauth/token exchange.
 * Produces Platform-system access_token / refresh_token / id_token and fills
 * external_account_id / workspace_id for downstream (Aether) upload.
 * Reuses the project's proxy/profile/identity/rapid-inbox/persistence config. */
const struct flow_provider *chatgpt2api_register_provider(void);

#endif
