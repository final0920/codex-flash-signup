#ifndef APP_CODEX_DIRECT_PROVIDER_H
#define APP_CODEX_DIRECT_PROVIDER_H

#include "flow/flow_engine.h"

/* Codex-CLI direct simplified-flow signup provider (4th registration method).
 * Mirrors the codex-team-oauth flow natively:
 *   authorize -> authorize/continue(signup) -> user/register -> email-otp
 *   -> create_account -> follow consent/workspace-select -> token exchange.
 * Reuses the project's proxy/profile/identity/rapid-inbox/persistence config. */
const struct flow_provider *codex_direct_provider(void);

#endif
