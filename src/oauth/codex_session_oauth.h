#ifndef APP_CODEX_SESSION_OAUTH_H
#define APP_CODEX_SESSION_OAUTH_H

#include "flow/flow_engine.h"

#include <stdbool.h>
#include <stddef.h>

enum codex_current_session_step {
  CODEX_CURRENT_SESSION_IDLE = 0,
  CODEX_CURRENT_SESSION_AUTHORIZE,
  CODEX_CURRENT_SESSION_SESSION_SELECT,
  CODEX_CURRENT_SESSION_SESSION_DUMP,
  CODEX_CURRENT_SESSION_CONSENT_PAGE,
  CODEX_CURRENT_SESSION_WORKSPACE_SELECT,
  CODEX_CURRENT_SESSION_FOLLOW_REDIRECT,
  CODEX_CURRENT_SESSION_TOKEN_EXCHANGE,
  CODEX_CURRENT_SESSION_DONE
};

struct codex_current_session_state {
  enum codex_current_session_step step;
  char state[128];
  char code_verifier[FLOW_PKCE_VERIFIER_LEN];
  char code_challenge[96];
  char authorize_url[FLOW_URL_LEN];
  char consent_url[FLOW_URL_LEN];
  char redirect_url[FLOW_URL_LEN];
  char redirect_referer[FLOW_URL_LEN];
  char redirect_site[32];
  char callback_url[FLOW_URL_LEN];
  char session_id[160];
  char workspace_id[FLOW_WORKSPACE_ID_LEN];
  char body[8192];
  char header_origin[96];
  char header_referer[FLOW_URL_LEN];
  char header_content_type[96];
  char header_accept[256];
  struct flow_http_header headers[16];
  size_t num_headers;
  int redirect_count;
  int authorize_retry_count;
};

int codex_current_session_persist_baseline(struct flow_context *flow,
                                           const char *status);
int codex_current_session_start(struct flow_context *flow,
                                struct codex_current_session_state *state);
enum flow_provider_action codex_current_session_next(
    struct flow_context *flow, struct codex_current_session_state *state,
    struct flow_http_request *request);
int codex_current_session_on_response(
    struct flow_context *flow, struct codex_current_session_state *state,
    const struct flow_http_response *response);
const char *codex_current_session_step_label(
    enum codex_current_session_step step);
bool codex_current_session_is_done(
    const struct codex_current_session_state *state);

#endif
