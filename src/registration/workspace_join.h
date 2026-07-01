#ifndef APP_WORKSPACE_JOIN_H
#define APP_WORKSPACE_JOIN_H

#include "flow/flow_engine.h"

#include <stdbool.h>
#include <stddef.h>

// 子号加入母号 workspace 的子流程(替代 codex OAuth 授权 —— 加入即完成完整注册)。
// 结构与 codex_session_oauth 一致: start / next / on_response / is_done。

enum workspace_join_step {
  WORKSPACE_JOIN_IDLE = 0,
  WORKSPACE_JOIN_REQUEST,  // POST /backend-api/accounts/{wsId}/invites/request
  WORKSPACE_JOIN_POLL,     // 轮询 accounts/check 确认已加入(等获批)
  WORKSPACE_JOIN_DONE
};

struct workspace_join_state {
  enum workspace_join_step step;
  char target_workspace_id[FLOW_WORKSPACE_ID_LEN];
  char device_id[48];
  char url[FLOW_URL_LEN];
  char auth_header[FLOW_TOKEN_LEN + 16];
  struct flow_http_header headers[8];
  size_t num_headers;
  int poll_attempts;
  long deadline_ms;
};

// 读全局目标 workspace id + 子号 access_token, 初始化子流程。
// 返回 0 就绪(flow->step 由调用方置为 STEP_WORKSPACE_JOIN), -1 失败(已 fail)。
int workspace_join_start(struct flow_context *flow,
                         struct workspace_join_state *state);
enum flow_provider_action workspace_join_next(
    struct flow_context *flow, struct workspace_join_state *state,
    struct flow_http_request *request);
int workspace_join_on_response(struct flow_context *flow,
                               struct workspace_join_state *state,
                               const struct flow_http_response *response);
bool workspace_join_is_done(const struct workspace_join_state *state);

#endif
