#include "registration/workspace_join.h"

#include "mail/outlook_pool.h"
#include "mongoose.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define APP_BASE_URL "https://chatgpt.com"
#define WS_JOIN_POLL_INTERVAL_MS 2500L
#define WS_JOIN_DEADLINE_MS 90000L

static void random_uuid_like(char *out, size_t out_len) {
  uint8_t bytes[16];
  if (out_len == 0) return;
  if (!mg_random(bytes, sizeof(bytes))) {
    for (size_t i = 0; i < sizeof(bytes); i++) bytes[i] = (uint8_t) rand();
  }
  bytes[6] = (uint8_t) ((bytes[6] & 0x0f) | 0x40);
  bytes[8] = (uint8_t) ((bytes[8] & 0x3f) | 0x80);
  mg_snprintf(out, out_len,
              "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
              "%02x%02x%02x%02x%02x%02x",
              bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
              bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
              bytes[12], bytes[13], bytes[14], bytes[15]);
}

// 组装请求头; post=true 时附带 Content-Type(发送加入申请)
static void build_headers(struct workspace_join_state *state, bool post) {
  size_t n = 0;
  state->headers[n].name = "Accept";
  state->headers[n++].value = "*/*";
  state->headers[n].name = "Authorization";
  state->headers[n++].value = state->auth_header;
  state->headers[n].name = "oai-device-id";
  state->headers[n++].value = state->device_id;
  state->headers[n].name = "oai-language";
  state->headers[n++].value = "en-US";
  state->headers[n].name = "Origin";
  state->headers[n++].value = APP_BASE_URL;
  state->headers[n].name = "Referer";
  state->headers[n++].value = APP_BASE_URL "/";
  if (post) {
    state->headers[n].name = "Content-Type";
    state->headers[n++].value = "application/json";
  }
  state->num_headers = n;
}

// 加入完成: 账号按 active 入库(区别于纯注册流程默认的 temp)
static void mark_join_done(struct flow_context *flow,
                           struct workspace_join_state *state) {
  state->step = WORKSPACE_JOIN_DONE;
  mg_snprintf(flow->success_account_status,
              sizeof(flow->success_account_status), "%s", "active");
}

int workspace_join_start(struct flow_context *flow,
                         struct workspace_join_state *state) {
  char *ws;
  if (flow == NULL || state == NULL) return -1;
  memset(state, 0, sizeof(*state));

  ws = outlook_pool_workspace_id(flow->db);
  if (ws == NULL || ws[0] == '\0') {
    free(ws);
    flow_context_fail(flow, "未配置要加入的母号 workspace id");
    return -1;
  }
  mg_snprintf(state->target_workspace_id, sizeof(state->target_workspace_id),
              "%s", ws);
  free(ws);

  if (flow->access_token[0] == '\0') {
    flow_context_fail(flow, "缺少子号 access token, 无法加入 workspace");
    return -1;
  }
  random_uuid_like(state->device_id, sizeof(state->device_id));
  mg_snprintf(state->auth_header, sizeof(state->auth_header), "Bearer %s",
              flow->access_token);
  state->step = WORKSPACE_JOIN_REQUEST;
  state->deadline_ms = (long) mg_millis() + WS_JOIN_DEADLINE_MS;
  // 加入确认可能较久, 顺带延长整体流程 deadline, 避免被其它步骤的超时打断
  if (flow->deadline_ms < state->deadline_ms + 30000) {
    flow->deadline_ms = state->deadline_ms + 30000;
  }
  flow_context_log(flow, "info", "准备加入母号 workspace: %s",
                   state->target_workspace_id);
  return 0;
}

enum flow_provider_action workspace_join_next(
    struct flow_context *flow, struct workspace_join_state *state,
    struct flow_http_request *request) {
  long now = (long) mg_millis();
  if (flow == NULL || state == NULL || request == NULL) {
    return FLOW_PROVIDER_FAILED;
  }

  switch (state->step) {
    case WORKSPACE_JOIN_REQUEST:
      mg_snprintf(state->url, sizeof(state->url),
                  APP_BASE_URL "/backend-api/accounts/%s/invites/request",
                  state->target_workspace_id);
      build_headers(state, true);
      memset(request, 0, sizeof(*request));
      request->method = "POST";
      request->url = state->url;
      request->body = "";
      request->body_len = 0;
      request->timeout_ms = 30000;
      request->follow_location = false;
      request->headers = state->headers;
      request->num_headers = state->num_headers;
      flow_context_log(flow, "info", "workspace 加入: 发送加入申请 %s",
                       state->target_workspace_id);
      return FLOW_PROVIDER_REQUEST;
    case WORKSPACE_JOIN_POLL:
      if (now > state->deadline_ms) {
        // 等获批超时: 申请已发出, 母号后续会批, 记为成功(避免丢号), 但告警
        flow_context_log(flow, "warn",
                         "workspace 加入确认超时(%lds), 申请已提交, 按成功入库",
                         WS_JOIN_DEADLINE_MS / 1000);
        mark_join_done(flow, state);
        return FLOW_PROVIDER_DONE;
      }
      if (now < flow->next_retry_ms) return FLOW_PROVIDER_WAIT;
      mg_snprintf(state->url, sizeof(state->url),
                  APP_BASE_URL "/backend-api/accounts/check/v4-2023-04-27?"
                               "timezone_offset_min=-480");
      build_headers(state, false);
      memset(request, 0, sizeof(*request));
      request->method = "GET";
      request->url = state->url;
      request->timeout_ms = 30000;
      request->follow_location = false;
      request->headers = state->headers;
      request->num_headers = state->num_headers;
      state->poll_attempts++;
      flow_context_log(flow, "debug", "workspace 加入确认轮询 第 %d 次",
                       state->poll_attempts);
      return FLOW_PROVIDER_REQUEST;
    case WORKSPACE_JOIN_DONE:
      return FLOW_PROVIDER_DONE;
    default:
      flow_context_fail(flow, "workspace join 状态异常");
      return FLOW_PROVIDER_FAILED;
  }
}

int workspace_join_on_response(struct flow_context *flow,
                               struct workspace_join_state *state,
                               const struct flow_http_response *response) {
  if (flow == NULL || state == NULL || response == NULL) return -1;

  switch (state->step) {
    case WORKSPACE_JOIN_REQUEST:
      if (response->status_code == 409) {
        // 已经是该 workspace 成员
        flow_context_log(flow, "info", "子号已在 workspace 内(409), 记为加入成功");
        mg_snprintf(flow->workspace_id, sizeof(flow->workspace_id), "%s",
                    state->target_workspace_id);
        mark_join_done(flow, state);
        return 0;
      }
      if (response->status_code < 200 || response->status_code >= 300) {
        flow_context_log(flow, "error", "workspace 加入申请失败: HTTP %ld",
                         response->status_code);
        flow_context_fail(flow, "加入 workspace 申请被拒");
        return -1;
      }
      flow_context_log(flow, "info", "workspace 加入申请已提交, 开始轮询确认获批");
      mg_snprintf(flow->workspace_id, sizeof(flow->workspace_id), "%s",
                  state->target_workspace_id);
      state->step = WORKSPACE_JOIN_POLL;
      flow->next_retry_ms = (long) mg_millis() + WS_JOIN_POLL_INTERVAL_MS;
      return 0;
    case WORKSPACE_JOIN_POLL:
      // accounts/check 返回体里出现目标 wsId 即视为已加入(获批)
      if (response->status_code >= 200 && response->status_code < 300 &&
          response->body != NULL &&
          strstr(response->body, state->target_workspace_id) != NULL) {
        flow_context_log(flow, "info", "已确认加入母号 workspace: %s",
                         state->target_workspace_id);
        mark_join_done(flow, state);
        return 0;
      }
      // 未获批, 继续轮询(next 依据 deadline 决定继续或超时收尾)
      flow->next_retry_ms = (long) mg_millis() + WS_JOIN_POLL_INTERVAL_MS;
      return 0;
    case WORKSPACE_JOIN_DONE:
      return 0;
    default:
      return -1;
  }
}

bool workspace_join_is_done(const struct workspace_join_state *state) {
  return state != NULL && state->step == WORKSPACE_JOIN_DONE;
}
