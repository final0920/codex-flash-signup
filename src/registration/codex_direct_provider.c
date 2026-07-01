#include "registration/codex_direct_provider.h"

#include "account/account_store.h"
#include "mail/rapid_inbox.h"
#include "mongoose.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CD_AUTH_BASE "https://auth.openai.com"
#define CD_CHATGPT_BASE "https://chatgpt.com"
#define CD_SENTINEL_URL "https://sentinel.openai.com/backend-api/sentinel/req"
#define CD_SENTINEL_ORIGIN "https://sentinel.openai.com"
#define CD_SENTINEL_VERSION "20260219f9f6"
#define CD_SENTINEL_REFERER \
  "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=" \
  CD_SENTINEL_VERSION
#define CD_CLIENT_ID "app_EMoamEEZ73f0CkXaXp7hrann"
#define CD_REDIRECT_URI "http://localhost:1455/auth/callback"
#define CD_SCOPE "openid email profile offline_access"
#define CD_OTP_POLL_INTERVAL_MS 2000L
#define CD_MAX_FOLLOW 15
#define CD_TOK 8192
#define CD_NODE_WRAPPER "/app/sentinel/wrapper.js"
#define CD_NODE_SDK "/app/sentinel/sdk.js"
#define CD_NODE_SDK_RUNTIME "/app/data/sentinel/sdk.js"
#define CD_SENTINEL_VER_FILE "/app/data/sentinel/version.txt"
#define CD_NODE_ADAPTER "/app/sentinel/openai_sentinel_quickjs.js"

enum cd_step {
  CD_AUTHORIZE = 0,
  CD_SENTINEL_REQ,
  CD_AUTHORIZE_CONTINUE,
  CD_CREATE_PWD_PAGE,
  CD_USER_REGISTER,
  CD_OTP_SEND,
  CD_OTP_VALIDATE,
  CD_CREATE_ACCOUNT,
  CD_FOLLOW,
  CD_WORKSPACE_SELECT,
  CD_TOKEN,
  CD_DONE
};

struct cd_state {
  int sentinel_next_step;
  char sentinel_flow[48];
  char sdk_version[40];
  char device_id[80];
  char state_param[80];
  char code_verifier[160];
  char code_challenge[96];
  char authorize_url[FLOW_URL_LEN];
  char current_url[FLOW_URL_LEN];
  char callback_url[FLOW_URL_LEN];
  char workspace_id[FLOW_WORKSPACE_ID_LEN];
  char request_p[CD_TOK];
  char c_token[CD_TOK];
  char final_p[CD_TOK];
  char sentinel_t[CD_TOK];
  char header_sentinel[CD_TOK * 4];
  char otp_code[64];
  long otp_sent_epoch;
  int otp_attempts;
  int redirect_count;
  bool workspace_selected;
  bool is_new_account;
  char body[2048];
  struct flow_http_header headers[12];
  size_t num_headers;
  char hbuf_accept[256];
  char hbuf_referer[FLOW_URL_LEN];
  char hbuf_origin[64];
};

/* ---------- small helpers ---------- */

static uint64_t cd_rand_u64(void) {
  uint64_t v = 0;
  if (!mg_random(&v, sizeof(v))) v = ((uint64_t) rand() << 32) ^ (uint64_t) rand();
  return v;
}

static void b64url_strip(char *s) {
  for (size_t i = 0; s[i]; i++) {
    if (s[i] == '+') s[i] = '-';
    else if (s[i] == '/') s[i] = '_';
    else if (s[i] == '=') { s[i] = '\0'; break; }
  }
}

static void cd_b64url_random(char *out, size_t out_len, size_t nbytes) {
  uint8_t raw[96];
  char tmp[160];
  if (nbytes > sizeof(raw)) nbytes = sizeof(raw);
  for (size_t i = 0; i < nbytes; i++) raw[i] = (uint8_t) (cd_rand_u64() & 0xff);
  mg_base64_encode(raw, nbytes, tmp, sizeof(tmp));
  b64url_strip(tmp);
  mg_snprintf(out, out_len, "%s", tmp);
}

static void cd_make_challenge(const char *verifier, char *out, size_t out_len) {
  uint8_t digest[32];
  if (out_len == 0) return;
  out[0] = '\0';
  mg_sha256(digest, (uint8_t *) verifier, strlen(verifier));
  mg_base64_encode(digest, sizeof(digest), out, out_len);
  b64url_strip(out);
}

static void cd_set_header(struct cd_state *st, const char *name,
                          const char *value) {
  if (st->num_headers >= sizeof(st->headers) / sizeof(st->headers[0])) return;
  if (name == NULL || value == NULL || value[0] == '\0') return;
  st->headers[st->num_headers].name = name;
  st->headers[st->num_headers].value = value;
  st->num_headers++;
}

static void cd_make_absolute(const char *base, const char *loc, char *out,
                             size_t out_len) {
  if (out_len == 0) return;
  out[0] = '\0';
  if (loc == NULL || loc[0] == '\0') return;
  if (strncmp(loc, "http://", 7) == 0 || strncmp(loc, "https://", 8) == 0) {
    mg_snprintf(out, out_len, "%s", loc);
  } else if (loc[0] == '/') {
    mg_snprintf(out, out_len, "%s%s", base ? base : CD_AUTH_BASE, loc);
  } else {
    mg_snprintf(out, out_len, "%s/%s", base ? base : CD_AUTH_BASE, loc);
  }
}

static bool cd_query_value(const char *url, const char *name, char *out,
                           size_t out_len) {
  const char *q;
  char decoded[FLOW_URL_LEN];
  size_t name_len;
  if (out_len == 0) return false;
  out[0] = '\0';
  if (url == NULL || name == NULL) return false;
  q = strchr(url, '?');
  if (q == NULL) return false;
  q++;
  name_len = strlen(name);
  while (*q) {
    const char *eq = strchr(q, '=');
    const char *amp = strchr(q, '&');
    if (eq == NULL || (amp != NULL && amp < eq)) {
      if (amp == NULL) break;
      q = amp + 1;
      continue;
    }
    if ((size_t) (eq - q) == name_len && strncmp(q, name, name_len) == 0) {
      size_t vlen = amp == NULL ? strlen(eq + 1) : (size_t) (amp - eq - 1);
      int n = mg_url_decode(eq + 1, vlen, decoded, sizeof(decoded), 1);
      if (n <= 0) return false;
      mg_snprintf(out, out_len, "%s", decoded);
      return true;
    }
    if (amp == NULL) break;
    q = amp + 1;
  }
  return false;
}

static bool cd_copy_json(const char *json, const char *path, char *out,
                         size_t out_len) {
  char *v;
  if (out_len == 0) return false;
  out[0] = '\0';
  if (json == NULL) return false;
  v = mg_json_get_str(mg_str(json), path);
  if (v == NULL) return false;
  mg_snprintf(out, out_len, "%s", v);
  mg_free(v);
  return out[0] != '\0';
}

static bool cd_extract_workspace_id(const char *text, char *out,
                                    size_t out_len) {
  const char *p;
  if (out_len == 0) return false;
  out[0] = '\0';
  if (text == NULL) return false;
  p = strstr(text, "\"workspaces\"");
  if (p == NULL) p = strstr(text, "\"workspace\"");
  if (p == NULL) return false;
  p = strstr(p, "\"id\"");
  if (p == NULL) return false;
  p = strchr(p + 4, ':');
  if (p == NULL) return false;
  p++;
  while (*p && isspace((unsigned char) *p)) p++;
  if (*p != '"') return false;
  p++;
  {
    size_t n = 0;
    while (*p && *p != '"' && n + 1 < out_len) {
      if (*p == '\\' && p[1]) p++;
      out[n++] = *p++;
    }
    out[n] = '\0';
  }
  return out[0] != '\0';
}

static bool cd_has(const char *s, const char *needle) {
  return s != NULL && needle != NULL && strstr(s, needle) != NULL;
}

/* ---------- node sentinel compute (fork node wrapper) ---------- */

static int cd_write_all(int fd, const char *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t w = write(fd, buf + off, len - off);
    if (w < 0) { if (errno == EINTR) continue; return -1; }
    off += (size_t) w;
  }
  return 0;
}

/* Runs node wrapper.js with payload on stdin, captures stdout into out.
 * Returns 0 on success. */
static int cd_node_run(const char *payload, size_t payload_len, char *out,
                       size_t out_len, long timeout_ms) {
  int inpipe[2], outpipe[2];
  pid_t pid;
  long deadline;
  size_t used = 0;
  int status = 0;
  bool killed = false;

  if (out_len == 0) return -1;
  out[0] = '\0';
  if (pipe(inpipe) != 0) return -1;
  if (pipe(outpipe) != 0) { close(inpipe[0]); close(inpipe[1]); return -1; }
  pid = fork();
  if (pid < 0) {
    close(inpipe[0]); close(inpipe[1]);
    close(outpipe[0]); close(outpipe[1]);
    return -1;
  }
  if (pid == 0) {
    char tbuf[24];
    dup2(inpipe[0], STDIN_FILENO);
    dup2(outpipe[1], STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) dup2(devnull, STDERR_FILENO);
    close(inpipe[0]); close(inpipe[1]);
    close(outpipe[0]); close(outpipe[1]);
    setenv("OPENAI_SENTINEL_SDK_FILE",
           access(CD_NODE_SDK_RUNTIME, R_OK) == 0 ? CD_NODE_SDK_RUNTIME
                                                  : CD_NODE_SDK,
           1);
    setenv("OPENAI_SENTINEL_QUICKJS_SCRIPT", CD_NODE_ADAPTER, 1);
    mg_snprintf(tbuf, sizeof(tbuf), "%ld", timeout_ms > 0 ? timeout_ms : 15000);
    setenv("OPENAI_SENTINEL_VM_TIMEOUT_MS", tbuf, 1);
    execlp("node", "node", CD_NODE_WRAPPER, (char *) NULL);
    _exit(127);
  }
  close(inpipe[0]);
  close(outpipe[1]);
  cd_write_all(inpipe[1], payload, payload_len);
  close(inpipe[1]);

  deadline = (long) mg_millis() + (timeout_ms > 0 ? timeout_ms + 5000 : 20000);
  for (;;) {
    fd_set rfds;
    struct timeval tv;
    long remaining = deadline - (long) mg_millis();
    int sel;
    if (remaining <= 0) { kill(pid, SIGKILL); killed = true; break; }
    FD_ZERO(&rfds);
    FD_SET(outpipe[0], &rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    sel = select(outpipe[0] + 1, &rfds, NULL, NULL, &tv);
    if (sel < 0) { if (errno == EINTR) continue; break; }
    if (sel == 0) continue;
    {
      ssize_t r = read(outpipe[0], out + used,
                       used + 1 < out_len ? out_len - used - 1 : 0);
      if (r <= 0) break;
      used += (size_t) r;
      if (used + 1 >= out_len) break;
    }
  }
  out[used] = '\0';
  close(outpipe[0]);
  if (waitpid(pid, &status, 0) < 0) return -1;
  if (killed) return -1;
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return -1;
  return used > 0 ? 0 : -1;
}

/* node requirements -> request_p (pure compute, no network) */
static int cd_node_requirements(struct flow_context *flow, struct cd_state *st) {
  char payload[256];
  char result[CD_TOK];
  mg_snprintf(payload, sizeof(payload), "{\"action\":\"requirements\",\"device_id\":\"%s\"}",
              st->device_id);
  if (cd_node_run(payload, strlen(payload), result, sizeof(result), 15000) != 0) {
    flow_context_fail(flow, "sentinel requirements (node) 失败");
    return -1;
  }
  if (!cd_copy_json(result, "$.request_p", st->request_p,
                    sizeof(st->request_p)) || st->request_p[0] == '\0') {
    flow_context_fail(flow, "sentinel requirements 未返回 request_p");
    return -1;
  }
  return 0;
}

/* node solve(challenge) -> final_p + t (pure compute, no network) */
static int cd_node_solve(struct flow_context *flow, struct cd_state *st,
                         const char *challenge_json) {
  size_t cap = strlen(challenge_json) + strlen(st->request_p) +
               strlen(st->device_id) + 128;
  char *payload = (char *) malloc(cap);
  char result[CD_TOK * 3];
  int rc;
  if (payload == NULL) {
    flow_context_fail(flow, "sentinel solve 内存不足");
    return -1;
  }
  mg_snprintf(payload, cap,
              "{\"action\":\"solve\",\"device_id\":\"%s\",\"request_p\":\"%s\","
              "\"challenge\":%s}",
              st->device_id, st->request_p, challenge_json);
  rc = cd_node_run(payload, strlen(payload), result, sizeof(result), 20000);
  free(payload);
  if (rc != 0) {
    flow_context_fail(flow, "sentinel solve (node) 失败");
    return -1;
  }
  if (!cd_copy_json(result, "$.final_p", st->final_p, sizeof(st->final_p))) {
    cd_copy_json(result, "$.p", st->final_p, sizeof(st->final_p));
  }
  cd_copy_json(result, "$.t", st->sentinel_t, sizeof(st->sentinel_t));
  if (st->final_p[0] == '\0') {
    flow_context_fail(flow, "sentinel solve 未返回 final_p");
    return -1;
  }
  return 0;
}

/* ---------- request builders ---------- */

static void cd_nav_get(struct cd_state *st, struct flow_http_request *req,
                       const char *url, const char *referer, bool follow) {
  st->num_headers = 0;
  mg_snprintf(st->hbuf_accept, sizeof(st->hbuf_accept),
              "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,*/*;q=0.8");
  mg_snprintf(st->hbuf_referer, sizeof(st->hbuf_referer), "%s",
              referer ? referer : CD_CHATGPT_BASE "/");
  cd_set_header(st, "Accept", st->hbuf_accept);
  cd_set_header(st, "Referer", st->hbuf_referer);
  cd_set_header(st, "Sec-Fetch-Dest", "document");
  cd_set_header(st, "Sec-Fetch-Mode", "navigate");
  cd_set_header(st, "Upgrade-Insecure-Requests", "1");
  memset(req, 0, sizeof(*req));
  req->method = "GET";
  req->url = url;
  req->timeout_ms = 30000;
  req->follow_location = follow;
  req->headers = st->headers;
  req->num_headers = st->num_headers;
}

static void cd_json_post(struct cd_state *st, struct flow_http_request *req,
                         const char *url, const char *body, const char *referer,
                         const char *sentinel_header) {
  st->num_headers = 0;
  mg_snprintf(st->hbuf_origin, sizeof(st->hbuf_origin), "%s", CD_CHATGPT_BASE);
  mg_snprintf(st->hbuf_referer, sizeof(st->hbuf_referer), "%s",
              referer ? referer : CD_CHATGPT_BASE "/");
  cd_set_header(st, "Accept", "application/json");
  cd_set_header(st, "Content-Type", "application/json");
  cd_set_header(st, "Origin", st->hbuf_origin);
  cd_set_header(st, "Referer", st->hbuf_referer);
  cd_set_header(st, "Sec-Fetch-Dest", "empty");
  cd_set_header(st, "Sec-Fetch-Mode", "cors");
  cd_set_header(st, "Sec-Fetch-Site", "same-origin");
  if (sentinel_header != NULL && sentinel_header[0] != '\0') {
    cd_set_header(st, "OpenAI-Sentinel-Token", sentinel_header);
  }
  memset(req, 0, sizeof(*req));
  req->method = "POST";
  req->url = url;
  req->body = body;
  req->body_len = body ? strlen(body) : 0;
  req->timeout_ms = 30000;
  req->follow_location = false;
  req->headers = st->headers;
  req->num_headers = st->num_headers;
}

static void cd_sentinel_post(struct cd_state *st, struct flow_http_request *req) {
  st->num_headers = 0;
  mg_snprintf(st->body, sizeof(st->body),
              "{\"p\":\"%s\",\"id\":\"%s\",\"flow\":\"%s\"}", st->request_p,
              st->device_id, st->sentinel_flow);
  mg_snprintf(st->hbuf_origin, sizeof(st->hbuf_origin), "%s",
              CD_SENTINEL_ORIGIN);
  mg_snprintf(st->hbuf_referer, sizeof(st->hbuf_referer),
              "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=%s",
              st->sdk_version[0] ? st->sdk_version : CD_SENTINEL_VERSION);
  cd_set_header(st, "Accept", "*/*");
  cd_set_header(st, "Content-Type", "text/plain;charset=UTF-8");
  cd_set_header(st, "Origin", st->hbuf_origin);
  cd_set_header(st, "Referer", st->hbuf_referer);
  cd_set_header(st, "Sec-Fetch-Dest", "empty");
  cd_set_header(st, "Sec-Fetch-Mode", "cors");
  cd_set_header(st, "Sec-Fetch-Site", "same-origin");
  memset(req, 0, sizeof(*req));
  req->method = "POST";
  req->url = CD_SENTINEL_URL;
  req->body = st->body;
  req->body_len = strlen(st->body);
  req->timeout_ms = 30000;
  req->follow_location = false;
  req->headers = st->headers;
  req->num_headers = st->num_headers;
}

static void cd_form_post(struct cd_state *st, struct flow_http_request *req,
                         const char *url, const char *body) {
  st->num_headers = 0;
  mg_snprintf(st->hbuf_origin, sizeof(st->hbuf_origin), "%s", CD_AUTH_BASE);
  cd_set_header(st, "Accept", "application/json");
  cd_set_header(st, "Content-Type", "application/x-www-form-urlencoded");
  cd_set_header(st, "Origin", st->hbuf_origin);
  cd_set_header(st, "Sec-Fetch-Dest", "empty");
  cd_set_header(st, "Sec-Fetch-Mode", "cors");
  cd_set_header(st, "Sec-Fetch-Site", "same-site");
  memset(req, 0, sizeof(*req));
  req->method = "POST";
  req->url = url;
  req->body = body;
  req->body_len = body ? strlen(body) : 0;
  req->timeout_ms = 30000;
  req->follow_location = false;
  req->headers = st->headers;
  req->num_headers = st->num_headers;
}

static void cd_build_sentinel_header(struct cd_state *st) {
  /* t may be empty -> emit JSON null so the field is still present */
  if (st->sentinel_t[0] != '\0') {
    mg_snprintf(st->header_sentinel, sizeof(st->header_sentinel),
                "{\"p\":\"%s\",\"t\":\"%s\",\"c\":\"%s\",\"id\":\"%s\","
                "\"flow\":\"%s\"}",
                st->final_p, st->sentinel_t, st->c_token, st->device_id,
                st->sentinel_flow);
  } else {
    mg_snprintf(st->header_sentinel, sizeof(st->header_sentinel),
                "{\"p\":\"%s\",\"t\":\"\",\"c\":\"%s\",\"id\":\"%s\","
                "\"flow\":\"%s\"}",
                st->final_p, st->c_token, st->device_id, st->sentinel_flow);
  }
}

/* Kick off a sentinel exchange: node requirements -> POST /sentinel/req. */
static int cd_begin_sentinel(struct flow_context *flow, struct cd_state *st,
                             const char *sentinel_flow, int next_step) {
  mg_snprintf(st->sentinel_flow, sizeof(st->sentinel_flow), "%s", sentinel_flow);
  st->sentinel_next_step = next_step;
  st->request_p[0] = st->c_token[0] = st->final_p[0] = st->sentinel_t[0] = '\0';
  if (cd_node_requirements(flow, st) != 0) return -1;
  flow->step = CD_SENTINEL_REQ;
  flow_context_log(flow, "info", "sentinel %s: requirements ok (%dB)",
                   sentinel_flow, (int) strlen(st->request_p));
  return 0;
}

/* ---------- provider callbacks ---------- */

static int cd_start(struct flow_context *flow) {
  struct cd_state *st = (struct cd_state *) calloc(1, sizeof(*st));
  char redirect_enc[160];
  char scope_enc[160];
  if (st == NULL) return -1;
  flow->provider_data = st;
  flow->step = CD_AUTHORIZE;
  if (flow->deadline_ms <= 0) flow->deadline_ms = (long) mg_millis() + 240000;

  /* sentinel 版本：优先用 entrypoint 启动时发现并写入数据卷的版本 */
  mg_snprintf(st->sdk_version, sizeof(st->sdk_version), "%s", CD_SENTINEL_VERSION);
  {
    FILE *vf = fopen(CD_SENTINEL_VER_FILE, "r");
    if (vf != NULL) {
      char vbuf[64] = "";
      if (fgets(vbuf, sizeof(vbuf), vf) != NULL) {
        size_t n = 0;
        while (vbuf[n] && isalnum((unsigned char) vbuf[n])) n++;
        vbuf[n] = '\0';
        if (vbuf[0])
          mg_snprintf(st->sdk_version, sizeof(st->sdk_version), "%s", vbuf);
      }
      fclose(vf);
    }
  }

  cd_b64url_random(st->state_param, sizeof(st->state_param), 24);
  cd_b64url_random(st->code_verifier, sizeof(st->code_verifier), 64);
  cd_make_challenge(st->code_verifier, st->code_challenge,
                    sizeof(st->code_challenge));
  mg_snprintf(flow->pkce_code_verifier, sizeof(flow->pkce_code_verifier), "%s",
              st->code_verifier);
  mg_url_encode(CD_REDIRECT_URI, strlen(CD_REDIRECT_URI), redirect_enc,
                sizeof(redirect_enc));
  mg_url_encode(CD_SCOPE, strlen(CD_SCOPE), scope_enc, sizeof(scope_enc));
  mg_snprintf(st->authorize_url, sizeof(st->authorize_url),
              CD_AUTH_BASE
              "/oauth/authorize?client_id=%s&response_type=code&redirect_uri=%s"
              "&scope=%s&state=%s&code_challenge=%s&code_challenge_method=S256"
              "&id_token_add_organizations=true&codex_cli_simplified_flow=true",
              CD_CLIENT_ID, redirect_enc, scope_enc, st->state_param,
              st->code_challenge);
  flow_context_log(flow, "info", "Codex 直注(node-sentinel): 邮箱 %s",
                   flow->identity.email);
  return 0;
}

static enum flow_provider_action cd_otp_request(struct flow_context *flow,
                                                struct flow_http_request *req) {
  struct cd_state *st = (struct cd_state *) flow->provider_data;
  char err[160] = "";
  long now = (long) mg_millis();
  int rc;

  if (now > flow->deadline_ms) {
    flow_context_fail(flow, "等待邮箱验证码超时");
    return FLOW_PROVIDER_FAILED;
  }
  if (now < flow->next_retry_ms) return FLOW_PROVIDER_WAIT;

  st->otp_attempts++;
  rc = rapid_inbox_fetch_latest_code_since(flow->db, flow->identity.email,
                                           st->otp_sent_epoch, st->otp_code,
                                           sizeof(st->otp_code), err,
                                           sizeof(err));
  if (rc <= 0) {
    if (rc < 0) flow_context_log(flow, "warn", "读取验证码失败: %s", err);
    flow->next_retry_ms = now + CD_OTP_POLL_INTERVAL_MS;
    return FLOW_PROVIDER_WAIT;
  }
  mg_snprintf(st->body, sizeof(st->body), "{\"code\":\"%s\"}", st->otp_code);
  cd_json_post(st, req, CD_AUTH_BASE "/api/accounts/email-otp/validate",
               st->body, CD_AUTH_BASE "/create-account/password", NULL);
  flow_context_log(flow, "info", "验证码已获取，提交邮箱验证");
  return FLOW_PROVIDER_REQUEST;
}

static enum flow_provider_action cd_next(struct flow_context *flow,
                                         struct flow_http_request *req) {
  struct cd_state *st = (struct cd_state *) flow->provider_data;
  if (st == NULL) {
    flow_context_fail(flow, "Codex 直注状态丢失");
    return FLOW_PROVIDER_FAILED;
  }
  switch (flow->step) {
    case CD_AUTHORIZE:
      cd_nav_get(st, req, st->authorize_url, CD_CHATGPT_BASE "/", true);
      flow_context_log(flow, "info", "步骤 authorize: 打开 Codex 授权入口");
      return FLOW_PROVIDER_REQUEST;
    case CD_SENTINEL_REQ:
      cd_sentinel_post(st, req);
      flow_context_log(flow, "info", "步骤 sentinel/req: %s", st->sentinel_flow);
      return FLOW_PROVIDER_REQUEST;
    case CD_AUTHORIZE_CONTINUE:
      mg_snprintf(st->body, sizeof(st->body),
                  "{\"username\":{\"value\":\"%s\",\"kind\":\"email\"},"
                  "\"screen_hint\":\"signup\"}",
                  flow->identity.email);
      cd_json_post(st, req, CD_AUTH_BASE "/api/accounts/authorize/continue",
                   st->body, CD_AUTH_BASE "/create-account",
                   st->header_sentinel);
      flow_context_log(flow, "info", "步骤 authorize/continue: 提交邮箱(注册)");
      return FLOW_PROVIDER_REQUEST;
    case CD_CREATE_PWD_PAGE:
      cd_nav_get(st, req, CD_AUTH_BASE "/create-account/password",
                 CD_AUTH_BASE "/create-account", false);
      return FLOW_PROVIDER_REQUEST;
    case CD_USER_REGISTER:
      mg_snprintf(st->body, sizeof(st->body),
                  "{\"password\":\"%s\",\"username\":\"%s\"}",
                  flow->identity.password, flow->identity.email);
      cd_json_post(st, req, CD_AUTH_BASE "/api/accounts/user/register",
                   st->body, CD_AUTH_BASE "/create-account/password",
                   st->header_sentinel);
      flow_context_log(flow, "info", "步骤 user/register: 设置密码");
      return FLOW_PROVIDER_REQUEST;
    case CD_OTP_SEND:
      st->otp_sent_epoch = (long) time(NULL);
      cd_nav_get(st, req, CD_AUTH_BASE "/api/accounts/email-otp/send",
                 CD_AUTH_BASE "/create-account/password", false);
      req->method = "GET";
      flow_context_log(flow, "info", "步骤 email-otp/send: 触发验证码");
      flow_context_emit_event(flow, FLOW_EVENT_EMAIL_OTP_WAITING);
      return FLOW_PROVIDER_REQUEST;
    case CD_OTP_VALIDATE:
      return cd_otp_request(flow, req);
    case CD_CREATE_ACCOUNT:
      mg_snprintf(st->body, sizeof(st->body),
                  "{\"name\":\"%s\",\"birthdate\":\"%s\"}",
                  flow->identity.full_name, flow->identity.birthdate);
      cd_json_post(st, req, CD_AUTH_BASE "/api/accounts/create_account",
                   st->body, CD_AUTH_BASE "/about-you", st->header_sentinel);
      flow_context_log(flow, "info", "步骤 create_account: %s / %s",
                       flow->identity.full_name, flow->identity.birthdate);
      return FLOW_PROVIDER_REQUEST;
    case CD_FOLLOW:
      cd_nav_get(st, req, st->current_url, CD_CHATGPT_BASE "/", false);
      flow_context_log(flow, "info", "步骤 follow %d/%d", st->redirect_count + 1,
                       CD_MAX_FOLLOW);
      return FLOW_PROVIDER_REQUEST;
    case CD_WORKSPACE_SELECT:
      mg_snprintf(st->body, sizeof(st->body), "{\"workspace_id\":\"%s\"}",
                  st->workspace_id);
      cd_json_post(st, req, CD_AUTH_BASE "/api/accounts/workspace/select",
                   st->body,
                   CD_AUTH_BASE "/sign-in-with-chatgpt/codex/consent", NULL);
      flow_context_log(flow, "info", "步骤 workspace/select: %s",
                       st->workspace_id);
      return FLOW_PROVIDER_REQUEST;
    case CD_TOKEN: {
      char code_enc[3072], redir_enc[160], ver_enc[256];
      char code[FLOW_CODE_LEN] = "";
      cd_query_value(st->callback_url, "code", code, sizeof(code));
      mg_url_encode(code, strlen(code), code_enc, sizeof(code_enc));
      mg_url_encode(CD_REDIRECT_URI, strlen(CD_REDIRECT_URI), redir_enc,
                    sizeof(redir_enc));
      mg_url_encode(flow->pkce_code_verifier, strlen(flow->pkce_code_verifier),
                    ver_enc, sizeof(ver_enc));
      mg_snprintf(st->body, sizeof(st->body),
                  "grant_type=authorization_code&client_id=%s&code=%s"
                  "&redirect_uri=%s&code_verifier=%s",
                  CD_CLIENT_ID, code_enc, redir_enc, ver_enc);
      cd_form_post(st, req, CD_AUTH_BASE "/oauth/token", st->body);
      flow_context_log(flow, "info", "步骤 token: 使用授权码换取 Token");
      return FLOW_PROVIDER_REQUEST;
    }
    case CD_DONE:
      return FLOW_PROVIDER_DONE;
    default:
      flow_context_fail(flow, "Codex 直注未知步骤");
      return FLOW_PROVIDER_FAILED;
  }
}

static bool cd_expect_ok(struct flow_context *flow,
                         const struct flow_http_response *res,
                         const char *label) {
  if (res->status_code >= 200 && res->status_code < 400) return true;
  if (flow_response_is_email_already_registered(res)) {
    flow_context_mark_identity_retry(flow, "邮箱已被注册，换邮箱重试");
  } else if (flow_response_is_edge_block(res)) {
    flow_context_mark_environment_retry(flow, "边缘风控拦截，换环境重试");
  } else {
    flow_context_fail(flow, "Codex 直注请求返回非成功状态");
  }
  {
    char code[96] = "";
    cd_copy_json(res->body, "$.error.code", code, sizeof(code));
    flow_context_log(flow, "error", "%s 失败: HTTP %ld code=%s body=%.300s",
                     label, res->status_code, code[0] ? code : "-",
                     res->body ? res->body : "");
  }
  return false;
}

static int cd_persist_and_finish(struct flow_context *flow,
                                 const struct flow_http_response *res) {
  struct cd_state *st = (struct cd_state *) flow->provider_data;
  struct mg_str json = mg_str_n(res->body ? res->body : "", res->body_len);
  char *at = mg_json_get_str(json, "$.access_token");
  char *rt = mg_json_get_str(json, "$.refresh_token");
  char *it = mg_json_get_str(json, "$.id_token");
  int rc = -1;

  if (at == NULL || at[0] == '\0') {
    flow_context_fail(flow, "Codex token 交换未返回 access_token");
    goto done;
  }
  mg_snprintf(flow->access_token, sizeof(flow->access_token), "%s", at);
  mg_snprintf(flow->refresh_token, sizeof(flow->refresh_token), "%s",
              rt ? rt : "");
  mg_snprintf(flow->id_token, sizeof(flow->id_token), "%s", it ? it : "");
  if (st->workspace_id[0]) {
    mg_snprintf(flow->workspace_id, sizeof(flow->workspace_id), "%s",
                st->workspace_id);
  }
  /* 不在此自行落库：返回 DONE 后由 flow 引擎的 persist_success 统一写入
     （它用 success_account_status + 上面这些 token 字段）。自行 insert 会与
     引擎重复写、触发 email 唯一约束失败。 */
  mg_snprintf(flow->success_account_status, sizeof(flow->success_account_status),
              "active");
  flow_context_log(flow, "info",
                   "Codex 直注完成: access=%dB refresh=%s id=%s workspace=%s",
                   (int) strlen(flow->access_token),
                   flow->refresh_token[0] ? "yes" : "no",
                   flow->id_token[0] ? "yes" : "no",
                   flow->workspace_id[0] ? flow->workspace_id : "-");
  flow->step = CD_DONE;
  rc = 0;
done:
  mg_free(at);
  mg_free(rt);
  mg_free(it);
  return rc;
}

static int cd_follow_advance(struct flow_context *flow,
                             const struct flow_http_response *res) {
  struct cd_state *st = (struct cd_state *) flow->provider_data;
  char code[FLOW_CODE_LEN] = "";
  char nextu[FLOW_URL_LEN] = "";

  if (cd_query_value(res->location, "code", code, sizeof(code)) ||
      cd_query_value(res->effective_url, "code", code, sizeof(code)) ||
      cd_query_value(st->current_url, "code", code, sizeof(code))) {
    if (res->location[0] && cd_has(res->location, "code=")) {
      mg_snprintf(st->callback_url, sizeof(st->callback_url), "%s",
                  res->location);
    } else if (cd_has(st->current_url, "code=")) {
      mg_snprintf(st->callback_url, sizeof(st->callback_url), "%s",
                  st->current_url);
    } else {
      mg_snprintf(st->callback_url, sizeof(st->callback_url), "%s",
                  res->effective_url);
    }
    flow->step = CD_TOKEN;
    return 0;
  }
  if (res->status_code >= 300 && res->status_code < 400 &&
      res->location[0] != '\0') {
    cd_make_absolute(CD_AUTH_BASE, res->location, st->current_url,
                     sizeof(st->current_url));
    if (++st->redirect_count > CD_MAX_FOLLOW) {
      flow_context_fail(flow, "Codex 直注重定向链超过上限");
      return -1;
    }
    flow->step = CD_FOLLOW;
    return 0;
  }
  if (!st->workspace_selected && st->workspace_id[0] &&
      (cd_has(st->current_url, "/consent") ||
       cd_has(st->current_url, "/organization") ||
       cd_has(res->body, "workspace/select") ||
       cd_has(res->effective_url, "/consent"))) {
    st->workspace_selected = true;
    flow->step = CD_WORKSPACE_SELECT;
    return 0;
  }
  if (cd_copy_json(res->body, "$.continue_url", nextu, sizeof(nextu)) &&
      nextu[0]) {
    cd_make_absolute(CD_AUTH_BASE, nextu, st->current_url,
                     sizeof(st->current_url));
    if (++st->redirect_count > CD_MAX_FOLLOW) {
      flow_context_fail(flow, "Codex 直注重定向链超过上限");
      return -1;
    }
    flow->step = CD_FOLLOW;
    return 0;
  }
  flow_context_fail(flow, "Codex 直注重定向链未返回下一跳");
  return -1;
}

static int cd_response(struct flow_context *flow,
                       const struct flow_http_response *res) {
  struct cd_state *st = (struct cd_state *) flow->provider_data;
  if (st == NULL || res == NULL) {
    flow_context_fail(flow, "Codex 直注响应丢失");
    return -1;
  }

  switch (flow->step) {
    case CD_AUTHORIZE:
      if (res->device_id[0]) {
        mg_snprintf(st->device_id, sizeof(st->device_id), "%s", res->device_id);
      }
      if (st->device_id[0] == '\0') {
        cd_b64url_random(st->device_id, sizeof(st->device_id), 16);
      }
      flow_context_log(flow, "info", "authorize: device_id=%s (%s) http=%ld",
                       st->device_id, res->device_id[0] ? "oai-did" : "random",
                       res->status_code);
      return cd_begin_sentinel(flow, st, "authorize_continue",
                               CD_AUTHORIZE_CONTINUE);
    case CD_SENTINEL_REQ:
      if (!cd_expect_ok(flow, res, "sentinel/req")) return -1;
      if (!cd_copy_json(res->body, "$.token", st->c_token,
                        sizeof(st->c_token))) {
        flow_context_fail(flow, "sentinel/req 未返回 token");
        return -1;
      }
      if (cd_node_solve(flow, st, res->body) != 0) return -1;
      cd_build_sentinel_header(st);
      flow_context_log(flow, "info",
                       "sentinel %s: solve ok (p=%dB t=%dB c=%dB)",
                       st->sentinel_flow, (int) strlen(st->final_p),
                       (int) strlen(st->sentinel_t), (int) strlen(st->c_token));
      flow->step = st->sentinel_next_step;
      return 0;
    case CD_AUTHORIZE_CONTINUE: {
      char pt[64] = "", cu[FLOW_URL_LEN] = "";
      if (!cd_expect_ok(flow, res, "authorize/continue")) return -1;
      cd_copy_json(res->body, "$.page.type", pt, sizeof(pt));
      cd_copy_json(res->body, "$.continue_url", cu, sizeof(cu));
      st->is_new_account = strcmp(pt, "create_account_password") == 0 ||
                           cd_has(cu, "/create-account/password");
      flow->step = st->is_new_account ? CD_CREATE_PWD_PAGE : CD_OTP_SEND;
      return 0;
    }
    case CD_CREATE_PWD_PAGE:
      return cd_begin_sentinel(flow, st, "username_password_create",
                               CD_USER_REGISTER);
    case CD_USER_REGISTER:
      if (!cd_expect_ok(flow, res, "user/register")) return -1;
      flow->step = CD_OTP_SEND;
      return 0;
    case CD_OTP_SEND:
      flow->next_retry_ms = (long) mg_millis() + CD_OTP_POLL_INTERVAL_MS;
      flow->step = CD_OTP_VALIDATE;
      return 0;
    case CD_OTP_VALIDATE:
      if (!cd_expect_ok(flow, res, "email-otp/validate")) return -1;
      flow_context_emit_event(flow, FLOW_EVENT_EMAIL_OTP_VALIDATED);
      return cd_begin_sentinel(flow, st, "create_account", CD_CREATE_ACCOUNT);
    case CD_CREATE_ACCOUNT: {
      char cu[FLOW_URL_LEN] = "";
      if (!cd_expect_ok(flow, res, "create_account")) return -1;
      cd_extract_workspace_id(res->body, st->workspace_id,
                              sizeof(st->workspace_id));
      if (!cd_copy_json(res->body, "$.continue_url", cu, sizeof(cu)) ||
          cu[0] == '\0') {
        flow_context_fail(flow, "create_account 未返回 continue_url");
        return -1;
      }
      cd_make_absolute(CD_AUTH_BASE, cu, st->current_url,
                       sizeof(st->current_url));
      st->redirect_count = 0;
      flow_context_log(flow, "info", "create_account 完成, workspace=%s",
                       st->workspace_id[0] ? st->workspace_id : "-");
      flow->step = CD_FOLLOW;
      return 0;
    }
    case CD_FOLLOW:
      if (!cd_expect_ok(flow, res, "follow")) return -1;
      return cd_follow_advance(flow, res);
    case CD_WORKSPACE_SELECT: {
      char cu[FLOW_URL_LEN] = "";
      if (!cd_expect_ok(flow, res, "workspace/select")) return -1;
      if (cd_copy_json(res->body, "$.continue_url", cu, sizeof(cu)) && cu[0]) {
        cd_make_absolute(CD_AUTH_BASE, cu, st->current_url,
                         sizeof(st->current_url));
      } else if (res->location[0]) {
        cd_make_absolute(CD_AUTH_BASE, res->location, st->current_url,
                         sizeof(st->current_url));
      } else {
        mg_snprintf(st->current_url, sizeof(st->current_url), "%s",
                    st->authorize_url);
      }
      flow->step = CD_FOLLOW;
      return 0;
    }
    case CD_TOKEN:
      if (!cd_expect_ok(flow, res, "token")) return -1;
      return cd_persist_and_finish(flow, res);
    default:
      flow_context_fail(flow, "Codex 直注收到未知步骤响应");
      return -1;
  }
}

static void cd_cleanup(struct flow_context *flow) {
  if (flow == NULL) return;
  free(flow->provider_data);
  flow->provider_data = NULL;
}

static const struct flow_provider s_provider = {
    "codex-direct-signup",
    cd_start,
    cd_next,
    cd_response,
    cd_cleanup,
};

const struct flow_provider *codex_direct_provider(void) { return &s_provider; }
