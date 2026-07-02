#include "registration/chatgpt2api_register_provider.h"

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

#define C2A_AUTH_BASE "https://auth.openai.com"
#define C2A_PLATFORM_BASE "https://platform.openai.com"
#define C2A_SENTINEL_URL "https://sentinel.openai.com/backend-api/sentinel/req"
#define C2A_SENTINEL_ORIGIN "https://sentinel.openai.com"
#define C2A_SENTINEL_VERSION "20260219f9f6"
#define C2A_SENTINEL_REFERER \
  "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=" \
  C2A_SENTINEL_VERSION
#define C2A_CLIENT_ID "app_2SKx67EdpoN0G6j64rFvigXD"
#define C2A_REDIRECT_URI "https://platform.openai.com/auth/callback"
#define C2A_AUDIENCE "https://api.openai.com/v1"
#define C2A_AUTH0_CLIENT "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"
#define C2A_SCOPE "openid profile email offline_access"
#define C2A_OTP_POLL_INTERVAL_MS 2000L
#define C2A_MAX_FOLLOW 15
#define C2A_TOK 8192
#define C2A_NODE_WRAPPER "/app/sentinel/wrapper.js"
#define C2A_NODE_SDK "/app/sentinel/sdk.js"
#define C2A_NODE_SDK_RUNTIME "/app/data/sentinel/sdk.js"
#define C2A_SENTINEL_VER_FILE "/app/data/sentinel/version.txt"
#define C2A_NODE_ADAPTER "/app/sentinel/openai_sentinel_quickjs.js"

enum c2a_step {
  C2A_AUTHORIZE = 0,
  C2A_SENTINEL_REQ,
  C2A_AUTHORIZE_CONTINUE,
  C2A_CREATE_PWD_PAGE,
  C2A_USER_REGISTER,
  C2A_OTP_SEND,
  C2A_OTP_VALIDATE,
  C2A_CREATE_ACCOUNT,
  C2A_FOLLOW,
  C2A_WORKSPACE_SELECT,
  C2A_TOKEN,
  C2A_DONE
};

struct c2a_state {
  int sentinel_next_step;
  char sentinel_flow[48];
  char sdk_version[40];
  char device_id[80];
  char nonce[80];
  char state_param[80];
  char code_verifier[160];
  char code_challenge[96];
  char authorize_url[FLOW_URL_LEN];
  char current_url[FLOW_URL_LEN];
  char callback_url[FLOW_URL_LEN];
  char workspace_id[FLOW_WORKSPACE_ID_LEN];
  char request_p[C2A_TOK];
  char c_token[C2A_TOK];
  char final_p[C2A_TOK];
  char sentinel_t[C2A_TOK];
  char header_sentinel[C2A_TOK * 4];
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

static uint64_t c2a_rand_u64(void) {
  uint64_t v = 0;
  if (!mg_random(&v, sizeof(v))) v = ((uint64_t) rand() << 32) ^ (uint64_t) rand();
  return v;
}

static void c2a_b64url_strip(char *s) {
  for (size_t i = 0; s[i]; i++) {
    if (s[i] == '+') s[i] = '-';
    else if (s[i] == '/') s[i] = '_';
    else if (s[i] == '=') { s[i] = '\0'; break; }
  }
}

static void c2a_b64url_random(char *out, size_t out_len, size_t nbytes) {
  uint8_t raw[96];
  char tmp[160];
  if (nbytes > sizeof(raw)) nbytes = sizeof(raw);
  for (size_t i = 0; i < nbytes; i++) raw[i] = (uint8_t) (c2a_rand_u64() & 0xff);
  mg_base64_encode(raw, nbytes, tmp, sizeof(tmp));
  c2a_b64url_strip(tmp);
  mg_snprintf(out, out_len, "%s", tmp);
}

/* RFC 4122 v4 style UUID (lowercase hex). chatgpt2api authorize needs a
 * device_id query param up-front, so it is generated in start (unlike the
 * codex flow which harvests oai-did from the authorize response). */
static void c2a_uuid(char *out, size_t len) {
  static const char hex[] = "0123456789abcdef";
  uint8_t b[16];
  char buf[37];
  int pos = 0;
  if (len == 0) return;
  out[0] = '\0';
  for (size_t i = 0; i < sizeof(b); i++) b[i] = (uint8_t) (c2a_rand_u64() & 0xff);
  b[6] = (uint8_t) ((b[6] & 0x0f) | 0x40); /* version 4 */
  b[8] = (uint8_t) ((b[8] & 0x3f) | 0x80); /* variant 10x */
  for (int i = 0; i < 16; i++) {
    buf[pos++] = hex[(b[i] >> 4) & 0x0f];
    buf[pos++] = hex[b[i] & 0x0f];
    if (i == 3 || i == 5 || i == 7 || i == 9) buf[pos++] = '-';
  }
  buf[pos] = '\0';
  mg_snprintf(out, len, "%s", buf);
}

static void c2a_make_challenge(const char *verifier, char *out, size_t out_len) {
  uint8_t digest[32];
  if (out_len == 0) return;
  out[0] = '\0';
  mg_sha256(digest, (uint8_t *) verifier, strlen(verifier));
  mg_base64_encode(digest, sizeof(digest), out, out_len);
  c2a_b64url_strip(out);
}

static void c2a_set_header(struct c2a_state *st, const char *name,
                           const char *value) {
  if (st->num_headers >= sizeof(st->headers) / sizeof(st->headers[0])) return;
  if (name == NULL || value == NULL || value[0] == '\0') return;
  st->headers[st->num_headers].name = name;
  st->headers[st->num_headers].value = value;
  st->num_headers++;
}

static void c2a_make_absolute(const char *base, const char *loc, char *out,
                              size_t out_len) {
  if (out_len == 0) return;
  out[0] = '\0';
  if (loc == NULL || loc[0] == '\0') return;
  if (strncmp(loc, "http://", 7) == 0 || strncmp(loc, "https://", 8) == 0) {
    mg_snprintf(out, out_len, "%s", loc);
  } else if (loc[0] == '/') {
    mg_snprintf(out, out_len, "%s%s", base ? base : C2A_AUTH_BASE, loc);
  } else {
    mg_snprintf(out, out_len, "%s/%s", base ? base : C2A_AUTH_BASE, loc);
  }
}

static bool c2a_query_value(const char *url, const char *name, char *out,
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

static bool c2a_copy_json(const char *json, const char *path, char *out,
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

static bool c2a_extract_workspace_id(const char *text, char *out,
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

static bool c2a_has(const char *s, const char *needle) {
  return s != NULL && needle != NULL && strstr(s, needle) != NULL;
}

/* Decode a JWT payload segment (base64url) into a JSON string.
 * Ported verbatim from codex_session_oauth.c so id_token claims can be mined
 * for chatgpt_account_id / chatgpt_workspace_id / email. */
static bool c2a_decode_jwt_payload(const char *token, char *out, size_t out_len) {
  const char *p1;
  const char *p2;
  char b64[4096];
  size_t len;

  if (out == NULL || out_len == 0) return false;
  out[0] = '\0';
  if (token == NULL) return false;
  p1 = strchr(token, '.');
  if (p1 == NULL) return false;
  p2 = strchr(p1 + 1, '.');
  if (p2 == NULL || p2 <= p1 + 1) return false;
  len = (size_t) (p2 - p1 - 1);
  if (len + 4 >= sizeof(b64)) return false;
  memcpy(b64, p1 + 1, len);
  for (size_t i = 0; i < len; i++) {
    if (b64[i] == '-') b64[i] = '+';
    else if (b64[i] == '_') b64[i] = '/';
  }
  while (len % 4 != 0) b64[len++] = '=';
  b64[len] = '\0';
  len = mg_base64_decode(b64, len, out, out_len - 1);
  if (len == 0) return false;
  out[len] = '\0';
  return true;
}

/* ---------- node sentinel compute (fork node wrapper) ---------- */

static int c2a_write_all(int fd, const char *buf, size_t len) {
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
static int c2a_node_run(const char *payload, size_t payload_len, char *out,
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
           access(C2A_NODE_SDK_RUNTIME, R_OK) == 0 ? C2A_NODE_SDK_RUNTIME
                                                   : C2A_NODE_SDK,
           1);
    setenv("OPENAI_SENTINEL_QUICKJS_SCRIPT", C2A_NODE_ADAPTER, 1);
    mg_snprintf(tbuf, sizeof(tbuf), "%ld", timeout_ms > 0 ? timeout_ms : 15000);
    setenv("OPENAI_SENTINEL_VM_TIMEOUT_MS", tbuf, 1);
    execlp("node", "node", C2A_NODE_WRAPPER, (char *) NULL);
    _exit(127);
  }
  close(inpipe[0]);
  close(outpipe[1]);
  c2a_write_all(inpipe[1], payload, payload_len);
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
static int c2a_node_requirements(struct flow_context *flow,
                                 struct c2a_state *st) {
  char payload[256];
  char result[C2A_TOK];
  mg_snprintf(payload, sizeof(payload), "{\"action\":\"requirements\",\"device_id\":\"%s\"}",
              st->device_id);
  if (c2a_node_run(payload, strlen(payload), result, sizeof(result), 15000) != 0) {
    flow_context_fail(flow, "sentinel requirements (node) 失败");
    return -1;
  }
  if (!c2a_copy_json(result, "$.request_p", st->request_p,
                     sizeof(st->request_p)) || st->request_p[0] == '\0') {
    flow_context_fail(flow, "sentinel requirements 未返回 request_p");
    return -1;
  }
  return 0;
}

/* node solve(challenge) -> final_p + t (pure compute, no network) */
static int c2a_node_solve(struct flow_context *flow, struct c2a_state *st,
                          const char *challenge_json) {
  size_t cap = strlen(challenge_json) + strlen(st->request_p) +
               strlen(st->device_id) + 128;
  char *payload = (char *) malloc(cap);
  char result[C2A_TOK * 3];
  int rc;
  if (payload == NULL) {
    flow_context_fail(flow, "sentinel solve 内存不足");
    return -1;
  }
  mg_snprintf(payload, cap,
              "{\"action\":\"solve\",\"device_id\":\"%s\",\"request_p\":\"%s\","
              "\"challenge\":%s}",
              st->device_id, st->request_p, challenge_json);
  rc = c2a_node_run(payload, strlen(payload), result, sizeof(result), 20000);
  free(payload);
  if (rc != 0) {
    flow_context_fail(flow, "sentinel solve (node) 失败");
    return -1;
  }
  if (!c2a_copy_json(result, "$.final_p", st->final_p, sizeof(st->final_p))) {
    c2a_copy_json(result, "$.p", st->final_p, sizeof(st->final_p));
  }
  c2a_copy_json(result, "$.t", st->sentinel_t, sizeof(st->sentinel_t));
  if (st->final_p[0] == '\0') {
    flow_context_fail(flow, "sentinel solve 未返回 final_p");
    return -1;
  }
  return 0;
}

/* ---------- request builders ---------- */

static void c2a_nav_get(struct c2a_state *st, struct flow_http_request *req,
                        const char *url, const char *referer, bool follow) {
  st->num_headers = 0;
  mg_snprintf(st->hbuf_accept, sizeof(st->hbuf_accept),
              "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,*/*;q=0.8");
  mg_snprintf(st->hbuf_referer, sizeof(st->hbuf_referer), "%s",
              referer ? referer : C2A_PLATFORM_BASE "/");
  c2a_set_header(st, "Accept", st->hbuf_accept);
  c2a_set_header(st, "Referer", st->hbuf_referer);
  c2a_set_header(st, "Sec-Fetch-Dest", "document");
  c2a_set_header(st, "Sec-Fetch-Mode", "navigate");
  c2a_set_header(st, "Upgrade-Insecure-Requests", "1");
  memset(req, 0, sizeof(*req));
  req->method = "GET";
  req->url = url;
  req->timeout_ms = 30000;
  req->follow_location = follow;
  req->headers = st->headers;
  req->num_headers = st->num_headers;
}

static void c2a_json_post(struct c2a_state *st, struct flow_http_request *req,
                          const char *url, const char *body, const char *referer,
                          const char *sentinel_header) {
  st->num_headers = 0;
  mg_snprintf(st->hbuf_origin, sizeof(st->hbuf_origin), "%s", C2A_AUTH_BASE);
  mg_snprintf(st->hbuf_referer, sizeof(st->hbuf_referer), "%s",
              referer ? referer : C2A_PLATFORM_BASE "/");
  c2a_set_header(st, "Accept", "application/json");
  c2a_set_header(st, "Content-Type", "application/json");
  c2a_set_header(st, "Origin", st->hbuf_origin);
  c2a_set_header(st, "Referer", st->hbuf_referer);
  c2a_set_header(st, "Sec-Fetch-Dest", "empty");
  c2a_set_header(st, "Sec-Fetch-Mode", "cors");
  c2a_set_header(st, "Sec-Fetch-Site", "same-origin");
  if (sentinel_header != NULL && sentinel_header[0] != '\0') {
    c2a_set_header(st, "OpenAI-Sentinel-Token", sentinel_header);
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

static void c2a_sentinel_post(struct c2a_state *st,
                              struct flow_http_request *req) {
  st->num_headers = 0;
  mg_snprintf(st->body, sizeof(st->body),
              "{\"p\":\"%s\",\"id\":\"%s\",\"flow\":\"%s\"}", st->request_p,
              st->device_id, st->sentinel_flow);
  mg_snprintf(st->hbuf_origin, sizeof(st->hbuf_origin), "%s",
              C2A_SENTINEL_ORIGIN);
  mg_snprintf(st->hbuf_referer, sizeof(st->hbuf_referer),
              "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=%s",
              st->sdk_version[0] ? st->sdk_version : C2A_SENTINEL_VERSION);
  c2a_set_header(st, "Accept", "*/*");
  c2a_set_header(st, "Content-Type", "text/plain;charset=UTF-8");
  c2a_set_header(st, "Origin", st->hbuf_origin);
  c2a_set_header(st, "Referer", st->hbuf_referer);
  c2a_set_header(st, "Sec-Fetch-Dest", "empty");
  c2a_set_header(st, "Sec-Fetch-Mode", "cors");
  c2a_set_header(st, "Sec-Fetch-Site", "same-origin");
  memset(req, 0, sizeof(*req));
  req->method = "POST";
  req->url = C2A_SENTINEL_URL;
  req->body = st->body;
  req->body_len = strlen(st->body);
  req->timeout_ms = 30000;
  req->follow_location = false;
  req->headers = st->headers;
  req->num_headers = st->num_headers;
}

static void c2a_build_sentinel_header(struct c2a_state *st) {
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
static int c2a_begin_sentinel(struct flow_context *flow, struct c2a_state *st,
                              const char *sentinel_flow, int next_step) {
  mg_snprintf(st->sentinel_flow, sizeof(st->sentinel_flow), "%s", sentinel_flow);
  st->sentinel_next_step = next_step;
  st->request_p[0] = st->c_token[0] = st->final_p[0] = st->sentinel_t[0] = '\0';
  if (c2a_node_requirements(flow, st) != 0) return -1;
  flow->step = C2A_SENTINEL_REQ;
  flow_context_log(flow, "info", "sentinel %s: requirements ok (%dB)",
                   sentinel_flow, (int) strlen(st->request_p));
  return 0;
}

/* ---------- provider callbacks ---------- */

static int c2a_start(struct flow_context *flow) {
  struct c2a_state *st = (struct c2a_state *) calloc(1, sizeof(*st));
  char aud_enc[128];
  char redirect_enc[160];
  char email_enc[256];
  char scope_enc[160];
  if (st == NULL) return -1;
  flow->provider_data = st;
  flow->step = C2A_AUTHORIZE;
  if (flow->deadline_ms <= 0) flow->deadline_ms = (long) mg_millis() + 240000;

  /* sentinel 版本：优先用 entrypoint 启动时发现并写入数据卷的版本 */
  mg_snprintf(st->sdk_version, sizeof(st->sdk_version), "%s", C2A_SENTINEL_VERSION);
  {
    FILE *vf = fopen(C2A_SENTINEL_VER_FILE, "r");
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

  /* chatgpt2api 的 authorize URL 需要 device_id/nonce 作查询参数，必须提前生成 */
  c2a_uuid(st->device_id, sizeof(st->device_id));
  c2a_b64url_random(st->nonce, sizeof(st->nonce), 24);
  c2a_b64url_random(st->state_param, sizeof(st->state_param), 24);
  c2a_b64url_random(st->code_verifier, sizeof(st->code_verifier), 64);
  c2a_make_challenge(st->code_verifier, st->code_challenge,
                     sizeof(st->code_challenge));
  mg_snprintf(flow->pkce_code_verifier, sizeof(flow->pkce_code_verifier), "%s",
              st->code_verifier);
  mg_url_encode(C2A_AUDIENCE, strlen(C2A_AUDIENCE), aud_enc, sizeof(aud_enc));
  mg_url_encode(C2A_REDIRECT_URI, strlen(C2A_REDIRECT_URI), redirect_enc,
                sizeof(redirect_enc));
  mg_url_encode(flow->identity.email, strlen(flow->identity.email), email_enc,
                sizeof(email_enc));
  mg_url_encode(C2A_SCOPE, strlen(C2A_SCOPE), scope_enc, sizeof(scope_enc));
  mg_snprintf(st->authorize_url, sizeof(st->authorize_url),
              C2A_AUTH_BASE "/api/accounts/authorize?issuer=" C2A_AUTH_BASE
              "&client_id=" C2A_CLIENT_ID
              "&audience=%s&redirect_uri=%s&device_id=%s&screen_hint=signup"
              "&max_age=0&login_hint=%s&scope=%s&response_type=code"
              "&response_mode=query&state=%s&nonce=%s&code_challenge=%s"
              "&code_challenge_method=S256&auth0Client=" C2A_AUTH0_CLIENT,
              aud_enc, redirect_enc, st->device_id, email_enc, scope_enc,
              st->state_param, st->nonce, st->code_challenge);
  flow_context_log(flow, "info", "chatgpt2api 注册(node-sentinel): 邮箱 %s",
                   flow->identity.email);
  return 0;
}

static enum flow_provider_action c2a_otp_request(struct flow_context *flow,
                                                 struct flow_http_request *req) {
  struct c2a_state *st = (struct c2a_state *) flow->provider_data;
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
    flow->next_retry_ms = now + C2A_OTP_POLL_INTERVAL_MS;
    return FLOW_PROVIDER_WAIT;
  }
  mg_snprintf(st->body, sizeof(st->body), "{\"code\":\"%s\"}", st->otp_code);
  c2a_json_post(st, req, C2A_AUTH_BASE "/api/accounts/email-otp/validate",
                st->body, C2A_AUTH_BASE "/create-account/password", NULL);
  flow_context_log(flow, "info", "验证码已获取，提交邮箱验证");
  return FLOW_PROVIDER_REQUEST;
}

static enum flow_provider_action c2a_next(struct flow_context *flow,
                                          struct flow_http_request *req) {
  struct c2a_state *st = (struct c2a_state *) flow->provider_data;
  if (st == NULL) {
    flow_context_fail(flow, "chatgpt2api 注册状态丢失");
    return FLOW_PROVIDER_FAILED;
  }
  switch (flow->step) {
    case C2A_AUTHORIZE:
      c2a_nav_get(st, req, st->authorize_url, C2A_PLATFORM_BASE "/", true);
      flow_context_log(flow, "info", "步骤 authorize: 打开 chatgpt2api 授权入口");
      return FLOW_PROVIDER_REQUEST;
    case C2A_SENTINEL_REQ:
      c2a_sentinel_post(st, req);
      flow_context_log(flow, "info", "步骤 sentinel/req: %s", st->sentinel_flow);
      return FLOW_PROVIDER_REQUEST;
    case C2A_AUTHORIZE_CONTINUE:
      mg_snprintf(st->body, sizeof(st->body),
                  "{\"username\":{\"value\":\"%s\",\"kind\":\"email\"},"
                  "\"screen_hint\":\"signup\"}",
                  flow->identity.email);
      c2a_json_post(st, req, C2A_AUTH_BASE "/api/accounts/authorize/continue",
                    st->body, C2A_AUTH_BASE "/create-account",
                    st->header_sentinel);
      flow_context_log(flow, "info", "步骤 authorize/continue: 提交邮箱(注册)");
      return FLOW_PROVIDER_REQUEST;
    case C2A_CREATE_PWD_PAGE:
      c2a_nav_get(st, req, C2A_AUTH_BASE "/create-account/password",
                  C2A_AUTH_BASE "/create-account", false);
      return FLOW_PROVIDER_REQUEST;
    case C2A_USER_REGISTER:
      mg_snprintf(st->body, sizeof(st->body),
                  "{\"password\":\"%s\",\"username\":\"%s\"}",
                  flow->identity.password, flow->identity.email);
      c2a_json_post(st, req, C2A_AUTH_BASE "/api/accounts/user/register",
                    st->body, C2A_AUTH_BASE "/create-account/password",
                    st->header_sentinel);
      flow_context_log(flow, "info", "步骤 user/register: 设置密码");
      return FLOW_PROVIDER_REQUEST;
    case C2A_OTP_SEND:
      st->otp_sent_epoch = (long) time(NULL);
      c2a_nav_get(st, req, C2A_AUTH_BASE "/api/accounts/email-otp/send",
                  C2A_AUTH_BASE "/create-account/password", false);
      req->method = "GET";
      flow_context_log(flow, "info", "步骤 email-otp/send: 触发验证码");
      flow_context_emit_event(flow, FLOW_EVENT_EMAIL_OTP_WAITING);
      return FLOW_PROVIDER_REQUEST;
    case C2A_OTP_VALIDATE:
      return c2a_otp_request(flow, req);
    case C2A_CREATE_ACCOUNT:
      mg_snprintf(st->body, sizeof(st->body),
                  "{\"name\":\"%s\",\"birthdate\":\"%s\"}",
                  flow->identity.full_name, flow->identity.birthdate);
      c2a_json_post(st, req, C2A_AUTH_BASE "/api/accounts/create_account",
                    st->body, C2A_AUTH_BASE "/about-you", st->header_sentinel);
      flow_context_log(flow, "info", "步骤 create_account: %s / %s",
                       flow->identity.full_name, flow->identity.birthdate);
      return FLOW_PROVIDER_REQUEST;
    case C2A_FOLLOW:
      c2a_nav_get(st, req, st->current_url, C2A_PLATFORM_BASE "/", false);
      flow_context_log(flow, "info", "步骤 follow %d/%d", st->redirect_count + 1,
                       C2A_MAX_FOLLOW);
      return FLOW_PROVIDER_REQUEST;
    case C2A_WORKSPACE_SELECT:
      mg_snprintf(st->body, sizeof(st->body), "{\"workspace_id\":\"%s\"}",
                  st->workspace_id);
      c2a_json_post(st, req, C2A_AUTH_BASE "/api/accounts/workspace/select",
                    st->body,
                    C2A_AUTH_BASE "/sign-in-with-chatgpt/codex/consent", NULL);
      flow_context_log(flow, "info", "步骤 workspace/select: %s",
                       st->workspace_id);
      return FLOW_PROVIDER_REQUEST;
    case C2A_TOKEN: {
      char code[FLOW_CODE_LEN] = "";
      c2a_query_value(st->callback_url, "code", code, sizeof(code));
      mg_snprintf(st->body, sizeof(st->body),
                  "{\"client_id\":\"" C2A_CLIENT_ID "\",\"code_verifier\":\"%s\","
                  "\"grant_type\":\"authorization_code\",\"code\":\"%s\","
                  "\"redirect_uri\":\"" C2A_REDIRECT_URI "\"}",
                  flow->pkce_code_verifier, code);
      c2a_json_post(st, req, C2A_AUTH_BASE "/api/accounts/oauth/token",
                    st->body, C2A_PLATFORM_BASE "/", NULL);
      flow_context_log(flow, "info", "步骤 token: 使用授权码换取 Token");
      return FLOW_PROVIDER_REQUEST;
    }
    case C2A_DONE:
      return FLOW_PROVIDER_DONE;
    default:
      flow_context_fail(flow, "chatgpt2api 注册未知步骤");
      return FLOW_PROVIDER_FAILED;
  }
}

static bool c2a_expect_ok(struct flow_context *flow,
                          const struct flow_http_response *res,
                          const char *label) {
  if (res->status_code >= 200 && res->status_code < 400) return true;
  if (flow_response_is_email_already_registered(res)) {
    flow_context_mark_identity_retry(flow, "邮箱已被注册，换邮箱重试");
  } else if (flow_response_is_edge_block(res)) {
    flow_context_mark_environment_retry(flow, "边缘风控拦截，换环境重试");
  } else {
    flow_context_fail(flow, "chatgpt2api 注册请求返回非成功状态");
  }
  {
    char code[96] = "";
    c2a_copy_json(res->body, "$.error.code", code, sizeof(code));
    flow_context_log(flow, "error", "%s 失败: HTTP %ld code=%s body=%.300s",
                     label, res->status_code, code[0] ? code : "-",
                     res->body ? res->body : "");
  }
  return false;
}

static int c2a_persist_and_finish(struct flow_context *flow,
                                  const struct flow_http_response *res) {
  struct c2a_state *st = (struct c2a_state *) flow->provider_data;
  struct mg_str json = mg_str_n(res->body ? res->body : "", res->body_len);
  char *at = mg_json_get_str(json, "$.access_token");
  char *rt = mg_json_get_str(json, "$.refresh_token");
  char *it = mg_json_get_str(json, "$.id_token");
  char payload[8192];
  int rc = -1;

  if (at == NULL || at[0] == '\0') {
    flow_context_fail(flow, "chatgpt2api token 交换未返回 access_token");
    goto done;
  }
  mg_snprintf(flow->access_token, sizeof(flow->access_token), "%s", at);
  mg_snprintf(flow->refresh_token, sizeof(flow->refresh_token), "%s",
              rt ? rt : "");
  mg_snprintf(flow->id_token, sizeof(flow->id_token), "%s", it ? it : "");

  /* JWT 增强：尽量填满 external_account_id / workspace_id（Aether 上传所需）。
     照搬 codex_session_oauth.c 的解析顺序：响应 JSON -> id_token 声明 ->
     create_account 阶段 st->workspace_id 兜底。 */
  if (flow->external_account_id[0] == '\0') {
    c2a_copy_json(res->body, "$.account_id", flow->external_account_id,
                  sizeof(flow->external_account_id));
  }
  if (flow->workspace_id[0] == '\0') {
    c2a_copy_json(res->body, "$.workspace_id", flow->workspace_id,
                  sizeof(flow->workspace_id));
  }
  if (it != NULL && c2a_decode_jwt_payload(it, payload, sizeof(payload))) {
    if (flow->identity.email[0] == '\0') {
      c2a_copy_json(payload, "$.email", flow->identity.email,
                    sizeof(flow->identity.email));
    }
    if (flow->external_account_id[0] == '\0') {
      c2a_copy_json(payload, "$.chatgpt_account_id", flow->external_account_id,
                    sizeof(flow->external_account_id));
    }
    if (flow->workspace_id[0] == '\0') {
      if (!c2a_copy_json(payload, "$.chatgpt_workspace_id", flow->workspace_id,
                         sizeof(flow->workspace_id))) {
        c2a_copy_json(payload, "$.workspace_id", flow->workspace_id,
                      sizeof(flow->workspace_id));
      }
    }
  }
  if (flow->workspace_id[0] == '\0' && st->workspace_id[0] != '\0') {
    mg_snprintf(flow->workspace_id, sizeof(flow->workspace_id), "%s",
                st->workspace_id);
  }
  /* 不在此自行落库：返回 DONE 后由 flow 引擎的 persist_success 统一写入
     （它用 success_account_status + 上面这些 token 字段）。自行 insert 会与
     引擎重复写、触发 email 唯一约束失败。 */
  mg_snprintf(flow->success_account_status, sizeof(flow->success_account_status),
              "active");
  mg_snprintf(flow->success_auth_source, sizeof(flow->success_auth_source),
              "chatgpt2api");
  flow_context_log(flow, "info",
                   "chatgpt2api 注册完成: access=%dB refresh=%s id=%s account=%s "
                   "workspace=%s",
                   (int) strlen(flow->access_token),
                   flow->refresh_token[0] ? "yes" : "no",
                   flow->id_token[0] ? "yes" : "no",
                   flow->external_account_id[0] ? flow->external_account_id : "-",
                   flow->workspace_id[0] ? flow->workspace_id : "-");
  flow->step = C2A_DONE;
  rc = 0;
done:
  mg_free(at);
  mg_free(rt);
  mg_free(it);
  return rc;
}

static int c2a_follow_advance(struct flow_context *flow,
                              const struct flow_http_response *res) {
  struct c2a_state *st = (struct c2a_state *) flow->provider_data;
  char code[FLOW_CODE_LEN] = "";
  char nextu[FLOW_URL_LEN] = "";

  if (c2a_query_value(res->location, "code", code, sizeof(code)) ||
      c2a_query_value(res->effective_url, "code", code, sizeof(code)) ||
      c2a_query_value(st->current_url, "code", code, sizeof(code))) {
    if (res->location[0] && c2a_has(res->location, "code=")) {
      mg_snprintf(st->callback_url, sizeof(st->callback_url), "%s",
                  res->location);
    } else if (c2a_has(st->current_url, "code=")) {
      mg_snprintf(st->callback_url, sizeof(st->callback_url), "%s",
                  st->current_url);
    } else {
      mg_snprintf(st->callback_url, sizeof(st->callback_url), "%s",
                  res->effective_url);
    }
    flow->step = C2A_TOKEN;
    return 0;
  }
  if (res->status_code >= 300 && res->status_code < 400 &&
      res->location[0] != '\0') {
    c2a_make_absolute(C2A_AUTH_BASE, res->location, st->current_url,
                      sizeof(st->current_url));
    if (++st->redirect_count > C2A_MAX_FOLLOW) {
      flow_context_fail(flow, "chatgpt2api 注册重定向链超过上限");
      return -1;
    }
    flow->step = C2A_FOLLOW;
    return 0;
  }
  if (!st->workspace_selected && st->workspace_id[0] &&
      (c2a_has(st->current_url, "/consent") ||
       c2a_has(st->current_url, "/organization") ||
       c2a_has(res->body, "workspace/select") ||
       c2a_has(res->effective_url, "/consent"))) {
    st->workspace_selected = true;
    flow->step = C2A_WORKSPACE_SELECT;
    return 0;
  }
  if (c2a_copy_json(res->body, "$.continue_url", nextu, sizeof(nextu)) &&
      nextu[0]) {
    c2a_make_absolute(C2A_AUTH_BASE, nextu, st->current_url,
                      sizeof(st->current_url));
    if (++st->redirect_count > C2A_MAX_FOLLOW) {
      flow_context_fail(flow, "chatgpt2api 注册重定向链超过上限");
      return -1;
    }
    flow->step = C2A_FOLLOW;
    return 0;
  }
  flow_context_fail(flow, "chatgpt2api 注册重定向链未返回下一跳");
  return -1;
}

static int c2a_response(struct flow_context *flow,
                        const struct flow_http_response *res) {
  struct c2a_state *st = (struct c2a_state *) flow->provider_data;
  if (st == NULL || res == NULL) {
    flow_context_fail(flow, "chatgpt2api 注册响应丢失");
    return -1;
  }

  switch (flow->step) {
    case C2A_AUTHORIZE:
      if (res->device_id[0]) {
        mg_snprintf(st->device_id, sizeof(st->device_id), "%s", res->device_id);
      } else if (st->device_id[0] == '\0') {
        c2a_uuid(st->device_id, sizeof(st->device_id));
      }
      flow_context_log(flow, "info", "authorize: device_id=%s (%s) http=%ld",
                       st->device_id,
                       res->device_id[0] ? "oai-did" : "start-uuid",
                       res->status_code);
      return c2a_begin_sentinel(flow, st, "authorize_continue",
                                C2A_AUTHORIZE_CONTINUE);
    case C2A_SENTINEL_REQ:
      if (!c2a_expect_ok(flow, res, "sentinel/req")) return -1;
      if (!c2a_copy_json(res->body, "$.token", st->c_token,
                         sizeof(st->c_token))) {
        flow_context_fail(flow, "sentinel/req 未返回 token");
        return -1;
      }
      if (c2a_node_solve(flow, st, res->body) != 0) return -1;
      c2a_build_sentinel_header(st);
      flow_context_log(flow, "info",
                       "sentinel %s: solve ok (p=%dB t=%dB c=%dB)",
                       st->sentinel_flow, (int) strlen(st->final_p),
                       (int) strlen(st->sentinel_t), (int) strlen(st->c_token));
      flow->step = st->sentinel_next_step;
      return 0;
    case C2A_AUTHORIZE_CONTINUE: {
      char pt[64] = "", cu[FLOW_URL_LEN] = "";
      if (!c2a_expect_ok(flow, res, "authorize/continue")) return -1;
      c2a_copy_json(res->body, "$.page.type", pt, sizeof(pt));
      c2a_copy_json(res->body, "$.continue_url", cu, sizeof(cu));
      st->is_new_account = strcmp(pt, "create_account_password") == 0 ||
                           c2a_has(cu, "/create-account/password");
      flow->step = st->is_new_account ? C2A_CREATE_PWD_PAGE : C2A_OTP_SEND;
      return 0;
    }
    case C2A_CREATE_PWD_PAGE:
      return c2a_begin_sentinel(flow, st, "username_password_create",
                                C2A_USER_REGISTER);
    case C2A_USER_REGISTER:
      if (!c2a_expect_ok(flow, res, "user/register")) return -1;
      flow->step = C2A_OTP_SEND;
      return 0;
    case C2A_OTP_SEND:
      flow->next_retry_ms = (long) mg_millis() + C2A_OTP_POLL_INTERVAL_MS;
      flow->step = C2A_OTP_VALIDATE;
      return 0;
    case C2A_OTP_VALIDATE:
      if (!c2a_expect_ok(flow, res, "email-otp/validate")) return -1;
      flow_context_emit_event(flow, FLOW_EVENT_EMAIL_OTP_VALIDATED);
      return c2a_begin_sentinel(flow, st, "create_account", C2A_CREATE_ACCOUNT);
    case C2A_CREATE_ACCOUNT: {
      char cu[FLOW_URL_LEN] = "";
      if (!c2a_expect_ok(flow, res, "create_account")) return -1;
      c2a_extract_workspace_id(res->body, st->workspace_id,
                               sizeof(st->workspace_id));
      if (!c2a_copy_json(res->body, "$.continue_url", cu, sizeof(cu)) ||
          cu[0] == '\0') {
        flow_context_fail(flow, "create_account 未返回 continue_url");
        return -1;
      }
      c2a_make_absolute(C2A_AUTH_BASE, cu, st->current_url,
                        sizeof(st->current_url));
      st->redirect_count = 0;
      flow_context_log(flow, "info", "create_account 完成, workspace=%s",
                       st->workspace_id[0] ? st->workspace_id : "-");
      flow->step = C2A_FOLLOW;
      return 0;
    }
    case C2A_FOLLOW:
      if (!c2a_expect_ok(flow, res, "follow")) return -1;
      return c2a_follow_advance(flow, res);
    case C2A_WORKSPACE_SELECT: {
      char cu[FLOW_URL_LEN] = "";
      if (!c2a_expect_ok(flow, res, "workspace/select")) return -1;
      if (c2a_copy_json(res->body, "$.continue_url", cu, sizeof(cu)) && cu[0]) {
        c2a_make_absolute(C2A_AUTH_BASE, cu, st->current_url,
                          sizeof(st->current_url));
      } else if (res->location[0]) {
        c2a_make_absolute(C2A_AUTH_BASE, res->location, st->current_url,
                          sizeof(st->current_url));
      } else {
        mg_snprintf(st->current_url, sizeof(st->current_url), "%s",
                    st->authorize_url);
      }
      flow->step = C2A_FOLLOW;
      return 0;
    }
    case C2A_TOKEN:
      if (!c2a_expect_ok(flow, res, "token")) return -1;
      return c2a_persist_and_finish(flow, res);
    default:
      flow_context_fail(flow, "chatgpt2api 注册收到未知步骤响应");
      return -1;
  }
}

static void c2a_cleanup(struct flow_context *flow) {
  if (flow == NULL) return;
  free(flow->provider_data);
  flow->provider_data = NULL;
}

static const struct flow_provider s_provider = {
    "chatgpt2api-register",
    c2a_start,
    c2a_next,
    c2a_response,
    c2a_cleanup,
};

const struct flow_provider *chatgpt2api_register_provider(void) {
  return &s_provider;
}
