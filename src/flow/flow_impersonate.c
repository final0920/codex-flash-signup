#include "flow/flow_impersonate.h"

#include "account/account_store.h"
#include "mongoose.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define IMP_ARG_MAX 256
#define IMP_PATH_LEN 512
#define IMP_REQUEST_MAX_RETRIES 3

struct impersonate_workspace {
  char dir[IMP_PATH_LEN];
  char cookie_file[IMP_PATH_LEN];
  char body_file[IMP_PATH_LEN];
  char header_file[IMP_PATH_LEN];
  char meta_file[IMP_PATH_LEN];
  char stderr_file[IMP_PATH_LEN];
  char request_body_file[IMP_PATH_LEN];
};

static void generate_flow_id(char *out, size_t out_len) {
  uint64_t seed = 0;
  if (out_len == 0) return;
  if (!mg_random(&seed, sizeof(seed))) seed = (uint64_t) time(NULL);
  mg_snprintf(out, out_len, "flow-%llx", (unsigned long long) seed);
}

static void sanitized_url(const char *url, char *out, size_t out_len) {
  const char *q;
  size_t len;
  if (out_len == 0) return;
  out[0] = '\0';
  if (url == NULL || url[0] == '\0') return;
  q = strchr(url, '?');
  len = q == NULL ? strlen(url) : (size_t) (q - url);
  if (len >= out_len) len = out_len - 1;
  memcpy(out, url, len);
  out[len] = '\0';
  if (q != NULL && len + 4 < out_len) {
    strncat(out, "?...", out_len - strlen(out) - 1);
  }
}

static void proxy_scheme_label(const char *proxy_url, char *out, size_t out_len) {
  const char *p;
  size_t len;
  if (out_len == 0) return;
  out[0] = '\0';
  if (proxy_url == NULL || proxy_url[0] == '\0') {
    mg_snprintf(out, out_len, "direct");
    return;
  }
  p = strstr(proxy_url, "://");
  if (p == NULL) {
    mg_snprintf(out, out_len, "proxy");
    return;
  }
  len = (size_t) (p - proxy_url);
  if (len >= out_len) len = out_len - 1;
  memcpy(out, proxy_url, len);
  out[len] = '\0';
}

static int persist_success(sqlite3 *db, struct flow_context *flow) {
  struct account_success_record record;
  if (db == NULL || flow == NULL || !flow->persist_on_success) return 0;
  memset(&record, 0, sizeof(record));
  record.email = flow->identity.email;
  record.password = flow->identity.password;
  record.status = flow->success_account_status[0] ? flow->success_account_status : "temp";
  record.upload_state = "not_uploaded";
  record.access_token = flow->access_token;
  record.refresh_token = flow->refresh_token;
  record.id_token = flow->id_token;
  record.session_token = flow->session_token;
  record.cookies = flow->cookies;
  record.external_account_id = flow->external_account_id;
  record.workspace_id = flow->workspace_id;
  if (account_insert_success(db, &record, &flow->persisted_account_id) != 0) {
    flow_context_fail(flow, "成功结果写入账号库失败");
    return -1;
  }
  return 0;
}

int flow_impersonate_available(char *path, size_t path_len) {
  const char *env = getenv("CURL_IMPERSONATE_BIN");
  static const char *candidates[] = {
      "/usr/local/bin/curl_chrome145",
      "/usr/bin/curl_chrome145",
      "curl_chrome145",
      "curl_chrome146",
      "curl_chrome142",
      "curl-impersonate",
  };

  if (path_len > 0) path[0] = '\0';
  if (env != NULL && env[0] != '\0' && access(env, X_OK) == 0) {
    if (path != NULL && path_len > 0) mg_snprintf(path, path_len, "%s", env);
    return 0;
  }
  for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
    const char *candidate = candidates[i];
    if (strchr(candidate, '/') != NULL) {
      if (access(candidate, X_OK) == 0) {
        if (path != NULL && path_len > 0) {
          mg_snprintf(path, path_len, "%s", candidate);
        }
        return 0;
      }
    } else {
      char command[IMP_PATH_LEN];
      int rc;
      mg_snprintf(command, sizeof(command), "command -v %s >/dev/null 2>&1",
                  candidate);
      rc = system(command);
      if (rc == 0) {
        if (path != NULL && path_len > 0) {
          mg_snprintf(path, path_len, "%s", candidate);
        }
        return 0;
      }
    }
  }
  return -1;
}

static int create_workspace(const char *flow_id, struct impersonate_workspace *ws) {
  if (ws == NULL) return -1;
  memset(ws, 0, sizeof(*ws));
  if (mkdir("tmp", 0700) != 0 && errno != EEXIST) return -1;
  if (mkdir("tmp/registration", 0700) != 0 && errno != EEXIST) return -1;
  mg_snprintf(ws->dir, sizeof(ws->dir), "tmp/registration/%s", flow_id);
  if (mkdir(ws->dir, 0700) != 0 && errno != EEXIST) return -1;
  mg_snprintf(ws->cookie_file, sizeof(ws->cookie_file), "%s/cookies.txt", ws->dir);
  mg_snprintf(ws->body_file, sizeof(ws->body_file), "%s/body.bin", ws->dir);
  mg_snprintf(ws->header_file, sizeof(ws->header_file), "%s/headers.txt", ws->dir);
  mg_snprintf(ws->meta_file, sizeof(ws->meta_file), "%s/meta.txt", ws->dir);
  mg_snprintf(ws->stderr_file, sizeof(ws->stderr_file), "%s/stderr.txt", ws->dir);
  mg_snprintf(ws->request_body_file, sizeof(ws->request_body_file),
              "%s/request-body.bin", ws->dir);
  return 0;
}

static void cleanup_workspace(const struct impersonate_workspace *ws) {
  if (ws == NULL || ws->dir[0] == '\0') return;
  unlink(ws->body_file);
  unlink(ws->header_file);
  unlink(ws->meta_file);
  unlink(ws->stderr_file);
  unlink(ws->request_body_file);
  unlink(ws->cookie_file);
  rmdir(ws->dir);
}

static int write_file(const char *path, const char *data, size_t len) {
  FILE *fp;
  if (path == NULL) return -1;
  fp = fopen(path, "wb");
  if (fp == NULL) return -1;
  if (len > 0 && fwrite(data, 1, len, fp) != len) {
    fclose(fp);
    return -1;
  }
  return fclose(fp) == 0 ? 0 : -1;
}

static char *read_file(const char *path, size_t *len_out) {
  FILE *fp;
  long size;
  char *buf;
  size_t len = 0;

  if (len_out != NULL) *len_out = 0;
  fp = fopen(path, "rb");
  if (fp == NULL) return NULL;
  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return NULL;
  }
  size = ftell(fp);
  if (size < 0) {
    fclose(fp);
    return NULL;
  }
  rewind(fp);
  buf = (char *) calloc(1, (size_t) size + 1);
  if (buf == NULL) {
    fclose(fp);
    return NULL;
  }
  if (size > 0) len = fread(buf, 1, (size_t) size, fp);
  fclose(fp);
  buf[len] = '\0';
  if (len_out != NULL) *len_out = len;
  return buf;
}

static void trim_line(char *s) {
  size_t len;
  if (s == NULL) return;
  len = strlen(s);
  while (len > 0 && (s[len - 1] == '\r' || s[len - 1] == '\n' ||
                     s[len - 1] == ' ' || s[len - 1] == '\t')) {
    s[--len] = '\0';
  }
  while (*s == ' ' || *s == '\t') memmove(s, s + 1, strlen(s));
}

static void copy_header_value(const char *line, const char *name, char *out,
                              size_t out_len) {
  const char *value;
  size_t name_len = strlen(name);
  if (out == NULL || out_len == 0 || line == NULL) return;
  if (strncasecmp(line, name, name_len) != 0 || line[name_len] != ':') return;
  value = line + name_len + 1;
  while (*value == ' ' || *value == '\t') value++;
  mg_snprintf(out, out_len, "%s", value);
  trim_line(out);
}

static void copy_set_cookie_value(const char *line, const char *name,
                                  char *out, size_t out_len) {
  const char *value;
  const char *end;
  size_t name_len;
  if (line == NULL || name == NULL || out == NULL || out_len == 0) return;
  if (strncasecmp(line, "Set-Cookie:", 11) != 0) return;
  value = line + 11;
  while (*value == ' ' || *value == '\t') value++;
  name_len = strlen(name);
  if (strncasecmp(value, name, name_len) != 0 || value[name_len] != '=') {
    return;
  }
  value += name_len + 1;
  end = strchr(value, ';');
  if (end == NULL) end = value + strlen(value);
  if ((size_t) (end - value) >= out_len) end = value + out_len - 1;
  mg_snprintf(out, out_len, "%.*s", (int) (end - value), value);
  trim_line(out);
}

static void append_nextauth_session_cookie(const char *line, char *out,
                                           size_t out_len) {
  static const char *name = "__Secure-next-auth.session-token";
  const char *value;
  const char *end;
  size_t name_len = strlen(name);
  size_t current;

  if (line == NULL || out == NULL || out_len == 0) return;
  if (strncasecmp(line, "Set-Cookie:", 11) != 0) return;
  value = line + 11;
  while (*value == ' ' || *value == '\t') value++;
  if (strncasecmp(value, name, name_len) != 0) return;
  if (value[name_len] == '=') {
    value += name_len + 1;
    out[0] = '\0';
  } else if (value[name_len] == '.' && value[name_len + 2] == '=') {
    value += name_len + 3;
  } else {
    return;
  }
  end = strchr(value, ';');
  if (end == NULL) end = value + strlen(value);
  current = strlen(out);
  if (current >= out_len - 1) return;
  if ((size_t) (end - value) >= out_len - current) {
    end = value + (out_len - current - 1);
  }
  strncat(out, value, (size_t) (end - value));
  trim_line(out);
}

static void append_cookie_file_line(char *out, size_t out_len,
                                    const char *line) {
  const char *fields[7] = {0};
  size_t lens[7] = {0};
  const char *p = line;
  size_t idx = 0;
  size_t current;

  if (out == NULL || out_len == 0 || line == NULL || line[0] == '\0' ||
      (line[0] == '#' && strncmp(line, "#HttpOnly_", 10) != 0)) {
    return;
  }
  while (idx < 7 && p != NULL) {
    const char *tab = strchr(p, '\t');
    fields[idx] = p;
    lens[idx] = tab ? (size_t) (tab - p) : strlen(p);
    idx++;
    p = tab ? tab + 1 : NULL;
  }
  if (idx < 7 || lens[5] == 0) return;
  current = strlen(out);
  if (current >= out_len - 1) return;
  mg_snprintf(out + current, out_len - current, "%s%.*s=%.*s",
              current > 0 ? "; " : "", (int) lens[5], fields[5],
              (int) lens[6], fields[6]);
}

static void parse_cookie_file(const char *path, char *out, size_t out_len) {
  char *cookies = read_file(path, NULL);
  char *line, *saveptr = NULL;
  if (out != NULL && out_len > 0) out[0] = '\0';
  if (cookies == NULL || out == NULL || out_len == 0) {
    free(cookies);
    return;
  }
  for (line = strtok_r(cookies, "\n", &saveptr); line != NULL;
       line = strtok_r(NULL, "\n", &saveptr)) {
    trim_line(line);
    append_cookie_file_line(out, out_len, line);
  }
  free(cookies);
}

static void parse_headers_file(const char *path, struct flow_http_response *response) {
  char *headers = read_file(path, NULL);
  char *line, *saveptr = NULL;
  if (headers == NULL || response == NULL) {
    free(headers);
    return;
  }
  for (line = strtok_r(headers, "\n", &saveptr); line != NULL;
       line = strtok_r(NULL, "\n", &saveptr)) {
    trim_line(line);
    if (strncasecmp(line, "HTTP/", 5) == 0) {
      response->location[0] = '\0';
      response->content_type[0] = '\0';
      response->server[0] = '\0';
      response->cf_mitigated[0] = '\0';
      response->cf_ray[0] = '\0';
      continue;
    }
    copy_header_value(line, "Location", response->location,
                      sizeof(response->location));
    copy_header_value(line, "Content-Type", response->content_type,
                      sizeof(response->content_type));
    copy_header_value(line, "Server", response->server, sizeof(response->server));
    copy_header_value(line, "CF-Mitigated", response->cf_mitigated,
                      sizeof(response->cf_mitigated));
    copy_header_value(line, "CF-Ray", response->cf_ray, sizeof(response->cf_ray));
    copy_set_cookie_value(line, "oai-did", response->device_id,
                          sizeof(response->device_id));
    copy_set_cookie_value(line, "oai-client-auth-session",
                          response->auth_session_cookie,
                          sizeof(response->auth_session_cookie));
    copy_set_cookie_value(line, "oai_client_auth_session",
                          response->auth_session_cookie,
                          sizeof(response->auth_session_cookie));
    copy_set_cookie_value(line, "oai-client-auth-info",
                          response->auth_info_cookie,
                          sizeof(response->auth_info_cookie));
    copy_set_cookie_value(line, "oai_client_auth_info",
                          response->auth_info_cookie,
                          sizeof(response->auth_info_cookie));
    append_nextauth_session_cookie(line, response->chatgpt_session_token,
                                   sizeof(response->chatgpt_session_token));
  }
  free(headers);
}

static void parse_meta_file(const char *path, struct flow_http_response *response) {
  char *meta = read_file(path, NULL);
  char *line, *saveptr = NULL;
  if (meta == NULL || response == NULL) {
    free(meta);
    return;
  }
  for (line = strtok_r(meta, "\n", &saveptr); line != NULL;
       line = strtok_r(NULL, "\n", &saveptr)) {
    trim_line(line);
    if (strncmp(line, "http_code=", 10) == 0) {
      response->status_code = strtol(line + 10, NULL, 10);
    } else if (strncmp(line, "url_effective=", 14) == 0) {
      sanitized_url(line + 14, response->effective_url,
                    sizeof(response->effective_url));
    } else if (strncmp(line, "remote_ip=", 10) == 0) {
      mg_snprintf(response->primary_ip, sizeof(response->primary_ip), "%s",
                  line + 10);
    } else if (strncmp(line, "content_type=", 13) == 0 &&
               response->content_type[0] == '\0') {
      mg_snprintf(response->content_type, sizeof(response->content_type), "%s",
                  line + 13);
    }
  }
  free(meta);
}

static int wait_for_child(pid_t pid, int *status) {
  for (;;) {
    pid_t waited = waitpid(pid, status, WNOHANG);
    if (waited == pid) return 1;
    if (waited < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    return 0;
  }
}

static int reap_cancelled_child(pid_t pid) {
  int status = 0;
  kill(pid, SIGTERM);
  for (int i = 0; i < 10; i++) {
    int waited = wait_for_child(pid, &status);
    if (waited > 0) return 130;
    if (waited < 0) return -1;
    usleep(10000);
  }
  kill(pid, SIGKILL);
  for (;;) {
    if (waitpid(pid, &status, 0) < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    return 137;
  }
}

static int run_process(struct flow_context *flow, char *const argv[],
                       const char *stdout_path, const char *stderr_path) {
  pid_t pid = fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    int out_fd = open(stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int err_fd = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out_fd < 0 || err_fd < 0) _exit(126);
    if (dup2(out_fd, STDOUT_FILENO) < 0) _exit(126);
    if (dup2(err_fd, STDERR_FILENO) < 0) _exit(126);
    close(out_fd);
    close(err_fd);
    execvp(argv[0], argv);
    _exit(127);
  }
  for (;;) {
    int status;
    int waited = wait_for_child(pid, &status);
    if (waited < 0) return -1;
    if (waited == 0) {
      if (flow_context_cancel_requested(flow)) return reap_cancelled_child(pid);
      usleep(25000);
      continue;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
  }
}

static int add_arg(char **argv, size_t *argc, const char *value) {
  if (*argc + 1 >= IMP_ARG_MAX) return -1;
  argv[(*argc)++] = (char *) value;
  argv[*argc] = NULL;
  return 0;
}

static int add_header_arg(char **argv, size_t *argc, char *storage,
                          size_t storage_len, const char *name,
                          const char *value) {
  if (name == NULL || value == NULL || value[0] == '\0') return 0;
  mg_snprintf(storage, storage_len, "%s: %s", name, value);
  return add_arg(argv, argc, "-H") == 0 && add_arg(argv, argc, storage) == 0
             ? 0
             : -1;
}

static bool is_raw_impersonate_binary(const char *path) {
  const char *base;
  if (path == NULL) return false;
  base = strrchr(path, '/');
  base = base == NULL ? path : base + 1;
  return strcmp(base, "curl-impersonate") == 0;
}

static char *read_trimmed_stderr(const char *path) {
  char *stderr_text = read_file(path, NULL);
  char *p = stderr_text;
  if (p != NULL) {
    trim_line(p);
    while (*p == '\r' || *p == '\n') p++;
    if (p != stderr_text) memmove(stderr_text, p, strlen(p) + 1);
  }
  return stderr_text;
}

static int execute_request(struct flow_context *flow,
                           const struct flow_http_request *request,
                           struct impersonate_workspace *ws,
                           const char *curl_bin,
                           struct flow_http_response *response) {
  char *argv[IMP_ARG_MAX] = {0};
  char header_storage[64][768];
  size_t header_len = 0;
  size_t argc = 0;
  char timeout_s[32];
  char connect_timeout_s[32];
  char body_arg[IMP_PATH_LEN + 2];
  char request_url[FLOW_URL_LEN];
  char method[16];
  char scheme[24];
  long connect_timeout_ms;

  if (flow == NULL || request == NULL || request->url == NULL ||
      request->url[0] == '\0' || ws == NULL || curl_bin == NULL ||
      response == NULL) {
    flow_context_fail(flow, "curl-impersonate 请求参数无效");
    return -1;
  }
  if (flow_context_cancel_requested(flow)) {
    flow_context_cancel(flow, "流程已取消");
    return -1;
  }

  memset(response, 0, sizeof(*response));
  method[0] = '\0';
  mg_snprintf(method, sizeof(method), "%s",
              request->method != NULL && request->method[0] != '\0'
                  ? request->method
                  : "GET");
  sanitized_url(request->url, request_url, sizeof(request_url));
  proxy_scheme_label(flow->proxy_url, scheme, sizeof(scheme));
  connect_timeout_ms = flow_http_effective_connect_timeout_ms(request);
  flow_context_log(flow, "debug",
                   "curl-impersonate 请求: %s %s timeout=%ldms connect=%ldms proxy=%s body=%luB",
                   method, request_url, request->timeout_ms,
                   connect_timeout_ms, scheme,
                   (unsigned long) request->body_len);

  unlink(ws->request_body_file);

  if (request->body != NULL && request->body_len > 0 &&
      write_file(ws->request_body_file, request->body, request->body_len) != 0) {
    flow_context_fail(flow, "写入 curl-impersonate 请求体失败");
    return -1;
  }

  if (add_arg(argv, &argc, curl_bin) != 0 ||
      add_arg(argv, &argc, "-sS") != 0 ||
      add_arg(argv, &argc, "--http2") != 0 ||
      add_arg(argv, &argc, "--path-as-is") != 0 ||
      add_arg(argv, &argc, "--cookie") != 0 ||
      add_arg(argv, &argc, ws->cookie_file) != 0 ||
      add_arg(argv, &argc, "--cookie-jar") != 0 ||
      add_arg(argv, &argc, ws->cookie_file) != 0 ||
      add_arg(argv, &argc, "--dump-header") != 0 ||
      add_arg(argv, &argc, ws->header_file) != 0 ||
      add_arg(argv, &argc, "--output") != 0 ||
      add_arg(argv, &argc, ws->body_file) != 0 ||
      add_arg(argv, &argc, "--write-out") != 0 ||
      add_arg(argv, &argc,
              "http_code=%{http_code}\nurl_effective=%{url_effective}\n"
              "remote_ip=%{remote_ip}\ncontent_type=%{content_type}\n") != 0) {
    flow_context_fail(flow, "curl-impersonate 参数过多");
    return -1;
  }
  if (is_raw_impersonate_binary(curl_bin)) {
    if (add_arg(argv, &argc, "--impersonate") != 0 ||
        add_arg(argv, &argc, "chrome145") != 0 ||
        add_arg(argv, &argc, "--compressed") != 0) {
      flow_context_fail(flow, "curl-impersonate 浏览器模式参数过多");
      return -1;
    }
  }

  if (request->timeout_ms > 0) {
    long seconds = (request->timeout_ms + 999) / 1000;
    long connect_seconds = (connect_timeout_ms + 999) / 1000;
    if (seconds <= 0) seconds = 1;
    if (connect_seconds <= 0) connect_seconds = 1;
    mg_snprintf(timeout_s, sizeof(timeout_s), "%ld", seconds);
    mg_snprintf(connect_timeout_s, sizeof(connect_timeout_s), "%ld",
                connect_seconds);
    if (add_arg(argv, &argc, "--max-time") != 0 ||
        add_arg(argv, &argc, timeout_s) != 0 ||
        add_arg(argv, &argc, "--connect-timeout") != 0 ||
        add_arg(argv, &argc, connect_timeout_s) != 0) {
      flow_context_fail(flow, "curl-impersonate 超时参数过多");
      return -1;
    }
  }

  if (flow->proxy_url[0] != '\0') {
    if (add_arg(argv, &argc, "--proxy") != 0 ||
        add_arg(argv, &argc, flow->proxy_url) != 0) {
      flow_context_fail(flow, "curl-impersonate 代理参数过多");
      return -1;
    }
  }

  for (size_t i = 0; i < request->num_headers; i++) {
    if (header_len >= sizeof(header_storage) / sizeof(header_storage[0])) {
      flow_context_fail(flow, "curl-impersonate 请求头过多");
      return -1;
    }
    if (add_header_arg(argv, &argc, header_storage[header_len],
                       sizeof(header_storage[header_len]),
                       request->headers[i].name, request->headers[i].value) != 0) {
      flow_context_fail(flow, "curl-impersonate 请求头参数过多");
      return -1;
    }
    header_len++;
  }
  if (flow->profile.accept_language[0] != '\0') {
    if (header_len >= sizeof(header_storage) / sizeof(header_storage[0])) {
      flow_context_fail(flow, "curl-impersonate 请求头过多");
      return -1;
    }
    if (add_header_arg(argv, &argc, header_storage[header_len],
                       sizeof(header_storage[header_len]), "Accept-Language",
                       flow->profile.accept_language) != 0) {
      flow_context_fail(flow, "curl-impersonate 请求头参数过多");
      return -1;
    }
    header_len++;
  }

  if (strcmp(method, "GET") != 0) {
    if (add_arg(argv, &argc, "-X") != 0 || add_arg(argv, &argc, method) != 0) {
      flow_context_fail(flow, "curl-impersonate 方法参数过多");
      return -1;
    }
  }
  if (request->body != NULL && request->body_len > 0) {
    mg_snprintf(body_arg, sizeof(body_arg), "@%s", ws->request_body_file);
    if (add_arg(argv, &argc, "--data-binary") != 0 ||
        add_arg(argv, &argc, body_arg) != 0) {
      flow_context_fail(flow, "curl-impersonate 请求体参数过多");
      return -1;
    }
  } else if (request->body != NULL && strcmp(method, "POST") == 0) {
    if (add_arg(argv, &argc, "--data-binary") != 0 ||
        add_arg(argv, &argc, "") != 0) {
      flow_context_fail(flow, "curl-impersonate 空请求体参数过多");
      return -1;
    }
  }
  if (add_arg(argv, &argc, request->url) != 0) {
    flow_context_fail(flow, "curl-impersonate URL 参数过多");
    return -1;
  }

  for (int attempt = 0; attempt <= IMP_REQUEST_MAX_RETRIES; attempt++) {
    int rc;
    unlink(ws->body_file);
    unlink(ws->header_file);
    unlink(ws->meta_file);
    unlink(ws->stderr_file);
    free(response->body);
    memset(response, 0, sizeof(*response));

    rc = run_process(flow, argv, ws->meta_file, ws->stderr_file);
    response->body = read_file(ws->body_file, &response->body_len);
    parse_headers_file(ws->header_file, response);
    parse_meta_file(ws->meta_file, response);
    parse_cookie_file(ws->cookie_file, response->cookie_header,
                      sizeof(response->cookie_header));
    if (response->effective_url[0] == '\0') {
      sanitized_url(request->url, response->effective_url,
                    sizeof(response->effective_url));
    }

    if (rc == 0) break;
    if (flow_context_cancel_requested(flow)) {
      flow_context_cancel(flow, "流程已取消");
      return -1;
    }
    {
      char *stderr_text = read_trimmed_stderr(ws->stderr_file);
      const char *message =
          stderr_text != NULL && stderr_text[0] != '\0'
              ? stderr_text
              : "curl-impersonate 请求失败";
      if (attempt < IMP_REQUEST_MAX_RETRIES) {
        flow_context_log(flow, "warn",
                         "curl-impersonate 请求失败，将重试 %d/%d: %s %s exit=%d error=%s proxy=%s",
                         attempt + 1, IMP_REQUEST_MAX_RETRIES, method,
                         request_url, rc, message, scheme);
        free(stderr_text);
        usleep((useconds_t) (250000 * (attempt + 1)));
        continue;
      }
      mg_snprintf(response->error, sizeof(response->error), "%s", message);
      free(stderr_text);
    }
    flow_context_fail(flow, response->error);
    flow_context_log(flow, "error",
                     "curl-impersonate 失败: %s %s exit=%d error=%s proxy=%s retries=%d",
                     method, request_url, rc, response->error, scheme,
                     IMP_REQUEST_MAX_RETRIES);
    return -1;
  }

  flow_context_log(flow, "debug",
                   "curl-impersonate 响应: %s %s -> %ld body=%luB ip=%s server=%s cf=%s ray=%s location=%s",
                   method, response->effective_url, response->status_code,
                   (unsigned long) response->body_len,
                   response->primary_ip[0] ? response->primary_ip : "-",
                   response->server[0] ? response->server : "-",
                   response->cf_mitigated[0] ? response->cf_mitigated : "-",
                   response->cf_ray[0] ? response->cf_ray : "-",
                   response->location[0] ? response->location : "-");
  return 0;
}

static bool sleep_until(struct flow_context *flow, long next_retry_ms) {
  long now = (long) mg_millis();
  long wait_ms = next_retry_ms > now ? next_retry_ms - now : 250;
  if (wait_ms < 50) wait_ms = 50;
  if (wait_ms > 1000) wait_ms = 1000;
  while (wait_ms > 0) {
    long chunk_ms = wait_ms > 50 ? 50 : wait_ms;
    if (flow_context_cancel_requested(flow)) {
      flow_context_cancel(flow, "流程已取消");
      return false;
    }
    usleep((useconds_t) chunk_ms * 1000);
    wait_ms -= chunk_ms;
  }
  if (flow_context_cancel_requested(flow)) {
    flow_context_cancel(flow, "流程已取消");
    return false;
  }
  return true;
}

int flow_impersonate_run(const struct flow_provider *provider,
                         const struct flow_start_options *options,
                         struct flow_context *snapshot) {
  struct flow_context flow;
  struct impersonate_workspace ws;
  char curl_bin[IMP_PATH_LEN];
  int result = -1;

  memset(&flow, 0, sizeof(flow));
  memset(&ws, 0, sizeof(ws));
  if (provider == NULL || provider->next_request == NULL || options == NULL) {
    return -1;
  }

  flow.status = FLOW_STATUS_PENDING;
  flow.mode = options->mode;
  flow.persist_on_success = options->persist_on_success;
  flow.account_id = options->account_id;
  flow.deadline_ms = options->deadline_ms;
  flow.oauth_otp_timeout_ms = options->oauth_otp_timeout_ms;
  flow.fast_email_otp_resend = options->fast_email_otp_resend;
  flow.db = options->db;
  flow.log_fn = options->log_fn;
  flow.finish_fn = options->finish_fn;
  flow.cancel_fn = options->cancel_fn;
  flow.event_fn = options->event_fn;
  flow.callback_data = options->callback_data;
  generate_flow_id(flow.id, sizeof(flow.id));
  if (options->proxy_url != NULL) {
    mg_snprintf(flow.proxy_url, sizeof(flow.proxy_url), "%s", options->proxy_url);
  }
  if (options->profile != NULL) flow.profile = *options->profile;
  if (options->identity != NULL) flow.identity = *options->identity;
  if (options->workspace_id != NULL) {
    mg_snprintf(flow.workspace_id, sizeof(flow.workspace_id), "%s",
                options->workspace_id);
  }

  if (flow_impersonate_available(curl_bin, sizeof(curl_bin)) != 0) {
    flow_context_fail(&flow, "未找到 curl-impersonate，请安装 curl_chrome145 或设置 CURL_IMPERSONATE_BIN");
    goto finish;
  }

  if (create_workspace(flow.id, &ws) != 0) {
    flow_context_fail(&flow, "创建 curl-impersonate 临时目录失败");
    goto finish;
  }

  flow_context_log(&flow, "info", "请求驱动: curl-impersonate (%s)",
                   curl_bin);
  if (provider->start != NULL && provider->start(&flow) != 0) {
    if (flow.error[0] == '\0') flow_context_fail(&flow, "provider start failed");
    goto finish;
  }
  flow.status = FLOW_STATUS_RUNNING;

  while (flow.status == FLOW_STATUS_RUNNING ||
         flow.status == FLOW_STATUS_PENDING) {
    struct flow_http_request request;
    struct flow_http_response response;
    enum flow_provider_action action;

    if (flow_context_cancel_requested(&flow)) {
      flow_context_cancel(&flow, "流程已取消");
      break;
    }
    memset(&request, 0, sizeof(request));
    action = provider->next_request(&flow, &request);
    if (action == FLOW_PROVIDER_WAIT) {
      if (!sleep_until(&flow, flow.next_retry_ms)) break;
      continue;
    }
    if (action == FLOW_PROVIDER_FAILED) {
      if (flow.error[0] == '\0') flow_context_fail(&flow, "provider failed");
      break;
    }
    if (action == FLOW_PROVIDER_DONE) {
      flow.status = FLOW_STATUS_SUCCESS;
      if (persist_success(flow.db, &flow) != 0) break;
      result = 0;
      break;
    }
    if (action != FLOW_PROVIDER_REQUEST) {
      flow_context_fail(&flow, "未知 flow provider 动作");
      break;
    }

    if (flow_context_cancel_requested(&flow)) {
      flow_context_cancel(&flow, "流程已取消");
      break;
    }
    memset(&response, 0, sizeof(response));
    if (execute_request(&flow, &request, &ws, curl_bin, &response) != 0) {
      free(response.body);
      break;
    }
    if (provider->on_response != NULL &&
        provider->on_response(&flow, &response) != 0) {
      free(response.body);
      if (flow.error[0] == '\0') {
        flow_context_fail(&flow, "provider response handling failed");
      }
      break;
    }
    free(response.body);
  }

finish:
  if (flow.status != FLOW_STATUS_SUCCESS &&
      flow.status != FLOW_STATUS_CANCELLED) {
    if (flow.error[0] == '\0') flow_context_fail(&flow, "流程失败");
    result = -1;
  }
  if (flow.finish_fn != NULL) flow.finish_fn(&flow, flow.callback_data);
  if (provider != NULL && provider->cleanup != NULL) provider->cleanup(&flow);
  if (snapshot != NULL) *snapshot = flow;
  cleanup_workspace(&ws);
  return result;
}
