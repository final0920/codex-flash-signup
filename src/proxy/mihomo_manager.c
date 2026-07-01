#include "proxy/mihomo_manager.h"

#include "http_client/http_client.h"
#include "mongoose.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MIHOMO_DEFAULT_MODE "pool"
#define MIHOMO_DEFAULT_SUBSCRIPTION_TYPE "url"
#define MIHOMO_DEFAULT_CORE "mihomo"
#define MIHOMO_DEFAULT_CONFIG_DIR "data/mihomo"
#define MIHOMO_DEFAULT_MIXED_HOST "127.0.0.1"
#define MIHOMO_DEFAULT_MIXED_PORT 7890
#define MIHOMO_DEFAULT_CONTROLLER_HOST "127.0.0.1"
#define MIHOMO_DEFAULT_CONTROLLER_PORT 9097
#define MIHOMO_DEFAULT_STRATEGY "round-robin"
#define MIHOMO_DEFAULT_GROUP_MODE "load-balance"
#define MIHOMO_GROUP_NAME "Mongoose-LB"
#define MIHOMO_TASK_GROUP_PREFIX "Mongoose-Task-"
#define MIHOMO_TASK_LISTENER_PREFIX "mongoose-task-"
#define MIHOMO_TASK_SLOT_COUNT 64
#define MIHOMO_DEFAULT_HEALTH_URL "https://www.gstatic.com/generate_204"
#define MIHOMO_DEFAULT_PROVIDER_INTERVAL 3600
#define MIHOMO_DEFAULT_HEALTH_INTERVAL 120
#define MIHOMO_TRACE_URL "https://cloudflare.com/cdn-cgi/trace"
#define MIHOMO_CONTROLLER_TIMEOUT_MS 8000L

struct mihomo_config {
  char mode[16];
  bool enabled;
  bool managed;
  char subscription_type[16];
  char subscription_url[2048];
  char core_path[512];
  char config_dir[512];
  char config_path[768];
  char log_path[768];
  char pid_path[768];
  char mixed_host[128];
  int mixed_port;
  char controller_host[128];
  int controller_port;
  char controller_secret[128];
  char strategy[64];
  char group_mode[32];
  char node_filter[512];
  char node_exclude_filter[512];
  char selected_node[512];
  char health_check_url[256];
  int provider_interval;
  int health_check_interval;
};

static pthread_mutex_t s_mihomo_mu = PTHREAD_MUTEX_INITIALIZER;
static pid_t s_mihomo_pid = -1;
static char s_last_error[256] = "";

struct mihomo_task_slot {
  bool used;
  char task_id[64];
  char node[512];
};

static struct mihomo_task_slot s_task_slots[MIHOMO_TASK_SLOT_COUNT];

static char *trim_inplace(char *s) {
  char *end;
  if (s == NULL) return NULL;
  while (*s && isspace((unsigned char) *s)) s++;
  end = s + strlen(s);
  while (end > s && isspace((unsigned char) end[-1])) *--end = '\0';
  return s;
}

static void lower_copy(char *dst, size_t dst_len, const char *src) {
  size_t i = 0;
  if (dst_len == 0) return;
  src = src ? src : "";
  for (; src[i] && i + 1 < dst_len; i++) {
    dst[i] = (char) tolower((unsigned char) src[i]);
  }
  dst[i] = '\0';
}

static int upsert_setting(sqlite3 *db, const char *key, const char *value) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "INSERT INTO proxy_settings(key,value,updated_at) VALUES(?,?,unixepoch()) "
      "ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
      "updated_at=unixepoch()";
  int rc;
  if (db == NULL || key == NULL) return -1;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
  sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, value ? value : "", -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  return rc == SQLITE_DONE ? 0 : -1;
}

static char *setting_value(sqlite3 *db, const char *key, const char *fallback) {
  sqlite3_stmt *stmt = NULL;
  char *value = NULL;
  if (db == NULL || key == NULL ||
      sqlite3_prepare_v2(db, "SELECT value FROM proxy_settings WHERE key=?", -1,
                         &stmt, NULL) != SQLITE_OK) {
    return strdup(fallback ? fallback : "");
  }
  sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *s = sqlite3_column_text(stmt, 0);
    value = strdup(s == NULL ? "" : (const char *) s);
  }
  sqlite3_finalize(stmt);
  if (value == NULL) value = strdup(fallback ? fallback : "");
  return value;
}

static bool setting_bool(sqlite3 *db, const char *key, bool fallback) {
  char *value = setting_value(db, key, fallback ? "1" : "0");
  char normalized[32];
  bool result;
  lower_copy(normalized, sizeof(normalized), trim_inplace(value));
  result = strcmp(normalized, "1") == 0 || strcmp(normalized, "true") == 0 ||
           strcmp(normalized, "yes") == 0 || strcmp(normalized, "on") == 0;
  free(value);
  return result;
}

static int clamp_int(long value, int min, int max, int fallback) {
  if (value < min || value > max) return fallback;
  return (int) value;
}

static int setting_int(sqlite3 *db, const char *key, int fallback, int min,
                       int max) {
  char *value = setting_value(db, key, "");
  char *end = NULL;
  long parsed = strtol(value ? value : "", &end, 10);
  int result = fallback;
  if (value != NULL && end != value && *trim_inplace(end) == '\0') {
    result = clamp_int(parsed, min, max, fallback);
  }
  free(value);
  return result;
}

static void normalize_mode(const char *value, char *out, size_t out_len) {
  char buf[32], *p;
  if (out_len == 0) return;
  mg_snprintf(buf, sizeof(buf), "%s", value ? value : "");
  p = trim_inplace(buf);
  lower_copy(buf, sizeof(buf), p);
  if (strcmp(buf, "mihomo") == 0 || strcmp(buf, "clash") == 0) {
    mg_snprintf(out, out_len, "mihomo");
  } else if (strcmp(buf, "direct") == 0 || strcmp(buf, "none") == 0) {
    mg_snprintf(out, out_len, "direct");
  } else {
    mg_snprintf(out, out_len, "pool");
  }
}

static void normalize_strategy(const char *value, char *out, size_t out_len) {
  char buf[64], *p;
  if (out_len == 0) return;
  mg_snprintf(buf, sizeof(buf), "%s", value ? value : "");
  p = trim_inplace(buf);
  lower_copy(buf, sizeof(buf), p);
  if (strcmp(buf, "consistent-hashing") == 0 ||
      strcmp(buf, "sticky-sessions") == 0) {
    mg_snprintf(out, out_len, "%s", buf);
  } else {
    mg_snprintf(out, out_len, "round-robin");
  }
}

static void normalize_group_mode(const char *value, char *out, size_t out_len) {
  char buf[64], *p;
  if (out_len == 0) return;
  mg_snprintf(buf, sizeof(buf), "%s", value ? value : "");
  p = trim_inplace(buf);
  lower_copy(buf, sizeof(buf), p);
  if (strcmp(buf, "select") == 0 || strcmp(buf, "manual") == 0 ||
      strcmp(buf, "node") == 0 || strcmp(buf, "fixed") == 0) {
    mg_snprintf(out, out_len, "select");
  } else {
    mg_snprintf(out, out_len, MIHOMO_DEFAULT_GROUP_MODE);
  }
}

static void normalize_subscription_type(const char *value, char *out,
                                        size_t out_len) {
  char buf[32], *p;
  if (out_len == 0) return;
  mg_snprintf(buf, sizeof(buf), "%s", value ? value : "");
  p = trim_inplace(buf);
  lower_copy(buf, sizeof(buf), p);
  if (strcmp(buf, "text") == 0 || strcmp(buf, "yaml") == 0 ||
      strcmp(buf, "file") == 0 || strcmp(buf, "content") == 0) {
    mg_snprintf(out, out_len, "text");
  } else {
    mg_snprintf(out, out_len, MIHOMO_DEFAULT_SUBSCRIPTION_TYPE);
  }
}

static bool has_non_space(const char *value) {
  if (value == NULL) return false;
  while (*value) {
    if (!isspace((unsigned char) *value)) return true;
    value++;
  }
  return false;
}

static void read_string_setting(sqlite3 *db, const char *key,
                                const char *fallback, char *out,
                                size_t out_len) {
  char *value;
  char *trimmed;
  if (out_len == 0) return;
  value = setting_value(db, key, fallback);
  trimmed = trim_inplace(value);
  mg_snprintf(out, out_len, "%s", trimmed && trimmed[0] ? trimmed : fallback);
  free(value);
}

static void build_paths(struct mihomo_config *cfg) {
  mg_snprintf(cfg->config_path, sizeof(cfg->config_path), "%s/config.yaml",
              cfg->config_dir);
  mg_snprintf(cfg->log_path, sizeof(cfg->log_path), "%s/mihomo.log",
              cfg->config_dir);
  mg_snprintf(cfg->pid_path, sizeof(cfg->pid_path), "%s/mihomo.pid",
              cfg->config_dir);
}

static void generate_secret(char *out, size_t out_len) {
  uint64_t now = (uint64_t) time(NULL);
  uint64_t mixed = now ^ ((uint64_t) getpid() << 32) ^ (uint64_t) rand();
  if (out_len == 0) return;
  mg_snprintf(out, out_len, "mongoose-%llx-%llx",
              (unsigned long long) now, (unsigned long long) mixed);
}

static void read_config(sqlite3 *db, struct mihomo_config *cfg) {
  char *mode;
  char *subscription_type;
  char *strategy;
  char *group_mode;
  char *secret;
  memset(cfg, 0, sizeof(*cfg));
  mode = setting_value(db, "proxy_mode", MIHOMO_DEFAULT_MODE);
  normalize_mode(mode, cfg->mode, sizeof(cfg->mode));
  free(mode);
  cfg->enabled = setting_bool(db, "mihomo_enabled", false);
  cfg->managed = setting_bool(db, "mihomo_managed", true);
  subscription_type = setting_value(db, "mihomo_subscription_type",
                                    MIHOMO_DEFAULT_SUBSCRIPTION_TYPE);
  normalize_subscription_type(subscription_type, cfg->subscription_type,
                              sizeof(cfg->subscription_type));
  free(subscription_type);
  read_string_setting(db, "mihomo_subscription_url", "", cfg->subscription_url,
                      sizeof(cfg->subscription_url));
  read_string_setting(db, "mihomo_core_path", MIHOMO_DEFAULT_CORE,
                      cfg->core_path, sizeof(cfg->core_path));
  read_string_setting(db, "mihomo_config_dir", MIHOMO_DEFAULT_CONFIG_DIR,
                      cfg->config_dir, sizeof(cfg->config_dir));
  read_string_setting(db, "mihomo_mixed_host", MIHOMO_DEFAULT_MIXED_HOST,
                      cfg->mixed_host, sizeof(cfg->mixed_host));
  cfg->mixed_port =
      setting_int(db, "mihomo_mixed_port", MIHOMO_DEFAULT_MIXED_PORT, 1, 65535);
  read_string_setting(db, "mihomo_controller_host",
                      MIHOMO_DEFAULT_CONTROLLER_HOST, cfg->controller_host,
                      sizeof(cfg->controller_host));
  cfg->controller_port = setting_int(db, "mihomo_controller_port",
                                     MIHOMO_DEFAULT_CONTROLLER_PORT, 1, 65535);
  strategy = setting_value(db, "mihomo_strategy", MIHOMO_DEFAULT_STRATEGY);
  normalize_strategy(strategy, cfg->strategy, sizeof(cfg->strategy));
  free(strategy);
  group_mode = setting_value(db, "mihomo_group_mode", MIHOMO_DEFAULT_GROUP_MODE);
  normalize_group_mode(group_mode, cfg->group_mode, sizeof(cfg->group_mode));
  free(group_mode);
  read_string_setting(db, "mihomo_node_filter", "", cfg->node_filter,
                      sizeof(cfg->node_filter));
  read_string_setting(db, "mihomo_node_exclude_filter", "",
                      cfg->node_exclude_filter,
                      sizeof(cfg->node_exclude_filter));
  read_string_setting(db, "mihomo_selected_node", "", cfg->selected_node,
                      sizeof(cfg->selected_node));
  read_string_setting(db, "mihomo_health_check_url", MIHOMO_DEFAULT_HEALTH_URL,
                      cfg->health_check_url, sizeof(cfg->health_check_url));
  cfg->provider_interval = setting_int(db, "mihomo_provider_interval",
                                       MIHOMO_DEFAULT_PROVIDER_INTERVAL, 60,
                                       86400);
  cfg->health_check_interval = setting_int(db, "mihomo_health_check_interval",
                                           MIHOMO_DEFAULT_HEALTH_INTERVAL, 30,
                                           3600);
  secret = setting_value(db, "mihomo_controller_secret", "");
  if (trim_inplace(secret)[0] == '\0') {
    generate_secret(cfg->controller_secret, sizeof(cfg->controller_secret));
    upsert_setting(db, "mihomo_controller_secret", cfg->controller_secret);
  } else {
    mg_snprintf(cfg->controller_secret, sizeof(cfg->controller_secret), "%s",
                trim_inplace(secret));
  }
  free(secret);
  build_paths(cfg);
}

static int ensure_dir_recursive(const char *path) {
  char tmp[768];
  size_t len;
  if (path == NULL || path[0] == '\0') return -1;
  mg_snprintf(tmp, sizeof(tmp), "%s", path);
  len = strlen(tmp);
  while (len > 1 && tmp[len - 1] == '/') tmp[--len] = '\0';
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
      *p = '/';
    }
  }
  if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
  return 0;
}

static void yaml_write_quoted(FILE *fp, const char *value) {
  fputc('"', fp);
  for (const unsigned char *p = (const unsigned char *) (value ? value : "");
       *p; p++) {
    if (*p == '\\' || *p == '"') {
      fputc('\\', fp);
      fputc(*p, fp);
    } else if (*p == '\n') {
      fputs("\\n", fp);
    } else if (*p == '\r') {
      fputs("\\r", fp);
    } else {
      fputc(*p, fp);
    }
  }
  fputc('"', fp);
}

static void task_group_name(int slot, char *out, size_t out_len) {
  if (out_len == 0) return;
  mg_snprintf(out, out_len, "%s%03d", MIHOMO_TASK_GROUP_PREFIX, slot + 1);
}

static void task_listener_name(int slot, char *out, size_t out_len) {
  if (out_len == 0) return;
  mg_snprintf(out, out_len, "%s%03d", MIHOMO_TASK_LISTENER_PREFIX, slot + 1);
}

static int task_slot_port(const struct mihomo_config *cfg, int slot) {
  int seen = 0;
  if (cfg == NULL || slot < 0 || slot >= MIHOMO_TASK_SLOT_COUNT ||
      cfg->mixed_port <= 0) {
    return -1;
  }
  for (int port = cfg->mixed_port + 1; port <= 65535; port++) {
    if (port == cfg->controller_port) continue;
    if (seen == slot) return port;
    seen++;
  }
  return -1;
}

static int write_subscription_text_provider(sqlite3 *db,
                                            const char *provider_path,
                                            char *error, size_t error_len) {
  char tmp_path[768];
  char *text;
  FILE *fp;
  size_t len;

  if (db == NULL || provider_path == NULL || provider_path[0] == '\0') {
    mg_snprintf(error, error_len, "无法读取 Clash/mihomo 订阅文本");
    return -1;
  }
  text = setting_value(db, "mihomo_subscription_text", "");
  if (!has_non_space(text)) {
    mg_snprintf(error, error_len, "请粘贴 Clash/mihomo 订阅文本");
    free(text);
    return -1;
  }

  mg_snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", provider_path);
  fp = fopen(tmp_path, "wb");
  if (fp == NULL) {
    mg_snprintf(error, error_len, "写入 mihomo provider 失败: %s",
                strerror(errno));
    free(text);
    return -1;
  }
  len = strlen(text);
  if (len > 0 && fwrite(text, 1, len, fp) != len) {
    mg_snprintf(error, error_len, "保存 mihomo provider 失败: %s",
                strerror(errno));
    fclose(fp);
    unlink(tmp_path);
    free(text);
    return -1;
  }
  if (fclose(fp) != 0) {
    mg_snprintf(error, error_len, "保存 mihomo provider 失败: %s",
                strerror(errno));
    unlink(tmp_path);
    free(text);
    return -1;
  }
  if (rename(tmp_path, provider_path) != 0) {
    mg_snprintf(error, error_len, "替换 mihomo provider 失败: %s",
                strerror(errno));
    unlink(tmp_path);
    free(text);
    return -1;
  }
  free(text);
  return 0;
}

static int write_mihomo_config(sqlite3 *db, const struct mihomo_config *cfg,
                               char *error, size_t error_len) {
  char providers_dir[768];
  char provider_path[768];
  char tmp_path[768];
  FILE *fp;
  if (cfg == NULL) return -1;
  if (strcmp(cfg->subscription_type, "text") != 0 &&
      cfg->subscription_url[0] == '\0') {
    mg_snprintf(error, error_len, "请填写 Clash/mihomo 订阅链接");
    return -1;
  }
  if (ensure_dir_recursive(cfg->config_dir) != 0) {
    mg_snprintf(error, error_len, "创建 mihomo 配置目录失败: %s",
                strerror(errno));
    return -1;
  }
  mg_snprintf(providers_dir, sizeof(providers_dir), "%s/providers",
              cfg->config_dir);
  if (ensure_dir_recursive(providers_dir) != 0) {
    mg_snprintf(error, error_len, "创建 mihomo provider 目录失败: %s",
                strerror(errno));
    return -1;
  }
  mg_snprintf(provider_path, sizeof(provider_path), "%s/mongoose-sub.yaml",
              providers_dir);
  if (strcmp(cfg->subscription_type, "text") == 0 &&
      write_subscription_text_provider(db, provider_path, error, error_len) !=
          0) {
    return -1;
  }
  mg_snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", cfg->config_path);
  fp = fopen(tmp_path, "w");
  if (fp == NULL) {
    mg_snprintf(error, error_len, "写入 mihomo 配置失败: %s", strerror(errno));
    return -1;
  }

  fprintf(fp, "mixed-port: %d\n", cfg->mixed_port);
  fprintf(fp, "allow-lan: false\n");
  fprintf(fp, "bind-address: ");
  yaml_write_quoted(fp, cfg->mixed_host);
  fprintf(fp, "\nmode: rule\nlog-level: warning\nipv6: false\n");
  fprintf(fp, "external-controller: ");
  {
    char controller_endpoint[256];
    mg_snprintf(controller_endpoint, sizeof(controller_endpoint), "%s:%d",
                cfg->controller_host, cfg->controller_port);
    yaml_write_quoted(fp, controller_endpoint);
  }
  fprintf(fp, "\nsecret: ");
  yaml_write_quoted(fp, cfg->controller_secret);
  fprintf(fp, "\nunified-delay: true\ntcp-concurrent: true\n");
  fprintf(fp, "profile:\n  store-selected: true\n  store-fake-ip: false\n");
  fprintf(fp, "proxy-providers:\n  mongoose-sub:\n");
  if (strcmp(cfg->subscription_type, "text") == 0) {
    fprintf(fp, "    type: file\n    path: ./providers/mongoose-sub.yaml\n");
  } else {
    fprintf(fp, "    type: http\n    url: ");
    yaml_write_quoted(fp, cfg->subscription_url);
    fprintf(fp, "\n    interval: %d\n    path: ./providers/mongoose-sub.yaml\n",
            cfg->provider_interval);
  }
  if (cfg->node_filter[0] != '\0') {
    fprintf(fp, "    filter: ");
    yaml_write_quoted(fp, cfg->node_filter);
    fprintf(fp, "\n");
  }
  if (cfg->node_exclude_filter[0] != '\0') {
    fprintf(fp, "    exclude-filter: ");
    yaml_write_quoted(fp, cfg->node_exclude_filter);
    fprintf(fp, "\n");
  }
  fprintf(fp, "    health-check:\n      enable: true\n      lazy: false\n");
  fprintf(fp, "      interval: %d\n      url: ", cfg->health_check_interval);
  yaml_write_quoted(fp, cfg->health_check_url);
  fprintf(fp, "\nproxy-groups:\n  - name: %s\n", MIHOMO_GROUP_NAME);
  if (strcmp(cfg->group_mode, "select") == 0) {
    fprintf(fp, "    type: select\n");
    fprintf(fp, "    proxies:\n      - DIRECT\n");
    fprintf(fp, "    use:\n      - mongoose-sub\n");
  } else {
    fprintf(fp, "    type: load-balance\n    strategy: %s\n", cfg->strategy);
    fprintf(fp, "    use:\n      - mongoose-sub\n    url: ");
    yaml_write_quoted(fp, cfg->health_check_url);
    fprintf(fp, "\n    interval: %d\n", cfg->health_check_interval);
  }
  for (int i = 0; i < MIHOMO_TASK_SLOT_COUNT; i++) {
    char group[96];
    if (task_slot_port(cfg, i) <= 0) break;
    task_group_name(i, group, sizeof(group));
    fprintf(fp, "  - name: ");
    yaml_write_quoted(fp, group);
    fprintf(fp, "\n    type: select\n");
    fprintf(fp, "    use:\n      - mongoose-sub\n");
  }
  fprintf(fp, "listeners:\n");
  for (int i = 0; i < MIHOMO_TASK_SLOT_COUNT; i++) {
    char group[96];
    char listener[96];
    int port = task_slot_port(cfg, i);
    if (port <= 0) break;
    task_group_name(i, group, sizeof(group));
    task_listener_name(i, listener, sizeof(listener));
    fprintf(fp, "  - name: ");
    yaml_write_quoted(fp, listener);
    fprintf(fp, "\n    type: mixed\n    listen: ");
    yaml_write_quoted(fp, cfg->mixed_host);
    fprintf(fp, "\n    port: %d\n    proxy: ", port);
    yaml_write_quoted(fp, group);
    fprintf(fp, "\n");
  }
  fprintf(fp, "rules:\n  - MATCH,%s\n", MIHOMO_GROUP_NAME);

  if (fclose(fp) != 0) {
    mg_snprintf(error, error_len, "保存 mihomo 配置失败: %s", strerror(errno));
    unlink(tmp_path);
    return -1;
  }
  if (rename(tmp_path, cfg->config_path) != 0) {
    mg_snprintf(error, error_len, "替换 mihomo 配置失败: %s", strerror(errno));
    unlink(tmp_path);
    return -1;
  }
  return 0;
}

static bool pid_alive(pid_t pid) {
  if (pid <= 0) return false;
  if (kill(pid, 0) == 0) return true;
  return errno == EPERM;
}

static pid_t read_pid_file(const char *path) {
  FILE *fp;
  long pid = -1;
  if (path == NULL || path[0] == '\0') return -1;
  fp = fopen(path, "r");
  if (fp == NULL) return -1;
  if (fscanf(fp, "%ld", &pid) != 1) pid = -1;
  fclose(fp);
  return pid > 0 ? (pid_t) pid : -1;
}

static void write_pid_file(const char *path, pid_t pid) {
  FILE *fp;
  if (path == NULL || path[0] == '\0' || pid <= 0) return;
  fp = fopen(path, "w");
  if (fp == NULL) return;
  fprintf(fp, "%ld\n", (long) pid);
  fclose(fp);
}

static pid_t reap_tracked_status_locked(int *status_out) {
  if (s_mihomo_pid > 0) {
    int status = 0;
    pid_t waited = waitpid(s_mihomo_pid, &status, WNOHANG);
    if (waited == s_mihomo_pid) {
      if (status_out != NULL) *status_out = status;
      s_mihomo_pid = -1;
      return waited;
    }
  }
  return -1;
}

static void reap_tracked_locked(void) {
  (void) reap_tracked_status_locked(NULL);
}

static int make_cloexec_pipe(int pipefd[2]) {
  pipefd[0] = -1;
  pipefd[1] = -1;
#if defined(O_CLOEXEC) && defined(__linux__)
  if (pipe2(pipefd, O_CLOEXEC) == 0) return 0;
  if (errno != ENOSYS && errno != EINVAL) return -1;
#endif
  if (pipe(pipefd) != 0) return -1;
  if (fcntl(pipefd[0], F_SETFD, FD_CLOEXEC) != 0 ||
      fcntl(pipefd[1], F_SETFD, FD_CLOEXEC) != 0) {
    int saved = errno;
    close(pipefd[0]);
    close(pipefd[1]);
    pipefd[0] = -1;
    pipefd[1] = -1;
    errno = saved;
    return -1;
  }
  return 0;
}

static void close_if_valid(int fd) {
  if (fd >= 0) close(fd);
}

static void set_nonblocking(int fd) {
  int flags;
  if (fd < 0) return;
  flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0) (void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int read_exec_errno(int fd, int *exec_errno) {
  if (fd < 0 || exec_errno == NULL) return 0;
  for (int i = 0; i < 50; i++) {
    int value = 0;
    ssize_t n = read(fd, &value, sizeof(value));
    if (n == (ssize_t) sizeof(value)) {
      *exec_errno = value;
      return 1;
    }
    if (n == 0) return 0;
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      usleep(10000);
      continue;
    }
    return 0;
  }
  return 0;
}

static void format_start_exit_error(const struct mihomo_config *cfg, int status,
                                    char *error, size_t error_len) {
  const char *log_path = cfg && cfg->log_path[0] ? cfg->log_path : "mihomo.log";
  if (WIFEXITED(status)) {
    mg_snprintf(error, error_len,
                "mihomo 启动后立即退出(exit %d)，请检查 %s",
                WEXITSTATUS(status), log_path);
  } else if (WIFSIGNALED(status)) {
    mg_snprintf(error, error_len,
                "mihomo 启动后立即退出(signal %d)，请检查 %s",
                WTERMSIG(status), log_path);
  } else {
    mg_snprintf(error, error_len, "mihomo 启动后立即退出，请检查 %s",
                log_path);
  }
}

static void stop_pid(pid_t pid) {
  if (pid <= 0 || !pid_alive(pid)) return;
  kill(pid, SIGTERM);
  for (int i = 0; i < 30; i++) {
    if (!pid_alive(pid)) return;
    if (s_mihomo_pid == pid) {
      int status = 0;
      if (waitpid(pid, &status, WNOHANG) == pid) {
        s_mihomo_pid = -1;
        return;
      }
    }
    usleep(100000);
  }
  if (pid_alive(pid)) kill(pid, SIGKILL);
  if (s_mihomo_pid == pid) {
    int status = 0;
    waitpid(pid, &status, 0);
    s_mihomo_pid = -1;
  }
}

static void stop_locked(const struct mihomo_config *cfg) {
  pid_t file_pid = cfg ? read_pid_file(cfg->pid_path) : -1;
  reap_tracked_locked();
  if (s_mihomo_pid > 0) stop_pid(s_mihomo_pid);
  if (file_pid > 0 && file_pid != s_mihomo_pid) stop_pid(file_pid);
  if (cfg != NULL) unlink(cfg->pid_path);
  s_mihomo_pid = -1;
}

static void stop_tracked_locked(const struct mihomo_config *cfg) {
  pid_t tracked_pid = s_mihomo_pid;
  pid_t file_pid = cfg ? read_pid_file(cfg->pid_path) : -1;
  reap_tracked_locked();
  if (s_mihomo_pid > 0) stop_pid(s_mihomo_pid);
  if (cfg != NULL && tracked_pid > 0 && file_pid == tracked_pid) {
    unlink(cfg->pid_path);
  }
  s_mihomo_pid = -1;
}

static void controller_error_message(const struct http_client_response *res,
                                     char *error, size_t error_len) {
  char *message = NULL;
  if (error_len == 0) return;
  if (res != NULL && res->body != NULL && res->body[0] != '\0') {
    struct mg_str body = mg_str(res->body);
    message = mg_json_get_str(body, "$.message");
    if (message == NULL) message = mg_json_get_str(body, "$.error");
  }
  if (message != NULL && message[0] != '\0') {
    mg_snprintf(error, error_len, "%s", message);
    mg_free(message);
    return;
  }
  mg_free(message);
  if (res != NULL && res->body != NULL && res->body[0] != '\0') {
    char preview[160];
    size_t n = res->body_len;
    if (n >= sizeof(preview)) n = sizeof(preview) - 1;
    memcpy(preview, res->body, n);
    preview[n] = '\0';
    mg_snprintf(error, error_len, "%s", preview);
  } else {
    mg_snprintf(error, error_len, "Mihomo controller 请求失败");
  }
}

static int controller_request(const struct mihomo_config *cfg,
                              const char *method, const char *path,
                              const char *body,
                              struct http_client_response *res, char *error,
                              size_t error_len) {
  struct http_client_request req;
  struct http_client_header headers[3];
  char url[1024];
  char auth_header[192];
  size_t header_count = 0;

  if (res != NULL) memset(res, 0, sizeof(*res));
  if (cfg == NULL || cfg->controller_host[0] == '\0' ||
      cfg->controller_port <= 0 || path == NULL || path[0] != '/') {
    mg_snprintf(error, error_len, "Mihomo controller 地址无效");
    return -1;
  }

  memset(&req, 0, sizeof(req));
  mg_snprintf(url, sizeof(url), "http://%s:%d%s", cfg->controller_host,
              cfg->controller_port, path);
  if (cfg->controller_secret[0] != '\0') {
    mg_snprintf(auth_header, sizeof(auth_header), "Bearer %s",
                cfg->controller_secret);
    headers[header_count].name = "Authorization";
    headers[header_count].value = auth_header;
    header_count++;
  }
  headers[header_count].name = "Accept";
  headers[header_count].value = "application/json";
  header_count++;
  if (body != NULL) {
    headers[header_count].name = "Content-Type";
    headers[header_count].value = "application/json";
    header_count++;
  }
  req.method = method ? method : "GET";
  req.url = url;
  req.body = body;
  req.body_len = body ? strlen(body) : 0;
  req.timeout_ms = MIHOMO_CONTROLLER_TIMEOUT_MS;
  req.headers = headers;
  req.num_headers = header_count;

  if (http_client_perform(&req, res) != 0) {
    mg_snprintf(error, error_len, "%s",
                res && res->error[0] ? res->error : "Mihomo controller 不可访问");
    return -1;
  }
  if (res->status_code < 200 || res->status_code >= 300) {
    char detail[192];
    controller_error_message(res, detail, sizeof(detail));
    mg_snprintf(error, error_len, "Mihomo controller HTTP %ld: %s",
                res->status_code, detail);
    return -1;
  }
  return 0;
}

static int controller_select_group_node(const struct mihomo_config *cfg,
                                        const char *group, const char *node,
                                        char *error, size_t error_len) {
  struct mg_iobuf body = {0, 0, 0, 128};
  struct http_client_response res;
  char path[128];
  int rc;

  if (group == NULL || group[0] == '\0') {
    mg_snprintf(error, error_len, "Mihomo 策略组无效");
    return -1;
  }
  if (node == NULL) {
    mg_snprintf(error, error_len, "请选择订阅节点");
    return -1;
  }
  for (const char *p = node; *p != '\0'; p++) {
    if (!isspace((unsigned char) *p)) goto node_ok;
  }
  mg_snprintf(error, error_len, "请选择订阅节点");
  return -1;
node_ok:
  mg_xprintf(mg_pfn_iobuf, &body, "{%m:%m}", MG_ESC("name"), MG_ESC(node));
  mg_iobuf_add(&body, body.len, "", 1);
  mg_snprintf(path, sizeof(path), "/proxies/%s", group);
  rc = controller_request(cfg, "PUT", path, (const char *) body.buf, &res, error,
                          error_len);
  http_client_response_free(&res);
  mg_iobuf_free(&body);
  return rc;
}

static int controller_select_node(const struct mihomo_config *cfg,
                                  const char *node, char *error,
                                  size_t error_len) {
  return controller_select_group_node(cfg, MIHOMO_GROUP_NAME, node, error,
                                      error_len);
}

static int apply_selected_node_locked(const struct mihomo_config *cfg,
                                      char *error, size_t error_len) {
  int rc = -1;
  if (cfg == NULL || strcmp(cfg->group_mode, "select") != 0 ||
      cfg->selected_node[0] == '\0') {
    return 0;
  }
  for (int i = 0; i < 10; i++) {
    rc = controller_select_node(cfg, cfg->selected_node, error, error_len);
    if (rc == 0) return 0;
    usleep(300000);
  }
  return rc;
}

static int start_locked(sqlite3 *db, char *error, size_t error_len,
                        bool apply_selected_node) {
  struct mihomo_config cfg;
  pid_t pid;
  int log_fd;
  int exec_pipe[2] = {-1, -1};
  int exec_errno = 0;
  read_config(db, &cfg);
  if (!cfg.enabled || strcmp(cfg.mode, "mihomo") != 0) {
    mg_snprintf(error, error_len, "mihomo 未启用");
    return 0;
  }
  if (!cfg.managed) {
    s_last_error[0] = '\0';
    return 0;
  }
  if (write_mihomo_config(db, &cfg, error, error_len) != 0) {
    mg_snprintf(s_last_error, sizeof(s_last_error), "%s", error);
    return -1;
  }
  stop_locked(&cfg);
  (void) make_cloexec_pipe(exec_pipe);

  pid = fork();
  if (pid < 0) {
    close_if_valid(exec_pipe[0]);
    close_if_valid(exec_pipe[1]);
    mg_snprintf(error, error_len, "启动 mihomo 失败: %s", strerror(errno));
    mg_snprintf(s_last_error, sizeof(s_last_error), "%s", error);
    return -1;
  }
  if (pid == 0) {
    close_if_valid(exec_pipe[0]);
    log_fd = open(cfg.log_path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (log_fd >= 0) {
      dup2(log_fd, STDOUT_FILENO);
      dup2(log_fd, STDERR_FILENO);
      if (log_fd > STDERR_FILENO) close(log_fd);
    }
    execlp(cfg.core_path, cfg.core_path, "-d", cfg.config_dir, "-f",
           cfg.config_path, (char *) NULL);
    exec_errno = errno;
    dprintf(STDERR_FILENO, "failed to execute mihomo core %s: %s\n",
            cfg.core_path, strerror(exec_errno));
    if (exec_pipe[1] >= 0) {
      ssize_t ignored = write(exec_pipe[1], &exec_errno, sizeof(exec_errno));
      (void) ignored;
    }
    _exit(127);
  }

  close_if_valid(exec_pipe[1]);
  s_mihomo_pid = pid;
  write_pid_file(cfg.pid_path, pid);
  set_nonblocking(exec_pipe[0]);
  if (read_exec_errno(exec_pipe[0], &exec_errno)) {
    int status = 0;
    close_if_valid(exec_pipe[0]);
    (void) waitpid(pid, &status, 0);
    if (s_mihomo_pid == pid) s_mihomo_pid = -1;
    unlink(cfg.pid_path);
    mg_snprintf(error, error_len, "启动 mihomo 失败: 无法执行 %s: %s",
                cfg.core_path, strerror(exec_errno));
    mg_snprintf(s_last_error, sizeof(s_last_error), "%s", error);
    return -1;
  }
  close_if_valid(exec_pipe[0]);
  usleep(250000);
  {
    int status = 0;
    (void) reap_tracked_status_locked(&status);
    if (s_mihomo_pid <= 0) {
      format_start_exit_error(&cfg, status, error, error_len);
      unlink(cfg.pid_path);
      mg_snprintf(s_last_error, sizeof(s_last_error), "%s", error);
      return -1;
    }
  }
  if (apply_selected_node &&
      apply_selected_node_locked(&cfg, error, error_len) != 0) {
    mg_snprintf(s_last_error, sizeof(s_last_error), "%s", error);
    return -1;
  }
  s_last_error[0] = '\0';
  return 0;
}

static void json_next_field(struct mg_iobuf *out, bool *first) {
  if (*first) {
    *first = false;
  } else {
    mg_xprintf(mg_pfn_iobuf, out, ",");
  }
}

static void json_field_string(struct mg_iobuf *out, bool *first,
                              const char *key, const char *value) {
  json_next_field(out, first);
  mg_xprintf(mg_pfn_iobuf, out, "%m:%m", MG_ESC(key),
             MG_ESC(value ? value : ""));
}

static void json_field_bool(struct mg_iobuf *out, bool *first, const char *key,
                            bool value) {
  json_next_field(out, first);
  mg_xprintf(mg_pfn_iobuf, out, "%m:%s", MG_ESC(key),
             value ? "true" : "false");
}

static void json_field_int(struct mg_iobuf *out, bool *first, const char *key,
                           int value) {
  json_next_field(out, first);
  mg_xprintf(mg_pfn_iobuf, out, "%m:%d", MG_ESC(key), value);
}

static void json_field_long(struct mg_iobuf *out, bool *first, const char *key,
                            long value) {
  json_next_field(out, first);
  mg_xprintf(mg_pfn_iobuf, out, "%m:%ld", MG_ESC(key), value);
}

static void append_config_json(struct mg_iobuf *out,
                               const struct mihomo_config *cfg,
                               bool process_running, pid_t pid,
                               const char *last_error,
                               const char *subscription_text) {
  char proxy_url[256];
  bool first = true;
  mg_snprintf(proxy_url, sizeof(proxy_url), "http://%s:%d", cfg->mixed_host,
              cfg->mixed_port);
  mg_xprintf(mg_pfn_iobuf, out, "{");
  json_field_string(out, &first, "mode", cfg->mode);
  json_field_bool(out, &first, "enabled", cfg->enabled);
  json_field_bool(out, &first, "managed", cfg->managed);
  json_field_string(out, &first, "subscription_type",
                    cfg->subscription_type);
  json_field_string(out, &first, "subscription_url", cfg->subscription_url);
  json_field_string(out, &first, "subscription_text", subscription_text);
  json_field_string(out, &first, "core_path", cfg->core_path);
  json_field_string(out, &first, "config_dir", cfg->config_dir);
  json_field_string(out, &first, "mixed_host", cfg->mixed_host);
  json_field_int(out, &first, "mixed_port", cfg->mixed_port);
  json_field_string(out, &first, "controller_host", cfg->controller_host);
  json_field_int(out, &first, "controller_port", cfg->controller_port);
  json_field_string(out, &first, "strategy", cfg->strategy);
  json_field_string(out, &first, "group_mode", cfg->group_mode);
  json_field_string(out, &first, "node_filter", cfg->node_filter);
  json_field_string(out, &first, "exclude_filter",
                    cfg->node_exclude_filter);
  json_field_string(out, &first, "selected_node", cfg->selected_node);
  json_field_string(out, &first, "health_check_url", cfg->health_check_url);
  json_field_int(out, &first, "provider_interval", cfg->provider_interval);
  json_field_int(out, &first, "health_check_interval",
                 cfg->health_check_interval);
  json_field_string(out, &first, "proxy_url", proxy_url);
  json_field_string(out, &first, "config_path", cfg->config_path);
  json_field_bool(out, &first, "process_running", process_running);
  json_field_long(out, &first, "pid", (long) pid);
  json_field_string(out, &first, "log_path", cfg->log_path);
  json_field_string(out, &first, "last_error", last_error);
  json_field_string(out, &first, "group_name", MIHOMO_GROUP_NAME);
  mg_xprintf(mg_pfn_iobuf, out, "}");
}

char *mihomo_config_json(sqlite3 *db) {
  struct mihomo_config cfg;
  struct mg_iobuf out = {0, 0, 0, 1024};
  bool running;
  pid_t pid;
  char last_error[256];
  char *subscription_text;
  pthread_mutex_lock(&s_mihomo_mu);
  reap_tracked_locked();
  read_config(db, &cfg);
  subscription_text = setting_value(db, "mihomo_subscription_text", "");
  pid = s_mihomo_pid > 0 ? s_mihomo_pid : read_pid_file(cfg.pid_path);
  running = cfg.managed ? pid_alive(pid) : cfg.enabled;
  mg_snprintf(last_error, sizeof(last_error), "%s", s_last_error);
  append_config_json(&out, &cfg, running, running ? pid : -1, last_error,
                     subscription_text);
  free(subscription_text);
  pthread_mutex_unlock(&s_mihomo_mu);
  mg_iobuf_add(&out, out.len, "", 1);
  return (char *) out.buf;
}

static void save_int(sqlite3 *db, const char *key, long value) {
  char buf[32];
  mg_snprintf(buf, sizeof(buf), "%ld", value);
  upsert_setting(db, key, buf);
}

static char *json_get_trim(struct mg_str body, const char *path) {
  char *raw = mg_json_get_str(body, path);
  char *trimmed;
  char *result;
  if (raw == NULL) return NULL;
  trimmed = trim_inplace(raw);
  result = strdup(trimmed ? trimmed : "");
  mg_free(raw);
  return result;
}

char *mihomo_save_config_json(sqlite3 *db, struct mg_str body) {
  char *mode = json_get_trim(body, "$.mode");
  char *subscription_type = json_get_trim(body, "$.subscription_type");
  char *subscription_url = json_get_trim(body, "$.subscription_url");
  char *subscription_text = mg_json_get_str(body, "$.subscription_text");
  char *core_path = json_get_trim(body, "$.core_path");
  char *config_dir = json_get_trim(body, "$.config_dir");
  char *mixed_host = json_get_trim(body, "$.mixed_host");
  char *controller_host = json_get_trim(body, "$.controller_host");
  char *strategy = json_get_trim(body, "$.strategy");
  char *group_mode = json_get_trim(body, "$.group_mode");
  char *node_filter = json_get_trim(body, "$.node_filter");
  char *exclude_filter = json_get_trim(body, "$.exclude_filter");
  char *selected_node = json_get_trim(body, "$.selected_node");
  char *health_url = json_get_trim(body, "$.health_check_url");
  char normalized_mode[16];
  char normalized_subscription_type[16];
  char normalized_strategy[64];
  char normalized_group_mode[32];
  char save_error[160] = "保存 mihomo 配置失败，请检查订阅配置";
  bool enabled = false;
  bool managed = true;
  long mixed_port = mg_json_get_long(body, "$.mixed_port",
                                     MIHOMO_DEFAULT_MIXED_PORT);
  long controller_port = mg_json_get_long(body, "$.controller_port",
                                          MIHOMO_DEFAULT_CONTROLLER_PORT);
  long provider_interval = mg_json_get_long(body, "$.provider_interval",
                                            MIHOMO_DEFAULT_PROVIDER_INTERVAL);
  long health_interval = mg_json_get_long(body, "$.health_check_interval",
                                          MIHOMO_DEFAULT_HEALTH_INTERVAL);
  int rc = 0;

  mg_json_get_bool(body, "$.enabled", &enabled);
  mg_json_get_bool(body, "$.managed", &managed);
  if (subscription_type == NULL) {
    subscription_type = setting_value(db, "mihomo_subscription_type",
                                      MIHOMO_DEFAULT_SUBSCRIPTION_TYPE);
  }
  normalize_mode(mode, normalized_mode, sizeof(normalized_mode));
  normalize_subscription_type(subscription_type, normalized_subscription_type,
                              sizeof(normalized_subscription_type));
  normalize_strategy(strategy, normalized_strategy, sizeof(normalized_strategy));
  normalize_group_mode(group_mode, normalized_group_mode,
                       sizeof(normalized_group_mode));
  if (strcmp(normalized_mode, "mihomo") == 0 && enabled && managed) {
    if (strcmp(normalized_subscription_type, "text") == 0) {
      bool text_present = has_non_space(subscription_text);
      if (subscription_text == NULL) {
        char *saved_text = setting_value(db, "mihomo_subscription_text", "");
        text_present = has_non_space(saved_text);
        free(saved_text);
      }
      if (!text_present) {
        mg_snprintf(save_error, sizeof(save_error),
                    "保存 mihomo 配置失败，请粘贴订阅文本");
        rc = -1;
      }
    } else {
      bool url_present = has_non_space(subscription_url);
      if (subscription_url == NULL) {
        char *saved_url = setting_value(db, "mihomo_subscription_url", "");
        url_present = has_non_space(saved_url);
        free(saved_url);
      }
      if (!url_present) {
        mg_snprintf(save_error, sizeof(save_error),
                    "保存 mihomo 配置失败，请填写订阅链接");
        rc = -1;
      }
    }
  }

  if (rc == 0) {
    sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
    if (upsert_setting(db, "proxy_mode", normalized_mode) != 0) rc = -1;
    if (upsert_setting(db, "mihomo_enabled", enabled ? "1" : "0") != 0) rc = -1;
    if (upsert_setting(db, "mihomo_managed", managed ? "1" : "0") != 0) rc = -1;
    if (upsert_setting(db, "mihomo_subscription_type",
                       normalized_subscription_type) != 0) {
      rc = -1;
    }
    if (subscription_url != NULL &&
        upsert_setting(db, "mihomo_subscription_url", subscription_url) != 0) {
      rc = -1;
    }
    if (subscription_text != NULL &&
        upsert_setting(db, "mihomo_subscription_text", subscription_text) !=
            0) {
      rc = -1;
    }
    if (core_path != NULL && trim_inplace(core_path)[0] != '\0' &&
        upsert_setting(db, "mihomo_core_path", core_path) != 0) {
      rc = -1;
    }
    if (config_dir != NULL && trim_inplace(config_dir)[0] != '\0' &&
        upsert_setting(db, "mihomo_config_dir", config_dir) != 0) {
      rc = -1;
    }
    if (mixed_host != NULL && trim_inplace(mixed_host)[0] != '\0' &&
        upsert_setting(db, "mihomo_mixed_host", mixed_host) != 0) {
      rc = -1;
    }
    if (controller_host != NULL && trim_inplace(controller_host)[0] != '\0' &&
        upsert_setting(db, "mihomo_controller_host", controller_host) != 0) {
      rc = -1;
    }
    if (health_url != NULL && trim_inplace(health_url)[0] != '\0' &&
        upsert_setting(db, "mihomo_health_check_url", health_url) != 0) {
      rc = -1;
    }
    if (upsert_setting(db, "mihomo_strategy", normalized_strategy) != 0) rc = -1;
    if (upsert_setting(db, "mihomo_group_mode", normalized_group_mode) != 0) {
      rc = -1;
    }
    if (upsert_setting(db, "mihomo_node_filter",
                       node_filter ? node_filter : "") != 0) {
      rc = -1;
    }
    if (upsert_setting(db, "mihomo_node_exclude_filter",
                       exclude_filter ? exclude_filter : "") != 0) {
      rc = -1;
    }
    if (upsert_setting(db, "mihomo_selected_node",
                       selected_node ? selected_node : "") != 0) {
      rc = -1;
    }
    save_int(db, "mihomo_mixed_port",
             clamp_int(mixed_port, 1, 65535, MIHOMO_DEFAULT_MIXED_PORT));
    save_int(db, "mihomo_controller_port",
             clamp_int(controller_port, 1, 65535,
                       MIHOMO_DEFAULT_CONTROLLER_PORT));
    save_int(db, "mihomo_provider_interval",
             clamp_int(provider_interval, 60, 86400,
                       MIHOMO_DEFAULT_PROVIDER_INTERVAL));
    save_int(db, "mihomo_health_check_interval",
             clamp_int(health_interval, 30, 3600,
                       MIHOMO_DEFAULT_HEALTH_INTERVAL));
    sqlite3_exec(db, rc == 0 ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
  }

  free(mode);
  free(subscription_type);
  free(subscription_url);
  mg_free(subscription_text);
  free(core_path);
  free(config_dir);
  free(mixed_host);
  free(controller_host);
  free(strategy);
  free(group_mode);
  free(node_filter);
  free(exclude_filter);
  free(selected_node);
  free(health_url);
  if (rc != 0) {
    struct mg_iobuf out = {0, 0, 0, 256};
    mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC(save_error));
    mg_iobuf_add(&out, out.len, "", 1);
    return (char *) out.buf;
  }
  return mihomo_config_json(db);
}

char *mihomo_start_json(sqlite3 *db) {
  char error[256] = "";
  int rc;
  upsert_setting(db, "proxy_mode", "mihomo");
  upsert_setting(db, "mihomo_enabled", "1");
  pthread_mutex_lock(&s_mihomo_mu);
  rc = start_locked(db, error, sizeof(error), true);
  pthread_mutex_unlock(&s_mihomo_mu);
  if (rc != 0) {
    struct mg_iobuf out = {0, 0, 0, 512};
    mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC(error[0] ? error : "mihomo 启动失败"),
               MG_ESC("config"), MG_ESC(""));
    mg_iobuf_add(&out, out.len, "", 1);
    return (char *) out.buf;
  }
  return mihomo_config_json(db);
}

char *mihomo_stop_json(sqlite3 *db) {
  struct mihomo_config cfg;
  pthread_mutex_lock(&s_mihomo_mu);
  read_config(db, &cfg);
  stop_locked(&cfg);
  s_last_error[0] = '\0';
  pthread_mutex_unlock(&s_mihomo_mu);
  upsert_setting(db, "mihomo_enabled", "0");
  upsert_setting(db, "proxy_mode", "pool");
  return mihomo_config_json(db);
}

int mihomo_start_configured(sqlite3 *db) {
  char error[256] = "";
  int rc;
  pthread_mutex_lock(&s_mihomo_mu);
  rc = start_locked(db, error, sizeof(error), true);
  pthread_mutex_unlock(&s_mihomo_mu);
  return rc;
}

int mihomo_current_proxy_mode(sqlite3 *db, char *mode, size_t mode_len) {
  char *value;
  if (mode != NULL && mode_len > 0) mode[0] = '\0';
  if (db == NULL || mode == NULL || mode_len == 0) return -1;
  value = setting_value(db, "proxy_mode", MIHOMO_DEFAULT_MODE);
  normalize_mode(value, mode, mode_len);
  free(value);
  return 0;
}

void mihomo_shutdown(sqlite3 *db) {
  struct mihomo_config cfg;
  pthread_mutex_lock(&s_mihomo_mu);
  if (db != NULL) {
    read_config(db, &cfg);
  } else {
    memset(&cfg, 0, sizeof(cfg));
    mg_snprintf(cfg.config_dir, sizeof(cfg.config_dir), "%s",
                MIHOMO_DEFAULT_CONFIG_DIR);
    build_paths(&cfg);
  }
  stop_tracked_locked(&cfg);
  pthread_mutex_unlock(&s_mihomo_mu);
}

int mihomo_proxy_pick_url(sqlite3 *db, char *url, size_t url_len,
                          int *handled) {
  struct mihomo_config cfg;
  if (handled != NULL) *handled = 0;
  if (url != NULL && url_len > 0) url[0] = '\0';
  if (db == NULL || url == NULL || url_len == 0) return -1;
  read_config(db, &cfg);
  if (strcmp(cfg.mode, "direct") == 0) {
    if (handled != NULL) *handled = 1;
    return 0;
  }
  if (strcmp(cfg.mode, "mihomo") != 0) return 0;
  if (!cfg.enabled) return 0;
  if (handled != NULL) *handled = 1;
  if (cfg.mixed_host[0] == '\0' || cfg.mixed_port <= 0) return -1;
  mg_snprintf(url, url_len, "http://%s:%d", cfg.mixed_host, cfg.mixed_port);
  return 1;
}

static bool is_usable_mihomo_node(const char *node) {
  return node != NULL && node[0] != '\0' && strcasecmp(node, "DIRECT") != 0 &&
         strcasecmp(node, "REJECT") != 0;
}

static void free_node_list(char **nodes, size_t count) {
  if (nodes == NULL) return;
  for (size_t i = 0; i < count; i++) free(nodes[i]);
  free(nodes);
}

static int load_group_nodes(const struct mihomo_config *cfg, const char *group,
                            char ***out_nodes, size_t *out_count, char *error,
                            size_t error_len) {
  struct http_client_response res;
  struct mg_str all;
  char path[128];
  size_t ofs = 0;
  char **nodes = NULL;
  size_t len = 0, cap = 0;

  if (out_nodes != NULL) *out_nodes = NULL;
  if (out_count != NULL) *out_count = 0;
  if (cfg == NULL || group == NULL || group[0] == '\0') return -1;
  mg_snprintf(path, sizeof(path), "/proxies/%s", group);
  if (controller_request(cfg, "GET", path, NULL, &res, error, error_len) != 0) {
    http_client_response_free(&res);
    return -1;
  }

  {
    struct mg_str body = mg_str(res.body ? res.body : "");
    all = mg_json_get_tok(body, "$.all");
    if (all.len == 0) all = mg_json_get_tok(body, "$.proxies");
  }

  while (all.len > 0) {
    struct mg_str key, val;
    char *node;
    ofs = mg_json_next(all, ofs, &key, &val);
    if (ofs == 0) break;
    node = mg_json_get_str(val, "$");
    if (!is_usable_mihomo_node(node)) {
      mg_free(node);
      continue;
    }
    if (len == cap) {
      size_t next_cap = cap == 0 ? 32 : cap * 2;
      char **next = (char **) realloc(nodes, next_cap * sizeof(*nodes));
      if (next == NULL) {
        mg_free(node);
        free_node_list(nodes, len);
        http_client_response_free(&res);
        mg_snprintf(error, error_len, "读取 Mihomo 节点内存不足");
        return -1;
      }
      nodes = next;
      cap = next_cap;
    }
    nodes[len] = strdup(node);
    mg_free(node);
    if (nodes[len] == NULL) {
      free_node_list(nodes, len);
      http_client_response_free(&res);
      mg_snprintf(error, error_len, "读取 Mihomo 节点内存不足");
      return -1;
    }
    len++;
  }
  http_client_response_free(&res);
  if (out_nodes != NULL) *out_nodes = nodes;
  else free_node_list(nodes, len);
  if (out_count != NULL) *out_count = len;
  return 0;
}

static int find_task_slot_locked(const char *task_id) {
  if (task_id == NULL || task_id[0] == '\0') return -1;
  for (int i = 0; i < MIHOMO_TASK_SLOT_COUNT; i++) {
    if (s_task_slots[i].used &&
        strcmp(s_task_slots[i].task_id, task_id) == 0) {
      return i;
    }
  }
  return -1;
}

static int allocate_task_slot_locked(const char *task_id) {
  int slot = find_task_slot_locked(task_id);
  if (slot >= 0) return slot;
  if (task_id == NULL || task_id[0] == '\0') return -1;
  for (int i = 0; i < MIHOMO_TASK_SLOT_COUNT; i++) {
    if (!s_task_slots[i].used) {
      memset(&s_task_slots[i], 0, sizeof(s_task_slots[i]));
      s_task_slots[i].used = true;
      mg_snprintf(s_task_slots[i].task_id, sizeof(s_task_slots[i].task_id),
                  "%s", task_id);
      return i;
    }
  }
  return -1;
}

static bool trim_copy_node(const char *value, char *out, size_t out_len) {
  char buf[512];
  char *trimmed;
  if (out_len == 0) return false;
  out[0] = '\0';
  mg_snprintf(buf, sizeof(buf), "%s", value ? value : "");
  trimmed = trim_inplace(buf);
  if (trimmed == NULL || trimmed[0] == '\0') return false;
  mg_snprintf(out, out_len, "%s", trimmed);
  return true;
}

static bool node_list_contains(char **nodes, size_t count, const char *node) {
  if (nodes == NULL || node == NULL) return false;
  for (size_t i = 0; i < count; i++) {
    if (nodes[i] != NULL && strcmp(nodes[i], node) == 0) return true;
  }
  return false;
}

static int ensure_mihomo_runtime_locked(sqlite3 *db, struct mihomo_config *cfg,
                                        char *error, size_t error_len) {
  if (cfg == NULL) return -1;
  read_config(db, cfg);
  if (strcmp(cfg->mode, "mihomo") != 0 || !cfg->enabled) {
    mg_snprintf(error, error_len, "Mihomo 代理模式未启用，不能为任务指定订阅节点");
    return 0;
  }
  if (cfg->managed) {
    pid_t pid = s_mihomo_pid > 0 ? s_mihomo_pid : read_pid_file(cfg->pid_path);
    if (!pid_alive(pid)) {
      if (start_locked(db, error, error_len, false) != 0) return -1;
      read_config(db, cfg);
    }
  }
  return 1;
}

static int ensure_group_has_node_locked(const struct mihomo_config *cfg,
                                        const char *node, char *error,
                                        size_t error_len) {
  char **nodes = NULL;
  size_t count = 0;
  int rc;
  if (cfg == NULL || node == NULL || node[0] == '\0') return -1;
  rc = load_group_nodes(cfg, MIHOMO_GROUP_NAME, &nodes, &count, error,
                        error_len);
  if (rc == 0 && count == 0) {
    mg_snprintf(error, error_len, "Mihomo 订阅节点为空，无法选择节点");
    rc = -1;
  } else if (rc == 0 && !node_list_contains(nodes, count, node)) {
    mg_snprintf(error, error_len, "Mihomo 订阅节点不存在或未参与当前节点组: %s",
                node);
    rc = -1;
  }
  free_node_list(nodes, count);
  return rc;
}

int mihomo_task_node_validate(sqlite3 *db, const char *preferred_node,
                              char *normalized_node,
                              size_t normalized_node_len, char *error,
                              size_t error_len) {
  struct mihomo_config cfg;
  char requested[512];
  bool has_requested;
  int rc;

  if (normalized_node != NULL && normalized_node_len > 0) {
    normalized_node[0] = '\0';
  }
  if (error != NULL && error_len > 0) error[0] = '\0';
  has_requested = trim_copy_node(preferred_node, requested, sizeof(requested));
  if (!has_requested) return 0;
  if (!is_usable_mihomo_node(requested)) {
    mg_snprintf(error, error_len, "请选择订阅节点，不能选择 DIRECT/REJECT");
    return -1;
  }
  if (db == NULL) {
    mg_snprintf(error, error_len, "Mihomo 节点校验参数无效");
    return -1;
  }

  pthread_mutex_lock(&s_mihomo_mu);
  rc = ensure_mihomo_runtime_locked(db, &cfg, error, error_len);
  if (rc > 0) {
    rc = ensure_group_has_node_locked(&cfg, requested, error, error_len) == 0
             ? 1
             : -1;
  }
  pthread_mutex_unlock(&s_mihomo_mu);
  if (rc <= 0) return -1;

  if (normalized_node != NULL && normalized_node_len > 0) {
    mg_snprintf(normalized_node, normalized_node_len, "%s", requested);
  }
  return 1;
}

int mihomo_task_proxy_pick_url(sqlite3 *db, const char *task_id,
                               const char *preferred_node, char *url,
                               size_t url_len, char *selected_node,
                               size_t selected_node_len, char *error,
                               size_t error_len) {
  struct mihomo_config cfg;
  char requested[512];
  char node[512];
  char group[96];
  int slot = -1;
  int port = -1;
  int rc = 0;
  bool has_requested;

  if (url != NULL && url_len > 0) url[0] = '\0';
  if (selected_node != NULL && selected_node_len > 0) selected_node[0] = '\0';
  if (error != NULL && error_len > 0) error[0] = '\0';
  if (db == NULL || task_id == NULL || task_id[0] == '\0' || url == NULL ||
      url_len == 0) {
    mg_snprintf(error, error_len, "Mihomo 任务代理参数无效");
    return -1;
  }

  has_requested = trim_copy_node(preferred_node, requested, sizeof(requested));
  if (has_requested && !is_usable_mihomo_node(requested)) {
    mg_snprintf(error, error_len, "请选择订阅节点，不能选择 DIRECT/REJECT");
    return -1;
  }

  pthread_mutex_lock(&s_mihomo_mu);
  rc = ensure_mihomo_runtime_locked(db, &cfg, error, error_len);
  if (rc < 0) {
    pthread_mutex_unlock(&s_mihomo_mu);
    return -1;
  }
  if (rc == 0) {
    pthread_mutex_unlock(&s_mihomo_mu);
    if (has_requested) return -1;
    return 0;
  }

  if (has_requested &&
      ensure_group_has_node_locked(&cfg, requested, error, error_len) != 0) {
    pthread_mutex_unlock(&s_mihomo_mu);
    return -1;
  }

  slot = allocate_task_slot_locked(task_id);
  if (slot < 0) {
    pthread_mutex_unlock(&s_mihomo_mu);
    mg_snprintf(error, error_len, "Mihomo 任务代理入口已用完，请稍后再试");
    return -1;
  }
  port = task_slot_port(&cfg, slot);
  if (port <= 0) {
    s_task_slots[slot].used = false;
    pthread_mutex_unlock(&s_mihomo_mu);
    mg_snprintf(error, error_len, "Mihomo 任务代理端口不足，请调低 Mixed Port");
    return -1;
  }

  node[0] = '\0';
  if (has_requested) {
    mg_snprintf(node, sizeof(node), "%s", requested);
  } else if (s_task_slots[slot].node[0] != '\0') {
    mg_snprintf(node, sizeof(node), "%s", s_task_slots[slot].node);
  } else {
    char **nodes = NULL;
    size_t count = 0;
    uint64_t r = 0;
    if (load_group_nodes(&cfg, MIHOMO_GROUP_NAME, &nodes, &count, error,
                         error_len) != 0 ||
        count == 0) {
      free_node_list(nodes, count);
      s_task_slots[slot].used = false;
      pthread_mutex_unlock(&s_mihomo_mu);
      if (error != NULL && error[0] == '\0') {
        mg_snprintf(error, error_len, "Mihomo 订阅节点为空，无法随机选择");
      }
      return -1;
    }
    if (!mg_random(&r, sizeof(r))) r = (uint64_t) time(NULL);
    mg_snprintf(node, sizeof(node), "%s", nodes[r % count]);
    free_node_list(nodes, count);
  }

  task_group_name(slot, group, sizeof(group));
  rc = controller_select_group_node(&cfg, group, node, error, error_len);
  if (rc != 0 && cfg.managed) {
    if (start_locked(db, error, error_len, false) == 0) {
      read_config(db, &cfg);
      rc = controller_select_group_node(&cfg, group, node, error, error_len);
    }
  }
  if (rc != 0) {
    s_task_slots[slot].used = false;
    pthread_mutex_unlock(&s_mihomo_mu);
    if (error != NULL && error[0] == '\0') {
      mg_snprintf(error, error_len, "应用任务订阅节点失败");
    }
    return -1;
  }

  mg_snprintf(s_task_slots[slot].node, sizeof(s_task_slots[slot].node), "%s",
              node);
  mg_snprintf(url, url_len, "http://%s:%d", cfg.mixed_host, port);
  if (selected_node != NULL && selected_node_len > 0) {
    mg_snprintf(selected_node, selected_node_len, "%s", node);
  }
  pthread_mutex_unlock(&s_mihomo_mu);
  return 1;
}

void mihomo_task_proxy_release(const char *task_id) {
  if (task_id == NULL || task_id[0] == '\0') return;
  pthread_mutex_lock(&s_mihomo_mu);
  for (int i = 0; i < MIHOMO_TASK_SLOT_COUNT; i++) {
    if (s_task_slots[i].used &&
        strcmp(s_task_slots[i].task_id, task_id) == 0) {
      memset(&s_task_slots[i], 0, sizeof(s_task_slots[i]));
      break;
    }
  }
  pthread_mutex_unlock(&s_mihomo_mu);
}

static void trace_value(const char *body, const char *key, char *out,
                        size_t out_len) {
  const char *p;
  size_t key_len, len = 0;
  if (out == NULL || out_len == 0) return;
  out[0] = '\0';
  if (body == NULL || key == NULL) return;
  key_len = strlen(key);
  for (p = body; *p; p++) {
    if ((p == body || p[-1] == '\n') && strncmp(p, key, key_len) == 0 &&
        p[key_len] == '=') {
      p += key_len + 1;
      while (p[len] && p[len] != '\r' && p[len] != '\n') len++;
      if (len >= out_len) len = out_len - 1;
      memcpy(out, p, len);
      out[len] = '\0';
      return;
    }
  }
}

static bool ip_seen(char ips[][128], size_t count, const char *ip) {
  for (size_t i = 0; i < count; i++) {
    if (strcmp(ips[i], ip) == 0) return true;
  }
  return false;
}

static char *mihomo_error_json(const char *message) {
  struct mg_iobuf out = {0, 0, 0, 256};
  mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
             MG_ESC("error"), MG_ESC(message ? message : "mihomo error"));
  mg_iobuf_add(&out, out.len, "", 1);
  return (char *) out.buf;
}

char *mihomo_sample_json(sqlite3 *db, int samples) {
  struct mihomo_config cfg;
  struct mg_iobuf out = {0, 0, 0, 1024};
  char proxy_url[256];
  char ips[64][128];
  size_t unique_count = 0;
  int limit = samples <= 0 ? 12 : samples;
  bool first = true;

  if (limit > 64) limit = 64;
  read_config(db, &cfg);
  if (!cfg.enabled || strcmp(cfg.mode, "mihomo") != 0) {
    mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("mihomo 代理模式未启用"));
    mg_iobuf_add(&out, out.len, "", 1);
    return (char *) out.buf;
  }
  mg_snprintf(proxy_url, sizeof(proxy_url), "http://%s:%d", cfg.mixed_host,
              cfg.mixed_port);
  mg_xprintf(mg_pfn_iobuf, &out, "{%m:%d,%m:%m,%m:%d,%m:[", MG_ESC("ok"), 1,
             MG_ESC("proxy_url"), MG_ESC(proxy_url), MG_ESC("samples"), limit,
             MG_ESC("items"));
  memset(ips, 0, sizeof(ips));
  for (int i = 0; i < limit; i++) {
    struct http_client_request req;
    struct http_client_response res;
    char ip[128] = "";
    char loc[32] = "";
    char colo[32] = "";
    int ok = 0;
    memset(&req, 0, sizeof(req));
    memset(&res, 0, sizeof(res));
    req.method = "GET";
    req.url = MIHOMO_TRACE_URL;
    req.proxy_url = proxy_url;
    req.timeout_ms = 15000;
    if (http_client_perform(&req, &res) == 0 && res.status_code == 200) {
      trace_value(res.body, "ip", ip, sizeof(ip));
      trace_value(res.body, "loc", loc, sizeof(loc));
      trace_value(res.body, "colo", colo, sizeof(colo));
      ok = ip[0] != '\0';
      if (ok && !ip_seen(ips, unique_count, ip) &&
          unique_count < sizeof(ips) / sizeof(ips[0])) {
        mg_snprintf(ips[unique_count++], sizeof(ips[0]), "%s", ip);
      }
    }
    mg_xprintf(mg_pfn_iobuf, &out,
               "%s{%m:%d,%m:%d,%m:%ld,%m:%m,%m:%m,%m:%m,%m:%m}",
               first ? "" : ",", MG_ESC("index"), i + 1, MG_ESC("ok"), ok,
               MG_ESC("http_status"), res.status_code, MG_ESC("exit_ip"),
               MG_ESC(ip), MG_ESC("exit_loc"), MG_ESC(loc), MG_ESC("exit_colo"),
               MG_ESC(colo), MG_ESC("error"), MG_ESC(res.error));
    first = false;
    http_client_response_free(&res);
  }
  mg_xprintf(mg_pfn_iobuf, &out, "],%m:%lu,%m:[", MG_ESC("unique_exit_count"),
             (unsigned long) unique_count, MG_ESC("unique_exit_ips"));
  for (size_t i = 0; i < unique_count; i++) {
    mg_xprintf(mg_pfn_iobuf, &out, "%s%m", i == 0 ? "" : ",",
               MG_ESC(ips[i]));
  }
  mg_xprintf(mg_pfn_iobuf, &out, "]}");
  mg_iobuf_add(&out, out.len, "", 1);
  return (char *) out.buf;
}

char *mihomo_nodes_json(sqlite3 *db) {
  struct mihomo_config cfg;
  struct http_client_response res;
  struct mg_iobuf out = {0, 0, 0, 2048};
  struct mg_str all;
  char path[128];
  char error[256] = "";
  char *now = NULL;
  char *type = NULL;
  size_t ofs = 0;
  bool first = true;
  int count = 0;

  read_config(db, &cfg);
  if (!cfg.enabled || strcmp(cfg.mode, "mihomo") != 0) {
    return mihomo_error_json("mihomo 代理模式未启用");
  }

  mg_snprintf(path, sizeof(path), "/proxies/%s", MIHOMO_GROUP_NAME);
  if (controller_request(&cfg, "GET", path, NULL, &res, error, sizeof(error)) !=
      0) {
    http_client_response_free(&res);
    return mihomo_error_json(error);
  }

  {
    struct mg_str body = mg_str(res.body ? res.body : "");
    now = mg_json_get_str(body, "$.now");
    type = mg_json_get_str(body, "$.type");
    all = mg_json_get_tok(body, "$.all");
    if (all.len == 0) all = mg_json_get_tok(body, "$.proxies");
  }

  mg_xprintf(mg_pfn_iobuf, &out,
             "{%m:%d,%m:%m,%m:%m,%m:%m,%m:%m,%m:[", MG_ESC("ok"), 1,
             MG_ESC("group_name"), MG_ESC(MIHOMO_GROUP_NAME),
             MG_ESC("group_mode"), MG_ESC(cfg.group_mode), MG_ESC("type"),
             MG_ESC(type ? type : ""), MG_ESC("now"), MG_ESC(now ? now : ""),
             MG_ESC("nodes"));
  while (all.len > 0) {
    struct mg_str key, val;
    char *node;
    ofs = mg_json_next(all, ofs, &key, &val);
    if (ofs == 0) break;
    node = mg_json_get_str(val, "$");
    if (!is_usable_mihomo_node(node)) {
      mg_free(node);
      continue;
    }
    mg_xprintf(mg_pfn_iobuf, &out, "%s%m", first ? "" : ",", MG_ESC(node));
    first = false;
    count++;
    mg_free(node);
  }
  mg_xprintf(mg_pfn_iobuf, &out, "],%m:%d}", MG_ESC("count"), count);

  mg_free(now);
  mg_free(type);
  http_client_response_free(&res);
  mg_iobuf_add(&out, out.len, "", 1);
  return (char *) out.buf;
}

char *mihomo_select_node_json(sqlite3 *db, struct mg_str body) {
  char *node = mg_json_get_str(body, "$.node");
  char *trimmed;
  struct mihomo_config cfg;
  char error[256] = "";
  int rc = 0;

  if (node == NULL) return mihomo_error_json("请选择订阅节点");
  trimmed = trim_inplace(node);
  if (trimmed == NULL || trimmed[0] == '\0') {
    mg_free(node);
    return mihomo_error_json("请选择订阅节点");
  }

  sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
  if (upsert_setting(db, "mihomo_group_mode", "select") != 0) rc = -1;
  if (upsert_setting(db, "mihomo_selected_node", trimmed) != 0) rc = -1;
  sqlite3_exec(db, rc == 0 ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
  if (rc != 0) {
    mg_free(node);
    return mihomo_error_json("保存订阅节点失败");
  }

  read_config(db, &cfg);
  if (cfg.enabled && strcmp(cfg.mode, "mihomo") == 0) {
    if (cfg.managed) {
      pthread_mutex_lock(&s_mihomo_mu);
      rc = start_locked(db, error, sizeof(error), true);
      pthread_mutex_unlock(&s_mihomo_mu);
    } else {
      rc = controller_select_node(&cfg, trimmed, error, sizeof(error));
    }
  }

  mg_free(node);
  if (rc != 0) return mihomo_error_json(error[0] ? error : "应用订阅节点失败");
  return mihomo_config_json(db);
}
