#include "auth/app_auth.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define AUTH_COOKIE_NAME "mongoose_session"
#define JSON_HEADERS "Content-Type: application/json\r\nCache-Control: no-store\r\n"
#define AUTH_DEFAULT_ITERATIONS 120000
#define AUTH_SALT_BYTES 16
#define AUTH_HASH_BYTES 32
#define AUTH_TOKEN_BYTES 32
#define AUTH_SESSION_TTL_SECONDS 43200
#define AUTH_MAX_LOGIN_FAILURES 8
#define AUTH_LOCK_SECONDS 300

static bool s_auth_disabled = false;

static bool env_truthy(const char *name) {
  const char *value = getenv(name);
  return value != NULL &&
         (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 ||
          strcmp(value, "yes") == 0 || strcmp(value, "on") == 0);
}

static long env_long(const char *name, long fallback, long min, long max) {
  char *end = NULL;
  long value;
  const char *raw = getenv(name);
  if (raw == NULL || *raw == '\0') return fallback;
  value = strtol(raw, &end, 10);
  if (end == raw) return fallback;
  if (value < min) return min;
  if (value > max) return max;
  return value;
}

static time_t now_seconds(void) {
  return time(NULL);
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out,
                         size_t out_len) {
  static const char hex[] = "0123456789abcdef";
  size_t i;
  if (out_len == 0) return;
  if (out_len < len * 2 + 1) {
    out[0] = '\0';
    return;
  }
  for (i = 0; i < len; i++) {
    out[i * 2] = hex[(bytes[i] >> 4) & 0xf];
    out[i * 2 + 1] = hex[bytes[i] & 0xf];
  }
  out[len * 2] = '\0';
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
  size_t i;
  if (hex == NULL || strlen(hex) != out_len * 2) return -1;
  for (i = 0; i < out_len; i++) {
    int hi = isdigit((unsigned char) hex[i * 2])
                 ? hex[i * 2] - '0'
                 : 10 + tolower((unsigned char) hex[i * 2]) - 'a';
    int lo = isdigit((unsigned char) hex[i * 2 + 1])
                 ? hex[i * 2 + 1] - '0'
                 : 10 + tolower((unsigned char) hex[i * 2 + 1]) - 'a';
    if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return -1;
    out[i] = (uint8_t) ((hi << 4) | lo);
  }
  return 0;
}

static bool constant_time_eq(const char *a, const char *b) {
  size_t alen = a ? strlen(a) : 0;
  size_t blen = b ? strlen(b) : 0;
  size_t len = alen > blen ? alen : blen;
  unsigned char diff = (unsigned char) (alen ^ blen);
  size_t i;
  for (i = 0; i < len; i++) {
    unsigned char ac = i < alen ? (unsigned char) a[i] : 0;
    unsigned char bc = i < blen ? (unsigned char) b[i] : 0;
    diff |= (unsigned char) (ac ^ bc);
  }
  return diff == 0;
}

static void pbkdf2_sha256(const char *password, const uint8_t *salt,
                          size_t salt_len, int iterations,
                          uint8_t out[AUTH_HASH_BYTES]) {
  uint8_t u[AUTH_HASH_BYTES], t[AUTH_HASH_BYTES];
  uint8_t block[AUTH_SALT_BYTES + 4];
  size_t password_len = password ? strlen(password) : 0;
  int i, j;

  memset(block, 0, sizeof(block));
  if (salt_len > AUTH_SALT_BYTES) salt_len = AUTH_SALT_BYTES;
  memcpy(block, salt, salt_len);
  block[salt_len + 0] = 0;
  block[salt_len + 1] = 0;
  block[salt_len + 2] = 0;
  block[salt_len + 3] = 1;

  mg_hmac_sha256(u, (uint8_t *) password, password_len, block, salt_len + 4);
  memcpy(t, u, sizeof(t));
  for (i = 1; i < iterations; i++) {
    mg_hmac_sha256(u, (uint8_t *) password, password_len, u, sizeof(u));
    for (j = 0; j < (int) sizeof(t); j++) t[j] ^= u[j];
  }
  memcpy(out, t, AUTH_HASH_BYTES);
}

static void password_hash_hex(const char *password, const char *salt_hex,
                              int iterations, char *out, size_t out_len) {
  uint8_t salt[AUTH_SALT_BYTES], hash[AUTH_HASH_BYTES];
  if (hex_to_bytes(salt_hex, salt, sizeof(salt)) != 0) {
    if (out_len > 0) out[0] = '\0';
    return;
  }
  pbkdf2_sha256(password, salt, sizeof(salt), iterations, hash);
  bytes_to_hex(hash, sizeof(hash), out, out_len);
}

static void token_hash_hex(const char *token, char *out, size_t out_len) {
  uint8_t hash[AUTH_HASH_BYTES];
  mg_sha256(hash, (uint8_t *) token, token ? strlen(token) : 0);
  bytes_to_hex(hash, sizeof(hash), out, out_len);
}

static int random_hex(size_t bytes_len, char *out, size_t out_len) {
  uint8_t bytes[64];
  if (bytes_len > sizeof(bytes)) return -1;
  if (!mg_random(bytes, bytes_len)) return -1;
  bytes_to_hex(bytes, bytes_len, out, out_len);
  return 0;
}

static int scalar_long(sqlite3 *db, const char *sql) {
  sqlite3_stmt *stmt = NULL;
  int value = 0;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK &&
      sqlite3_step(stmt) == SQLITE_ROW) {
    value = sqlite3_column_int(stmt, 0);
  }
  sqlite3_finalize(stmt);
  return value;
}

static int exec_sql(sqlite3 *db, const char *sql) {
  char *err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "auth sqlite error: %s\n", err ? err : sqlite3_errmsg(db));
    sqlite3_free(err);
    return -1;
  }
  return 0;
}

static int auth_user_count(sqlite3 *db) {
  return scalar_long(db, "SELECT count(*) FROM auth_users");
}

static int create_admin_user(sqlite3 *db, const char *username,
                             const char *password) {
  sqlite3_stmt *stmt = NULL;
  char salt_hex[AUTH_SALT_BYTES * 2 + 1];
  char hash_hex[AUTH_HASH_BYTES * 2 + 1];
  int iterations =
      (int) env_long("APP_PASSWORD_ITERATIONS", AUTH_DEFAULT_ITERATIONS, 50000,
                     600000);
  int rc;

  if (random_hex(AUTH_SALT_BYTES, salt_hex, sizeof(salt_hex)) != 0) return -1;
  password_hash_hex(password, salt_hex, iterations, hash_hex, sizeof(hash_hex));

  rc = sqlite3_prepare_v2(
      db,
      "INSERT INTO auth_users(username,password_hash,password_salt,iterations) "
      "VALUES(?,?,?,?)",
      -1, &stmt, NULL);
  if (rc != SQLITE_OK) return -1;
  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, hash_hex, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, salt_hex, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 4, iterations);
  rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
  sqlite3_finalize(stmt);
  return rc;
}

static int reset_admin_password(sqlite3 *db, const char *username,
                                const char *password) {
  sqlite3_stmt *stmt = NULL;
  char salt_hex[AUTH_SALT_BYTES * 2 + 1];
  char hash_hex[AUTH_HASH_BYTES * 2 + 1];
  int iterations =
      (int) env_long("APP_PASSWORD_ITERATIONS", AUTH_DEFAULT_ITERATIONS, 50000,
                     600000);
  int rc;

  if (random_hex(AUTH_SALT_BYTES, salt_hex, sizeof(salt_hex)) != 0) return -1;
  password_hash_hex(password, salt_hex, iterations, hash_hex, sizeof(hash_hex));

  rc = sqlite3_prepare_v2(
      db,
      "INSERT INTO auth_users(username,password_hash,password_salt,iterations) "
      "VALUES(?,?,?,?) "
      "ON CONFLICT(username) DO UPDATE SET "
      "password_hash=excluded.password_hash,"
      "password_salt=excluded.password_salt,"
      "iterations=excluded.iterations,"
      "updated_at=unixepoch()",
      -1, &stmt, NULL);
  if (rc != SQLITE_OK) return -1;
  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, hash_hex, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, salt_hex, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 4, iterations);
  rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
  sqlite3_finalize(stmt);

  if (rc == 0 &&
      sqlite3_prepare_v2(
          db,
          "DELETE FROM auth_sessions WHERE user_id=("
          "SELECT id FROM auth_users WHERE username=? COLLATE NOCASE)",
          -1, &stmt, NULL) == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
  }
  return rc;
}

static void get_request_ip(struct mg_connection *c, struct mg_http_message *hm,
                           char *out, size_t out_len) {
  struct mg_str *xff = mg_http_get_header(hm, "X-Forwarded-For");
  if (out_len == 0) return;
  out[0] = '\0';
  if (env_truthy("APP_TRUST_PROXY") && xff != NULL && xff->len > 0) {
    size_t n = 0;
    while (n < xff->len && xff->buf[n] != ',' && !isspace((unsigned char) xff->buf[n])) n++;
    if (n >= out_len) n = out_len - 1;
    memcpy(out, xff->buf, n);
    out[n] = '\0';
    return;
  }
  mg_snprintf(out, out_len, "%M", mg_print_ip, &c->rem);
}

static void get_user_agent(struct mg_http_message *hm, char *out,
                           size_t out_len) {
  struct mg_str *ua = mg_http_get_header(hm, "User-Agent");
  if (out_len == 0) return;
  out[0] = '\0';
  if (ua != NULL && ua->len > 0) {
    mg_snprintf(out, out_len, "%.*s", (int) ua->len, ua->buf);
  }
}

static bool get_cookie_token(struct mg_http_message *hm, char *out,
                             size_t out_len) {
  struct mg_str *cookie = mg_http_get_header(hm, "Cookie");
  struct mg_str value;
  if (out_len == 0) return false;
  out[0] = '\0';
  if (cookie == NULL) return false;
  value = mg_http_get_header_var(*cookie, mg_str(AUTH_COOKIE_NAME));
  if (value.len == 0 || value.len >= out_len) return false;
  mg_snprintf(out, out_len, "%.*s", (int) value.len, value.buf);
  return true;
}

static bool current_user(sqlite3 *db, struct mg_http_message *hm, long *user_id,
                         char *username, size_t username_len) {
  char token[AUTH_TOKEN_BYTES * 2 + 1];
  char token_hash[AUTH_HASH_BYTES * 2 + 1];
  sqlite3_stmt *stmt = NULL;
  bool ok = false;

  if (!get_cookie_token(hm, token, sizeof(token))) return false;
  token_hash_hex(token, token_hash, sizeof(token_hash));
  if (sqlite3_prepare_v2(
          db,
          "SELECT u.id,u.username FROM auth_sessions s "
          "JOIN auth_users u ON u.id=s.user_id "
          "WHERE s.token_hash=? AND s.expires_at>unixepoch()",
          -1, &stmt, NULL) != SQLITE_OK) {
    return false;
  }
  sqlite3_bind_text(stmt, 1, token_hash, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *name = sqlite3_column_text(stmt, 1);
    if (user_id != NULL) *user_id = sqlite3_column_int64(stmt, 0);
    if (username != NULL && username_len > 0) {
      mg_snprintf(username, username_len, "%s", name ? (const char *) name : "");
    }
    ok = true;
  }
  sqlite3_finalize(stmt);
  return ok;
}

static void cleanup_expired_sessions(sqlite3 *db) {
  exec_sql(db, "DELETE FROM auth_sessions WHERE expires_at<=unixepoch()");
}

static bool login_locked(sqlite3 *db, const char *ip, long *remaining_seconds) {
  sqlite3_stmt *stmt = NULL;
  long locked_until = 0;
  time_t now = now_seconds();
  if (remaining_seconds != NULL) *remaining_seconds = 0;
  if (sqlite3_prepare_v2(
          db, "SELECT locked_until FROM auth_login_attempts WHERE ip_address=?",
          -1, &stmt, NULL) != SQLITE_OK) {
    return false;
  }
  sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    locked_until = sqlite3_column_int64(stmt, 0);
  }
  sqlite3_finalize(stmt);
  if (locked_until > (long) now) {
    if (remaining_seconds != NULL) *remaining_seconds = locked_until - now;
    return true;
  }
  return false;
}

static void record_login_failure(sqlite3 *db, const char *ip) {
  sqlite3_stmt *stmt = NULL;
  int count = 0;
  long locked_until = 0;

  if (sqlite3_prepare_v2(
          db,
          "SELECT failed_count FROM auth_login_attempts WHERE ip_address=?",
          -1, &stmt, NULL) == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
  }
  sqlite3_finalize(stmt);

  count++;
  if (count >= AUTH_MAX_LOGIN_FAILURES) locked_until = now_seconds() + AUTH_LOCK_SECONDS;
  if (sqlite3_prepare_v2(
          db,
          "INSERT INTO auth_login_attempts(ip_address,failed_count,locked_until,"
          "updated_at) VALUES(?,?,?,unixepoch()) "
          "ON CONFLICT(ip_address) DO UPDATE SET "
          "failed_count=excluded.failed_count,"
          "locked_until=excluded.locked_until,updated_at=unixepoch()",
          -1, &stmt, NULL) != SQLITE_OK) {
    return;
  }
  sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 2, count);
  sqlite3_bind_int64(stmt, 3, locked_until);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

static void clear_login_failures(sqlite3 *db, const char *ip) {
  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2(db,
                         "DELETE FROM auth_login_attempts WHERE ip_address=?",
                         -1, &stmt, NULL) != SQLITE_OK) {
    return;
  }
  sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

static bool verify_password(sqlite3 *db, const char *username,
                            const char *password, long *user_id,
                            char *stored_username,
                            size_t stored_username_len) {
  sqlite3_stmt *stmt = NULL;
  char expected[AUTH_HASH_BYTES * 2 + 1] = "";
  char salt[AUTH_SALT_BYTES * 2 + 1] = "";
  char actual[AUTH_HASH_BYTES * 2 + 1] = "";
  int iterations = AUTH_DEFAULT_ITERATIONS;
  bool ok = false;

  if (sqlite3_prepare_v2(
          db,
          "SELECT id,username,password_hash,password_salt,iterations "
          "FROM auth_users WHERE username=? COLLATE NOCASE",
          -1, &stmt, NULL) != SQLITE_OK) {
    return false;
  }
  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *db_user = sqlite3_column_text(stmt, 1);
    const unsigned char *db_hash = sqlite3_column_text(stmt, 2);
    const unsigned char *db_salt = sqlite3_column_text(stmt, 3);
    if (user_id != NULL) *user_id = sqlite3_column_int64(stmt, 0);
    if (stored_username != NULL && stored_username_len > 0) {
      mg_snprintf(stored_username, stored_username_len, "%s",
                  db_user ? (const char *) db_user : "");
    }
    mg_snprintf(expected, sizeof(expected), "%s",
                db_hash ? (const char *) db_hash : "");
    mg_snprintf(salt, sizeof(salt), "%s", db_salt ? (const char *) db_salt : "");
    iterations = sqlite3_column_int(stmt, 4);
    if (iterations < 50000) iterations = 50000;
  }
  sqlite3_finalize(stmt);
  if (expected[0] == '\0' || salt[0] == '\0') return false;
  password_hash_hex(password, salt, iterations, actual, sizeof(actual));
  ok = constant_time_eq(expected, actual);
  return ok;
}

static int create_session(sqlite3 *db, long user_id, const char *ip,
                          const char *user_agent, char *token,
                          size_t token_len, long *ttl_seconds) {
  sqlite3_stmt *stmt = NULL;
  char token_hash[AUTH_HASH_BYTES * 2 + 1];
  long ttl =
      env_long("APP_SESSION_TTL_SECONDS", AUTH_SESSION_TTL_SECONDS, 3600,
               60L * 60L * 24L * 30L);
  long expires_at = now_seconds() + ttl;
  int rc;

  if (random_hex(AUTH_TOKEN_BYTES, token, token_len) != 0) return -1;
  token_hash_hex(token, token_hash, sizeof(token_hash));
  rc = sqlite3_prepare_v2(
      db,
      "INSERT INTO auth_sessions(user_id,token_hash,ip_address,user_agent,"
      "expires_at,last_seen_at) VALUES(?,?,?,?,?,unixepoch())",
      -1, &stmt, NULL);
  if (rc != SQLITE_OK) return -1;
  sqlite3_bind_int64(stmt, 1, user_id);
  sqlite3_bind_text(stmt, 2, token_hash, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, ip, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, user_agent, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 5, expires_at);
  rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
  sqlite3_finalize(stmt);
  if (rc == 0) {
    sqlite3_stmt *u = NULL;
    if (sqlite3_prepare_v2(
            db, "UPDATE auth_users SET last_login_at=unixepoch() WHERE id=?",
            -1, &u, NULL) == SQLITE_OK) {
      sqlite3_bind_int64(u, 1, user_id);
      sqlite3_step(u);
    }
    sqlite3_finalize(u);
    if (ttl_seconds != NULL) *ttl_seconds = ttl;
  }
  return rc;
}

static void delete_session(sqlite3 *db, struct mg_http_message *hm) {
  char token[AUTH_TOKEN_BYTES * 2 + 1];
  char token_hash[AUTH_HASH_BYTES * 2 + 1];
  sqlite3_stmt *stmt = NULL;
  if (!get_cookie_token(hm, token, sizeof(token))) return;
  token_hash_hex(token, token_hash, sizeof(token_hash));
  if (sqlite3_prepare_v2(db, "DELETE FROM auth_sessions WHERE token_hash=?",
                         -1, &stmt, NULL) != SQLITE_OK) {
    return;
  }
  sqlite3_bind_text(stmt, 1, token_hash, -1, SQLITE_TRANSIENT);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

static bool cookie_should_be_secure(struct mg_http_message *hm) {
  struct mg_str *proto;
  const char *env = getenv("APP_COOKIE_SECURE");
  if (env != NULL && *env != '\0') return env_truthy("APP_COOKIE_SECURE");
  proto = mg_http_get_header(hm, "X-Forwarded-Proto");
  return proto != NULL && proto->len == 5 && memcmp(proto->buf, "https", 5) == 0;
}

static void reply_login_ok(struct mg_connection *c, struct mg_http_message *hm,
                           const char *token, long ttl_seconds,
                           const char *username) {
  char headers[512];
  mg_snprintf(headers, sizeof(headers),
              JSON_HEADERS
              "Set-Cookie: %s=%s; Path=/; Max-Age=%ld; HttpOnly; SameSite=Lax%s\r\n",
              AUTH_COOKIE_NAME, token, ttl_seconds,
              cookie_should_be_secure(hm) ? "; Secure" : "");
  mg_http_reply(c, 200, headers,
                "{%m:%d,%m:{%m:%m},%m:%ld}\n", MG_ESC("ok"), 1,
                MG_ESC("user"), MG_ESC("username"), MG_ESC(username),
                MG_ESC("expires_in"), ttl_seconds);
}

static void reply_logout_ok(struct mg_connection *c, struct mg_http_message *hm) {
  char headers[384];
  mg_snprintf(headers, sizeof(headers),
              JSON_HEADERS
              "Set-Cookie: %s=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax%s\r\n",
              AUTH_COOKIE_NAME,
              cookie_should_be_secure(hm) ? "; Secure" : "");
  mg_http_reply(c, 200, headers, "{%m:%d}\n", MG_ESC("ok"), 1);
}

int app_auth_init(sqlite3 *db) {
  const char *username = getenv("APP_ADMIN_USER");
  const char *password = getenv("APP_ADMIN_PASSWORD");

  s_auth_disabled = env_truthy("APP_AUTH_DISABLED");
  if (s_auth_disabled) {
    fprintf(stderr, "Auth is disabled by APP_AUTH_DISABLED=1\n");
    return 0;
  }

  cleanup_expired_sessions(db);
  if (username == NULL || *username == '\0') username = "admin";
  if (env_truthy("APP_RESET_ADMIN_PASSWORD")) {
    if (password == NULL || strlen(password) < 8) {
      fprintf(stderr,
              "APP_RESET_ADMIN_PASSWORD requires APP_ADMIN_PASSWORD with at "
              "least 8 characters.\n");
      return -1;
    }
    if (reset_admin_password(db, username, password) != 0) {
      fprintf(stderr, "Cannot reset admin password\n");
      return -1;
    }
    fprintf(stderr, "Reset admin password for user: %s\n", username);
    return 0;
  }

  if (auth_user_count(db) > 0) return 0;

  if (password == NULL || strlen(password) < 8) {
    fprintf(stderr,
            "No admin user is configured. Start once with "
            "APP_ADMIN_USER=admin APP_ADMIN_PASSWORD='strong-password', "
            "or set APP_AUTH_DISABLED=1 for local-only debugging.\n");
    return -1;
  }
  if (create_admin_user(db, username, password) != 0) {
    fprintf(stderr, "Cannot create initial admin user\n");
    return -1;
  }
  fprintf(stderr, "Created initial admin user: %s\n", username);
  return 0;
}

bool app_auth_enabled(void) {
  return !s_auth_disabled;
}

bool app_auth_is_public_route(struct mg_http_message *hm) {
  if (mg_match(hm->uri, mg_str("/login"), NULL) ||
      mg_match(hm->uri, mg_str("/index.html"), NULL) ||
      mg_match(hm->uri, mg_str("/favicon.ico"), NULL)) {
    return true;
  }
  if (hm->uri.len >= 8 && memcmp(hm->uri.buf, "/assets/", 8) == 0) return true;
  if (hm->uri.len >= 10 && memcmp(hm->uri.buf, "/api/auth/", 10) == 0) return true;
  return false;
}

bool app_auth_is_authenticated(sqlite3 *db, struct mg_http_message *hm) {
  if (!app_auth_enabled()) return true;
  return current_user(db, hm, NULL, NULL, 0);
}

void app_auth_reply_unauthorized(struct mg_connection *c,
                                 struct mg_http_message *hm) {
  if (hm->uri.len >= 5 && memcmp(hm->uri.buf, "/api/", 5) == 0) {
    mg_http_reply(c, 401, JSON_HEADERS,
                  "{%m:%m,%m:%m}\n", MG_ESC("error"),
                  MG_ESC("unauthorized"), MG_ESC("message"),
                  MG_ESC("请先登录"));
  } else if (mg_match(hm->uri, mg_str("/ws"), NULL)) {
    mg_http_reply(c, 401, JSON_HEADERS,
                  "{%m:%m,%m:%m}\n", MG_ESC("error"),
                  MG_ESC("unauthorized"), MG_ESC("message"),
                  MG_ESC("WebSocket 需要登录会话"));
  } else {
    mg_http_reply(c, 302, "Location: /login\r\nCache-Control: no-store\r\n",
                  "");
  }
}

void app_auth_handle_api(sqlite3 *db, struct mg_connection *c,
                         struct mg_http_message *hm) {
  if (mg_strcmp(hm->method, mg_str("GET")) == 0 &&
      mg_match(hm->uri, mg_str("/api/auth/me"), NULL)) {
    char username[128] = "";
    bool authenticated = !app_auth_enabled() ||
                         current_user(db, hm, NULL, username, sizeof(username));
    if (!app_auth_enabled()) {
      mg_http_reply(c, 200, JSON_HEADERS,
                    "{%m:%d,%m:%d,%m:{%m:%m}}\n", MG_ESC("authenticated"), 1,
                    MG_ESC("auth_disabled"), 1, MG_ESC("user"),
                    MG_ESC("username"), MG_ESC("local-debug"));
    } else if (authenticated) {
      mg_http_reply(c, 200, JSON_HEADERS,
                    "{%m:%d,%m:{%m:%m}}\n", MG_ESC("authenticated"), 1,
                    MG_ESC("user"), MG_ESC("username"), MG_ESC(username));
    } else {
      mg_http_reply(c, 200, JSON_HEADERS, "{%m:%d}\n",
                    MG_ESC("authenticated"), 0);
    }
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/auth/login"), NULL)) {
    char *username = mg_json_get_str(hm->body, "$.username");
    char *password = mg_json_get_str(hm->body, "$.password");
    char ip[96], user_agent[256], stored_username[128] = "";
    char token[AUTH_TOKEN_BYTES * 2 + 1];
    long user_id = 0, ttl = 0, lock_remaining = 0;

    get_request_ip(c, hm, ip, sizeof(ip));
    get_user_agent(hm, user_agent, sizeof(user_agent));
    if (!app_auth_enabled()) {
      mg_free(username);
      mg_free(password);
      mg_http_reply(c, 200, JSON_HEADERS,
                    "{%m:%d,%m:{%m:%m}}\n", MG_ESC("ok"), 1,
                    MG_ESC("user"), MG_ESC("username"),
                    MG_ESC("local-debug"));
      return;
    }
    if (username == NULL || password == NULL || *username == '\0' ||
        *password == '\0') {
      mg_free(username);
      mg_free(password);
      mg_http_reply(c, 400, JSON_HEADERS,
                    "{%m:%d,%m:%m}\n", MG_ESC("ok"), 0,
                    MG_ESC("error"), MG_ESC("请输入用户名和密码"));
      return;
    }
    if (login_locked(db, ip, &lock_remaining)) {
      mg_free(username);
      mg_free(password);
      mg_http_reply(c, 429, JSON_HEADERS,
                    "{%m:%d,%m:%m,%m:%ld}\n", MG_ESC("ok"), 0,
                    MG_ESC("error"), MG_ESC("登录失败次数过多，请稍后再试"),
                    MG_ESC("retry_after"), lock_remaining);
      return;
    }
    if (!verify_password(db, username, password, &user_id, stored_username,
                         sizeof(stored_username)) ||
        create_session(db, user_id, ip, user_agent, token, sizeof(token),
                       &ttl) != 0) {
      record_login_failure(db, ip);
      mg_free(username);
      mg_free(password);
      mg_http_reply(c, 401, JSON_HEADERS,
                    "{%m:%d,%m:%m}\n", MG_ESC("ok"), 0,
                    MG_ESC("error"), MG_ESC("用户名或密码错误"));
      return;
    }
    clear_login_failures(db, ip);
    mg_free(username);
    mg_free(password);
    reply_login_ok(c, hm, token, ttl, stored_username);
  } else if (mg_strcmp(hm->method, mg_str("POST")) == 0 &&
             mg_match(hm->uri, mg_str("/api/auth/logout"), NULL)) {
    delete_session(db, hm);
    reply_logout_ok(c, hm);
  } else {
    mg_http_reply(c, 404, JSON_HEADERS, "{\"error\":\"not found\"}\n");
  }
}
