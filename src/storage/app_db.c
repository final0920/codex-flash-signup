#include "storage/app_db.h"

#include <pthread.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define APP_DB_DEFAULT_BUSY_TIMEOUT_MS 30000
#define APP_DB_DEFAULT_OPEN_RETRIES 12
#define APP_DB_OPEN_BACKOFF_INITIAL_MS 20
#define APP_DB_OPEN_BACKOFF_MAX_MS 1000

static pthread_mutex_t s_open_mu = PTHREAD_MUTEX_INITIALIZER;

static int exec_sql(sqlite3 *db, const char *sql, bool log_errors) {
  char *err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) {
    if (log_errors) {
      fprintf(stderr, "sqlite error: %s\n", err ? err : sqlite3_errmsg(db));
    }
    sqlite3_free(err);
    return rc;
  }
  return SQLITE_OK;
}

static bool table_has_column(sqlite3 *db, const char *table,
                             const char *column) {
  sqlite3_stmt *stmt = NULL;
  char sql[160];
  bool found = false;

  if (db == NULL || table == NULL || column == NULL) return false;
  snprintf(sql, sizeof(sql), "PRAGMA table_info(%s);", table);
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
    return false;
  }
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *name = sqlite3_column_text(stmt, 1);
    if (name != NULL && strcmp((const char *) name, column) == 0) {
      found = true;
      break;
    }
  }
  sqlite3_finalize(stmt);
  return found;
}

static int ensure_column(sqlite3 *db, const char *table, const char *column,
                         const char *definition) {
  char sql[512];

  if (table_has_column(db, table, column)) return SQLITE_OK;
  snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s", table,
           definition);
  return exec_sql(db, sql, true);
}

static int ensure_schema_columns(sqlite3 *db) {
  int rc = ensure_column(db, "aether_services", "retry_count",
                         "retry_count INTEGER NOT NULL DEFAULT 2");
  if (rc != SQLITE_OK) return rc;
  rc = ensure_column(db, "aether_services", "proxy_node_mode",
                     "proxy_node_mode TEXT NOT NULL DEFAULT 'fixed'");
  if (rc != SQLITE_OK) return rc;
  rc = ensure_column(db, "aether_services", "oauth_provider_ids",
                     "oauth_provider_ids TEXT NOT NULL DEFAULT '[]'");
  if (rc != SQLITE_OK) return rc;
  rc = ensure_column(db, "aether_services", "oauth_provider_names",
                     "oauth_provider_names TEXT NOT NULL DEFAULT '[]'");
  if (rc != SQLITE_OK) return rc;
  rc = ensure_column(db, "aether_services", "chatgpt_web_provider_id",
                     "chatgpt_web_provider_id TEXT");
  if (rc != SQLITE_OK) return rc;
  rc = ensure_column(db, "aether_services", "chatgpt_web_provider_name",
                     "chatgpt_web_provider_name TEXT");
  if (rc != SQLITE_OK) return rc;
  rc = ensure_column(db, "account_secrets", "id_token", "id_token TEXT");
  if (rc != SQLITE_OK) return rc;
  rc = ensure_column(db, "account_secrets", "session_token",
                     "session_token TEXT");
  if (rc != SQLITE_OK) return rc;
  rc = ensure_column(db, "account_secrets", "cookies", "cookies TEXT");
  if (rc != SQLITE_OK) return rc;
  return ensure_column(db, "accounts", "auth_source", "auth_source TEXT");
}

static int ensure_data_dir(void) {
  if (mkdir("data", 0755) == 0) return 0;
  return 0;
}

static int env_int_clamped(const char *name, int fallback, int min, int max) {
  const char *env = getenv(name);
  char *end = NULL;
  long value;
  if (env == NULL || env[0] == '\0') return fallback;
  value = strtol(env, &end, 10);
  if (end == env || *end != '\0') return fallback;
  if (value < min) return min;
  if (value > max) return max;
  return (int) value;
}

static int busy_timeout_ms(void) {
  return env_int_clamped("APP_SQLITE_BUSY_TIMEOUT_MS",
                         APP_DB_DEFAULT_BUSY_TIMEOUT_MS, 0, 600000);
}

static int open_retries(void) {
  return env_int_clamped("APP_SQLITE_OPEN_RETRIES",
                         APP_DB_DEFAULT_OPEN_RETRIES, 0, 100);
}

static bool sqlite_rc_retryable(int rc) {
  int primary = rc & 0xff;
  return primary == SQLITE_BUSY || primary == SQLITE_LOCKED ||
         primary == SQLITE_CANTOPEN || primary == SQLITE_IOERR;
}

static int migrate(sqlite3 *db) {
  const char *sql =
      "CREATE TABLE IF NOT EXISTS proxy_nodes ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "scheme TEXT NOT NULL,"
      "host TEXT NOT NULL,"
      "port INTEGER NOT NULL,"
      "username TEXT,"
      "password TEXT,"
      "proxy_url TEXT NOT NULL UNIQUE,"
      "label TEXT,"
      "status TEXT NOT NULL DEFAULT 'new',"
      "last_test_ok INTEGER,"
      "last_http_status INTEGER,"
      "exit_ip TEXT,"
      "exit_loc TEXT,"
      "exit_colo TEXT,"
      "trace_http TEXT,"
      "trace_tls TEXT,"
      "last_error TEXT,"
      "last_tested_at INTEGER,"
      "created_at INTEGER NOT NULL DEFAULT (unixepoch()),"
      "updated_at INTEGER NOT NULL DEFAULT (unixepoch())"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_proxy_nodes_status "
      "ON proxy_nodes(status);"
      "CREATE INDEX IF NOT EXISTS idx_proxy_nodes_exit_loc "
      "ON proxy_nodes(exit_loc);"
      "CREATE TABLE IF NOT EXISTS proxy_settings ("
      "key TEXT PRIMARY KEY,"
      "value TEXT NOT NULL,"
      "updated_at INTEGER NOT NULL DEFAULT (unixepoch())"
      ");"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('proxy_mode','pool');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_enabled','0');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_managed','1');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_subscription_type','url');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_subscription_text','');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_core_path','mihomo');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_config_dir','data/mihomo');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_mixed_host','127.0.0.1');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_mixed_port','7890');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_controller_host','127.0.0.1');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_controller_port','9097');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_strategy','round-robin');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_group_mode','load-balance');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_node_filter','');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_node_exclude_filter','');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_selected_node','');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_health_check_url','https://www.gstatic.com/generate_204');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_provider_interval','3600');"
      "INSERT OR IGNORE INTO proxy_settings(key,value) "
      "VALUES('mihomo_health_check_interval','120');"
      "CREATE TABLE IF NOT EXISTS mail_settings ("
      "key TEXT PRIMARY KEY,"
      "value TEXT NOT NULL,"
      "updated_at INTEGER NOT NULL DEFAULT (unixepoch())"
      ");"
      "CREATE TABLE IF NOT EXISTS mail_domain_rules ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "pattern TEXT NOT NULL UNIQUE,"
      "base_domain TEXT NOT NULL,"
      "wildcard_depth INTEGER NOT NULL DEFAULT 0,"
      "is_active INTEGER NOT NULL DEFAULT 1,"
      "created_at INTEGER NOT NULL DEFAULT (unixepoch()),"
      "updated_at INTEGER NOT NULL DEFAULT (unixepoch())"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_mail_domain_rules_active "
      "ON mail_domain_rules(is_active);"
      "INSERT OR IGNORE INTO mail_settings(key,value) "
      "VALUES('rapid_inbox_base_url','http://127.0.0.1:8000');"
      "INSERT OR IGNORE INTO mail_settings(key,value) "
      "VALUES('rapid_inbox_backend','rapid_inbox');"
      "INSERT OR IGNORE INTO mail_settings(key,value) "
      "VALUES('rapid_inbox_transport','http');"
      "CREATE TABLE IF NOT EXISTS auth_users ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "username TEXT NOT NULL COLLATE NOCASE UNIQUE,"
      "password_hash TEXT NOT NULL,"
      "password_salt TEXT NOT NULL,"
      "iterations INTEGER NOT NULL,"
      "created_at INTEGER NOT NULL DEFAULT (unixepoch()),"
      "updated_at INTEGER NOT NULL DEFAULT (unixepoch()),"
      "last_login_at INTEGER"
      ");"
      "CREATE TABLE IF NOT EXISTS auth_sessions ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "user_id INTEGER NOT NULL,"
      "token_hash TEXT NOT NULL UNIQUE,"
      "ip_address TEXT,"
      "user_agent TEXT,"
      "expires_at INTEGER NOT NULL,"
      "created_at INTEGER NOT NULL DEFAULT (unixepoch()),"
      "last_seen_at INTEGER,"
      "FOREIGN KEY(user_id) REFERENCES auth_users(id) ON DELETE CASCADE"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_auth_sessions_hash_expires "
      "ON auth_sessions(token_hash,expires_at);"
      "CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_expires "
      "ON auth_sessions(user_id,expires_at);"
      "CREATE TABLE IF NOT EXISTS auth_login_attempts ("
      "ip_address TEXT PRIMARY KEY,"
      "failed_count INTEGER NOT NULL DEFAULT 0,"
      "locked_until INTEGER NOT NULL DEFAULT 0,"
      "updated_at INTEGER NOT NULL DEFAULT (unixepoch())"
      ");"
      "CREATE TABLE IF NOT EXISTS accounts ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "email TEXT NOT NULL COLLATE NOCASE UNIQUE,"
      "status TEXT NOT NULL DEFAULT 'active' "
      "CHECK(status IN ('active','expired','temp','failed')),"
      "upload_state TEXT NOT NULL DEFAULT 'not_uploaded' "
      "CHECK(upload_state IN ('uploaded','not_uploaded')),"
      "created_at INTEGER NOT NULL DEFAULT (unixepoch()),"
      "updated_at INTEGER NOT NULL DEFAULT (unixepoch()),"
      "last_refreshed_at INTEGER"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_accounts_status_upload_id "
      "ON accounts(status,upload_state,id DESC);"
      "CREATE INDEX IF NOT EXISTS idx_accounts_upload_id "
      "ON accounts(upload_state,id DESC);"
      "CREATE INDEX IF NOT EXISTS idx_accounts_created_id "
      "ON accounts(created_at DESC,id DESC);"
      "CREATE INDEX IF NOT EXISTS idx_accounts_last_refreshed "
      "ON accounts(last_refreshed_at DESC);"
      "CREATE TABLE IF NOT EXISTS account_secrets ("
      "account_id INTEGER PRIMARY KEY,"
      "password TEXT,"
      "access_token TEXT,"
      "refresh_token TEXT,"
      "id_token TEXT,"
      "session_token TEXT,"
      "cookies TEXT,"
      "external_account_id TEXT,"
      "workspace_id TEXT,"
      "created_at INTEGER NOT NULL DEFAULT (unixepoch()),"
      "updated_at INTEGER NOT NULL DEFAULT (unixepoch()),"
      "FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_account_secrets_external_account "
      "ON account_secrets(external_account_id);"
      "CREATE INDEX IF NOT EXISTS idx_account_secrets_workspace "
      "ON account_secrets(workspace_id);"
      "CREATE TABLE IF NOT EXISTS account_stats ("
      "id INTEGER PRIMARY KEY CHECK(id=1),"
      "total INTEGER NOT NULL DEFAULT 0,"
      "active_count INTEGER NOT NULL DEFAULT 0,"
      "expired_count INTEGER NOT NULL DEFAULT 0,"
      "temp_count INTEGER NOT NULL DEFAULT 0,"
      "failed_count INTEGER NOT NULL DEFAULT 0,"
      "uploaded_count INTEGER NOT NULL DEFAULT 0,"
      "not_uploaded_count INTEGER NOT NULL DEFAULT 0,"
      "updated_at INTEGER NOT NULL DEFAULT (unixepoch())"
      ");"
      "INSERT OR IGNORE INTO account_stats("
      "id,total,active_count,expired_count,temp_count,failed_count,"
      "uploaded_count,not_uploaded_count) VALUES(1,0,0,0,0,0,0,0);"
      "CREATE TRIGGER IF NOT EXISTS trg_accounts_stats_insert "
      "AFTER INSERT ON accounts BEGIN "
      "UPDATE account_stats SET "
      "total=total+1,"
      "active_count=active_count+CASE WHEN NEW.status='active' THEN 1 ELSE 0 END,"
      "expired_count=expired_count+CASE WHEN NEW.status='expired' THEN 1 ELSE 0 END,"
      "temp_count=temp_count+CASE WHEN NEW.status='temp' THEN 1 ELSE 0 END,"
      "failed_count=failed_count+CASE WHEN NEW.status='failed' THEN 1 ELSE 0 END,"
      "uploaded_count=uploaded_count+CASE WHEN NEW.upload_state='uploaded' THEN 1 ELSE 0 END,"
      "not_uploaded_count=not_uploaded_count+CASE WHEN NEW.upload_state='not_uploaded' THEN 1 ELSE 0 END,"
      "updated_at=unixepoch() WHERE id=1;"
      "END;"
      "CREATE TRIGGER IF NOT EXISTS trg_accounts_stats_delete "
      "AFTER DELETE ON accounts BEGIN "
      "UPDATE account_stats SET "
      "total=total-1,"
      "active_count=active_count-CASE WHEN OLD.status='active' THEN 1 ELSE 0 END,"
      "expired_count=expired_count-CASE WHEN OLD.status='expired' THEN 1 ELSE 0 END,"
      "temp_count=temp_count-CASE WHEN OLD.status='temp' THEN 1 ELSE 0 END,"
      "failed_count=failed_count-CASE WHEN OLD.status='failed' THEN 1 ELSE 0 END,"
      "uploaded_count=uploaded_count-CASE WHEN OLD.upload_state='uploaded' THEN 1 ELSE 0 END,"
      "not_uploaded_count=not_uploaded_count-CASE WHEN OLD.upload_state='not_uploaded' THEN 1 ELSE 0 END,"
      "updated_at=unixepoch() WHERE id=1;"
      "END;"
      "CREATE TRIGGER IF NOT EXISTS trg_accounts_stats_update "
      "AFTER UPDATE OF status,upload_state ON accounts BEGIN "
      "UPDATE account_stats SET "
      "active_count=active_count"
      "+CASE WHEN NEW.status='active' THEN 1 ELSE 0 END"
      "-CASE WHEN OLD.status='active' THEN 1 ELSE 0 END,"
      "expired_count=expired_count"
      "+CASE WHEN NEW.status='expired' THEN 1 ELSE 0 END"
      "-CASE WHEN OLD.status='expired' THEN 1 ELSE 0 END,"
      "temp_count=temp_count"
      "+CASE WHEN NEW.status='temp' THEN 1 ELSE 0 END"
      "-CASE WHEN OLD.status='temp' THEN 1 ELSE 0 END,"
      "failed_count=failed_count"
      "+CASE WHEN NEW.status='failed' THEN 1 ELSE 0 END"
      "-CASE WHEN OLD.status='failed' THEN 1 ELSE 0 END,"
      "uploaded_count=uploaded_count"
      "+CASE WHEN NEW.upload_state='uploaded' THEN 1 ELSE 0 END"
      "-CASE WHEN OLD.upload_state='uploaded' THEN 1 ELSE 0 END,"
      "not_uploaded_count=not_uploaded_count"
      "+CASE WHEN NEW.upload_state='not_uploaded' THEN 1 ELSE 0 END"
      "-CASE WHEN OLD.upload_state='not_uploaded' THEN 1 ELSE 0 END,"
      "updated_at=unixepoch() WHERE id=1;"
      "END;"
      "CREATE TABLE IF NOT EXISTS aether_services ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "name TEXT NOT NULL,"
      "api_url TEXT NOT NULL,"
      "management_token TEXT NOT NULL,"
      "provider_id TEXT NOT NULL,"
      "provider_name TEXT,"
      "oauth_provider_ids TEXT NOT NULL DEFAULT '[]',"
      "oauth_provider_names TEXT NOT NULL DEFAULT '[]',"
      "chatgpt_web_provider_id TEXT,"
      "chatgpt_web_provider_name TEXT,"
      "proxy_node_id TEXT,"
      "proxy_node_name TEXT,"
      "proxy_node_mode TEXT NOT NULL DEFAULT 'fixed',"
      "enabled INTEGER NOT NULL DEFAULT 1,"
      "priority INTEGER NOT NULL DEFAULT 0,"
      "retry_count INTEGER NOT NULL DEFAULT 2,"
      "created_at INTEGER NOT NULL DEFAULT (unixepoch()),"
      "updated_at INTEGER NOT NULL DEFAULT (unixepoch())"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_aether_services_enabled_priority "
      "ON aether_services(enabled,priority,id);"
      "CREATE TABLE IF NOT EXISTS aether_upload_stats ("
      "id INTEGER PRIMARY KEY CHECK(id=1),"
      "total_attempted INTEGER NOT NULL DEFAULT 0,"
      "success_count INTEGER NOT NULL DEFAULT 0,"
      "failed_count INTEGER NOT NULL DEFAULT 0,"
      "skipped_count INTEGER NOT NULL DEFAULT 0,"
      "last_success_at INTEGER,"
      "last_failed_at INTEGER,"
      "last_message TEXT,"
      "updated_at INTEGER NOT NULL DEFAULT (unixepoch())"
      ");"
      "INSERT OR IGNORE INTO aether_upload_stats("
      "id,total_attempted,success_count,failed_count,skipped_count) "
      "VALUES(1,0,0,0,0);";
  int rc = exec_sql(db, sql, true);
  if (rc != SQLITE_OK) return rc;
  return ensure_schema_columns(db);
}

static int configure_runtime_connection(sqlite3 *db, bool initialize,
                                        bool log_errors) {
  int rc;
  sqlite3_busy_timeout(db, busy_timeout_ms());
  rc = exec_sql(db, "PRAGMA synchronous=NORMAL;", log_errors);
  if (rc != SQLITE_OK) return rc;
  rc = exec_sql(db, "PRAGMA foreign_keys=ON;", log_errors);
  if (rc != SQLITE_OK) return rc;
  if (!initialize) return SQLITE_OK;
  rc = exec_sql(db, "PRAGMA journal_mode=WAL;", log_errors);
  if (rc != SQLITE_OK) return rc;
  return migrate(db);
}

static int app_db_open_once(const char *path, sqlite3 **db, bool initialize,
                            bool log_errors) {
  int rc;
  if (db == NULL) return SQLITE_MISUSE;
  *db = NULL;
  ensure_data_dir();
  pthread_mutex_lock(&s_open_mu);
  rc = sqlite3_open_v2(path, db,
                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                           SQLITE_OPEN_FULLMUTEX,
                       NULL);
  if (rc != SQLITE_OK) {
    if (log_errors) {
      fprintf(stderr, "cannot open sqlite db %s: %s\n", path,
              *db ? sqlite3_errmsg(*db) : sqlite3_errstr(rc));
    }
    app_db_close(*db);
    *db = NULL;
    pthread_mutex_unlock(&s_open_mu);
    return rc == SQLITE_OK ? SQLITE_CANTOPEN : rc;
  }
  sqlite3_extended_result_codes(*db, 1);
  rc = configure_runtime_connection(*db, initialize, log_errors);
  if (rc != SQLITE_OK) {
    app_db_close(*db);
    *db = NULL;
    pthread_mutex_unlock(&s_open_mu);
    return rc;
  }
  pthread_mutex_unlock(&s_open_mu);
  return SQLITE_OK;
}

static int app_db_open_with_retry(const char *path, sqlite3 **db,
                                  bool initialize) {
  int retries = open_retries();
  int backoff_ms = APP_DB_OPEN_BACKOFF_INITIAL_MS;
  int rc = SQLITE_OK;

  if (db == NULL) return -1;
  for (int attempt = 0; attempt <= retries; attempt++) {
    bool final_attempt = attempt == retries;
    rc = app_db_open_once(path, db, initialize, final_attempt);
    if (rc == SQLITE_OK) return 0;
    if (!sqlite_rc_retryable(rc) || final_attempt) break;
    usleep((useconds_t) backoff_ms * 1000U);
    if (backoff_ms < APP_DB_OPEN_BACKOFF_MAX_MS) backoff_ms *= 2;
    if (backoff_ms > APP_DB_OPEN_BACKOFF_MAX_MS) {
      backoff_ms = APP_DB_OPEN_BACKOFF_MAX_MS;
    }
  }
  fprintf(stderr, "sqlite open failed after retries: %s\n", sqlite3_errstr(rc));
  return -1;
}

int app_db_init(const char *path, sqlite3 **db) {
  return app_db_open_with_retry(path, db, true);
}

int app_db_open(const char *path, sqlite3 **db) {
  return app_db_open_with_retry(path, db, false);
}

void app_db_close(sqlite3 *db) {
  if (db != NULL) sqlite3_close(db);
}
