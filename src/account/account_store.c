#include "account/account_store.h"

#include "mongoose.h"

#include <ctype.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static const char *column_text(sqlite3_stmt *stmt, int col) {
  const unsigned char *s = sqlite3_column_text(stmt, col);
  return s == NULL ? "" : (const char *) s;
}

static char *trim(char *s) {
  char *end;
  while (*s && isspace((unsigned char) *s)) s++;
  end = s + strlen(s);
  while (end > s && isspace((unsigned char) end[-1])) *--end = '\0';
  return s;
}

static bool all_digits(const char *s) {
  if (s == NULL || *s == '\0') return false;
  for (; *s; s++) {
    if (!isdigit((unsigned char) *s)) return false;
  }
  return true;
}

static long clamp_limit(long limit) {
  if (limit <= 0) return 50;
  if (limit > 200) return 200;
  return limit;
}

char *account_summary_json(sqlite3 *db) {
  sqlite3_stmt *stmt = NULL;
  struct mg_iobuf io = {0, 0, 0, 256};
  sqlite3_int64 total = 0, active = 0, expired = 0, temp = 0, failed = 0;
  sqlite3_int64 uploaded = 0, not_uploaded = 0, updated_at = 0;
  const char *sql =
      "SELECT total,active_count,expired_count,temp_count,failed_count,"
      "uploaded_count,not_uploaded_count,updated_at "
      "FROM account_stats WHERE id=1";

  if (db != NULL &&
      sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK &&
      sqlite3_step(stmt) == SQLITE_ROW) {
    total = sqlite3_column_int64(stmt, 0);
    active = sqlite3_column_int64(stmt, 1);
    expired = sqlite3_column_int64(stmt, 2);
    temp = sqlite3_column_int64(stmt, 3);
    failed = sqlite3_column_int64(stmt, 4);
    uploaded = sqlite3_column_int64(stmt, 5);
    not_uploaded = sqlite3_column_int64(stmt, 6);
    updated_at = sqlite3_column_int64(stmt, 7);
  }
  sqlite3_finalize(stmt);

  mg_xprintf(mg_pfn_iobuf, &io,
             "{%m:%lld,%m:%lld,%m:%lld,%m:%lld,%m:%lld,%m:%lld,%m:%lld,"
             "%m:%lld}",
             MG_ESC("total"), total, MG_ESC("active"), active,
             MG_ESC("expired"), expired, MG_ESC("temp"), temp,
             MG_ESC("failed"), failed, MG_ESC("uploaded"), uploaded,
             MG_ESC("not_uploaded"), not_uploaded, MG_ESC("updated_at"),
             updated_at);
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

static void append_account_row(struct mg_iobuf *io, sqlite3_stmt *stmt) {
  mg_xprintf(
      mg_pfn_iobuf, io,
      "{%m:%lld,%m:%m,%m:%m,%m:%m,%m:%lld,%m:%lld,%m:%lld,%m:%m}",
      MG_ESC("id"), sqlite3_column_int64(stmt, 0), MG_ESC("email"),
      MG_ESC(column_text(stmt, 1)), MG_ESC("status"),
      MG_ESC(column_text(stmt, 2)), MG_ESC("upload_state"),
      MG_ESC(column_text(stmt, 3)), MG_ESC("created_at"),
      sqlite3_column_int64(stmt, 4), MG_ESC("updated_at"),
      sqlite3_column_int64(stmt, 5), MG_ESC("last_refreshed_at"),
      sqlite3_column_int64(stmt, 6), MG_ESC("auth_source"),
      MG_ESC(column_text(stmt, 7)));
}

static sqlite3_int64 account_count_rows(sqlite3 *db, const char *q,
                                        const char *status,
                                        const char *upload_state,
                                        const char *auth_source,
                                        bool has_query) {
  sqlite3_stmt *stmt = NULL;
  sqlite3_int64 total = 0;
  char prefix_buf[260];
  const char *sql;

  if (!has_query) {
    sql =
        "SELECT COUNT(*) FROM accounts "
        "WHERE (?1='' OR status=?1) "
        "AND (?2='' OR upload_state=?2) "
        "AND (?3='' OR COALESCE(NULLIF(auth_source,''),'standard')=?3)";
  } else if (all_digits(q)) {
    sql =
        "SELECT COUNT(*) FROM accounts "
        "WHERE (?1='' OR status=?1) "
        "AND (?2='' OR upload_state=?2) "
        "AND (?3='' OR COALESCE(NULLIF(auth_source,''),'standard')=?3) "
        "AND id=?4";
  } else {
    sql =
        "SELECT COUNT(*) FROM accounts "
        "WHERE (?1='' OR status=?1) "
        "AND (?2='' OR upload_state=?2) "
        "AND (?3='' OR COALESCE(NULLIF(auth_source,''),'standard')=?3) "
        "AND email LIKE ?4 COLLATE NOCASE";
  }

  if (db == NULL || sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
    sqlite3_finalize(stmt);
    return 0;
  }

  sqlite3_bind_text(stmt, 1, status ? status : "", -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, upload_state ? upload_state : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, auth_source ? auth_source : "", -1,
                    SQLITE_TRANSIENT);
  if (has_query) {
    if (all_digits(q)) {
      sqlite3_bind_int64(stmt, 4, strtol(q, NULL, 10));
    } else {
      mg_snprintf(prefix_buf, sizeof(prefix_buf), "%s%%", q);
      sqlite3_bind_text(stmt, 4, prefix_buf, -1, SQLITE_TRANSIENT);
    }
  }

  if (sqlite3_step(stmt) == SQLITE_ROW) {
    total = sqlite3_column_int64(stmt, 0);
  }
  sqlite3_finalize(stmt);
  return total;
}

char *account_list_json(sqlite3 *db, const char *query, const char *status,
                        const char *upload_state, const char *auth_source,
                        long cursor, long limit, long page) {
  sqlite3_stmt *stmt = NULL;
  struct mg_iobuf io = {0, 0, 0, 1024};
  char query_buf[256], prefix_buf[260];
  char *q;
  long effective_limit = clamp_limit(limit);
  long bind_limit = effective_limit + 1;
  long effective_page = page > 0 ? page : 1;
  long next_cursor = 0;
  sqlite3_int64 total_count = 0, total_pages = 1, offset = 0;
  int returned = 0, row_count = 0;
  bool has_more = false;
  bool has_query;
  bool page_mode = page > 0;
  const char *sql;

  mg_snprintf(query_buf, sizeof(query_buf), "%s", query ? query : "");
  q = trim(query_buf);
  has_query = q[0] != '\0';
  total_count =
      account_count_rows(db, q, status, upload_state, auth_source, has_query);
  if (total_count > 0) {
    total_pages = (total_count + effective_limit - 1) / effective_limit;
  }
  if (page_mode) {
    if (effective_page < 1) effective_page = 1;
    if (effective_page > total_pages) effective_page = (long) total_pages;
    offset = ((sqlite3_int64) effective_page - 1) * effective_limit;
  }

  if (!has_query) {
    if (page_mode) {
      sql =
          "SELECT id,email,status,upload_state,created_at,updated_at,"
          "last_refreshed_at,COALESCE(auth_source,'') FROM accounts "
          "WHERE (?1='' OR status=?1) "
          "AND (?2='' OR upload_state=?2) "
          "AND (?3='' OR COALESCE(NULLIF(auth_source,''),'standard')=?3) "
          "ORDER BY id DESC LIMIT ?4 OFFSET ?5";
    } else {
      sql =
          "SELECT id,email,status,upload_state,created_at,updated_at,"
          "last_refreshed_at,COALESCE(auth_source,'') FROM accounts "
          "WHERE (?1='' OR status=?1) "
          "AND (?2='' OR upload_state=?2) "
          "AND (?3='' OR COALESCE(NULLIF(auth_source,''),'standard')=?3) "
          "AND (?4=0 OR id < ?4) "
          "ORDER BY id DESC LIMIT ?5";
    }
  } else if (all_digits(q)) {
    if (page_mode) {
      sql =
          "SELECT id,email,status,upload_state,created_at,updated_at,"
          "last_refreshed_at,COALESCE(auth_source,'') FROM accounts "
          "WHERE (?1='' OR status=?1) "
          "AND (?2='' OR upload_state=?2) "
          "AND (?3='' OR COALESCE(NULLIF(auth_source,''),'standard')=?3) "
          "AND id=?4 ORDER BY id DESC LIMIT ?5 OFFSET ?6";
    } else {
      sql =
          "SELECT id,email,status,upload_state,created_at,updated_at,"
          "last_refreshed_at,COALESCE(auth_source,'') FROM accounts "
          "WHERE (?1='' OR status=?1) "
          "AND (?2='' OR upload_state=?2) "
          "AND (?3='' OR COALESCE(NULLIF(auth_source,''),'standard')=?3) "
          "AND id=?4 ORDER BY id DESC LIMIT ?5";
    }
  } else {
    if (page_mode) {
      sql =
          "SELECT id,email,status,upload_state,created_at,updated_at,"
          "last_refreshed_at,COALESCE(auth_source,'') FROM accounts "
          "WHERE (?1='' OR status=?1) "
          "AND (?2='' OR upload_state=?2) "
          "AND (?3='' OR COALESCE(NULLIF(auth_source,''),'standard')=?3) "
          "AND email LIKE ?4 COLLATE NOCASE "
          "ORDER BY id DESC LIMIT ?5 OFFSET ?6";
    } else {
      sql =
          "SELECT id,email,status,upload_state,created_at,updated_at,"
          "last_refreshed_at,COALESCE(auth_source,'') FROM accounts "
          "WHERE (?1='' OR status=?1) "
          "AND (?2='' OR upload_state=?2) "
          "AND (?3='' OR COALESCE(NULLIF(auth_source,''),'standard')=?3) "
          "AND email LIKE ?4 COLLATE NOCASE "
          "ORDER BY id DESC LIMIT ?5";
    }
  }

  mg_xprintf(mg_pfn_iobuf, &io, "{\"items\":[");
  if (db != NULL && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, status ? status : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, upload_state ? upload_state : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, auth_source ? auth_source : "", -1,
                      SQLITE_TRANSIENT);
    if (!has_query) {
      if (page_mode) {
        sqlite3_bind_int64(stmt, 4, effective_limit);
        sqlite3_bind_int64(stmt, 5, offset);
      } else {
        sqlite3_bind_int64(stmt, 4, cursor > 0 ? cursor : 0);
        sqlite3_bind_int64(stmt, 5, bind_limit);
      }
    } else if (all_digits(q)) {
      sqlite3_bind_int64(stmt, 4, strtol(q, NULL, 10));
      sqlite3_bind_int64(stmt, 5, page_mode ? effective_limit : bind_limit);
      if (page_mode) sqlite3_bind_int64(stmt, 6, offset);
    } else {
      mg_snprintf(prefix_buf, sizeof(prefix_buf), "%s%%", q);
      sqlite3_bind_text(stmt, 4, prefix_buf, -1, SQLITE_TRANSIENT);
      sqlite3_bind_int64(stmt, 5, page_mode ? effective_limit : bind_limit);
      if (page_mode) sqlite3_bind_int64(stmt, 6, offset);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
      row_count++;
      if (!page_mode && row_count > effective_limit) {
        has_more = true;
        break;
      }
      if (returned > 0) mg_xprintf(mg_pfn_iobuf, &io, ",");
      append_account_row(&io, stmt);
      next_cursor = (long) sqlite3_column_int64(stmt, 0);
      returned++;
    }
  }
  sqlite3_finalize(stmt);
  if (page_mode) has_more = total_count > offset + returned;
  if (!has_more) next_cursor = 0;
  mg_xprintf(mg_pfn_iobuf, &io,
             "],%m:%d,%m:%ld,%m:%ld,%m:%ld,%m:%d,%m:%ld,%m:%lld,%m:%lld}",
             MG_ESC("has_more"), has_more, MG_ESC("next_cursor"),
             next_cursor, MG_ESC("cursor"), cursor > 0 ? cursor : 0,
             MG_ESC("limit"), effective_limit, MG_ESC("returned"), returned,
             MG_ESC("page"), page_mode ? effective_page : 1,
             MG_ESC("total_count"), (long long) total_count,
             MG_ESC("total_pages"), (long long) total_pages);
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

char *account_detail_json(sqlite3 *db, long id) {
  sqlite3_stmt *stmt = NULL;
  struct mg_iobuf io = {0, 0, 0, 1024};
  const char *sql =
      "SELECT a.id,a.email,a.status,a.upload_state,a.created_at,a.updated_at,"
      "a.last_refreshed_at,s.password,s.access_token,s.refresh_token,"
      "s.id_token,s.session_token,s.cookies,s.external_account_id,"
      "s.workspace_id,COALESCE(a.auth_source,'') "
      "FROM accounts a LEFT JOIN account_secrets s ON s.account_id=a.id "
      "WHERE a.id=?";

  if (db == NULL || id <= 0 ||
      sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("数据库查询失败"));
    mg_iobuf_add(&io, io.len, "", 1);
    return (char *) io.buf;
  }

  sqlite3_bind_int64(stmt, 1, id);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    mg_xprintf(
        mg_pfn_iobuf, &io,
        "{%m:%d,%m:{%m:%lld,%m:%m,%m:%m,%m:%m,%m:%lld,%m:%lld,%m:%lld,"
        "%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m}}",
        MG_ESC("ok"), 1, MG_ESC("account"), MG_ESC("id"),
        sqlite3_column_int64(stmt, 0), MG_ESC("email"),
        MG_ESC(column_text(stmt, 1)), MG_ESC("status"),
        MG_ESC(column_text(stmt, 2)), MG_ESC("upload_state"),
        MG_ESC(column_text(stmt, 3)), MG_ESC("created_at"),
        sqlite3_column_int64(stmt, 4), MG_ESC("updated_at"),
        sqlite3_column_int64(stmt, 5), MG_ESC("last_refreshed_at"),
        sqlite3_column_int64(stmt, 6), MG_ESC("password"),
        MG_ESC(column_text(stmt, 7)), MG_ESC("access_token"),
        MG_ESC(column_text(stmt, 8)), MG_ESC("refresh_token"),
        MG_ESC(column_text(stmt, 9)), MG_ESC("id_token"),
        MG_ESC(column_text(stmt, 10)), MG_ESC("session_token"),
        MG_ESC(column_text(stmt, 11)), MG_ESC("cookies"),
        MG_ESC(column_text(stmt, 12)), MG_ESC("external_account_id"),
        MG_ESC(column_text(stmt, 13)), MG_ESC("workspace_id"),
        MG_ESC(column_text(stmt, 14)), MG_ESC("auth_source"),
        MG_ESC(column_text(stmt, 15)));
  } else {
    mg_xprintf(mg_pfn_iobuf, &io, "{%m:%d,%m:%m}", MG_ESC("ok"), 0,
               MG_ESC("error"), MG_ESC("账号不存在"));
  }
  sqlite3_finalize(stmt);
  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}

int account_insert_success(sqlite3 *db,
                           const struct account_success_record *record,
                           long *out_id) {
  sqlite3_stmt *account_stmt = NULL;
  sqlite3_stmt *secret_stmt = NULL;
  sqlite3_int64 account_id = 0;
  int rc;
  const char *status = "temp";
  const char *upload_state = "not_uploaded";
  const char *account_sql =
      "INSERT INTO accounts(email,status,upload_state,auth_source,created_at,"
      "updated_at,last_refreshed_at) VALUES(?,?,?,?,unixepoch(),unixepoch(),?)";
  const char *secret_sql =
      "INSERT INTO account_secrets(account_id,password,access_token,"
      "refresh_token,id_token,session_token,cookies,external_account_id,"
      "workspace_id,created_at,updated_at) "
      "VALUES(?,?,?,?,?,?,?,?,?,unixepoch(),unixepoch())";

  if (out_id != NULL) *out_id = 0;
  if (db == NULL || record == NULL || record->email == NULL ||
      record->email[0] == '\0') {
    return -1;
  }
  if (record->status != NULL && record->status[0] != '\0') {
    status = record->status;
  }
  if (record->upload_state != NULL && record->upload_state[0] != '\0') {
    upload_state = record->upload_state;
  }

  if (sqlite3_prepare_v2(db, account_sql, -1, &account_stmt, NULL) !=
      SQLITE_OK) {
    return -1;
  }
  if (sqlite3_prepare_v2(db, secret_sql, -1, &secret_stmt, NULL) !=
      SQLITE_OK) {
    sqlite3_finalize(account_stmt);
    return -1;
  }

  sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
  sqlite3_bind_text(account_stmt, 1, record->email, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(account_stmt, 2, status, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(account_stmt, 3, upload_state, -1, SQLITE_TRANSIENT);
  if (record->auth_source != NULL && record->auth_source[0] != '\0') {
    sqlite3_bind_text(account_stmt, 4, record->auth_source, -1,
                      SQLITE_TRANSIENT);
  } else {
    sqlite3_bind_null(account_stmt, 4);
  }
  if (record->last_refreshed_at > 0) {
    sqlite3_bind_int64(account_stmt, 5, record->last_refreshed_at);
  } else {
    sqlite3_bind_null(account_stmt, 5);
  }
  rc = sqlite3_step(account_stmt);
  if (rc != SQLITE_DONE) goto fail;
  account_id = sqlite3_last_insert_rowid(db);

  sqlite3_bind_int64(secret_stmt, 1, account_id);
  sqlite3_bind_text(secret_stmt, 2, record->password ? record->password : "",
                    -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_stmt, 3,
                    record->access_token ? record->access_token : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_stmt, 4,
                    record->refresh_token ? record->refresh_token : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_stmt, 5,
                    record->id_token ? record->id_token : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_stmt, 6,
                    record->session_token ? record->session_token : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_stmt, 7, record->cookies ? record->cookies : "",
                    -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_stmt, 8,
                    record->external_account_id ? record->external_account_id
                                                : "",
                    -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_stmt, 9,
                    record->workspace_id ? record->workspace_id : "", -1,
                    SQLITE_TRANSIENT);
  rc = sqlite3_step(secret_stmt);
  if (rc != SQLITE_DONE) goto fail;

  sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
  sqlite3_finalize(secret_stmt);
  sqlite3_finalize(account_stmt);
  if (out_id != NULL) *out_id = (long) account_id;
  return 0;

fail:
  sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
  sqlite3_finalize(secret_stmt);
  sqlite3_finalize(account_stmt);
  return -1;
}

int account_load_oauth_record(sqlite3 *db, long id,
                              struct account_oauth_record *out) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "SELECT a.id,a.email,COALESCE(s.password,''),COALESCE(s.workspace_id,'') "
      "FROM accounts a LEFT JOIN account_secrets s ON s.account_id=a.id "
      "WHERE a.id=?";

  if (out != NULL) memset(out, 0, sizeof(*out));
  if (db == NULL || id <= 0 || out == NULL) return -1;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
  sqlite3_bind_int64(stmt, 1, id);
  if (sqlite3_step(stmt) != SQLITE_ROW) {
    sqlite3_finalize(stmt);
    return -1;
  }
  out->id = (long) sqlite3_column_int64(stmt, 0);
  mg_snprintf(out->email, sizeof(out->email), "%s", column_text(stmt, 1));
  mg_snprintf(out->password, sizeof(out->password), "%s", column_text(stmt, 2));
  mg_snprintf(out->workspace_id, sizeof(out->workspace_id), "%s",
              column_text(stmt, 3));
  sqlite3_finalize(stmt);
  return out->email[0] == '\0' ? -1 : 0;
}

int account_apply_oauth_success(sqlite3 *db, long id,
                                const struct account_success_record *record) {
  sqlite3_stmt *account_stmt = NULL;
  sqlite3_stmt *secret_update = NULL;
  sqlite3_stmt *secret_insert = NULL;
  int ok = 0;
  const char *account_sql =
      "UPDATE accounts SET status='active',updated_at=unixepoch(),"
      "last_refreshed_at=unixepoch() WHERE id=?";
  const char *secret_update_sql =
      "UPDATE account_secrets SET "
      "access_token=?,refresh_token=?,"
      "id_token=CASE WHEN ?<>'' THEN ? ELSE id_token END,"
      "session_token=CASE WHEN ?<>'' THEN ? ELSE session_token END,"
      "cookies=CASE WHEN ?<>'' THEN ? ELSE cookies END,"
      "external_account_id=CASE WHEN ?<>'' THEN ? ELSE external_account_id END,"
      "workspace_id=CASE WHEN ?<>'' THEN ? ELSE workspace_id END,"
      "updated_at=unixepoch() WHERE account_id=?";
  const char *secret_insert_sql =
      "INSERT OR IGNORE INTO account_secrets(account_id,password,access_token,"
      "refresh_token,id_token,session_token,cookies,external_account_id,"
      "workspace_id,created_at,updated_at) "
      "VALUES(?,?,?,?,?,?,?,?,?,unixepoch(),unixepoch())";

  if (db == NULL || id <= 0 || record == NULL) return -1;
  if (sqlite3_prepare_v2(db, account_sql, -1, &account_stmt, NULL) !=
          SQLITE_OK ||
      sqlite3_prepare_v2(db, secret_update_sql, -1, &secret_update, NULL) !=
          SQLITE_OK ||
      sqlite3_prepare_v2(db, secret_insert_sql, -1, &secret_insert, NULL) !=
          SQLITE_OK) {
    sqlite3_finalize(account_stmt);
    sqlite3_finalize(secret_update);
    sqlite3_finalize(secret_insert);
    return -1;
  }

  sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
  sqlite3_bind_int64(account_stmt, 1, id);
  if (sqlite3_step(account_stmt) != SQLITE_DONE || sqlite3_changes(db) <= 0) {
    goto done;
  }

  sqlite3_bind_text(secret_update, 1,
                    record->access_token ? record->access_token : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_update, 2,
                    record->refresh_token ? record->refresh_token : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_update, 3,
                    record->id_token ? record->id_token : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_update, 4,
                    record->id_token ? record->id_token : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_update, 5,
                    record->session_token ? record->session_token : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_update, 6,
                    record->session_token ? record->session_token : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_update, 7, record->cookies ? record->cookies : "",
                    -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_update, 8, record->cookies ? record->cookies : "",
                    -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_update, 9,
                    record->external_account_id ? record->external_account_id
                                                : "",
                    -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_update, 10,
                    record->external_account_id ? record->external_account_id
                                                : "",
                    -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_update, 11,
                    record->workspace_id ? record->workspace_id : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(secret_update, 12,
                    record->workspace_id ? record->workspace_id : "", -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_int64(secret_update, 13, id);
  if (sqlite3_step(secret_update) != SQLITE_DONE) goto done;

  if (sqlite3_changes(db) == 0) {
    sqlite3_bind_int64(secret_insert, 1, id);
    sqlite3_bind_text(secret_insert, 2, record->password ? record->password : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 3,
                      record->access_token ? record->access_token : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 4,
                      record->refresh_token ? record->refresh_token : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 5,
                      record->id_token ? record->id_token : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 6,
                      record->session_token ? record->session_token : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 7, record->cookies ? record->cookies : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 8,
                      record->external_account_id ? record->external_account_id
                                                  : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 9,
                      record->workspace_id ? record->workspace_id : "", -1,
                      SQLITE_TRANSIENT);
    if (sqlite3_step(secret_insert) != SQLITE_DONE) goto done;
  }

  ok = 1;

done:
  sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
  sqlite3_finalize(account_stmt);
  sqlite3_finalize(secret_update);
  sqlite3_finalize(secret_insert);
  return ok ? 0 : -1;
}

int account_apply_chatgpt_login_success(
    sqlite3 *db, long id, const struct account_success_record *record) {
  sqlite3_stmt *account_stmt = NULL;
  sqlite3_stmt *secret_update = NULL;
  sqlite3_stmt *secret_insert = NULL;
  int ok = 0;
  const char *account_sql =
      "UPDATE accounts SET status='active',updated_at=unixepoch(),"
      "last_refreshed_at=unixepoch() WHERE id=?";
  const char *secret_update_sql =
      "UPDATE account_secrets SET "
      "access_token=CASE WHEN ?<>'' THEN ? ELSE access_token END,"
      "refresh_token=CASE WHEN ?<>'' THEN ? ELSE refresh_token END,"
      "id_token=CASE WHEN ?<>'' THEN ? ELSE id_token END,"
      "session_token=CASE WHEN ?<>'' THEN ? ELSE session_token END,"
      "cookies=CASE WHEN ?<>'' THEN ? ELSE cookies END,"
      "external_account_id=CASE WHEN ?<>'' THEN ? ELSE external_account_id END,"
      "workspace_id=CASE WHEN ?<>'' THEN ? ELSE workspace_id END,"
      "updated_at=unixepoch() WHERE account_id=?";
  const char *secret_insert_sql =
      "INSERT OR IGNORE INTO account_secrets(account_id,password,access_token,"
      "refresh_token,id_token,session_token,cookies,external_account_id,"
      "workspace_id,created_at,updated_at) "
      "VALUES(?,?,?,?,?,?,?,?,?,unixepoch(),unixepoch())";

  if (db == NULL || id <= 0 || record == NULL ||
      record->access_token == NULL || record->access_token[0] == '\0') {
    return -1;
  }
  if (sqlite3_prepare_v2(db, account_sql, -1, &account_stmt, NULL) !=
          SQLITE_OK ||
      sqlite3_prepare_v2(db, secret_update_sql, -1, &secret_update, NULL) !=
          SQLITE_OK ||
      sqlite3_prepare_v2(db, secret_insert_sql, -1, &secret_insert, NULL) !=
          SQLITE_OK) {
    sqlite3_finalize(account_stmt);
    sqlite3_finalize(secret_update);
    sqlite3_finalize(secret_insert);
    return -1;
  }

  sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
  sqlite3_bind_int64(account_stmt, 1, id);
  if (sqlite3_step(account_stmt) != SQLITE_DONE || sqlite3_changes(db) <= 0) {
    goto done;
  }

#define BIND_OPTIONAL(stmt, offset, value)                                     \
  do {                                                                         \
    const char *v__ = (value) ? (value) : "";                                  \
    sqlite3_bind_text((stmt), (offset), v__, -1, SQLITE_TRANSIENT);            \
    sqlite3_bind_text((stmt), (offset) + 1, v__, -1, SQLITE_TRANSIENT);        \
  } while (0)

  BIND_OPTIONAL(secret_update, 1, record->access_token);
  BIND_OPTIONAL(secret_update, 3, record->refresh_token);
  BIND_OPTIONAL(secret_update, 5, record->id_token);
  BIND_OPTIONAL(secret_update, 7, record->session_token);
  BIND_OPTIONAL(secret_update, 9, record->cookies);
  BIND_OPTIONAL(secret_update, 11, record->external_account_id);
  BIND_OPTIONAL(secret_update, 13, record->workspace_id);
  sqlite3_bind_int64(secret_update, 15, id);
#undef BIND_OPTIONAL

  if (sqlite3_step(secret_update) != SQLITE_DONE) goto done;

  if (sqlite3_changes(db) == 0) {
    sqlite3_bind_int64(secret_insert, 1, id);
    sqlite3_bind_text(secret_insert, 2, record->password ? record->password : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 3,
                      record->access_token ? record->access_token : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 4,
                      record->refresh_token ? record->refresh_token : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 5,
                      record->id_token ? record->id_token : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 6,
                      record->session_token ? record->session_token : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 7, record->cookies ? record->cookies : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 8,
                      record->external_account_id ? record->external_account_id
                                                  : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(secret_insert, 9,
                      record->workspace_id ? record->workspace_id : "", -1,
                      SQLITE_TRANSIENT);
    if (sqlite3_step(secret_insert) != SQLITE_DONE) goto done;
  }

  ok = 1;

done:
  sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
  sqlite3_finalize(account_stmt);
  sqlite3_finalize(secret_update);
  sqlite3_finalize(secret_insert);
  return ok ? 0 : -1;
}

static int execute_for_ids(sqlite3 *db, const char *sql, const long *ids,
                           size_t count) {
  sqlite3_stmt *stmt = NULL;
  int changed = 0, ok = 1;

  if (db == NULL || ids == NULL || count == 0) return 0;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

  sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
  for (size_t i = 0; i < count; i++) {
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_int64(stmt, 1, ids[i]);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
      ok = 0;
      break;
    }
    changed += sqlite3_changes(db);
  }
  sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
  sqlite3_finalize(stmt);
  return ok ? changed : -1;
}

int account_refresh_tokens(sqlite3 *db, const long *ids, size_t count) {
  const char *sql =
      "UPDATE accounts SET last_refreshed_at=unixepoch(),"
      "updated_at=unixepoch() WHERE id=?";
  return execute_for_ids(db, sql, ids, count);
}

int account_set_upload_state(sqlite3 *db, const long *ids, size_t count,
                             int uploaded) {
  const char *sql_uploaded =
      "UPDATE accounts SET upload_state='uploaded',updated_at=unixepoch() "
      "WHERE id=?";
  const char *sql_not_uploaded =
      "UPDATE accounts SET upload_state='not_uploaded',updated_at=unixepoch() "
      "WHERE id=?";
  return execute_for_ids(db, uploaded ? sql_uploaded : sql_not_uploaded, ids,
                         count);
}

int account_delete_ids(sqlite3 *db, const long *ids, size_t count) {
  return execute_for_ids(db, "DELETE FROM accounts WHERE id=?", ids, count);
}
