#ifndef ACCOUNT_STORE_H
#define ACCOUNT_STORE_H

#include <sqlite3.h>
#include <stddef.h>

struct account_success_record {
  const char *email;
  const char *password;
  const char *status;
  const char *upload_state;
  const char *access_token;
  const char *refresh_token;
  const char *id_token;
  const char *session_token;
  const char *cookies;
  const char *external_account_id;
  const char *workspace_id;
  long last_refreshed_at;
};

struct account_oauth_record {
  long id;
  char email[320];
  char password[96];
  char workspace_id[160];
};

char *account_summary_json(sqlite3 *db);
char *account_list_json(sqlite3 *db, const char *query, const char *status,
                        const char *upload_state, long cursor, long limit,
                        long page);
char *account_detail_json(sqlite3 *db, long id);
int account_insert_success(sqlite3 *db, const struct account_success_record *record,
                           long *out_id);
int account_load_oauth_record(sqlite3 *db, long id,
                              struct account_oauth_record *out);
int account_apply_oauth_success(sqlite3 *db, long id,
                                const struct account_success_record *record);
int account_apply_chatgpt_login_success(
    sqlite3 *db, long id, const struct account_success_record *record);

int account_refresh_tokens(sqlite3 *db, const long *ids, size_t count);
int account_set_upload_state(sqlite3 *db, const long *ids, size_t count,
                             int uploaded);
int account_delete_ids(sqlite3 *db, const long *ids, size_t count);

#endif
