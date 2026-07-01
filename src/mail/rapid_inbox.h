#ifndef APP_RAPID_INBOX_H
#define APP_RAPID_INBOX_H

#include <sqlite3.h>
#include <stddef.h>

char *rapid_inbox_config_json(sqlite3 *db);
int rapid_inbox_save_config(sqlite3 *db, const char *base_url,
                            const char *api_key, const char *backend,
                            const char *transport);
int rapid_inbox_start_configured(sqlite3 *db);
void rapid_inbox_shutdown(void);
int rapid_inbox_provision_mailbox(sqlite3 *db, const char *mailbox,
                                  char *error, size_t error_len);
char *rapid_inbox_add_domain_json(sqlite3 *db, const char *pattern);
char *rapid_inbox_add_domains_json(sqlite3 *db, const char *text);
int rapid_inbox_delete_domain_ids(sqlite3 *db, const long *ids, size_t count);
char *rapid_inbox_fetch_json(sqlite3 *db, const char *mailbox,
                             const char *action, const char *delivery_id,
                             long limit);
int rapid_inbox_fetch_latest_code(sqlite3 *db, const char *mailbox,
                                  char *code, size_t code_len,
                                  char *error, size_t error_len);
int rapid_inbox_fetch_latest_code_since(sqlite3 *db, const char *mailbox,
                                        long min_received_at,
                                        char *code, size_t code_len,
                                        char *error, size_t error_len);

#endif
