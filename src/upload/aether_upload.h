#ifndef APP_AETHER_UPLOAD_H
#define APP_AETHER_UPLOAD_H

#include "mongoose.h"

#include <stdbool.h>
#include <sqlite3.h>
#include <stddef.h>

char *aether_config_json(sqlite3 *db);
char *aether_service_save_json(sqlite3 *db, struct mg_str body);
char *aether_service_delete_json(sqlite3 *db, struct mg_str body);
char *aether_service_test_json(sqlite3 *db, struct mg_str body);
char *aether_options_json(sqlite3 *db, struct mg_str body);
int aether_resolve_enabled_upload_service(sqlite3 *db, long requested_id,
                                          bool random, long *out_id,
                                          char *out_name, size_t out_name_len,
                                          char *error, size_t error_len);
bool aether_has_chatgpt_web_upload_service(sqlite3 *db);
bool aether_has_chatgpt_web_upload_service_id(sqlite3 *db, long service_id);
char *aether_upload_accounts_json(sqlite3 *db, const long *ids, size_t count,
                                  const char *pool_type);
char *aether_upload_accounts_to_service_json(sqlite3 *db, const long *ids,
                                             size_t count,
                                             const char *pool_type,
                                             long service_id);

#endif
