#ifndef APP_AUTH_H
#define APP_AUTH_H

#include "mongoose.h"

#include <sqlite3.h>
#include <stdbool.h>

int app_auth_init(sqlite3 *db);
bool app_auth_enabled(void);
bool app_auth_is_public_route(struct mg_http_message *hm);
bool app_auth_is_authenticated(sqlite3 *db, struct mg_http_message *hm);
void app_auth_reply_unauthorized(struct mg_connection *c,
                                 struct mg_http_message *hm);
void app_auth_handle_api(sqlite3 *db, struct mg_connection *c,
                         struct mg_http_message *hm);

#endif
