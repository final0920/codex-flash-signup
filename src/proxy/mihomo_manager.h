#ifndef APP_MIHOMO_MANAGER_H
#define APP_MIHOMO_MANAGER_H

#include "mongoose.h"

#include <sqlite3.h>
#include <stddef.h>

char *mihomo_config_json(sqlite3 *db);
char *mihomo_save_config_json(sqlite3 *db, struct mg_str body);
char *mihomo_start_json(sqlite3 *db);
char *mihomo_stop_json(sqlite3 *db);
char *mihomo_sample_json(sqlite3 *db, int samples);
char *mihomo_nodes_json(sqlite3 *db);
char *mihomo_select_node_json(sqlite3 *db, struct mg_str body);

int mihomo_start_configured(sqlite3 *db);
void mihomo_shutdown(sqlite3 *db);
int mihomo_current_proxy_mode(sqlite3 *db, char *mode, size_t mode_len);

int mihomo_proxy_pick_url(sqlite3 *db, char *url, size_t url_len,
                          int *handled);
int mihomo_task_node_validate(sqlite3 *db, const char *preferred_node,
                              char *normalized_node,
                              size_t normalized_node_len, char *error,
                              size_t error_len);
int mihomo_task_proxy_pick_url(sqlite3 *db, const char *task_id,
                               const char *preferred_node, char *url,
                               size_t url_len, char *selected_node,
                               size_t selected_node_len, char *error,
                               size_t error_len);
void mihomo_task_proxy_release(const char *task_id);

#endif
