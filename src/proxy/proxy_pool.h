#ifndef APP_PROXY_POOL_H
#define APP_PROXY_POOL_H

#include <sqlite3.h>
#include <stddef.h>

struct proxy_import_result {
  int imported;
  int skipped;
  int invalid;
};

int proxy_pool_import_text(sqlite3 *db, const char *text,
                           struct proxy_import_result *result);
char *proxy_pool_list_json(sqlite3 *db);
int proxy_pool_delete_ids(sqlite3 *db, const long *ids, size_t count);
char *proxy_pool_test_ids(sqlite3 *db, const long *ids, size_t count);
int proxy_pool_pick_active_url(sqlite3 *db, char *url, size_t url_len);

#endif
