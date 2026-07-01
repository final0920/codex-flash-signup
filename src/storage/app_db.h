#ifndef APP_DB_H
#define APP_DB_H

#include <sqlite3.h>

int app_db_init(const char *path, sqlite3 **db);
int app_db_open(const char *path, sqlite3 **db);
void app_db_close(sqlite3 *db);

#endif
