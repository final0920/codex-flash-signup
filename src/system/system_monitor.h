#ifndef APP_SYSTEM_MONITOR_H
#define APP_SYSTEM_MONITOR_H

#include <sqlite3.h>
#include <stdint.h>

char *system_monitor_status_json(sqlite3 *db, uint64_t uptime_ms,
                                 unsigned connections);

#endif
