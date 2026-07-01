#include "system/system_monitor.h"

#include "mongoose.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

struct cpu_sample_state {
  bool ready;
  uint64_t total;
  uint64_t idle;
};

struct net_sample_state {
  bool ready;
  uint64_t rx_bytes;
  uint64_t tx_bytes;
  uint64_t ts_ms;
};

struct memory_snapshot {
  uint64_t total_bytes;
  uint64_t used_bytes;
  uint64_t free_bytes;
  uint64_t shared_bytes;
  uint64_t buff_cache_bytes;
  uint64_t available_bytes;
  uint64_t swap_total_bytes;
  uint64_t swap_used_bytes;
  uint64_t swap_free_bytes;
  double usage_pct;
  double swap_usage_pct;
};

static struct cpu_sample_state s_cpu;
static struct net_sample_state s_net;

static uint64_t now_ms(void) {
  return mg_millis();
}

static uint64_t read_block_size(const struct statvfs *fs) {
  if (fs == NULL) return 0;
  return fs->f_frsize != 0 ? (uint64_t) fs->f_frsize : (uint64_t) fs->f_bsize;
}

static bool read_proc_cpu(uint64_t *total_out, uint64_t *idle_out) {
  FILE *fp = fopen("/proc/stat", "r");
  char line[512];
  unsigned long long user = 0, nice = 0, system = 0, idle = 0, iowait = 0;
  unsigned long long irq = 0, softirq = 0, steal = 0, guest = 0, guest_nice = 0;

  if (total_out != NULL) *total_out = 0;
  if (idle_out != NULL) *idle_out = 0;
  if (fp == NULL) return false;
  if (fgets(line, sizeof(line), fp) == NULL) {
    fclose(fp);
    return false;
  }
  fclose(fp);
  if (sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
             &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal,
             &guest, &guest_nice) < 5) {
    return false;
  }
  if (total_out != NULL) {
    *total_out = user + nice + system + idle + iowait + irq + softirq + steal +
                 guest + guest_nice;
  }
  if (idle_out != NULL) *idle_out = idle + iowait;
  return true;
}

static double cpu_usage_percent(void) {
  uint64_t total = 0, idle = 0;
  double usage = 0.0;

  if (!read_proc_cpu(&total, &idle)) return 0.0;
  if (!s_cpu.ready) {
    s_cpu.ready = true;
    s_cpu.total = total;
    s_cpu.idle = idle;
    return 0.0;
  }

  {
    uint64_t total_delta = total - s_cpu.total;
    uint64_t idle_delta = idle - s_cpu.idle;
    if (total_delta > 0 && total_delta >= idle_delta) {
      usage = 100.0 * (double) (total_delta - idle_delta) / (double) total_delta;
    }
  }
  s_cpu.total = total;
  s_cpu.idle = idle;
  return usage;
}

static bool read_loadavg(double *load1, double *load5, double *load15) {
  double values[3] = {0.0, 0.0, 0.0};
  int rc = getloadavg(values, 3);
  if (rc < 3) return false;
  if (load1 != NULL) *load1 = values[0];
  if (load5 != NULL) *load5 = values[1];
  if (load15 != NULL) *load15 = values[2];
  return true;
}

static bool read_meminfo(struct memory_snapshot *memory) {
  FILE *fp = fopen("/proc/meminfo", "r");
  char line[256];
  uint64_t buffers = 0, cached = 0, sreclaimable = 0;

  if (memory == NULL) return false;
  memset(memory, 0, sizeof(*memory));
  if (fp == NULL) return false;
  while (fgets(line, sizeof(line), fp) != NULL) {
    char key[64];
    unsigned long long value = 0;
    if (sscanf(line, "%63[^:]: %llu", key, &value) != 2) continue;
    value *= 1024ULL;
    if (strcmp(key, "MemTotal") == 0) memory->total_bytes = (uint64_t) value;
    else if (strcmp(key, "MemFree") == 0) memory->free_bytes = (uint64_t) value;
    else if (strcmp(key, "MemAvailable") == 0) memory->available_bytes = (uint64_t) value;
    else if (strcmp(key, "Buffers") == 0) buffers = (uint64_t) value;
    else if (strcmp(key, "Cached") == 0) cached = (uint64_t) value;
    else if (strcmp(key, "SReclaimable") == 0) sreclaimable = (uint64_t) value;
    else if (strcmp(key, "Shmem") == 0) memory->shared_bytes = (uint64_t) value;
    else if (strcmp(key, "SwapTotal") == 0) memory->swap_total_bytes = (uint64_t) value;
    else if (strcmp(key, "SwapFree") == 0) memory->swap_free_bytes = (uint64_t) value;
  }
  fclose(fp);
  memory->buff_cache_bytes = buffers + cached + sreclaimable;
  memory->used_bytes = memory->total_bytes > memory->available_bytes
                           ? memory->total_bytes - memory->available_bytes
                           : 0;
  memory->usage_pct = memory->total_bytes > 0
                          ? 100.0 * (double) memory->used_bytes /
                                (double) memory->total_bytes
                          : 0.0;
  memory->swap_used_bytes =
      memory->swap_total_bytes > memory->swap_free_bytes
          ? memory->swap_total_bytes - memory->swap_free_bytes
          : 0;
  memory->swap_usage_pct = memory->swap_total_bytes > 0
                               ? 100.0 * (double) memory->swap_used_bytes /
                                     (double) memory->swap_total_bytes
                               : 0.0;
  return memory->total_bytes > 0;
}

static bool read_net_totals(uint64_t *rx_bytes, uint64_t *tx_bytes) {
  FILE *fp = fopen("/proc/net/dev", "r");
  char line[512];
  uint64_t rx = 0, tx = 0;

  if (fp == NULL) return false;
  fgets(line, sizeof(line), fp);
  fgets(line, sizeof(line), fp);
  while (fgets(line, sizeof(line), fp) != NULL) {
    char *colon = strchr(line, ':');
    char iface[64];
    unsigned long long rxb = 0, txb = 0;
    if (colon == NULL) continue;
    *colon = '\0';
    if (sscanf(line, " %63s", iface) != 1) continue;
    if (strcmp(iface, "lo") == 0) continue;
    if (sscanf(colon + 1,
               " %llu %*llu %*llu %*llu %*llu %*llu %*llu %*llu %llu",
               &rxb, &txb) == 2) {
      rx += (uint64_t) rxb;
      tx += (uint64_t) txb;
    }
  }
  fclose(fp);
  if (rx_bytes != NULL) *rx_bytes = rx;
  if (tx_bytes != NULL) *tx_bytes = tx;
  return true;
}

static void net_rate_snapshot(double *rx_rate, double *tx_rate) {
  uint64_t rx = 0, tx = 0;
  uint64_t now = now_ms();

  if (rx_rate != NULL) *rx_rate = 0.0;
  if (tx_rate != NULL) *tx_rate = 0.0;
  if (!read_net_totals(&rx, &tx)) return;
  if (!s_net.ready) {
    s_net.ready = true;
    s_net.rx_bytes = rx;
    s_net.tx_bytes = tx;
    s_net.ts_ms = now;
    return;
  }

  {
    double dt = (double) (now - s_net.ts_ms) / 1000.0;
    if (dt > 0.0) {
      if (rx_rate != NULL) {
        *rx_rate = (double) (rx - s_net.rx_bytes) / dt;
      }
      if (tx_rate != NULL) {
        *tx_rate = (double) (tx - s_net.tx_bytes) / dt;
      }
    }
  }
  s_net.rx_bytes = rx;
  s_net.tx_bytes = tx;
  s_net.ts_ms = now;
}

static uint64_t file_size_bytes(const char *path) {
  struct stat st;
  if (path == NULL || stat(path, &st) != 0) return 0;
  return (uint64_t) st.st_size;
}

struct disk_snapshot {
  char path[32];
  uint64_t total_bytes;
  uint64_t used_bytes;
  uint64_t free_bytes;
  double usage_pct;
};

static void fill_disk_snapshot(const char *path, struct disk_snapshot *out) {
  struct statvfs fs;
  uint64_t block_size;
  uint64_t total = 0, available = 0;

  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  mg_snprintf(out->path, sizeof(out->path), "%s", path ? path : "");
  if (path == NULL || statvfs(path, &fs) != 0) return;
  block_size = read_block_size(&fs);
  total = (uint64_t) fs.f_blocks * block_size;
  available = (uint64_t) fs.f_bavail * block_size;
  out->total_bytes = total;
  out->free_bytes = available;
  out->used_bytes = total > available ? total - available : 0;
  out->usage_pct = total > 0 ? 100.0 * (double) out->used_bytes / (double) total
                             : 0.0;
}

static sqlite3_int64 pragma_int(sqlite3 *db, const char *sql) {
  sqlite3_stmt *stmt = NULL;
  sqlite3_int64 value = 0;
  if (db == NULL || sql == NULL) return 0;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK &&
      sqlite3_step(stmt) == SQLITE_ROW) {
    value = sqlite3_column_int64(stmt, 0);
  }
  sqlite3_finalize(stmt);
  return value;
}

static void pragma_text(sqlite3 *db, const char *sql, char *out, size_t out_len) {
  sqlite3_stmt *stmt = NULL;
  if (out_len == 0) return;
  out[0] = '\0';
  if (db == NULL || sql == NULL) return;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK &&
      sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *value = sqlite3_column_text(stmt, 0);
    mg_snprintf(out, out_len, "%s", value == NULL ? "" : (const char *) value);
  }
  sqlite3_finalize(stmt);
}

struct account_stats_snapshot {
  sqlite3_int64 total;
  sqlite3_int64 active;
  sqlite3_int64 expired;
  sqlite3_int64 temp;
  sqlite3_int64 failed;
  sqlite3_int64 uploaded;
  sqlite3_int64 not_uploaded;
  sqlite3_int64 updated_at;
};

static void read_account_stats(sqlite3 *db, struct account_stats_snapshot *out) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "SELECT total,active_count,expired_count,temp_count,failed_count,"
      "uploaded_count,not_uploaded_count,updated_at FROM account_stats WHERE id=1";

  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  if (db == NULL) return;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    out->total = sqlite3_column_int64(stmt, 0);
    out->active = sqlite3_column_int64(stmt, 1);
    out->expired = sqlite3_column_int64(stmt, 2);
    out->temp = sqlite3_column_int64(stmt, 3);
    out->failed = sqlite3_column_int64(stmt, 4);
    out->uploaded = sqlite3_column_int64(stmt, 5);
    out->not_uploaded = sqlite3_column_int64(stmt, 6);
    out->updated_at = sqlite3_column_int64(stmt, 7);
  }
  sqlite3_finalize(stmt);
}

static void append_disk_json(struct mg_iobuf *io, const char *name,
                             const struct disk_snapshot *disk) {
  mg_xprintf(mg_pfn_iobuf, io,
             "{%m:%m,%m:%m,%m:%llu,%m:%llu,%m:%llu,%m:%.1f}",
             MG_ESC("name"), MG_ESC(name ? name : ""),
             MG_ESC("path"), MG_ESC(disk->path),
             MG_ESC("total_bytes"), (unsigned long long) disk->total_bytes,
             MG_ESC("used_bytes"), (unsigned long long) disk->used_bytes,
             MG_ESC("free_bytes"), (unsigned long long) disk->free_bytes,
             MG_ESC("usage_pct"), disk->usage_pct);
}

char *system_monitor_status_json(sqlite3 *db, uint64_t uptime_ms,
                                 unsigned connections) {
  struct mg_iobuf io = {0, 0, 0, 4096};
  struct memory_snapshot memory;
  double cpu_pct = cpu_usage_percent();
  double load1 = 0.0, load5 = 0.0, load15 = 0.0;
  double rx_rate = 0.0, tx_rate = 0.0;
  struct disk_snapshot root_disk;
  struct disk_snapshot data_disk;
  struct account_stats_snapshot stats;
  sqlite3_int64 page_count = 0, freelist_count = 0, page_size = 0;
  sqlite3_int64 synchronous = 0, wal_autocheckpoint = 0, cache_size = 0;
  sqlite3_int64 foreign_keys = 0, schema_version = 0, user_version = 0;
  sqlite3_int64 tables_count = 0, indexes_count = 0, triggers_count = 0;
  uint64_t db_size = 0, wal_size = 0, shm_size = 0;
  uint64_t estimated_size = 0;
  double freelist_pct = 0.0;
  char journal_mode[32];
  int cpu_cores = (int) sysconf(_SC_NPROCESSORS_ONLN);

  if (cpu_cores < 1) cpu_cores = 1;
  memset(&memory, 0, sizeof(memory));
  read_loadavg(&load1, &load5, &load15);
  read_meminfo(&memory);
  net_rate_snapshot(&rx_rate, &tx_rate);
  fill_disk_snapshot("/", &root_disk);
  fill_disk_snapshot("data", &data_disk);
  read_account_stats(db, &stats);
  page_count = pragma_int(db, "PRAGMA page_count;");
  freelist_count = pragma_int(db, "PRAGMA freelist_count;");
  page_size = pragma_int(db, "PRAGMA page_size;");
  synchronous = pragma_int(db, "PRAGMA synchronous;");
  wal_autocheckpoint = pragma_int(db, "PRAGMA wal_autocheckpoint;");
  cache_size = pragma_int(db, "PRAGMA cache_size;");
  foreign_keys = pragma_int(db, "PRAGMA foreign_keys;");
  schema_version = pragma_int(db, "PRAGMA schema_version;");
  user_version = pragma_int(db, "PRAGMA user_version;");
  tables_count = pragma_int(db, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%';");
  indexes_count = pragma_int(db, "SELECT count(*) FROM sqlite_schema WHERE type='index' AND name NOT LIKE 'sqlite_%';");
  triggers_count = pragma_int(db, "SELECT count(*) FROM sqlite_schema WHERE type='trigger';");
  pragma_text(db, "PRAGMA journal_mode;", journal_mode, sizeof(journal_mode));
  db_size = file_size_bytes("data/app.db");
  wal_size = file_size_bytes("data/app.db-wal");
  shm_size = file_size_bytes("data/app.db-shm");
  estimated_size = (uint64_t) page_size * (uint64_t) page_count;
  freelist_pct = page_count > 0 ? 100.0 * (double) freelist_count /
                                      (double) page_count
                                : 0.0;

  mg_xprintf(
      mg_pfn_iobuf, &io,
      "{%m:%m,%m:%llu,%m:%u,%m:%m,%m:%llu,"
      "%m:{%m:%d,%m:%.1f,%m:%.2f,%m:%.2f,%m:%.2f},"
      "%m:{%m:%llu,%m:%llu,%m:%llu,%m:%llu,%m:%llu,%m:%llu,%m:%.1f,"
      "%m:%llu,%m:%llu,%m:%llu,%m:%.1f},"
      "%m:{%m:",
      MG_ESC("status"), MG_ESC("ok"),
      MG_ESC("uptime_ms"), (unsigned long long) uptime_ms,
      MG_ESC("connections"), connections,
      MG_ESC("server"), MG_ESC("mongoose"),
      MG_ESC("sampled_at_ms"), (unsigned long long) now_ms(),
      MG_ESC("cpu"),
        MG_ESC("cores"), cpu_cores,
        MG_ESC("usage_pct"), cpu_pct,
        MG_ESC("load1"), load1,
        MG_ESC("load5"), load5,
        MG_ESC("load15"), load15,
      MG_ESC("memory"),
        MG_ESC("total_bytes"), (unsigned long long) memory.total_bytes,
        MG_ESC("used_bytes"), (unsigned long long) memory.used_bytes,
        MG_ESC("free_bytes"), (unsigned long long) memory.free_bytes,
        MG_ESC("shared_bytes"), (unsigned long long) memory.shared_bytes,
        MG_ESC("buff_cache_bytes"), (unsigned long long) memory.buff_cache_bytes,
        MG_ESC("available_bytes"), (unsigned long long) memory.available_bytes,
        MG_ESC("usage_pct"), memory.usage_pct,
        MG_ESC("swap_total_bytes"), (unsigned long long) memory.swap_total_bytes,
        MG_ESC("swap_used_bytes"), (unsigned long long) memory.swap_used_bytes,
        MG_ESC("swap_free_bytes"), (unsigned long long) memory.swap_free_bytes,
        MG_ESC("swap_usage_pct"), memory.swap_usage_pct,
      MG_ESC("storage"), MG_ESC("root"));

  append_disk_json(&io, "root", &root_disk);
  mg_xprintf(mg_pfn_iobuf, &io, ",%m:", MG_ESC("data"));
  append_disk_json(&io, "data", &data_disk);

  mg_xprintf(mg_pfn_iobuf, &io,
             "},%m:{%m:%llu,%m:%llu,%m:%.1f,%m:%.1f},"
             "%m:{%m:%m,%m:%llu,%m:%llu,%m:%llu,%m:%llu,%m:%llu,%m:%llu,%m:%llu,"
             "%m:%.2f,%m:%m,%m:%lld,%m:%lld,%m:%lld,%m:%lld,%m:%lld,%m:%lld,"
             "%m:%lld,%m:%lld,%m:%lld,%m:%lld,%m:%lld,%m:%lld,%m:%lld,%m:%lld,"
             "%m:%lld,%m:%lld,%m:%lld}}",
             MG_ESC("network"),
             MG_ESC("rx_bytes"), (unsigned long long) s_net.rx_bytes,
             MG_ESC("tx_bytes"), (unsigned long long) s_net.tx_bytes,
             MG_ESC("rx_rate_Bps"), rx_rate,
             MG_ESC("tx_rate_Bps"), tx_rate,
             MG_ESC("sqlite"),
             MG_ESC("path"), MG_ESC("data/app.db"),
             MG_ESC("size_bytes"), (unsigned long long) db_size,
             MG_ESC("wal_size_bytes"), (unsigned long long) wal_size,
             MG_ESC("shm_size_bytes"), (unsigned long long) shm_size,
             MG_ESC("page_size"), (unsigned long long) page_size,
             MG_ESC("page_count"), (unsigned long long) page_count,
             MG_ESC("freelist_count"), (unsigned long long) freelist_count,
             MG_ESC("estimated_size_bytes"), (unsigned long long) estimated_size,
             MG_ESC("freelist_pct"), freelist_pct,
             MG_ESC("journal_mode"), MG_ESC(journal_mode),
             MG_ESC("synchronous"), (long long) synchronous,
             MG_ESC("wal_autocheckpoint"), (long long) wal_autocheckpoint,
             MG_ESC("cache_size"), (long long) cache_size,
             MG_ESC("foreign_keys"), (long long) foreign_keys,
             MG_ESC("schema_version"), (long long) schema_version,
             MG_ESC("user_version"), (long long) user_version,
             MG_ESC("tables_count"), (long long) tables_count,
             MG_ESC("indexes_count"), (long long) indexes_count,
             MG_ESC("triggers_count"), (long long) triggers_count,
             MG_ESC("accounts_total"), (long long) stats.total,
             MG_ESC("accounts_active"), (long long) stats.active,
             MG_ESC("accounts_expired"), (long long) stats.expired,
             MG_ESC("accounts_temp"), (long long) stats.temp,
             MG_ESC("accounts_failed"), (long long) stats.failed,
             MG_ESC("accounts_uploaded"), (long long) stats.uploaded,
             MG_ESC("accounts_not_uploaded"), (long long) stats.not_uploaded,
             MG_ESC("stats_updated_at"), (long long) stats.updated_at);

  mg_iobuf_add(&io, io.len, "", 1);
  return (char *) io.buf;
}
