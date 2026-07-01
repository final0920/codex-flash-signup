#include "identity/identity_generator.h"

#include "mail/rapid_inbox.h"
#include "mongoose.h"
#include "name/name_generator.h"

#include <ctype.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct domain_rule_row {
  char base_domain[IDENTITY_DOMAIN_LEN];
  int wildcard_depth;
};

static uint64_t random_u64(void) {
  uint64_t value = 0;
  if (!mg_random(&value, sizeof(value))) {
    value = ((uint64_t) rand() << 32) ^ (uint64_t) rand();
  }
  return value;
}

static unsigned random_bounded(unsigned count) {
  return count == 0 ? 0 : (unsigned) (random_u64() % count);
}

static void set_error(char *error, size_t error_len, const char *message) {
  if (error_len == 0) return;
  mg_snprintf(error, error_len, "%s", message ? message : "identity error");
}

static bool is_leap_year(int year) {
  return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

static int days_in_month(int year, int month) {
  static const int days[] = {31, 28, 31, 30, 31, 30,
                             31, 31, 30, 31, 30, 31};
  if (month == 2 && is_leap_year(year)) return 29;
  if (month < 1 || month > 12) return 30;
  return days[month - 1];
}

static int exact_age(int year, int month, int day, const struct tm *now_tm) {
  int age = (now_tm->tm_year + 1900) - year;
  int now_month = now_tm->tm_mon + 1;
  int now_day = now_tm->tm_mday;
  if (month > now_month || (month == now_month && day > now_day)) age--;
  return age;
}

static void generate_birthdate(char *out, size_t out_len, int *age_out) {
  time_t now = time(NULL);
  struct tm now_tm_storage;
  struct tm *now_tm = localtime_r(&now, &now_tm_storage);
  int year, month, day, age;

  if (now_tm == NULL) {
    mg_snprintf(out, out_len, "2001-01-01");
    if (age_out != NULL) *age_out = 24;
    return;
  }

  do {
    int current_year = now_tm->tm_year + 1900;
    year = current_year - 25 + (int) random_bounded(7);
    month = 1 + (int) random_bounded(12);
    day = 1 + (int) random_bounded((unsigned) days_in_month(year, month));
    age = exact_age(year, month, day, now_tm);
  } while (age < 19 || age > 25);

  mg_snprintf(out, out_len, "%04d-%02d-%02d", year, month, day);
  if (age_out != NULL) *age_out = age;
}

static void normalize_name_local(const char *name, char *out, size_t out_len) {
  size_t n = 0;
  if (out_len == 0) return;
  for (size_t i = 0; name != NULL && name[i] && n + 1 < out_len; i++) {
    unsigned char ch = (unsigned char) name[i];
    if (isalnum(ch)) out[n++] = (char) tolower(ch);
  }
  if (n == 0 && out_len > 1) out[n++] = 'u';
  out[n] = '\0';
}

static char random_alnum(void) {
  static const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  return chars[random_bounded((unsigned) strlen(chars))];
}

static void append_entropy_suffix(char *local, size_t local_len) {
  enum { suffix_len = 10 };
  size_t len = strlen(local);
  size_t base_limit = 22;
  size_t target_len;

  if (local_len == 0) return;
  if (base_limit + suffix_len + 1 > local_len) {
    if (local_len <= suffix_len + 1) return;
    base_limit = local_len - suffix_len - 1;
  }
  if (len > base_limit) {
    local[base_limit] = '\0';
    len = base_limit;
  }
  target_len = len + suffix_len;
  if (target_len + 1 > local_len) target_len = local_len - 1;
  while (len < target_len) {
    local[len++] = random_alnum();
    local[len] = '\0';
  }
}

static bool pick_domain_rule(sqlite3 *db, struct domain_rule_row *row,
                             char *error, size_t error_len) {
  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "SELECT base_domain,wildcard_depth FROM mail_domain_rules "
      "WHERE is_active=1 ORDER BY random() LIMIT 1";

  memset(row, 0, sizeof(*row));
  if (db == NULL) {
    set_error(error, error_len, "数据库未打开");
    return false;
  }
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
    set_error(error, error_len, sqlite3_errmsg(db));
    return false;
  }
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *domain = sqlite3_column_text(stmt, 0);
    mg_snprintf(row->base_domain, sizeof(row->base_domain), "%s",
                domain == NULL ? "" : (const char *) domain);
    row->wildcard_depth = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);
    return row->base_domain[0] != '\0';
  }
  sqlite3_finalize(stmt);
  set_error(error, error_len, "请先在邮件配置中添加可用域名");
  return false;
}

static void generate_domain_label(char *out, size_t out_len) {
  unsigned len = 4 + random_bounded(5);
  size_t n = 0;
  if (out_len == 0) return;
  for (unsigned i = 0; i < len && n + 1 < out_len; i++) {
    out[n++] = random_alnum();
  }
  out[n] = '\0';
}

// outlook 别名后缀: 5-8 位随机小写字母数字(如 a3k9c)
static void generate_alias_suffix(char *out, size_t out_len) {
  unsigned len = 5 + random_bounded(4);
  size_t n = 0;
  if (out_len == 0) return;
  for (unsigned i = 0; i < len && n + 1 < out_len; i++) {
    out[n++] = random_alnum();
  }
  out[n] = '\0';
}

static void build_email_domain(const struct domain_rule_row *rule, char *out,
                               size_t out_len) {
  struct mg_iobuf io = {0, 0, 0, 128};
  int depth = rule->wildcard_depth;

  if (depth < 0) depth = 0;
  for (int i = 0; i < depth; i++) {
    char label[9];
    generate_domain_label(label, sizeof(label));
    mg_xprintf(mg_pfn_iobuf, &io, "%s.", label);
  }
  mg_xprintf(mg_pfn_iobuf, &io, "%s", rule->base_domain);
  mg_iobuf_add(&io, io.len, "", 1);
  mg_snprintf(out, out_len, "%s", io.buf ? (char *) io.buf : "");
  mg_iobuf_free(&io);
}

static void generate_password(char *out, size_t out_len) {
  static const char chars[] =
      "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
  size_t n = 0;
  size_t len = 18 + random_bounded(7);
  if (out_len == 0) return;
  while (n < len && n + 1 < out_len) {
    out[n++] = chars[random_bounded((unsigned) strlen(chars))];
  }
  out[n] = '\0';
}

static bool email_exists(sqlite3 *db, const char *email) {
  sqlite3_stmt *stmt = NULL;
  bool exists = false;
  if (db == NULL || email == NULL || email[0] == '\0') return false;
  if (sqlite3_prepare_v2(db, "SELECT 1 FROM accounts WHERE email=? LIMIT 1",
                         -1, &stmt, NULL) != SQLITE_OK) {
    return false;
  }
  sqlite3_bind_text(stmt, 1, email, -1, SQLITE_TRANSIENT);
  exists = sqlite3_step(stmt) == SQLITE_ROW;
  sqlite3_finalize(stmt);
  return exists;
}

int identity_generate(sqlite3 *db, struct identity_result *out, char *error,
                      size_t error_len) {
  struct generated_name name;
  struct domain_rule_row rule;
  int attempts = 0;

  if (out == NULL) {
    set_error(error, error_len, "identity output is null");
    return -1;
  }
  memset(out, 0, sizeof(*out));
  if (!pick_domain_rule(db, &rule, error, error_len)) return -1;

  do {
    if (name_generator_generate(&name) != 0) {
      set_error(error, error_len, "姓名生成失败");
      return -1;
    }
    mg_snprintf(out->full_name, sizeof(out->full_name), "%s", name.full_name);
    mg_snprintf(out->given_name, sizeof(out->given_name), "%s",
                name.given_name);
    mg_snprintf(out->family_name, sizeof(out->family_name), "%s",
                name.family_name);
    normalize_name_local(out->full_name, out->email_local,
                         sizeof(out->email_local));
    append_entropy_suffix(out->email_local, sizeof(out->email_local));
    build_email_domain(&rule, out->email_domain, sizeof(out->email_domain));
    mg_snprintf(out->email, sizeof(out->email), "%s@%s", out->email_local,
                out->email_domain);
    attempts++;
  } while (attempts < 16 && email_exists(db, out->email));

  if (email_exists(db, out->email)) {
    set_error(error, error_len, "生成邮箱与现有账号重复");
    return -1;
  }
  if (rapid_inbox_provision_mailbox(db, out->email, error, error_len) != 0) {
    return -1;
  }
  generate_password(out->password, sizeof(out->password));
  generate_birthdate(out->birthdate, sizeof(out->birthdate), &out->age);
  return 0;
}

int identity_generate_outlook_alias(sqlite3 *db, const char *mother_email,
                                    struct identity_result *out, char *error,
                                    size_t error_len) {
  struct generated_name name;
  const char *at;
  char local[128];
  size_t local_len;
  int attempts = 0;

  if (out == NULL) {
    set_error(error, error_len, "identity output is null");
    return -1;
  }
  memset(out, 0, sizeof(*out));
  if (mother_email == NULL || (at = strchr(mother_email, '@')) == NULL) {
    set_error(error, error_len, "母邮箱地址无效");
    return -1;
  }
  local_len = (size_t) (at - mother_email);
  if (local_len == 0 || local_len >= sizeof(local)) {
    set_error(error, error_len, "母邮箱本地名长度非法");
    return -1;
  }
  memcpy(local, mother_email, local_len);
  local[local_len] = '\0';
  mg_snprintf(out->email_domain, sizeof(out->email_domain), "%s", at + 1);

  if (name_generator_generate(&name) != 0) {
    set_error(error, error_len, "姓名生成失败");
    return -1;
  }
  mg_snprintf(out->full_name, sizeof(out->full_name), "%s", name.full_name);
  mg_snprintf(out->given_name, sizeof(out->given_name), "%s", name.given_name);
  mg_snprintf(out->family_name, sizeof(out->family_name), "%s", name.family_name);

  // outlook_alias_mode: "direct"=母号直注(一号一注册, 不加别名),
  // 缺省/"alias"=别名复用(母号本地名 + "+随机后缀", 一母号多号)
  int use_direct = 0;
  {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db, "SELECT value FROM mail_settings WHERE key='outlook_alias_mode'",
            -1, &st, NULL) == SQLITE_OK) {
      if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(st, 0);
        if (v != NULL && strcmp((const char *) v, "direct") == 0) use_direct = 1;
      }
      sqlite3_finalize(st);
    }
  }

  if (use_direct) {
    // 母号直注: email = 母号本身(不加 +别名)
    mg_snprintf(out->email_local, sizeof(out->email_local), "%s", local);
    mg_snprintf(out->email, sizeof(out->email), "%s", mother_email);
    if (email_exists(db, out->email)) {
      set_error(error, error_len,
                "母号已注册过账号(direct 模式一号一注册), 请换母号或切回别名模式");
      return -1;
    }
  } else {
    // 别名 = 母邮箱本地名 + "+随机后缀", 避开本地库已有账号
    do {
      char suffix[12];
      generate_alias_suffix(suffix, sizeof(suffix));
      mg_snprintf(out->email_local, sizeof(out->email_local), "%s+%s", local,
                  suffix);
      mg_snprintf(out->email, sizeof(out->email), "%s@%s", out->email_local,
                  out->email_domain);
      attempts++;
    } while (attempts < 16 && email_exists(db, out->email));

    if (email_exists(db, out->email)) {
      set_error(error, error_len, "生成的 outlook 别名与现有账号重复");
      return -1;
    }
  }
  {
    /* outlook 渠道: 优先用母号导入的密码, 未导入则随机兜底 */
    char imported_pw[IDENTITY_PASSWORD_LEN] = "";
    sqlite3_stmt *pst = NULL;
    if (sqlite3_prepare_v2(
            db, "SELECT password FROM outlook_mailboxes WHERE email=? COLLATE NOCASE",
            -1, &pst, NULL) == SQLITE_OK) {
      sqlite3_bind_text(pst, 1, mother_email, -1, SQLITE_TRANSIENT);
      if (sqlite3_step(pst) == SQLITE_ROW) {
        const unsigned char *pv = sqlite3_column_text(pst, 0);
        if (pv != NULL)
          mg_snprintf(imported_pw, sizeof(imported_pw), "%s", (const char *) pv);
      }
      sqlite3_finalize(pst);
    }
    if (imported_pw[0] != '\0')
      mg_snprintf(out->password, sizeof(out->password), "%s", imported_pw);
    else
      generate_password(out->password, sizeof(out->password));
  }
  generate_birthdate(out->birthdate, sizeof(out->birthdate), &out->age);
  return 0;
}

size_t identity_to_json(const struct identity_result *identity, char *buf,
                        size_t len) {
  if (buf == NULL || len == 0) return 0;
  if (identity == NULL) {
    return (size_t) mg_snprintf(buf, len, "{}");
  }
  return (size_t) mg_snprintf(
      buf, len,
      "{%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%d}",
      MG_ESC("full_name"), MG_ESC(identity->full_name),
      MG_ESC("given_name"), MG_ESC(identity->given_name),
      MG_ESC("family_name"), MG_ESC(identity->family_name), MG_ESC("email"),
      MG_ESC(identity->email), MG_ESC("email_local"),
      MG_ESC(identity->email_local), MG_ESC("email_domain"),
      MG_ESC(identity->email_domain), MG_ESC("birthdate"),
      MG_ESC(identity->birthdate), MG_ESC("age"), identity->age);
}
