#ifndef APP_IDENTITY_GENERATOR_H
#define APP_IDENTITY_GENERATOR_H

#include <sqlite3.h>
#include <stddef.h>

#define IDENTITY_NAME_LEN 192
#define IDENTITY_EMAIL_LEN 320
#define IDENTITY_PASSWORD_LEN 96
#define IDENTITY_BIRTHDATE_LEN 16
#define IDENTITY_DOMAIN_LEN 256

struct identity_result {
  char full_name[IDENTITY_NAME_LEN];
  char given_name[128];
  char family_name[96];
  char email[IDENTITY_EMAIL_LEN];
  char email_local[128];
  char email_domain[IDENTITY_DOMAIN_LEN];
  char password[IDENTITY_PASSWORD_LEN];
  char birthdate[IDENTITY_BIRTHDATE_LEN];
  int age;
};

int identity_generate(sqlite3 *db, struct identity_result *out, char *error,
                      size_t error_len);
size_t identity_to_json(const struct identity_result *identity, char *buf,
                        size_t len);

#endif
