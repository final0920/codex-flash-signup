#ifndef ACCOUNT_TOKEN_VALIDATOR_H
#define ACCOUNT_TOKEN_VALIDATOR_H

#include <sqlite3.h>
#include <stddef.h>

char *account_refresh_tokens_json(sqlite3 *db, const long *ids, size_t count);
char *account_validate_tokens_json(sqlite3 *db, const long *ids, size_t count);

#endif
