#ifndef APP_NAME_GENERATOR_H
#define APP_NAME_GENERATOR_H

#include <stddef.h>

struct generated_name {
  char full_name[192];
  char given_name[128];
  char family_name[96];
};

int name_generator_generate(struct generated_name *name);
char *name_generator_json(long count);

#endif
