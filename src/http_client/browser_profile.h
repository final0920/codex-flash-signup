#ifndef APP_BROWSER_PROFILE_H
#define APP_BROWSER_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#define BROWSER_PROFILE_SMALL 32
#define BROWSER_PROFILE_MEDIUM 96
#define BROWSER_PROFILE_LARGE 256

struct browser_profile {
  char id[BROWSER_PROFILE_SMALL];
  char browser[BROWSER_PROFILE_SMALL];
  char browser_version[BROWSER_PROFILE_SMALL];
  char os[BROWSER_PROFILE_SMALL];
  char os_version[BROWSER_PROFILE_SMALL];
  char device_class[BROWSER_PROFILE_SMALL];
  char device_model[BROWSER_PROFILE_MEDIUM];
  char region[BROWSER_PROFILE_SMALL];
  char locale[BROWSER_PROFILE_SMALL];
  char timezone[BROWSER_PROFILE_MEDIUM];
  char user_agent[BROWSER_PROFILE_LARGE];
  char accept[BROWSER_PROFILE_LARGE];
  char accept_language[BROWSER_PROFILE_MEDIUM];
  char accept_encoding[BROWSER_PROFILE_MEDIUM];
  char sec_ch_ua[BROWSER_PROFILE_MEDIUM];
  char sec_ch_ua_platform[BROWSER_PROFILE_SMALL];
  char sec_ch_ua_mobile[BROWSER_PROFILE_SMALL];
};

void browser_profile_seed(uint64_t seed);
void browser_profile_generate(struct browser_profile *profile,
                              const char *region_hint,
                              const char *device_hint);
size_t browser_profile_to_json(const struct browser_profile *profile, char *buf,
                               size_t len);

#endif
