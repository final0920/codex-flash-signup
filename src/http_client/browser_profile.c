#include "http_client/browser_profile.h"

#include "mongoose.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

struct region_seed {
  const char *code;
  const char *locale;
  const char *accept_language;
  const char *timezone;
};

struct desktop_seed {
  const char *os;
  const char *os_version;
  const char *ua_platform;
  const char *sec_ch_platform;
};

struct android_seed {
  const char *model;
  const char *android_version;
};

struct ios_seed {
  const char *model;
  const char *ios_version;
  const char *version_token;
};

static uint64_t s_rng = 0x9e3779b97f4a7c15ULL;

static const struct region_seed s_regions[] = {
    {"US", "en-US", "en-US,en;q=0.9", "America/New_York"},
    {"GB", "en-GB", "en-GB,en;q=0.9,en-US;q=0.8", "Europe/London"},
    {"JP", "ja-JP", "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7", "Asia/Tokyo"},
    {"DE", "de-DE", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7", "Europe/Berlin"},
    {"FR", "fr-FR", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", "Europe/Paris"},
    {"BR", "pt-BR", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
     "America/Sao_Paulo"},
    {"IN", "en-IN", "en-IN,en;q=0.9,hi-IN;q=0.8,hi;q=0.7",
     "Asia/Kolkata"},
    {"CN", "zh-CN", "zh-CN,zh;q=0.9,en;q=0.8", "Asia/Shanghai"},
    {"KR", "ko-KR", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7", "Asia/Seoul"},
    {"AU", "en-AU", "en-AU,en;q=0.9,en-US;q=0.8", "Australia/Sydney"},
};

static const struct desktop_seed s_desktops[] = {
    {"windows", "10.0", "Windows NT 10.0; Win64; x64", "\"Windows\""},
    {"windows", "11", "Windows NT 10.0; Win64; x64", "\"Windows\""},
    {"macos", "14.7", "Macintosh; Intel Mac OS X 10_15_7", "\"macOS\""},
    {"macos", "15.4", "Macintosh; Intel Mac OS X 10_15_7", "\"macOS\""},
    {"linux", "x86_64", "X11; Linux x86_64", "\"Linux\""},
};

static const struct android_seed s_androids[] = {
    {"Pixel 8", "14"},
    {"Pixel 8 Pro", "14"},
    {"Pixel 9", "15"},
    {"SM-S921B", "14"},
    {"SM-S928B", "14"},
    {"Xiaomi 14", "14"},
};

static const struct ios_seed s_ios[] = {
    {"iPhone", "17_6", "17.6"},
    {"iPhone", "18_4", "18.4"},
    {"iPad", "17_6", "17.6"},
    {"iPad", "18_4", "18.4"},
};

static const char *s_chrome_versions[] = {
    "148.0.7778.167",
    "147.0.7730.214",
    "146.0.7698.120",
};

static const char *s_firefox_versions[] = {
    "150.0.3",
    "149.0.2",
    "140.10.2esr",
};

static uint64_t rng_next(void) {
  uint64_t x = s_rng;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  s_rng = x;
  return x * 2685821657736338717ULL;
}

static size_t pick(size_t count) {
  return count == 0 ? 0 : (size_t) (rng_next() % count);
}

static bool same_token(const char *a, const char *b) {
  if (a == NULL || b == NULL || a[0] == '\0' || b[0] == '\0') return false;
  return strcasecmp(a, b) == 0;
}

static const struct region_seed *choose_region(const char *hint) {
  size_t count = sizeof(s_regions) / sizeof(s_regions[0]);
  if (hint != NULL && hint[0] != '\0') {
    for (size_t i = 0; i < count; i++) {
      if (same_token(hint, s_regions[i].code)) return &s_regions[i];
    }
  }
  return &s_regions[pick(count)];
}

static int major_version(const char *version) {
  return version == NULL ? 0 : atoi(version);
}

static const char *chrome_major_ua(const char *version) {
  static char buf[32];
  mg_snprintf(buf, sizeof(buf), "%d.0.0.0", major_version(version));
  return buf;
}

static void make_id(char *buf, size_t len) {
  mg_snprintf(buf, len, "%08lx%08lx", (unsigned long) rng_next(),
              (unsigned long) rng_next());
}

static void set_common(struct browser_profile *p, const struct region_seed *r) {
  mg_snprintf(p->id, sizeof(p->id), "");
  make_id(p->id, sizeof(p->id));
  mg_snprintf(p->region, sizeof(p->region), "%s", r->code);
  mg_snprintf(p->locale, sizeof(p->locale), "%s", r->locale);
  mg_snprintf(p->timezone, sizeof(p->timezone), "%s", r->timezone);
  mg_snprintf(p->accept_language, sizeof(p->accept_language), "%s",
              r->accept_language);
  mg_snprintf(p->accept, sizeof(p->accept),
              "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8");
  mg_snprintf(p->accept_encoding, sizeof(p->accept_encoding),
              "gzip, deflate, br, zstd");
}

static void build_chrome_desktop(struct browser_profile *p) {
  const char *version =
      s_chrome_versions[pick(sizeof(s_chrome_versions) / sizeof(s_chrome_versions[0]))];
  const struct desktop_seed *os =
      &s_desktops[pick(sizeof(s_desktops) / sizeof(s_desktops[0]))];
  int major = major_version(version);
  const char *brand_first = pick(2) ? "Google Chrome" : "Chromium";
  const char *brand_second = strcmp(brand_first, "Google Chrome") == 0
                                 ? "Chromium"
                                 : "Google Chrome";

  mg_snprintf(p->browser, sizeof(p->browser), "chrome");
  mg_snprintf(p->browser_version, sizeof(p->browser_version), "%s", version);
  mg_snprintf(p->os, sizeof(p->os), "%s", os->os);
  mg_snprintf(p->os_version, sizeof(p->os_version), "%s", os->os_version);
  mg_snprintf(p->device_class, sizeof(p->device_class), "desktop");
  mg_snprintf(p->device_model, sizeof(p->device_model), "");
  mg_snprintf(p->sec_ch_ua, sizeof(p->sec_ch_ua),
              "\"Not_A Brand\";v=\"24\", \"%s\";v=\"%d\", \"%s\";v=\"%d\"",
              brand_first, major, brand_second, major);
  mg_snprintf(p->sec_ch_ua_platform, sizeof(p->sec_ch_ua_platform), "%s",
              os->sec_ch_platform);
  mg_snprintf(p->sec_ch_ua_mobile, sizeof(p->sec_ch_ua_mobile), "?0");
  mg_snprintf(p->user_agent, sizeof(p->user_agent),
              "Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/%s Safari/537.36",
              os->ua_platform, chrome_major_ua(version));
}

static void build_chrome_android(struct browser_profile *p) {
  const char *version =
      s_chrome_versions[pick(sizeof(s_chrome_versions) / sizeof(s_chrome_versions[0]))];
  const struct android_seed *device =
      &s_androids[pick(sizeof(s_androids) / sizeof(s_androids[0]))];
  int major = major_version(version);

  mg_snprintf(p->browser, sizeof(p->browser), "chrome");
  mg_snprintf(p->browser_version, sizeof(p->browser_version), "%s", version);
  mg_snprintf(p->os, sizeof(p->os), "android");
  mg_snprintf(p->os_version, sizeof(p->os_version), "%s",
              device->android_version);
  mg_snprintf(p->device_class, sizeof(p->device_class), "mobile");
  mg_snprintf(p->device_model, sizeof(p->device_model), "%s", device->model);
  mg_snprintf(p->sec_ch_ua, sizeof(p->sec_ch_ua),
              "\"Not_A Brand\";v=\"24\", \"Chromium\";v=\"%d\", "
              "\"Google Chrome\";v=\"%d\"",
              major, major);
  mg_snprintf(p->sec_ch_ua_platform, sizeof(p->sec_ch_ua_platform),
              "\"Android\"");
  mg_snprintf(p->sec_ch_ua_mobile, sizeof(p->sec_ch_ua_mobile), "?1");
  mg_snprintf(p->user_agent, sizeof(p->user_agent),
              "Mozilla/5.0 (Linux; Android %s; %s) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/%s Mobile Safari/537.36",
              device->android_version, device->model, version);
}

static void build_firefox_desktop(struct browser_profile *p) {
  const char *version =
      s_firefox_versions[pick(sizeof(s_firefox_versions) / sizeof(s_firefox_versions[0]))];
  const struct desktop_seed *os =
      &s_desktops[pick(sizeof(s_desktops) / sizeof(s_desktops[0]))];
  int major = major_version(version);

  mg_snprintf(p->browser, sizeof(p->browser), "firefox");
  mg_snprintf(p->browser_version, sizeof(p->browser_version), "%s", version);
  mg_snprintf(p->os, sizeof(p->os), "%s", os->os);
  mg_snprintf(p->os_version, sizeof(p->os_version), "%s", os->os_version);
  mg_snprintf(p->device_class, sizeof(p->device_class), "desktop");
  mg_snprintf(p->device_model, sizeof(p->device_model), "");
  mg_snprintf(p->sec_ch_ua, sizeof(p->sec_ch_ua), "");
  mg_snprintf(p->sec_ch_ua_platform, sizeof(p->sec_ch_ua_platform), "");
  mg_snprintf(p->sec_ch_ua_mobile, sizeof(p->sec_ch_ua_mobile), "");
  mg_snprintf(p->user_agent, sizeof(p->user_agent),
              "Mozilla/5.0 (%s; rv:%d.0) Gecko/20100101 Firefox/%d.0",
              os->ua_platform, major, major);
}

static void build_safari_ios(struct browser_profile *p) {
  const struct ios_seed *device = &s_ios[pick(sizeof(s_ios) / sizeof(s_ios[0]))];

  mg_snprintf(p->browser, sizeof(p->browser), "safari");
  mg_snprintf(p->browser_version, sizeof(p->browser_version), "%s",
              device->version_token);
  mg_snprintf(p->os, sizeof(p->os), "ios");
  mg_snprintf(p->os_version, sizeof(p->os_version), "%s", device->ios_version);
  mg_snprintf(p->device_class, sizeof(p->device_class), "mobile");
  mg_snprintf(p->device_model, sizeof(p->device_model), "%s", device->model);
  mg_snprintf(p->sec_ch_ua, sizeof(p->sec_ch_ua), "");
  mg_snprintf(p->sec_ch_ua_platform, sizeof(p->sec_ch_ua_platform), "");
  mg_snprintf(p->sec_ch_ua_mobile, sizeof(p->sec_ch_ua_mobile), "");
  if (strcmp(device->model, "iPad") == 0) {
    mg_snprintf(p->user_agent, sizeof(p->user_agent),
                "Mozilla/5.0 (iPad; CPU OS %s like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s "
                "Mobile/15E148 Safari/604.1",
                device->ios_version, device->version_token);
  } else {
    mg_snprintf(p->user_agent, sizeof(p->user_agent),
                "Mozilla/5.0 (iPhone; CPU iPhone OS %s like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s "
                "Mobile/15E148 Safari/604.1",
                device->ios_version, device->version_token);
  }
}

void browser_profile_seed(uint64_t seed) {
  if (seed == 0) seed = (uint64_t) time(NULL);
  s_rng = seed ^ 0x9e3779b97f4a7c15ULL;
}

void browser_profile_generate(struct browser_profile *profile,
                              const char *region_hint,
                              const char *device_hint) {
  const struct region_seed *region = choose_region(region_hint);
  int family;

  memset(profile, 0, sizeof(*profile));
  set_common(profile, region);

  if (same_token(device_hint, "desktop")) {
    family = pick(100) < 72 ? 0 : 1;
  } else if (same_token(device_hint, "mobile")) {
    family = pick(100) < 72 ? 2 : 3;
  } else {
    int roll = (int) pick(100);
    family = roll < 56 ? 0 : roll < 76 ? 1 : roll < 91 ? 2 : 3;
  }

  if (family == 0) {
    build_chrome_desktop(profile);
  } else if (family == 1) {
    build_firefox_desktop(profile);
  } else if (family == 2) {
    build_chrome_android(profile);
  } else {
    build_safari_ios(profile);
  }
}

size_t browser_profile_to_json(const struct browser_profile *profile, char *buf,
                               size_t len) {
  return mg_snprintf(
      buf, len,
      "{%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,"
      "%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m,%m:%m}\n",
      MG_ESC("id"), MG_ESC(profile->id),
      MG_ESC("browser"), MG_ESC(profile->browser),
      MG_ESC("browser_version"), MG_ESC(profile->browser_version),
      MG_ESC("os"), MG_ESC(profile->os),
      MG_ESC("os_version"), MG_ESC(profile->os_version),
      MG_ESC("device_class"), MG_ESC(profile->device_class),
      MG_ESC("device_model"), MG_ESC(profile->device_model),
      MG_ESC("region"), MG_ESC(profile->region),
      MG_ESC("locale"), MG_ESC(profile->locale),
      MG_ESC("timezone"), MG_ESC(profile->timezone),
      MG_ESC("user_agent"), MG_ESC(profile->user_agent),
      MG_ESC("accept"), MG_ESC(profile->accept),
      MG_ESC("accept_language"), MG_ESC(profile->accept_language),
      MG_ESC("accept_encoding"), MG_ESC(profile->accept_encoding),
      MG_ESC("sec_ch_ua"), MG_ESC(profile->sec_ch_ua),
      MG_ESC("sec_ch_ua_platform"), MG_ESC(profile->sec_ch_ua_platform),
      MG_ESC("sec_ch_ua_mobile"), MG_ESC(profile->sec_ch_ua_mobile));
}
