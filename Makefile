APP := build/mongoose-svelte
CC ?= gcc
CFLAGS ?= -std=gnu11 -O2 -D_GNU_SOURCE -Ithird_party/mongoose -DMG_ENABLE_DIRLIST=0
LDFLAGS ?=
CURL_CFLAGS := $(shell curl-config --cflags 2>/dev/null)
CURL_LIBS := $(shell curl-config --libs 2>/dev/null || printf '%s' '-lcurl')
SQLITE_CFLAGS := $(shell pkg-config --cflags sqlite3 2>/dev/null)
SQLITE_LIBS := $(shell pkg-config --libs sqlite3 2>/dev/null || printf '%s' '-lsqlite3')
DL_LIBS ?= -ldl
PTHREAD_FLAGS := -pthread
APP_SOURCES := $(shell find src -name '*.c' | sort)
RUN_ADMIN_USER ?= admin
RUN_ADMIN_PASSWORD := $(shell if command -v openssl >/dev/null 2>&1; then openssl rand -base64 30 | tr -d '\n'; else LC_ALL=C tr -dc 'A-Za-z0-9_@%+=:,.~-' </dev/urandom | head -c 40; fi)

WEB_DIR := web
DIST_DIR := $(WEB_DIR)/dist
PACKED_C := build/generated/packed_fs.c
WEB_STAMP := $(WEB_DIR)/node_modules/.install-stamp
WEB_SOURCES := $(shell find $(WEB_DIR)/src -type f 2>/dev/null) \
	$(WEB_DIR)/index.html \
	$(WEB_DIR)/package.json \
	$(WEB_DIR)/tsconfig.json \
	$(WEB_DIR)/vite.config.ts

.PHONY: all app web pack run clean npm-install docker-build docker-up docker-down test-mail

all: app

app: $(APP)

npm-install: $(WEB_STAMP)

$(WEB_STAMP): $(WEB_DIR)/package.json
	npm --prefix $(WEB_DIR) install
	touch $@

web: $(DIST_DIR)/index.html

$(DIST_DIR)/index.html: $(WEB_STAMP) $(WEB_SOURCES)
	npm --prefix $(WEB_DIR) run build

pack: $(PACKED_C)

$(PACKED_C): $(DIST_DIR)/index.html tools/pack_assets.py
	python3 tools/pack_assets.py $(DIST_DIR) $@ --mount /web

$(APP): $(APP_SOURCES) third_party/mongoose/mongoose.c third_party/mongoose/mongoose.h $(PACKED_C)
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) $(CURL_CFLAGS) $(SQLITE_CFLAGS) -Isrc -o $@ $(APP_SOURCES) third_party/mongoose/mongoose.c $(PACKED_C) $(LDFLAGS) $(CURL_LIBS) $(SQLITE_LIBS) $(DL_LIBS) $(PTHREAD_FLAGS)

run: $(APP)
	@printf '\n开发登录账号: %s\n开发登录密码: %s\n\n' '$(RUN_ADMIN_USER)' '$(RUN_ADMIN_PASSWORD)'
	APP_ADMIN_USER='$(RUN_ADMIN_USER)' APP_ADMIN_PASSWORD='$(RUN_ADMIN_PASSWORD)' APP_RESET_ADMIN_PASSWORD=1 ./$(APP)

docker-build:
	docker build --platform "$${MONGOOSE_PLATFORM:-linux/amd64}" -t mongoose-svelte:local .

docker-up:
	docker-compose --env-file .env.docker up -d --build

docker-down:
	docker-compose --env-file .env.docker down

test-mail:
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) $(SQLITE_CFLAGS) -Isrc -o /tmp/test_rapid_inbox_head tests/test_rapid_inbox_head.c third_party/mongoose/mongoose.c $(SQLITE_LIBS) $(PTHREAD_FLAGS)
	/tmp/test_rapid_inbox_head

clean:
	rm -rf build $(DIST_DIR)
