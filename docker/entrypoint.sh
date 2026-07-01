#!/usr/bin/env sh
set -eu

if [ -z "${LIBCURL_IMPERSONATE_LIB:-}" ]; then
  for candidate in \
    /usr/lib/libcurl-impersonate.so \
    /usr/local/lib/libcurl-impersonate.so \
    /opt/curl-impersonate/lib/libcurl-impersonate.so; do
    if [ -r "$candidate" ]; then
      export LIBCURL_IMPERSONATE_LIB="$candidate"
      break
    fi
  done
fi

mkdir -p /app/data

# --- Codex 直注: sentinel sdk.js 启动自动更新 (best-effort, 直连) ---
# OpenAI 会轮换 sentinel 版本；启动时发现当前版本并把 sdk.js 拉到数据卷，
# Codex 直注 provider 优先用卷里的版本，避免镜像里烤死的 sdk.js 过期导致建号 400。
refresh_sentinel_sdk() {
  sdk_dir=/app/data/sentinel
  ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
  mkdir -p "$sdk_dir" || return 0
  ver=$(curl -fsS -m 15 -A "$ua" "https://sentinel.openai.com/backend-api/sentinel/frame.html" 2>/dev/null \
        | grep -oE 'sentinel/[0-9a-f]{6,}/' | head -n1 | grep -oE '[0-9a-f]{6,}' || true)
  if [ -z "$ver" ]; then
    echo "[sentinel] 版本发现失败，沿用现有 sdk.js"
    return 0
  fi
  if [ "$(cat "$sdk_dir/version.txt" 2>/dev/null || true)" = "$ver" ] && [ -s "$sdk_dir/sdk.js" ]; then
    echo "[sentinel] sdk.js 已是最新版本 $ver"
    return 0
  fi
  tmp="$sdk_dir/sdk.js.tmp"
  if curl -fsS -m 30 -A "$ua" "https://sentinel.openai.com/sentinel/$ver/sdk.js" -o "$tmp" 2>/dev/null \
     && [ "$(wc -c < "$tmp" 2>/dev/null || echo 0)" -gt 1000 ] \
     && ! grep -q "Just a moment" "$tmp" 2>/dev/null; then
    mv "$tmp" "$sdk_dir/sdk.js"
    printf '%s' "$ver" > "$sdk_dir/version.txt"
    echo "[sentinel] sdk.js 已更新到版本 $ver ($(wc -c < "$sdk_dir/sdk.js") 字节)"
  else
    rm -f "$tmp" 2>/dev/null || true
    echo "[sentinel] sdk.js 拉取失败，沿用现有"
  fi
  return 0
}
refresh_sentinel_sdk || true

if [ "$#" -eq 0 ]; then
  set -- "${MONGOOSE_LISTEN_URL:-http://0.0.0.0:8000}"
fi

case "$1" in
  http://*|https://*)
    set -- /app/mongoose-svelte "$@"
    ;;
esac

exec "$@"
