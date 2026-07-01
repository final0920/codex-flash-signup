# syntax=docker/dockerfile:1

FROM archlinux:base-devel AS builder

RUN pacman -Syu --noconfirm \
  && pacman -S --noconfirm --needed \
    base-devel \
    curl \
    nodejs \
    npm \
    pkgconf \
    python \
    sqlite \
  && pacman -Scc --noconfirm

WORKDIR /src
COPY . .
RUN make

FROM archlinux:base AS runtime

ARG MIHOMO_VERSION=v1.19.25

RUN pacman -Syu --noconfirm \
  && pacman -S --noconfirm --needed \
    ca-certificates \
    curl \
    curl-impersonate \
    gzip \
    nodejs \
    sqlite \
  && pacman -Scc --noconfirm

RUN curl -fsSL \
      "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/mihomo-linux-amd64-compatible-${MIHOMO_VERSION}.gz" \
      -o /tmp/mihomo.gz \
  && gunzip /tmp/mihomo.gz \
  && install -m 0755 /tmp/mihomo /usr/local/bin/mihomo

WORKDIR /app
COPY --from=builder /src/build/mongoose-svelte /app/mongoose-svelte
COPY docker/entrypoint.sh /usr/local/bin/mongoose-entrypoint
# Node sentinel assets (Codex 直注 method): sdk.js + adapter + wrapper
COPY vendor/sentinel /app/sentinel

RUN chmod +x /usr/local/bin/mongoose-entrypoint \
  && mkdir -p /app/data

ENV LIBCURL_IMPERSONATE_LIB=/usr/lib/libcurl-impersonate.so

EXPOSE 8000
VOLUME ["/app/data"]

ENTRYPOINT ["mongoose-entrypoint"]
CMD ["http://0.0.0.0:8000"]
