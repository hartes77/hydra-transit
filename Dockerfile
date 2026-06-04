# syntax=docker/dockerfile:1
#
# Build multi-stage per hydra-transit.
#  - builder: rust:alpine -> il target host e' gia' x86_64-unknown-linux-musl,
#    quindi il binario risulta STATICO (nessuna dipendenza runtime).
#  - runtime: alpine minimale, utente non-root, solo il binario.
#
# Ottimizzazione CPU: di default x86-64-v3 (AVX2/BMI2/FMA, ampiamente diffuso
# sui server moderni) per un'immagine PORTABILE. Per spremere al massimo l'host
# di deployment on-prem, builda con:
#     docker build --build-arg TARGET_CPU=native -t hydra-transit .
# (il binario NON sara' piu' portabile su CPU diverse da quella di build).

ARG RUST_VERSION=1.93
ARG ALPINE_VERSION=3.20
# Vuoto = build generica e PORTABILE. NB: blake3 e chacha20poly1305 scelgono il
# backend SIMD a runtime, quindi il path crittografico e' gia' "spremuto" anche
# senza questo flag. Per l'auto-vettorizzazione massima sull'host di deploy:
#   docker build --build-arg TARGET_CPU=native ...   (binario non portabile)
ARG TARGET_CPU=

# ---------- Stage 1: build ----------
FROM rust:${RUST_VERSION}-alpine AS builder
ARG TARGET_CPU
RUN apk add --no-cache musl-dev
WORKDIR /build

# Cache delle dipendenze: prima solo i manifest + un main fittizio.
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
# RUSTFLAGS impostato solo se TARGET_CPU e' valorizzato (evita flag invalidi
# cross-arch, es. nomi x86 su aarch64). Sovrascrive il target-cpu=native di
# .cargo/config.toml (RUSTFLAGS ha precedenza sul config).
RUN set -eu; \
    if [ -n "$TARGET_CPU" ]; then export RUSTFLAGS="-C target-cpu=$TARGET_CPU"; fi; \
    mkdir src && echo 'fn main() {}' > src/main.rs; \
    cargo build --release; \
    rm -rf src

# Sorgenti reali e build finale (le dipendenze restano in cache).
COPY src ./src
# `touch` per invalidare il main fittizio in cache.
RUN set -eu; \
    if [ -n "$TARGET_CPU" ]; then export RUSTFLAGS="-C target-cpu=$TARGET_CPU"; fi; \
    touch src/main.rs; \
    cargo build --release

# ---------- Stage 2: runtime ----------
FROM alpine:${ALPINE_VERSION} AS runtime
LABEL org.opencontainers.image.title="hydra-transit" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Utente non privilegiato.
RUN addgroup -S hydra && adduser -S -G hydra hydra

COPY --from=builder /build/target/release/hydra-transit /usr/local/bin/hydra-transit

USER hydra
EXPOSE 8080

# La chiave si fornisce a runtime: -e HYDRA_KEY=<hex64>
ENTRYPOINT ["hydra-transit"]
CMD ["--help"]
