# justfile per hydra-transit — task ripetibili.
# Installazione di `just`:  brew install just  |  cargo install just
# Elenco task:  just --list

# Mostra l'elenco dei task (default).
default:
    @just --list

image := "hydra-transit"
port  := "8080"

# --- Build & test -----------------------------------------------------------

# Compila in release (lto, target-cpu=native via .cargo/config.toml).
build:
    cargo build --release

# Suite completa: crypto in-memory + wire su socket reali.
test:
    cargo test

# Lint rigoroso: i warning diventano errori.
lint:
    cargo clippy --all-targets -- -D warnings
    cargo fmt --check

# Genera una chiave K_0 (hex, 32 byte) da esportare come HYDRA_KEY.
gen-key:
    @openssl rand -hex 32

# --- Benchmark & stress -----------------------------------------------------

# Throughput grezzo su loopback (SIZE in MiB, default 2048).
bench size="2048": build
    #!/usr/bin/env bash
    set -euo pipefail
    export HYDRA_KEY="$(openssl rand -hex 32)"
    ./target/release/hydra-transit --mode receiver --port {{port}} >/dev/null &
    RX=$!; sleep 0.4
    dd if=/dev/zero bs=1M count={{size}} 2>/dev/null \
      | ./target/release/hydra-transit --mode sender --target 127.0.0.1:{{port}}
    wait $RX 2>/dev/null || true

# Stress-test + validazione latenza sub-ms (SIZE_MB, ITERS, MAX_US).
stress size="2048" iters="5" max_us="1000": build
    ./scripts/stress.sh {{size}} {{iters}} {{max_us}}

# --- Docker (On-Premise) ----------------------------------------------------

# Build immagine portabile (target-cpu=x86-64-v3).
docker-build:
    docker build -t {{image}}:latest .

# Build immagine spremuta sull'host di deploy (NON portabile).
docker-build-native:
    docker build --build-arg TARGET_CPU=native -t {{image}}:native .

# Avvia il receiver in container (richiede HYDRA_KEY nell'ambiente).
docker-receiver:
    docker run --rm -e HYDRA_KEY -p {{port}}:8080 {{image}}:latest \
        --mode receiver --port 8080

# Mostra la dimensione dell'immagine.
docker-size:
    docker images {{image}} --format '{{{{.Repository}}}}:{{{{.Tag}}}}  {{{{.Size}}}}'

# --- Manutenzione -----------------------------------------------------------

clean:
    cargo clean
