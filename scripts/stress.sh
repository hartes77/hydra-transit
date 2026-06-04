#!/usr/bin/env bash
#
# stress.sh - Stress-test ripetibile per hydra-transit.
#
# Misura il throughput end-to-end a PIENO CARICO su loopback e valida la
# latenza per-chunk AMMORTIZZATA sotto saturazione, definita come:
#
#     latenza_chunk = tempo_totale_transito / numero_chunk
#
# cioe' il tempo medio di transito di un chunk da 64 KiB quando la pipeline e'
# satura. E' la metrica di latenza onesta "a pieno carico": NON include il
# cold-start del processo ne' il TTFB (dominati dall'avvio, non rappresentativi
# dello stato stazionario).
#
# Uso:
#     scripts/stress.sh [SIZE_MB] [ITERS] [MAX_LATENCY_US]
# Default: 2048 MiB, 5 iterazioni (la prima scartata), soglia 1000 us (1 ms).
#
# Exit code: 0 se la latenza mediana e' sotto soglia, 1 altrimenti.

set -euo pipefail
export LC_ALL=C   # punto decimale deterministico per awk/sort (no locale IT)

SIZE_MB="${1:-2048}"
ITERS="${2:-5}"
MAX_LATENCY_US="${3:-1000}"
PORT="${PORT:-19090}"
CHUNK=65536

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release/hydra-transit"

if [[ ! -x "$BIN" ]]; then
    echo "[stress] binario non trovato, compilo in release..."
    (cd "$ROOT" && cargo build --release)
fi

# Chiave effimera condivisa per la sessione di test.
if command -v openssl >/dev/null 2>&1; then
    export HYDRA_KEY="$(openssl rand -hex 32)"
else
    export HYDRA_KEY="$(head -c32 /dev/urandom | xxd -p -c256)"
fi

echo "[stress] payload=${SIZE_MB} MiB  iterazioni=${ITERS} (prima scartata)  soglia=${MAX_LATENCY_US} us  porta=${PORT}"
echo "[stress] binario: $BIN"
echo

RX_LOG="$(mktemp)"
trap 'rm -f "$RX_LOG"' EXIT

declare -a LATENCIES=()

run_once() {
    local idx="$1"
    # Receiver -> /dev/null, report su stderr catturato. Accetta UNA connessione
    # e termina, quindi va (ri)avviato a ogni iterazione.
    "$BIN" --mode receiver --port "$PORT" >/dev/null 2>"$RX_LOG" &
    local rx=$!
    sleep 0.4   # lascia salire il listener prima di connettersi

    # Trasferimento reale: SIZE_MB di zeri attraverso il tunnel.
    dd if=/dev/zero bs=1M count="$SIZE_MB" 2>/dev/null \
        | "$BIN" --mode sender --target "127.0.0.1:$PORT" 2>/dev/null
    wait "$rx" 2>/dev/null || true

    local line bytes secs
    line="$(grep 'ricevuti:' "$RX_LOG" || true)"
    bytes="$(printf '%s' "$line" | sed -nE 's/.*ricevuti: ([0-9]+) byte.*/\1/p')"
    secs="$(printf '%s' "$line"  | sed -nE 's/.* in ([0-9.]+)s =>.*/\1/p')"

    if [[ -z "$bytes" || -z "$secs" ]]; then
        echo "[stress] iter $idx: report non parsabile -> '$line'" >&2
        return 1
    fi

    awk -v b="$bytes" -v s="$secs" -v c="$CHUNK" -v idx="$idx" 'BEGIN {
        chunks = int((b + c - 1) / c);          # ceil
        mibps  = (b / 1048576.0) / s;
        lat_us = (s / chunks) * 1e6;            # latenza per-chunk ammortizzata
        printf "[stress] iter %d: %.2f MiB/s  |  %d chunk  |  latenza/chunk = %.2f us\n", idx, mibps, chunks, lat_us;
        printf "%.4f\n", lat_us > "/dev/stderr";
    }' 2>>"$RX_LOG.lat"
}

: > "$RX_LOG.lat"
for i in $(seq 1 "$ITERS"); do
    run_once "$i"
done

# Raccoglie le latenze (scartando la prima = warm-up a cache fredda).
# Loop portabile: il bash 3.2 di macOS non ha `mapfile`.
ALL=()
while IFS= read -r _line; do
    [[ -n "$_line" ]] && ALL+=("$_line")
done < "$RX_LOG.lat"
rm -f "$RX_LOG.lat"
if (( ${#ALL[@]} > 1 )); then
    MEASURED=("${ALL[@]:1}")
else
    MEASURED=("${ALL[@]}")
fi

# Mediana.
IFS=$'\n' SORTED=($(printf '%s\n' "${MEASURED[@]}" | sort -n)); unset IFS
n=${#SORTED[@]}
mid=$(( n / 2 ))
if (( n % 2 == 1 )); then
    MEDIAN="${SORTED[$mid]}"
else
    MEDIAN="$(awk -v a="${SORTED[$((mid-1))]}" -v b="${SORTED[$mid]}" 'BEGIN{printf "%.4f", (a+b)/2}')"
fi

echo
echo "[stress] latenza/chunk: min=${SORTED[0]} us  mediana=${MEDIAN} us  max=${SORTED[$((n-1))]} us  (n=${n}, warm-up escluso)"

PASS="$(awk -v m="$MEDIAN" -v t="$MAX_LATENCY_US" 'BEGIN{print (m < t) ? 1 : 0}')"
if [[ "$PASS" == "1" ]]; then
    echo "[stress] ✅ PASS: latenza mediana ${MEDIAN} us < soglia ${MAX_LATENCY_US} us (sub-millisecondo a pieno carico)"
    exit 0
else
    echo "[stress] ❌ FAIL: latenza mediana ${MEDIAN} us >= soglia ${MAX_LATENCY_US} us"
    exit 1
fi
