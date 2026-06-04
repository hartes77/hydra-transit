# hydra-transit

Tunnel TCP cifrato point-to-point con key-ratchet deterministico (*Morphing Key*),
ChaCha20-Poly1305 e cifratura in-place zero-copy. Vedi `README.md` per il design.

## Comandi

- **Build**: `cargo build --release`
- **Test**: `cargo test` (crypto in-memory + wire su socket TCP reali)
- **Lint**: `cargo clippy --all-targets -- -D warnings`
- **Format**: `cargo fmt`
- **Stress + latenza**: `./scripts/stress.sh [SIZE_MB] [ITERS] [MAX_US]`
- **Demo Docker**: `cp .env.example .env` → imposta `HYDRA_KEY=$(openssl rand -hex 32)` → `docker compose up --build`

## Invarianti da NON rompere

- **Fail-closed assoluto**: un tag/AAD non valido NON deve far avanzare il ratchet
  (`MorphingCipher::open_in_place`). I test `wire_*_fails_closed` lo blindano.
- **Nonce mai sul filo**: contatore deterministico interno; la sicurezza dipende
  dal fatto che la chiave muta a ogni chunk (no nonce-reuse).
- **Header u32 come AAD**: il campo lunghezza e' autenticato. Non rimuoverlo.
- **Zero malloc nel transito**: cifratura/decifratura in-place sul buffer riusato
  `FRAME_BUF`. Non introdurre allocazioni nei loop `pump_*`.

## CI

`.github/workflows/ci.yml`: `cargo fmt --check`, `clippy -D warnings`, `cargo test`,
build dell'immagine Docker. Mantieni la pipeline verde prima di considerare un
cambiamento concluso.
