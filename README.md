# hydra-transit

Tunnel di transito dati **cifrato point-to-point** ad alte prestazioni su socket
TCP, con key-ratchet deterministico (*Morphing Key*), cifratura **in-place
zero-copy** e nonce a costo-di-banda zero.

> ⚠️ **Nota di sicurezza onesta.** `hydra-transit` è un protocollo proprietario
> a scopo didattico/prestazionale. Usa una **PSK statica** (`K_0`) e **non**
> esegue un handshake autenticato né offre forward secrecy *tra* sessioni o
> autenticazione del peer. Per la produzione, il pattern vetato è il
> [Noise Protocol Framework](https://noiseprotocol.org/) (lo stesso di
> WireGuard) o TLS 1.3. Qui il ratchet fornisce mutazione della chiave e
> rilevamento manomissioni *all'interno* della singola sessione.

---

## Design deterministico

### Protocollo "Morphing Key" (Moving Target Defense)

La sessione parte da una chiave simmetrica `K_0` di 32 byte pre-condivisa. Il
flusso è segmentato in **chunk rigidi da 64 KiB**. Per ogni chunk `N`:

1. il payload è cifrato **in-place** con ChaCha20-Poly1305 sotto la chiave `K_N`
   e un nonce-contatore deterministico;
2. l'AEAD produce un tag Poly1305 di 16 byte (`Tag_N`);
3. la chiave del chunk successivo è derivata via BLAKE3:

```
K_{N+1} = BLAKE3( K_N || Tag_N )
```

Il **ratchet avviene solo dopo** che il tag è stato prodotto (in cifratura) o
**verificato con successo** (in decifratura). Un singolo tag non valido lascia
la chiave invariata, fa fallire la decifratura e forza il tear-down della
connessione (**fail-closed**).

### Nonce deterministico (zero overhead di banda)

Il nonce è un **contatore interno a 64 bit** incrementato in modo identico dai
due nodi: **non viaggia mai sulla rete**. Poiché la chiave cambia a ogni chunk,
la coppia `(key, nonce)` non si ripete mai per costruzione — niente nonce-reuse,
che è il fallimento catastrofico di ChaCha20-Poly1305.

### Struttura del frame TCP

```
[ 4 byte: lunghezza payload (u32 LE) ] [ X byte: payload cifrato in-place ] [ 16 byte: tag Poly1305 ]
```

L'header di lunghezza è passato come **AAD** all'AEAD: è autenticato dal tag,
quindi non manomettibile senza far fallire la verifica. (Nota: 64 KiB = 65536 B
**non** entra in un campo da 2 byte → l'header è `u32`.)

### Zero-copy / zero-malloc

Ogni nodo riusa **un solo buffer** pre-allocato (`4 + 65536 + 16` byte) per
l'intera sessione e cifra/decifra direttamente sulla regione letta dal socket,
via le API AEAD `*_in_place_detached`. Nessuna `malloc` durante il transito.

---

## Build

```bash
cargo build --release
```

Il profilo di release usa `lto = true`, `opt-level = 3`, `codegen-units = 1`,
`panic = "abort"`, `strip = true`. Il file `.cargo/config.toml` imposta
`target-cpu=native` (il binario **non** è portabile su CPU più vecchie della
macchina di build, ma sfrutta AVX2/AVX-512/NEON per BLAKE3 e ChaCha20).

## Test

```bash
cargo test
```

I test in `src/crypto.rs` validano che la catena difensiva sia **speculare** tra
i due nodi, che la chiave muti a ogni chunk, e che tag/AAD manomessi o un
disallineamento di chunk falliscano la verifica **senza** far avanzare la chiave.

## Uso

Genera una chiave `K_0` (32 byte, hex) e condividila fuori banda:

```bash
export HYDRA_KEY=$(openssl rand -hex 32)
```

Terminale 1 — **receiver** (scrive il chiaro su stdout):

```bash
HYDRA_KEY=$HYDRA_KEY ./target/release/hydra-transit \
    --mode receiver --port 8080 > output.bin
```

Terminale 2 — **sender** (legge il chiaro da stdin):

```bash
HYDRA_KEY=$HYDRA_KEY ./target/release/hydra-transit \
    --mode sender --target 127.0.0.1:8080 < input.bin
```

La chiave può anche essere passata con `--key <HEX>` (sconsigliato: finisce in
shell history e nella lista processi).

---

## Benchmark di throughput

Con [`pv`](https://www.ivarch.com/programs/pv.shtml) per misurare la banda
end-to-end attraverso il tunnel (loopback):

```bash
# Terminale 1: receiver -> /dev/null
HYDRA_KEY=$HYDRA_KEY ./target/release/hydra-transit \
    --mode receiver --port 8080 > /dev/null

# Terminale 2: 2 GiB di zeri attraverso il tunnel, con barra di banda
dd if=/dev/zero bs=1M count=2048 2>/dev/null \
  | pv \
  | HYDRA_KEY=$HYDRA_KEY ./target/release/hydra-transit \
        --mode sender --target 127.0.0.1:8080
```

A fine sessione entrambi i nodi stampano un report su **stderr**:

```
[hydra-transit] inviati: 2147483648 byte (2048.00 MiB) in 1.42s => 1442.25 MiB/s
```

Per misurare solo il costo crittografico (senza rete), confronta con un
`pv < input.bin > /dev/null` a vuoto. Per profili più precisi, esegui più volte
e scarta la prima run (cache fredda).

---

## Stress-test & validazione latenza

`scripts/stress.sh` misura il throughput a pieno carico su loopback (senza
dipendenze esterne: usa il report di timing del binario) e **valida** la
*latenza per-chunk ammortizzata sotto saturazione* — definita come
`tempo_totale / numero_chunk`, cioè il tempo medio di transito di un chunk da
64 KiB quando la pipeline è satura. Esce con codice ≠ 0 se la mediana supera la
soglia (default 1 ms).

```bash
scripts/stress.sh [SIZE_MB] [ITERS] [MAX_LATENCY_US]   # default: 2048 5 1000
```

```
[stress] iter 2: 280.39 MiB/s  |  8192 chunk  |  latenza/chunk = 222.90 us
[stress] ✅ PASS: latenza mediana 224.06 us < soglia 1000 us (sub-millisecondo a pieno carico)
```

> La metrica esclude volutamente cold-start del processo e TTFB (dominati
> dall'avvio, non rappresentativi dello stato stazionario).

## Docker (On-Premise)

Immagine multi-stage: builder `rust:alpine` (binario **statico musl**) →
runtime `alpine` minimale, utente **non-root**, ~15 MB.

```bash
docker build -t hydra-transit .                          # portabile (generico)
docker build --build-arg TARGET_CPU=native -t hydra-transit:native .   # spremuto sull'host

export HYDRA_KEY=$(openssl rand -hex 32)
docker run --rm -e HYDRA_KEY -p 8080:8080 hydra-transit --mode receiver --port 8080
```

### Demo a due servizi (`docker compose`)

`docker-compose.yml` avvia **sender** e **receiver** come servizi isolati su una
rete bridge interna, hardening completo (non-root, `read_only`, `cap_drop: ALL`,
`no-new-privileges`). Il sender spinge `PAYLOAD_MB` di dati nel tunnel e a fine
sessione entrambi stampano il throughput.

```bash
cp .env.example .env          # imposta HYDRA_KEY=$(openssl rand -hex 32)
docker compose up --build --abort-on-container-exit
```

```
hydra-sender    | [hydra-transit] inviati: 268435456 byte (256.00 MiB) in 1.198s => 213.68 MiB/s
hydra-receiver  | [hydra-transit] ricevuti: 268435456 byte (256.00 MiB) in 1.199s => 213.58 MiB/s
```

> `blake3` e `chacha20poly1305` scelgono il backend SIMD **a runtime**: il path
> crittografico è già ottimizzato anche con la build generica. `-C target-cpu`
> incide solo sull'auto-vettorizzazione del codice di framing (impatto minore).

## Task ripetibili (`just`)

Con [`just`](https://github.com/casey/just) installato:

```bash
just              # elenco task
just build        # release
just test         # crypto in-memory + wire su socket reali
just gen-key      # genera una K_0
just bench 2048   # throughput grezzo (2 GiB)
just stress       # stress-test + validazione latenza sub-ms
just docker-build # immagine portabile
```

---

## Licensing & Enterprise Support

Questo progetto è rilasciato sotto **Business Source License 1.1 (BSL)**.
L'uso del software è gratuito ed esclusivamente consentito per scopi di sviluppo
locale, test, ricerca e didattica.

> ⚠️ **ATTENZIONE:** Qualsiasi utilizzo in ambienti di produzione (inclusi ma non
> limitati a: reti aziendali interne, servizi rivolti al pubblico, integrazione in
> prodotti commerciali) richiede l'acquisizione esplicita di una **Licenza
> Commerciale**.

### Parametri della licenza ([LICENSE](LICENSE))

| Parametro | Valore |
| --- | --- |
| **Licensed Work** | hydra-transit |
| **Licensor** | Jean Piroddi |
| **Change Date** | 2029-06-04 |
| **Change License** | Apache License 2.0 |

Alla **Change Date** (4 giugno 2029) la versione corrispondente del software si
converte automaticamente ad **Apache License 2.0**. Fino ad allora valgono i
termini BSL 1.1: libero per sviluppo/test/ricerca, **a pagamento per la
produzione**.

Per informazioni e licenze enterprise, contattare:
📧 **[Inserisci la tua email qui]** *(placeholder — sostituire con l'indirizzo reale)*
