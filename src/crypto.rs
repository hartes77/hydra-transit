//! Logica crittografica di `hydra-transit`.
//!
//! ## Protocollo "Morphing Key" (Moving Target Defense)
//!
//! La sessione parte da una chiave simmetrica `K_0` di 32 byte pre-condivisa.
//! Il flusso e' segmentato in chunk rigidi da [`CHUNK_SIZE`] byte. Per ogni
//! chunk `N`:
//!
//! 1. si cifra il payload **in-place** con ChaCha20-Poly1305 sotto la chiave
//!    `K_N` e un nonce-contatore deterministico;
//! 2. l'AEAD produce un Tag Poly1305 di 16 byte (`Tag_N`);
//! 3. la chiave del chunk successivo e' derivata via BLAKE3:
//!
//! ```text
//!     K_{N+1} = BLAKE3( K_N || Tag_N )
//! ```
//!
//! Il nonce e' un contatore interno a 64 bit incrementato in modo identico dai
//! due nodi: **non viaggia mai sulla rete** (overhead di banda azzerato).
//! Poiche' la chiave cambia a ogni chunk, la coppia `(key, nonce)` non si
//! ripete mai per costruzione: niente nonce-reuse, che e' il fallimento
//! catastrofico di ChaCha20-Poly1305.
//!
//! Il "ratchet" della chiave avviene **solo dopo** che il tag e' stato
//! prodotto (in cifratura) o verificato con successo (in decifratura): un
//! singolo tag non valido lascia la chiave invariata e fa fallire la
//! decifratura, costringendo lo strato di rete al tear-down (fail-closed).

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

/// Lunghezza della chiave simmetrica (ChaCha20 e output BLAKE3).
pub const KEY_LEN: usize = 32;
/// Lunghezza del tag di autenticazione Poly1305.
pub const TAG_LEN: usize = 16;
/// Lunghezza del nonce ChaCha20-Poly1305 (IETF, 96 bit).
pub const NONCE_LEN: usize = 12;
/// Dimensione rigida del payload in chiaro di ogni chunk: 64 KiB pieni.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Errori crittografici. Volutamente opachi: non rivelano *dove* la
/// verifica e' fallita (no oracle).
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// La cifratura in-place e' fallita (input troppo lungo per l'AEAD).
    Seal,
    /// La decifratura/verifica del tag e' fallita: dato non autentico.
    Open,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Seal => write!(f, "cifratura in-place fallita"),
            CryptoError::Open => write!(f, "verifica autenticazione fallita (dato non autentico)"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Cifrario mutazionale con stato (chiave corrente + contatore nonce).
///
/// Un'istanza rappresenta **una direzione** del flusso. Mittente e ricevente
/// inizializzano un `MorphingCipher` con la stessa `K_0` e, processando gli
/// stessi chunk nello stesso ordine, mantengono catene di chiavi speculari.
pub struct MorphingCipher {
    key: [u8; KEY_LEN],
    counter: u64,
}

impl MorphingCipher {
    /// Inizializza la catena dalla chiave `K_0`.
    pub fn new(k0: [u8; KEY_LEN]) -> Self {
        Self {
            key: k0,
            counter: 0,
        }
    }

    /// Costruisce il nonce deterministico dal contatore corrente.
    /// Layout: 4 byte a zero (prefisso fisso) + 8 byte contatore little-endian.
    #[inline]
    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n[NONCE_LEN - 8..].copy_from_slice(&self.counter.to_le_bytes());
        n
    }

    /// Esegue il ratchet: `K_{N+1} = BLAKE3(K_N || Tag_N)` e incrementa il
    /// contatore del nonce. Chiamato **solo** dopo un'operazione AEAD riuscita.
    #[inline]
    fn ratchet(&mut self, tag: &[u8; TAG_LEN]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.key);
        hasher.update(tag);
        self.key = *hasher.finalize().as_bytes();
        // Wrap difensivo: un overflow del contatore con la stessa chiave sarebbe
        // un nonce-reuse, ma e' irraggiungibile (la chiave muta a ogni chunk).
        self.counter = self.counter.wrapping_add(1);
    }

    /// Cifra `buf` **in-place** sotto la chiave corrente. `aad` (l'header di
    /// lunghezza) viene autenticato ma non cifrato. Ritorna il tag da 16 byte
    /// e fa avanzare la catena.
    pub fn seal_in_place(
        &mut self,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; TAG_LEN], CryptoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = self.nonce();
        let tag: Tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, buf)
            .map_err(|_| CryptoError::Seal)?;

        let mut tag_arr = [0u8; TAG_LEN];
        tag_arr.copy_from_slice(tag.as_slice());
        self.ratchet(&tag_arr);
        Ok(tag_arr)
    }

    /// Decifra `buf` **in-place** verificando `tag` (e `aad`) sotto la chiave
    /// corrente. In caso di fallimento la chiave **non** avanza e il chiamante
    /// deve trattare la connessione come compromessa (fail-closed).
    pub fn open_in_place(
        &mut self,
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), CryptoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = self.nonce();
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), aad, buf, Tag::from_slice(tag))
            .map_err(|_| CryptoError::Open)?;

        self.ratchet(tag);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodifica una chiave hex di comodo per i test.
    fn k0() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(13);
        }
        k
    }

    const AAD: &[u8] = &[0x00, 0x01, 0x00, 0x00]; // header lunghezza fittizio

    #[test]
    fn roundtrip_single_chunk() {
        let mut tx = MorphingCipher::new(k0());
        let mut rx = MorphingCipher::new(k0());

        let plain = b"Attrahere: dato sensibile da tunnelizzare".to_vec();
        let mut buf = plain.clone();

        let tag = tx.seal_in_place(AAD, &mut buf).unwrap();
        assert_ne!(buf, plain, "il buffer deve risultare cifrato");

        rx.open_in_place(AAD, &mut buf, &tag).unwrap();
        assert_eq!(buf, plain, "roundtrip deve restituire il chiaro originale");
    }

    #[test]
    fn key_chain_is_mirror_and_deterministic() {
        // Due nodi indipendenti dalla stessa K_0, stessi tag => stesse chiavi.
        let mut a = MorphingCipher::new(k0());
        let mut b = MorphingCipher::new(k0());

        for n in 0..64u32 {
            let mut buf_a = vec![n as u8; 1024];
            let plain = buf_a.clone();
            let aad = n.to_le_bytes();

            let tag = a.seal_in_place(&aad, &mut buf_a).unwrap();
            // b decifra cio' che a ha cifrato: le catene restano speculari.
            let mut buf_b = buf_a.clone();
            b.open_in_place(&aad, &mut buf_b, &tag).unwrap();

            assert_eq!(buf_b, plain, "chunk {n}: decifratura corretta");
            assert_eq!(a.key, b.key, "chunk {n}: chiavi speculari dopo il ratchet");
            assert_eq!(a.counter, b.counter, "chunk {n}: contatori allineati");
            assert_eq!(a.counter, (n + 1) as u64, "il contatore deve incrementare");
        }
    }

    #[test]
    fn key_actually_mutates_each_chunk() {
        let mut c = MorphingCipher::new(k0());
        let mut seen = std::collections::HashSet::new();
        seen.insert(c.key);
        for _ in 0..16 {
            let mut buf = vec![0u8; 256];
            c.seal_in_place(AAD, &mut buf).unwrap();
            assert!(
                seen.insert(c.key),
                "ogni chunk deve produrre una chiave nuova"
            );
        }
    }

    #[test]
    fn tampered_tag_fails_and_does_not_ratchet() {
        let mut tx = MorphingCipher::new(k0());
        let mut rx = MorphingCipher::new(k0());

        let mut buf = b"payload integro".to_vec();
        let mut tag = tx.seal_in_place(AAD, &mut buf).unwrap();
        tag[0] ^= 0x01; // flip di 1 bit

        let key_before = rx.key;
        let counter_before = rx.counter;
        let err = rx.open_in_place(AAD, &mut buf, &tag).unwrap_err();

        assert_eq!(err, CryptoError::Open);
        assert_eq!(
            rx.key, key_before,
            "un tag falso non deve far avanzare la chiave"
        );
        assert_eq!(rx.counter, counter_before, "ne' il contatore");
    }

    #[test]
    fn tampered_aad_fails() {
        // L'header di lunghezza e' autenticato come AAD: alterarlo invalida il frame.
        let mut tx = MorphingCipher::new(k0());
        let mut rx = MorphingCipher::new(k0());

        let mut buf = b"payload".to_vec();
        let good_aad = 7u32.to_le_bytes();
        let bad_aad = 9u32.to_le_bytes();
        let tag = tx.seal_in_place(&good_aad, &mut buf).unwrap();

        assert_eq!(
            rx.open_in_place(&bad_aad, &mut buf, &tag).unwrap_err(),
            CryptoError::Open
        );
    }

    #[test]
    fn desync_breaks_the_chain() {
        // Se il ricevente "salta" un chunk, la sua chiave non corrisponde piu'.
        let mut tx = MorphingCipher::new(k0());
        let mut rx = MorphingCipher::new(k0());

        // tx cifra due chunk; rx ne riceve solo il secondo (chunk 0 perso).
        let mut c0 = b"primo chunk".to_vec();
        let _t0 = tx.seal_in_place(AAD, &mut c0).unwrap();

        let mut c1 = b"secondo chunk".to_vec();
        let t1 = tx.seal_in_place(AAD, &mut c1).unwrap();

        // rx prova ad aprire c1 con K_0 (chiave del chunk 0): deve fallire.
        assert_eq!(
            rx.open_in_place(AAD, &mut c1, &t1).unwrap_err(),
            CryptoError::Open
        );
    }

    #[test]
    fn full_size_chunk_roundtrip() {
        let mut tx = MorphingCipher::new(k0());
        let mut rx = MorphingCipher::new(k0());

        let plain: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 251) as u8).collect();
        let mut buf = plain.clone();
        let aad = (CHUNK_SIZE as u32).to_le_bytes();

        let tag = tx.seal_in_place(&aad, &mut buf).unwrap();
        rx.open_in_place(&aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plain, "roundtrip su chunk pieno da 64 KiB");
    }
}
