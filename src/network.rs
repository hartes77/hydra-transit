//! Strato di rete: framing dei chunk su socket TCP asincroni (`tokio`) con
//! cifratura/decifratura **in-place** su un unico buffer pre-allocato.
//!
//! ## Struttura del frame sul filo
//!
//! ```text
//!   [ 4 byte: lunghezza payload (u32 LE) ] [ X byte: payload cifrato ] [ 16 byte: tag Poly1305 ]
//! ```
//!
//! L'header di lunghezza viene passato come **AAD** all'AEAD: e' autenticato
//! dal tag, quindi un attaccante non puo' alterarlo senza far fallire la
//! verifica. Il nonce non e' nel frame: e' un contatore deterministico
//! ricostruito a entrambi i lati (vedi [`crate::crypto`]).
//!
//! Durante il transito non avvengono allocazioni: ogni nodo riusa un solo
//! buffer [`FRAME_BUF`] per l'intera sessione e cifra direttamente sulla
//! regione di payload letta dal socket/sorgente.

use crate::crypto::{CryptoError, MorphingCipher, CHUNK_SIZE, TAG_LEN};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Byte dell'header di lunghezza (u32 little-endian).
pub const LEN_LEN: usize = 4;
/// Payload in chiaro massimo per frame (chunk rigido).
pub const MAX_PAYLOAD: usize = CHUNK_SIZE;
/// Dimensione del buffer riusato: header + payload pieno + tag.
pub const FRAME_BUF: usize = LEN_LEN + MAX_PAYLOAD + TAG_LEN;

/// Errore unificato dello strato di tunnel.
#[derive(Debug)]
pub enum TunnelError {
    /// Errore di I/O sul socket o sulla sorgente/destinazione locale.
    Io(io::Error),
    /// Fallimento crittografico: dato non autentico => tear-down (fail-closed).
    Crypto(CryptoError),
    /// Frame malformato (lunghezza fuori range): possibile manomissione.
    Protocol(&'static str),
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelError::Io(e) => write!(f, "errore I/O: {e}"),
            TunnelError::Crypto(e) => write!(f, "errore crittografico: {e}"),
            TunnelError::Protocol(m) => write!(f, "errore di protocollo: {m}"),
        }
    }
}

impl std::error::Error for TunnelError {}

impl From<io::Error> for TunnelError {
    fn from(e: io::Error) -> Self {
        TunnelError::Io(e)
    }
}

impl From<CryptoError> for TunnelError {
    fn from(e: CryptoError) -> Self {
        TunnelError::Crypto(e)
    }
}

/// Riempie `buf` leggendo ripetutamente da `src` finche' e' pieno o si
/// raggiunge l'EOF. Ritorna i byte effettivamente letti (0 = EOF immediato).
/// Garantisce chunk pieni da [`MAX_PAYLOAD`], tranne l'ultimo.
async fn read_filled<R: AsyncRead + Unpin>(src: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = src.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Pompa il flusso `src` -> `net`: legge il chiaro a chunk, lo cifra in-place
/// e scrive i frame. Ritorna il totale di byte di chiaro trasmessi.
pub async fn pump_sender<R, W>(
    mut src: R,
    mut net: W,
    mut cipher: MorphingCipher,
) -> Result<u64, TunnelError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut frame = vec![0u8; FRAME_BUF];
    let mut total: u64 = 0;

    loop {
        // Legge fino a un chunk pieno direttamente nella regione di payload.
        let n = read_filled(&mut src, &mut frame[LEN_LEN..LEN_LEN + MAX_PAYLOAD]).await?;
        if n == 0 {
            break; // EOF: niente piu' dati da inviare.
        }

        // Header = lunghezza payload; funge anche da AAD autenticato.
        let aad = (n as u32).to_le_bytes();
        frame[..LEN_LEN].copy_from_slice(&aad);

        // Cifratura IN-PLACE sulla sola porzione letta (zero-copy, zero-malloc).
        let tag = cipher.seal_in_place(&aad, &mut frame[LEN_LEN..LEN_LEN + n])?;

        // Accoda il tag subito dopo il payload.
        frame[LEN_LEN + n..LEN_LEN + n + TAG_LEN].copy_from_slice(&tag);

        // Scrive l'intero frame in un colpo: header + payload + tag.
        net.write_all(&frame[..LEN_LEN + n + TAG_LEN]).await?;
        total += n as u64;
    }

    net.flush().await?;
    Ok(total)
}

/// Pompa il flusso `net` -> `sink`: legge i frame, decifra in-place verificando
/// il tag e scrive il chiaro. Qualsiasi fallimento di autenticazione propaga
/// un errore e chiude la connessione (fail-closed). Ritorna il totale di byte
/// di chiaro ricevuti.
pub async fn pump_receiver<R, W>(
    mut net: R,
    mut sink: W,
    mut cipher: MorphingCipher,
) -> Result<u64, TunnelError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut frame = vec![0u8; FRAME_BUF];
    let mut total: u64 = 0;

    loop {
        // Header di lunghezza. UnexpectedEof qui = chiusura pulita della sessione.
        let mut len_buf = [0u8; LEN_LEN];
        match net.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let n = u32::from_le_bytes(len_buf) as usize;
        if n == 0 || n > MAX_PAYLOAD {
            return Err(TunnelError::Protocol(
                "lunghezza frame fuori range (0 o > 64 KiB)",
            ));
        }

        // Legge payload + tag in un'unica passata.
        net.read_exact(&mut frame[..n + TAG_LEN]).await?;
        let (payload, tail) = frame[..n + TAG_LEN].split_at_mut(n);

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&tail[..TAG_LEN]);

        // Decifratura IN-PLACE + verifica. `?` => fail-closed su dato non autentico.
        cipher.open_in_place(&len_buf, payload, &tag)?;

        sink.write_all(payload).await?;
        total += n as u64;
    }

    sink.flush().await?;
    Ok(total)
}

#[cfg(test)]
mod wire_tests {
    //! Test d'integrazione end-to-end su socket TCP **reali** (loopback, porta
    //! effimera). Validano il comportamento sul filo, non solo in-memory.
    use super::*;
    use crate::crypto::{CryptoError, MorphingCipher, KEY_LEN};
    use tokio::net::{TcpListener, TcpStream};

    fn key(seed: u8) -> [u8; KEY_LEN] {
        [seed; KEY_LEN]
    }

    /// Controllo positivo: stessa K_0 sui due lati => roundtrip integro sul filo.
    #[tokio::test]
    async fn wire_roundtrip_ok() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let k0 = key(0xA5);

        let rx = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut out: Vec<u8> = Vec::new();
            let res = pump_receiver(sock, &mut out, MorphingCipher::new(k0)).await;
            (res, out)
        });

        // Payload multi-chunk (oltre 64 KiB) per esercitare piu' anelli del ratchet.
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
        let sock = TcpStream::connect(addr).await.unwrap();
        pump_sender(&data[..], sock, MorphingCipher::new(k0))
            .await
            .unwrap();

        let (rx_res, out) = rx.await.unwrap();
        assert_eq!(rx_res.unwrap(), data.len() as u64);
        assert_eq!(out, data, "il chiaro deve attraversare il tunnel intatto");
    }

    /// Controllo avverso: chiave errata sul ricevente => **fail-closed assoluto**.
    /// La decifratura del primissimo chunk fallisce; la sessione si chiude e
    /// **nessun byte di chiaro** raggiunge la destinazione.
    #[tokio::test]
    async fn wire_wrong_key_fails_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let k_sender = key(0x11);
        let k_receiver = key(0x22); // chiave DIVERSA

        let rx = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut out: Vec<u8> = Vec::new();
            let res = pump_receiver(sock, &mut out, MorphingCipher::new(k_receiver)).await;
            (res, out)
        });

        let data = vec![0x42u8; 200_000]; // > 64 KiB: almeno un frame pieno parte
        let sock = TcpStream::connect(addr).await.unwrap();
        // Il sender puo' terminare Ok (buffer di socket) o con Io (peer chiuso):
        // non e' rilevante per la garanzia di sicurezza, che e' lato ricevente.
        let _ = pump_sender(&data[..], sock, MorphingCipher::new(k_sender)).await;

        let (rx_res, out) = rx.await.unwrap();
        match rx_res {
            Err(TunnelError::Crypto(CryptoError::Open)) => {}
            other => panic!("atteso fail-closed Crypto(Open), ottenuto: {other:?}"),
        }
        assert!(
            out.is_empty(),
            "con chiave errata NESSUN chiaro deve trapelare (trovati {} byte)",
            out.len()
        );
    }

    /// Manomissione di un singolo bit del payload sul filo => fail-closed,
    /// deterministico e indipendente dalla chiave (man-in-the-middle).
    #[tokio::test]
    async fn wire_bitflip_fails_closed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let k0 = key(0x33);

        // Ricevente legittimo con la chiave corretta.
        let rx = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut out: Vec<u8> = Vec::new();
            let res = pump_receiver(sock, &mut out, MorphingCipher::new(k0)).await;
            (res, out)
        });

        // "Sender" manuale: produce un frame valido e poi gli flippa un bit
        // nel payload prima di spedirlo (simula un MITM attivo).
        let mut cipher = MorphingCipher::new(k0);
        let payload = vec![0x55u8; 4096];
        let mut buf = payload.clone();
        let aad = (buf.len() as u32).to_le_bytes();
        let tag = cipher.seal_in_place(&aad, &mut buf).unwrap();

        buf[10] ^= 0x01; // bit-flip nel ciphertext

        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(&aad).await.unwrap();
        sock.write_all(&buf).await.unwrap();
        sock.write_all(&tag).await.unwrap();
        sock.shutdown().await.ok();
        let _ = sock.read(&mut [0u8; 1]).await; // attende la chiusura del peer

        let (rx_res, out) = rx.await.unwrap();
        match rx_res {
            Err(TunnelError::Crypto(CryptoError::Open)) => {}
            other => panic!("atteso fail-closed Crypto(Open), ottenuto: {other:?}"),
        }
        assert!(
            out.is_empty(),
            "un payload manomesso non deve produrre output"
        );
    }
}
