//! `hydra-transit` — tunnel di transito dati cifrato point-to-point.
//!
//! Due modalita':
//!   * `--mode receiver --port 8080`  : accetta una connessione e scrive il
//!     chiaro decifrato su **stdout**.
//!   * `--mode sender --target IP:PORT`: legge il chiaro da **stdin**, lo cifra
//!     e lo invia al receiver.
//!
//! La chiave iniziale K_0 (32 byte) si fornisce in esadecimale (64 caratteri)
//! via variabile d'ambiente `HYDRA_KEY` oppure, come override esplicito, con
//! `--key`. Entrambi i lati devono usare la **stessa** K_0.

mod crypto;
mod network;

use crate::crypto::{MorphingCipher, KEY_LEN};
use crate::network::{pump_receiver, pump_sender};
use clap::{Parser, ValueEnum};
use std::process::ExitCode;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Debug, ValueEnum)]
enum Mode {
    /// Riceve e decifra: scrive il chiaro su stdout.
    Receiver,
    /// Invia e cifra: legge il chiaro da stdin.
    Sender,
}

/// Tunnel di transito dati cifrato point-to-point (Morphing Key + ChaCha20-Poly1305).
#[derive(Parser, Debug)]
#[command(name = "hydra-transit", version, about, long_about = None)]
struct Cli {
    /// Modalita' operativa del nodo.
    #[arg(long, value_enum)]
    mode: Mode,

    /// Porta di ascolto (solo modalita' receiver).
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// Indirizzo del receiver "IP:PORT" (solo modalita' sender).
    #[arg(long)]
    target: Option<String>,

    /// Chiave iniziale K_0 in esadecimale (64 caratteri = 32 byte).
    /// Default dalla variabile d'ambiente HYDRA_KEY.
    #[arg(long, env = "HYDRA_KEY", hide_env_values = true)]
    key: String,
}

/// Converte una stringa esadecimale di 64 caratteri in K_0 da 32 byte.
fn parse_key(hex_key: &str) -> Result<[u8; KEY_LEN], String> {
    let bytes = hex::decode(hex_key.trim())
        .map_err(|e| format!("chiave non valida (atteso esadecimale): {e}"))?;
    if bytes.len() != KEY_LEN {
        return Err(format!(
            "la chiave deve essere di {KEY_LEN} byte ({} caratteri hex), trovati {} byte",
            KEY_LEN * 2,
            bytes.len()
        ));
    }
    let mut k0 = [0u8; KEY_LEN];
    k0.copy_from_slice(&bytes);
    Ok(k0)
}

/// Stampa un report di throughput su stderr (stdout resta riservato ai dati).
fn report(label: &str, bytes: u64, elapsed_secs: f64) {
    let mib = bytes as f64 / (1024.0 * 1024.0);
    let mibps = if elapsed_secs > 0.0 {
        mib / elapsed_secs
    } else {
        0.0
    };
    eprintln!(
        "[hydra-transit] {label}: {bytes} byte ({mib:.2} MiB) in {elapsed_secs:.3}s => {mibps:.2} MiB/s"
    );
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let k0 = match parse_key(&cli.key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[hydra-transit] errore chiave: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = match cli.mode {
        Mode::Receiver => run_receiver(cli.port, k0).await,
        Mode::Sender => match cli.target {
            Some(target) => run_sender(&target, k0).await,
            None => Err("modalita' sender richiede --target IP:PORT".to_string()),
        },
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[hydra-transit] {e}");
            ExitCode::FAILURE
        }
    }
}

/// Receiver: accetta una connessione e decifra verso stdout.
async fn run_receiver(port: u16, k0: [u8; KEY_LEN]) -> Result<(), String> {
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("bind {addr} fallito: {e}"))?;
    eprintln!("[hydra-transit] receiver in ascolto su {addr}");

    let (socket, peer) = listener
        .accept()
        .await
        .map_err(|e| format!("accept fallita: {e}"))?;
    socket.set_nodelay(true).ok();
    eprintln!("[hydra-transit] connessione da {peer}");

    let cipher = MorphingCipher::new(k0);
    let start = Instant::now();
    let total = pump_receiver(socket, tokio::io::stdout(), cipher)
        .await
        .map_err(|e| format!("sessione interrotta: {e}"))?;

    report("ricevuti", total, start.elapsed().as_secs_f64());
    Ok(())
}

/// Sender: si connette al receiver e cifra il chiaro letto da stdin.
async fn run_sender(target: &str, k0: [u8; KEY_LEN]) -> Result<(), String> {
    let socket = TcpStream::connect(target)
        .await
        .map_err(|e| format!("connessione a {target} fallita: {e}"))?;
    socket.set_nodelay(true).ok();
    eprintln!("[hydra-transit] connesso a {target}");

    let cipher = MorphingCipher::new(k0);
    let start = Instant::now();
    let total = pump_sender(tokio::io::stdin(), socket, cipher)
        .await
        .map_err(|e| format!("sessione interrotta: {e}"))?;

    report("inviati", total, start.elapsed().as_secs_f64());
    Ok(())
}
