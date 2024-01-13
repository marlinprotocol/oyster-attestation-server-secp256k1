mod handler;
mod types;

use std::fs;

use actix_web::{web, App, HttpServer};
use anyhow::{Context, Result};
use clap::Parser;

use types::AppState;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// path to enclave private key file
    #[arg(short, long)]
    ed25519_secret: String,

    /// path to secp256k1 public key file
    #[arg(short, long)]
    secp256k1_public: String,

    /// attestation endpoint
    #[arg(short, long)]
    attestation_port: u16,

    ///max age of attestation
    #[arg(short, long)]
    max_age: usize,

    /// server ip
    #[arg(short, long)]
    ip: String,

    /// server port
    #[arg(short, long)]
    port: u16,
}

#[actix_web::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let ed25519_secret: [u8; 32] = fs::read(cli.ed25519_secret.clone())
        .with_context(|| format!("Failed to read ed25519_secret from {}", cli.ed25519_secret))?[..]
        .try_into()
        .context("invalid ed25519_secret")?;
    let secp256k1_public: [u8; 65] = fs::read(cli.secp256k1_public.clone()).with_context(|| {
        format!(
            "Failed to read secp256k1_public from {}",
            cli.secp256k1_public
        )
    })?[..]
        .try_into()
        .context("invalid secp256k1_public")?;
    let attestation_server_uri = format!("http://127.0.0.1:{}/", cli.attestation_port);
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                ed25519_secret,
                secp256k1_public,
                attestation_uri: attestation_server_uri.clone(),
                max_age: cli.max_age,
            }))
            .service(handler::build_attestation_verification)
    })
    .bind((cli.ip.clone(), cli.port))
    .context("unable to start the server")?
    .run();
    println!("oyster-utility running at {}:{}", cli.ip, cli.port);
    server.await.context("error while running server")?;
    Ok(())
}
