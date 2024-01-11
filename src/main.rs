use actix_web::{web, App, HttpServer};
use std::error::Error;
use std::fs;

mod handler;
mod types;

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
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let enclave_private_key = fs::read(cli.ed25519_secret.clone())?;
    let secp256k1_public_key: [u8; 65] =
        fs::read(cli.secp256k1_public.clone())?[0..65].try_into()?;
    let attestation_server_uri = format!("http://127.0.0.1:{}/", cli.attestation_port);
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                enclave_private_key: enclave_private_key.clone(),
                secp256k1_public_key: secp256k1_public_key.clone(),
                attestation_uri: attestation_server_uri.clone(),
                max_age: cli.max_age.clone(),
            }))
            .service(handler::build_attestation_verification)
    })
    .bind((cli.ip.clone(), cli.port))?
    .run();
    println!("oyster-utility running at {}:{}", cli.ip, cli.port);
    server.await?;
    Ok(())
}
