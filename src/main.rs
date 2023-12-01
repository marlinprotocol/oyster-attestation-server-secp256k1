use actix_web::{web, App, HttpServer};
use std::error::Error;
use std::fs;

mod handlers;
mod types;

use clap::Parser;
use types::handlers::AppState;
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// path to enclave private key file
    #[arg(short, long)]
    enclaveprivatekey: String,

    /// path to secp private key file
    #[arg(short, long)]
    secpprivatekey: String,

    /// attestation endpoint
    #[arg(short, long)]
    attestationport: u16,

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
    let enclave_private_key = fs::read(cli.enclaveprivatekey.clone())?;
    let secp_private_key = fs::read(cli.secpprivatekey.clone())?;
    let secp_private_key = secp256k1::SecretKey::from_slice(&secp_private_key)?;
    let secp = secp256k1::Secp256k1::new();
    let secp_public_key = secp_private_key.public_key(&secp).serialize_uncompressed();
    let attestation_server_uri = format!("http://127.0.0.1:{}/", cli.attestationport);
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                enclave_private_key: enclave_private_key.clone(),
                secp_public_key: secp_public_key.clone(),
                attestation_uri: attestation_server_uri.clone(),
                max_age: cli.max_age.clone(),
            }))
            .service(handlers::attestation_sig::build_attestation_verification)
    })
    .bind((cli.ip.clone(), cli.port))?
    .run();
    println!("oyster-utility running at {}:{}", cli.ip, cli.port);
    server.await?;
    Ok(())
}
