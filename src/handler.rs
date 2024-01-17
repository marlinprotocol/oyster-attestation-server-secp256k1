use std::error::Error;

use actix_web::{
    error, get,
    http::{StatusCode, Uri},
    web, Responder,
};
use libsodium_sys::crypto_sign_detached;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub struct AppState {
    pub ed25519_secret: [u8; 64],
    pub secp256k1_public: [u8; 64],
    pub attestation_uri: Uri,
}

#[derive(Deserialize, Serialize)]
struct AttestationVerificationBuilderResponse {
    attestation: String,
    pcrs: Vec<String>,
    min_cpus: usize,
    min_mem: usize,
    signature: String,
    secp256k1_public: String,
}

#[derive(Error)]
pub enum UserError {
    #[error("error while signing signature")]
    Signing,
    #[error("error while fetching attestation document")]
    AttestationFetch(#[source] oyster::AttestationError),
    #[error("error while decoding attestation document")]
    AttestationDecode(#[source] oyster::AttestationError),
}

impl error::ResponseError for UserError {
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        actix_web::HttpResponse::build(self.status_code())
            .insert_header(actix_web::http::header::ContentType::plaintext())
            .body(format!("{self:?}"))
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl std::fmt::Debug for UserError {
    // pretty print like anyhow
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)?;

        if self.source().is_some() {
            writeln!(f, "\n\nCaused by:")?;
        }

        let mut err: &dyn Error = self;
        loop {
            let Some(source) = err.source() else { break };
            writeln!(f, "\t{}", source)?;

            err = source;
        }

        Ok(())
    }
}

#[get("/attestation")]
async fn build_attestation_verification(
    state: web::Data<AppState>,
) -> actix_web::Result<impl Responder, UserError> {
    let mut msg_to_sign = "attestation-verification-".to_owned().into_bytes();
    msg_to_sign.extend_from_slice(&state.secp256k1_public);

    let mut sig = [0u8; 64];
    unsafe {
        let is_signed = crypto_sign_detached(
            sig.as_mut_ptr(),
            std::ptr::null_mut(),
            msg_to_sign.as_ptr(),
            msg_to_sign.len() as u64,
            state.ed25519_secret.as_ptr(),
        );
        if is_signed != 0 {
            return Err(UserError::Signing);
        }
    }

    let attestation_doc = oyster::get_attestation_doc(state.attestation_uri.clone())
        .await
        .map_err(UserError::AttestationFetch)?;

    let decoded_attestation = oyster::decode_attestation(attestation_doc.clone())
        .map_err(UserError::AttestationDecode)?;

    Ok(web::Json(AttestationVerificationBuilderResponse {
        attestation: hex::encode(attestation_doc),
        pcrs: decoded_attestation.pcrs,
        min_cpus: decoded_attestation.total_cpus,
        min_mem: decoded_attestation.total_memory,
        signature: hex::encode(sig),
        secp256k1_public: hex::encode(state.secp256k1_public),
    }))
}
