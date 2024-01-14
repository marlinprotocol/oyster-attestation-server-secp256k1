use crate::types::AppState;

use actix_web::{error, http::StatusCode, post, web, Responder};
use libsodium_sys::crypto_sign_detached;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Deserialize, Serialize)]
struct AttestationVerificationBuilderResponse {
    attestation_doc: String,
    pcrs: Vec<String>,
    min_cpus: usize,
    min_mem: usize,
    max_age: usize,
    signature: String,
    secp256k1_key: String,
}

#[derive(Serialize, Deserialize)]
struct AttestationVerificationBuilderRequest {
    max_age: Option<usize>,
}

#[derive(Debug, Error)]
pub enum UserError {
    #[error("error while encoding signature")]
    SignatureEncoding,
    #[error("error while signing signature")]
    Signing,
    #[error("error while parsing attestation uri")]
    UriParse,
    #[error("error while fetching attestation document")]
    AttestationFetch,
    #[error("error while decoding attestation document")]
    AttestationDecode,
}

impl error::ResponseError for UserError {
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        actix_web::HttpResponse::build(self.status_code())
            .insert_header(actix_web::http::header::ContentType::plaintext())
            .body(self.to_string())
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

#[post("/build/attestation")]
async fn build_attestation_verification(
    req: web::Json<AttestationVerificationBuilderRequest>,
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

    let attestation_doc = oyster::get_attestation_doc(
        state
            .attestation_uri
            .parse()
            .map_err(|_| UserError::UriParse)?,
    )
    .await
    .map_err(|_| UserError::AttestationFetch)?;

    let decoded_attestation = oyster::decode_attestation(attestation_doc.clone())
        .map_err(|_| UserError::AttestationDecode)?;

    Ok(web::Json(AttestationVerificationBuilderResponse {
        attestation_doc: hex::encode(attestation_doc),
        pcrs: decoded_attestation.pcrs,
        min_cpus: decoded_attestation.total_cpus,
        min_mem: decoded_attestation.total_memory,
        max_age: req.max_age.unwrap_or(state.max_age),
        signature: hex::encode(sig),
        secp256k1_key: hex::encode(state.secp256k1_public),
    }))
}
