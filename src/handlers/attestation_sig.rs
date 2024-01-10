use crate::types::handlers::AppState;
use actix_web::{error, http::StatusCode, post, web, Responder};
use derive_more::{Display, Error};
use hex;
use libsodium_sys::crypto_sign_detached;
use oyster;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
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

#[derive(Debug, Display, Error)]
pub enum UserError {
    InternalServerError,
}

impl error::ResponseError for UserError {
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        actix_web::HttpResponse::build(self.status_code())
            .insert_header(actix_web::http::header::ContentType::plaintext())
            .body(self.to_string())
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            UserError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

fn verification_message(pubkey: &String) -> String {
    const PREFIX: &str = "attestation-verification-";
    format!("{}{:?}", PREFIX.to_string(), pubkey)
}

#[post("/build/attestation")]
async fn build_attestation_verification(
    req: web::Json<AttestationVerificationBuilderRequest>,
    state: web::Data<AppState>,
) -> actix_web::Result<impl Responder, UserError> {
    let msg_to_sign = verification_message(&hex::encode(&state.secp256k1_public_key));
    let mut sig = [0u8; 64];
    unsafe {
        let is_signed = crypto_sign_detached(
            sig.as_mut_ptr(),
            std::ptr::null_mut(),
            msg_to_sign.as_ptr(),
            msg_to_sign.len() as u64,
            state.enclave_private_key.as_ptr(),
        );
        if is_signed != 0 {
            panic!("not signed");
        }
    }

    let attestation_doc = oyster::get_attestation_doc(
        state
            .attestation_uri
            .parse()
            .map_err(|_| UserError::InternalServerError)?,
    )
    .await
    .map_err(|_| UserError::InternalServerError)?;

    let decoded_attestation = oyster::decode_attestation(attestation_doc.clone())
        .map_err(|_| UserError::InternalServerError)?;

    Ok(web::Json(AttestationVerificationBuilderResponse {
        attestation_doc: hex::encode(attestation_doc),
        pcrs: decoded_attestation.pcrs,
        min_cpus: decoded_attestation.total_cpus,
        min_mem: decoded_attestation.total_memory,
        max_age: req.max_age.unwrap_or(state.max_age),
        signature: hex::encode(sig),
        secp256k1_key: hex::encode(&state.secp256k1_public_key),
    }))
}
