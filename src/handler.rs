use crate::types::AppState;
use actix_web::{error, http::StatusCode, post, web, Responder};
use derive_more::{Display, Error};
use libsodium_sys::crypto_sign_detached;
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
    #[display(fmt = "error while encoding signature")]
    SignatureEncoding,
    #[display(fmt = "error while signing signature")]
    Signing,
    #[display(fmt = "error while parsing attestation uri")]
    UriParse,
    #[display(fmt = "error while fetching attestation document")]
    AttestationFetch,
    #[display(fmt = "error while decoding attestation document")]
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
    let msg_to_sign = ethers::abi::encode_packed(&[
        ethers::abi::Token::String("attestation-verification-".to_string()),
        ethers::abi::Token::Bytes(state.secp256k1_public.to_vec()),
    ])
    .map_err(|_| UserError::SignatureEncoding)?;

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
