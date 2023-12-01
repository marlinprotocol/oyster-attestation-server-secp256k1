pub struct AppState {
    pub enclave_private_key: Vec<u8>,
    pub secp_public_key: [u8; 65],
    pub attestation_uri: String,
    pub max_age: usize,
}
