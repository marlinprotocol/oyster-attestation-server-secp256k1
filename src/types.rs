pub struct AppState {
    pub ed25519_secret: Vec<u8>,
    pub secp256k1_public: [u8; 65],
    pub attestation_uri: String,
    pub max_age: usize,
}
