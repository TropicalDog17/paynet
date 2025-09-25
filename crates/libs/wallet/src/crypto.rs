use bitcoin::bip32::{DerivationPath, Xpriv};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use std::str::FromStr;
use rand::RngCore;
use base64::Engine;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("derivation path: {0}")]
    DerivationPath(String),
    #[error("key derivation: {0}")]
    KeyDerivation(String),
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: {0}")]
    Decrypt(String),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
}

pub fn derive_encryption_key_bip32(master_key: &Xpriv, key_index: u32) -> Result<[u8; 32], Error> {
    let path_str = format!("m/1337'/{}'", key_index);
    let derivation_path = DerivationPath::from_str(&path_str)
        .map_err(|e| Error::DerivationPath(e.to_string()))?;

    let derived_key = master_key
        .derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &derivation_path)
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;

    Ok(derived_key.private_key.secret_bytes())
}

#[derive(Clone)]
pub struct EncryptionService {
    cipher: ChaCha20Poly1305,
}

impl EncryptionService {
    pub fn from_master_key(master_key: &Xpriv) -> Result<Self, Error> {
        let key_bytes = derive_encryption_key_bip32(master_key, 0)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        Ok(Self { cipher })
    }

    pub fn encrypt_to_base64(&self, plaintext: &str) -> Result<String, Error> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| Error::Encrypt(e.to_string()))?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(base64::engine::general_purpose::STANDARD.encode(result))
    }

    pub fn decrypt_from_base64(&self, encrypted_data_b64: &str) -> Result<String, Error> {
        let data = base64::engine::general_purpose::STANDARD.decode(encrypted_data_b64)?;
        if data.len() < 12 {
            return Err(Error::Decrypt("invalid encrypted data".to_string()));
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| Error::Decrypt(e.to_string()))?;

        String::from_utf8(plaintext).map_err(|e| Error::Decrypt(e.to_string()))
    }
}


