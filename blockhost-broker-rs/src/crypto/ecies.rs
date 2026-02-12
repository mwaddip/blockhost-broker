//! ECIES encryption/decryption for on-chain communication.
//!
//! Uses secp256k1 curve for encryption of request/response payloads.
//! Compatible with Python eciespy library for interoperability.

use std::path::Path;

use ecies::{decrypt, encrypt};
use k256::SecretKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum EciesError {
    #[error("Failed to read key file: {0}")]
    KeyFileError(#[from] std::io::Error),

    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),
}

/// Decrypted request payload from Blockhost server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPayload {
    /// Base64 WireGuard public key.
    pub wg_pubkey: String,
    /// Checksummed NFT contract address.
    pub nft_contract: String,
    /// Hex secp256k1 pubkey for response encryption.
    pub server_pubkey: String,
}

/// Response payload to encrypt for Blockhost server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponsePayload {
    /// IPv6 prefix (e.g., "2a11:6c7:f04:276::100/120").
    pub prefix: String,
    /// Gateway address (e.g., "2a11:6c7:f04:276::2").
    pub gateway: String,
    /// Base64 WireGuard public key.
    pub broker_pubkey: String,
    /// Broker endpoint (e.g., "95.179.128.177:51820").
    pub broker_endpoint: String,
    /// DNS zone for this broker (e.g., "blockhost.thawaras.org"). Optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_zone: Option<String>,
}

/// ECIES encryption handler using secp256k1.
pub struct EciesEncryption {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl EciesEncryption {
    /// Create a new ECIES encryption handler with a new random key.
    pub fn new() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        let private_key = secret_key.to_bytes().to_vec();
        let public_key = Self::derive_public_key(&private_key);

        Self {
            private_key,
            public_key,
        }
    }

    /// Create from an existing private key (hex encoded).
    pub fn from_hex(private_key_hex: &str) -> Result<Self, EciesError> {
        let hex_str = private_key_hex.strip_prefix("0x").unwrap_or(private_key_hex);
        let private_key = hex::decode(hex_str)?;

        if private_key.len() != 32 {
            return Err(EciesError::InvalidPrivateKey(
                "Private key must be 32 bytes".to_string(),
            ));
        }

        let public_key = Self::derive_public_key(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Load private key from file.
    pub fn from_file(key_path: &Path) -> Result<Self, EciesError> {
        let content = std::fs::read_to_string(key_path)?;
        Self::from_hex(content.trim())
    }

    /// Save private key to file.
    pub fn save_to_file(&self, key_path: &Path) -> Result<(), EciesError> {
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(key_path, self.private_key_hex())?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Derive uncompressed public key (65 bytes: 04 || x || y).
    fn derive_public_key(private_key: &[u8]) -> Vec<u8> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::PublicKey;

        let secret_key = SecretKey::from_slice(private_key).expect("Valid private key");
        let public_key = PublicKey::from(secret_key.public_key());
        let point = public_key.to_encoded_point(false); // uncompressed
        point.as_bytes().to_vec()
    }

    /// Get private key as hex string.
    pub fn private_key_hex(&self) -> String {
        hex::encode(&self.private_key)
    }

    /// Get uncompressed public key (65 bytes).
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Get public key as hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    /// Encrypt data for a recipient.
    pub fn encrypt_for(&self, plaintext: &[u8], recipient_pubkey: &[u8]) -> Result<Vec<u8>, EciesError> {
        encrypt(recipient_pubkey, plaintext)
            .map_err(|e| EciesError::EncryptionFailed(e.to_string()))
    }

    /// Decrypt data encrypted for this key.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EciesError> {
        decrypt(&self.private_key, ciphertext)
            .map_err(|e| EciesError::DecryptionFailed(e.to_string()))
    }

    /// Encrypt JSON data for a recipient.
    pub fn encrypt_json<T: Serialize>(
        &self,
        data: &T,
        recipient_pubkey: &[u8],
    ) -> Result<Vec<u8>, EciesError> {
        let plaintext = serde_json::to_vec(data)?;
        self.encrypt_for(&plaintext, recipient_pubkey)
    }

    /// Decrypt JSON data.
    pub fn decrypt_json<T: for<'de> Deserialize<'de>>(&self, ciphertext: &[u8]) -> Result<T, EciesError> {
        let plaintext = self.decrypt(ciphertext)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// Decrypt and parse a request payload from Blockhost server.
    pub fn decrypt_request_payload(&self, encrypted_payload: &[u8]) -> Result<RequestPayload, EciesError> {
        self.decrypt_json(encrypted_payload)
    }

    /// Encrypt a response payload for Blockhost server.
    pub fn encrypt_response_payload(
        &self,
        response: &ResponsePayload,
        server_pubkey_hex: &str,
    ) -> Result<Vec<u8>, EciesError> {
        let server_pubkey = hex::decode(server_pubkey_hex)?;
        self.encrypt_json(response, &server_pubkey)
    }
}

impl Default for EciesEncryption {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EciesEncryption {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// Generate a new ECIES keypair and save to file.
pub fn generate_ecies_keypair(key_path: &Path) -> Result<EciesEncryption, EciesError> {
    let encryption = EciesEncryption::new();
    encryption.save_to_file(key_path)?;
    Ok(encryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let enc = EciesEncryption::new();
        assert_eq!(enc.private_key.len(), 32);
        assert_eq!(enc.public_key.len(), 65);
        assert_eq!(enc.public_key[0], 0x04); // Uncompressed point marker
    }

    #[test]
    fn test_encrypt_decrypt() {
        let sender = EciesEncryption::new();
        let recipient = EciesEncryption::new();

        let plaintext = b"Hello, World!";
        let ciphertext = sender.encrypt_for(plaintext, recipient.public_key_bytes()).unwrap();
        let decrypted = recipient.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_json_encrypt_decrypt() {
        let sender = EciesEncryption::new();
        let recipient = EciesEncryption::new();

        let response = ResponsePayload {
            prefix: "2001:db8::/48".to_string(),
            gateway: "2001:db8::1".to_string(),
            broker_pubkey: "test-pubkey".to_string(),
            broker_endpoint: "example.com:51820".to_string(),
            dns_zone: None,
        };

        let encrypted = sender.encrypt_json(&response, recipient.public_key_bytes()).unwrap();
        let decrypted: ResponsePayload = recipient.decrypt_json(&encrypted).unwrap();

        assert_eq!(decrypted.prefix, response.prefix);
        assert_eq!(decrypted.broker_endpoint, response.broker_endpoint);
    }

    #[test]
    fn test_from_hex() {
        let original = EciesEncryption::new();
        let hex_key = original.private_key_hex();

        let restored = EciesEncryption::from_hex(&hex_key).unwrap();
        assert_eq!(restored.public_key_hex(), original.public_key_hex());
    }
}
