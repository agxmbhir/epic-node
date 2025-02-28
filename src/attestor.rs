#[cfg(feature = "server")]
use anyhow::Result;
#[cfg(feature = "server")]
use std::fs;
#[cfg(feature = "server")]
use tracing::{ debug, info };
#[cfg(feature = "server")]
use serde::{ Serialize, Deserialize };
#[cfg(feature = "server")]
use bincode;

use crate::types::{ Attestation, AttestationValue, AttestorError, EncryptedValue };
use crate::homomorphic::{SimpleHomomorphic, PublicKey, PrivateKey, Ciphertext, sp1_helpers};

/// Individual attestation node
#[cfg(feature = "server")]
pub struct AttestorNode {
    /// Unique identifier for this attestor
    node_id: u64,
    /// Encryption key for encryption, loaded from file or coordinator
    encryption_key: PublicKey,
}

#[cfg(feature = "server")]
impl AttestorNode {
    /// Create a new attestor node with an encryption key
    pub fn new(node_id: u64, encryption_key: PublicKey) -> Self {
        Self {
            node_id,
            encryption_key,
        }
    }

    /// Create a new attestor with encryption key from a file
    pub fn new_from_file(node_id: u64, encryption_key_path: &str) -> Result<Self> {
        // Read file content
        let encryption_key_data = fs
            ::read(encryption_key_path)
            .map_err(|e|
                AttestorError::KeyLoadError(format!("Failed to read encryption key file: {}", e))
            )?;

        // Deserialize the encryption key 
        let encryption_key = PublicKey::from_bytes(&encryption_key_data)
            .map_err(|e|
                AttestorError::KeyLoadError(format!("Failed to deserialize encryption key: {}", e))
            )?;

        Ok(Self {
            node_id,
            encryption_key,
        })
    }

    /// Create an attestation from a vector of u64 values
    pub fn create_attestation(&self, values: &[u64]) -> Result<Attestation> {
        info!("Creating attestation with {} values", values.len());

        // Encrypt each value using deterministic encryption for SP1
        let encrypted_values: Vec<EncryptedValue> = values
            .iter()
            .enumerate()
            .map(|(i, &value)| {
                // Convert the value to a Ciphertext using deterministic encryption
                let ciphertext = sp1_helpers::encrypt_for_sp1(&self.encryption_key, value, i);

                // Convert to our serializable EncryptedValue
                EncryptedValue::from(ciphertext)
            })
            .collect();

        debug!("Encrypted {} values", encrypted_values.len());

        Ok(Attestation {
            values: encrypted_values,
            metadata: Some(format!("Attestor: {}", self.node_id)),
        })
    }

    /// Create an attestation from attestation values
    pub fn create_attestation_from_values(
        &self,
        attestation_values: &[AttestationValue]
    ) -> Result<Attestation> {
        let values: Vec<u64> = attestation_values
            .iter()
            .map(|av| av.value) // Use u64 directly
            .collect();

        self.create_attestation(&values)
    }

    /// Save an attestation to a file
    pub fn save_attestation(&self, attestation: &Attestation, path: &str) -> Result<()> {
        // Serialize the attestation directly with bincode
        let serialized_attestation = bincode
            ::serialize(attestation)
            .map_err(|e|
                AttestorError::SerializationError(format!("Failed to serialize attestation: {}", e))
            )?;

        // Write the serialized data to file
        fs
            ::write(path, serialized_attestation)
            .map_err(|e|
                AttestorError::KeySaveError(format!("Failed to write attestation: {}", e))
            )?;

        info!("Saved attestation to {}", path);
        Ok(())
    }

    // Deserializing attestation values
    pub fn load_attestation(&self, path: &str) -> Result<Attestation> {
        // Read from file
        let data = fs
            ::read(path)
            .map_err(|e|
                AttestorError::KeyLoadError(format!("Failed to read attestation: {}", e))
            )?;

        // Deserialize the attestation directly
        let attestation: Attestation = bincode
            ::deserialize(&data)
            .map_err(|e|
                AttestorError::SerializationError(
                    format!("Failed to deserialize attestation: {}", e)
                )
            )?;

        info!("Loaded attestation from {} with {} values", path, attestation.values.len());
        Ok(attestation)
    }

    /// Get encryption key
    pub fn get_encryption_key(&self) -> &PublicKey {
        &self.encryption_key
    }
}

/// Key generation utilities
pub struct KeyGeneration;

impl KeyGeneration {
    /// Generate a new key pair for homomorphic encryption
    pub fn generate_key_pair(bit_length: usize, seed: &[u8]) -> (PublicKey, PrivateKey) {
        SimpleHomomorphic::generate_key_pair(bit_length, seed)
    }
    
    #[cfg(feature = "server")]
    /// Save public key to a file
    pub fn save_public_key(key: &PublicKey, path: &str) -> Result<()> {
        let key_bytes = key.to_bytes();
        fs::write(path, key_bytes)
            .map_err(|e| AttestorError::KeySaveError(format!("Failed to save public key: {}", e)).into())
    }
    
    #[cfg(feature = "server")]
    /// Save private key to a file
    pub fn save_private_key(key: &PrivateKey, path: &str) -> Result<()> {
        let key_bytes = key.to_bytes();
        fs::write(path, key_bytes)
            .map_err(|e| AttestorError::KeySaveError(format!("Failed to save private key: {}", e)).into())
    }
    
    #[cfg(feature = "server")]
    /// Load public key from a file
    pub fn load_public_key(path: &str) -> Result<PublicKey> {
        let key_bytes = fs::read(path)
            .map_err(|e| AttestorError::KeyLoadError(format!("Failed to read public key: {}", e)))?;
            
        PublicKey::from_bytes(&key_bytes)
            .map_err(|e| AttestorError::KeyLoadError(format!("Invalid public key data: {}", e)).into())
    }
    
    #[cfg(feature = "server")]
    /// Load private key from a file
    pub fn load_private_key(path: &str) -> Result<PrivateKey> {
        let key_bytes = fs::read(path)
            .map_err(|e| AttestorError::KeyLoadError(format!("Failed to read private key: {}", e)))?;
            
        PrivateKey::from_bytes(&key_bytes)
            .map_err(|e| AttestorError::KeyLoadError(format!("Invalid private key data: {}", e)).into())
    }
}