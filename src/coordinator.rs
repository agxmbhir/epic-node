#[cfg(feature = "server")]
use anyhow::Result;
#[cfg(feature = "server")]
use std::fs;
#[cfg(feature = "server")]
use tracing::info;
#[cfg(feature = "server")]
use serde::{ Serialize, Deserialize };
#[cfg(feature = "server")]
use bincode;
#[cfg(feature = "server")]
use crate::types::AttestorError;
use crate::homomorphic::{SimpleHomomorphic, PublicKey, PrivateKey};

/// Key coordinator for homomorphic operations
#[cfg(feature = "server")]
pub struct AttestationCoordinator {
    /// Encryption key (can be shared safely)
    pub encryption_key: PublicKey,
    /// Decryption key (PRIVATE - must stay secure)
    pub decryption_key: PrivateKey,
}

#[cfg(feature = "server")]
impl AttestationCoordinator {
    /// Create a new coordinator with newly generated keys
    pub fn new() -> Result<Self> {
        // Generate a fresh keypair with default settings
        let seed = b"epic-node-deterministic-seed";
        let (encryption_key, decryption_key) = SimpleHomomorphic::generate_key_pair(1024, seed);

        Ok(Self {
            encryption_key,
            decryption_key,
        })
    }

    /// Load from existing key files
    pub fn from_key_files(encryption_key_path: &str, decryption_key_path: &str) -> Result<Self> {
        // Read and deserialize the encryption key
        let encryption_key_data = fs
            ::read(encryption_key_path)
            .map_err(|e|
                AttestorError::KeyLoadError(format!("Failed to read encryption key: {}", e))
            )?;

        let encryption_key = PublicKey::from_bytes(&encryption_key_data)
            .map_err(|e|
                AttestorError::KeyLoadError(format!("Failed to deserialize encryption key: {}", e))
            )?;

        // Read and deserialize the decryption key (PRIVATE)
        let decryption_key_data = fs
            ::read(decryption_key_path)
            .map_err(|e|
                AttestorError::KeyLoadError(format!("Failed to read decryption key: {}", e))
            )?;

        let decryption_key = PrivateKey::from_bytes(&decryption_key_data)
            .map_err(|e|
                AttestorError::KeyLoadError(format!("Failed to deserialize decryption key: {}", e))
            )?;

        Ok(Self {
            encryption_key,
            decryption_key,
        })
    }

    /// Save the decryption key to a file (PRIVATE - should be kept secure)
    pub fn save_decryption_key(&self, path: &str) -> Result<()> {
        // Serialize the decryption key
        let serialized_key = self.decryption_key.to_bytes();

        // Write the buffer to file
        fs
            ::write(path, serialized_key)
            .map_err(|e|
                AttestorError::KeySaveError(
                    format!("Failed to write decryption key to file: {}", e)
                )
            )?;

        info!("Saved decryption key to: {}", path);
        info!("WARNING: Keep this file secure. It contains your private key.");
        Ok(())
    }

    /// Generate and save all keys (encryption and decryption)
    pub fn generate_and_save_all_keys(
        encryption_key_path: &str,
        decryption_key_path: &str
    ) -> Result<Self> {
        // Generate a fresh keypair
        let seed = b"epic-node-deterministic-seed";
        let (encryption_key, decryption_key) = SimpleHomomorphic::generate_key_pair(1024, seed);

        // Save the encryption key
        let serialized_encryption_key = encryption_key.to_bytes();

        fs
            ::write(encryption_key_path, serialized_encryption_key)
            .map_err(|e|
                AttestorError::KeySaveError(
                    format!("Failed to write encryption key to file: {}", e)
                )
            )?;

        // Save the decryption key (PRIVATE)
        let serialized_decryption_key = decryption_key.to_bytes();

        fs
            ::write(decryption_key_path, serialized_decryption_key)
            .map_err(|e|
                AttestorError::KeySaveError(
                    format!("Failed to write decryption key to file: {}", e)
                )
            )?;

        info!("Generated and saved all keys");
        info!("Encryption key: {}", encryption_key_path);
        info!("Decryption key (PRIVATE): {}", decryption_key_path);

        // Return the coordinator with the generated keys
        Ok(Self {
            encryption_key,
            decryption_key,
        })
    }

    /// Save encryption key to a file
    pub fn save_encryption_key(&self, path: &str) -> Result<()> {
        // Serialize the encryption key
        let serialized_key = self.encryption_key.to_bytes();

        // Write the buffer to file
        fs
            ::write(path, serialized_key)
            .map_err(|e|
                AttestorError::KeySaveError(
                    format!("Failed to write encryption key to file: {}", e)
                )
            )?;

        info!("Saved encryption key to {}", path);
        Ok(())
    }

    /// Get the encryption key (can be shared)
    pub fn get_encryption_key(&self) -> &PublicKey {
        &self.encryption_key
    }

    /// Get the decryption key (PRIVATE)
    pub fn get_decryption_key(&self) -> &PrivateKey {
        &self.decryption_key
    }
}