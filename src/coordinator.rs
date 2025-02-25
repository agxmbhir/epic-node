use anyhow::{ anyhow, Result };
use std::fs;
use tfhe::{
    generate_keys,
    prelude::*,
    safe_serialization::{ safe_deserialize, safe_deserialize_conformant, safe_serialize },
    set_server_key,
    ClientKey,
    ConfigBuilder,
    PublicKey,
    ServerKey,
};
use tracing::info;

use crate::types::AttestorError;

/// Key coordinator for TFHE operations
pub struct AttestationCoordinator {
    /// Client key (PRIVATE - should not be shared)
    pub client_key: ClientKey,
    /// Server key for homomorphic operations (can be shared)
    pub server_key: ServerKey,
    /// Config used to generate keys
    config: tfhe::Config,
}

impl AttestationCoordinator {
    /// Create a new coordinator with newly generated keys
    pub fn new() -> Result<Self> {
        // Configure TFHE parameters using default settings
        let config = ConfigBuilder::default().build();

        let (client_key, server_key) = generate_keys(config.clone());

        Ok(Self {
            client_key,
            server_key,
            config,
        })
    }

    /// Load from existing key files
    pub fn from_key_files(client_key_path: &str, server_key_path: &str) -> Result<Self> {
        // Create config with default parameters
        let config = ConfigBuilder::default().build();

        // Maximum allowed size for deserialization (1GB)
        let max_size = 1 << 30;

        // Read and deserialize the client key (PRIVATE)
        let client_key_data = fs
            ::read(client_key_path)
            .map_err(|e| AttestorError::KeyLoadError(format!("Failed to read client key: {}", e)))?;

        let client_key: ClientKey = safe_deserialize(&*client_key_data, max_size).map_err(|e|
            AttestorError::KeyLoadError(format!("Failed to deserialize client key: {}", e))
        )?;

        // Read and deserialize the server key
        let server_key_data = fs
            ::read(server_key_path)
            .map_err(|e| AttestorError::KeyLoadError(format!("Failed to read server key: {}", e)))?;

        let server_key: ServerKey = safe_deserialize_conformant(
            &*server_key_data,
            max_size,
            &config.into()
        ).map_err(|e|
            AttestorError::KeyLoadError(format!("Failed to deserialize server key: {}", e))
        )?;

        Ok(Self {
            client_key,
            server_key,
            config,
        })
    }

    /// Save the client key to a file (PRIVATE - should be kept secure)
    pub fn save_client_key(&self, path: &str) -> Result<()> {
        // Maximum allowed size for serialization (1GB)
        let max_size = 1 << 30;

        // Create a buffer to hold the serialized data
        let mut buffer = Vec::new();

        // Serialize the client key
        safe_serialize(&self.client_key, &mut buffer, max_size).map_err(|e|
            AttestorError::KeySaveError(format!("Failed to serialize client key: {}", e))
        )?;

        // Write the buffer to file
        fs
            ::write(path, buffer)
            .map_err(|e|
                AttestorError::KeySaveError(format!("Failed to write client key to file: {}", e))
            )?;

        info!("Saved client key to: {}", path);
        info!("WARNING: Keep this file secure. It contains your private key.");
        Ok(())
    }

    /// Generate and save all keys (client, server, and public)
    pub fn generate_and_save_all_keys(
        client_key_path: &str,
        server_key_path: &str,
        public_key_path: &str
    ) -> Result<Self> {
        // Configure TFHE parameters with default settings
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config.clone());

        // Maximum allowed size for serialization (1GB)
        let max_size = 1 << 40;

        // Save the client key (PRIVATE)
        let mut client_buffer = Vec::new();
        safe_serialize(&client_key, &mut client_buffer, max_size).map_err(|e|
            AttestorError::KeySaveError(format!("Failed to serialize client key: {}", e))
        )?;

        fs
            ::write(client_key_path, client_buffer)
            .map_err(|e|
                AttestorError::KeySaveError(format!("Failed to write client key to file: {}", e))
            )?;

        // Save the server key
        let mut server_buffer = Vec::new();
        safe_serialize(&server_key, &mut server_buffer, max_size).map_err(|e|
            AttestorError::KeySaveError(format!("Failed to serialize server key: {}", e))
        )?;

        fs
            ::write(server_key_path, server_buffer)
            .map_err(|e|
                AttestorError::KeySaveError(format!("Failed to write server key to file: {}", e))
            )?;

        // Generate the public key from the client key
        let public_key = PublicKey::new(&client_key);

        // Save the public key
        let mut public_buffer = Vec::new();
        safe_serialize(&public_key, &mut public_buffer, max_size).map_err(|e|
            AttestorError::KeySaveError(format!("Failed to serialize public key: {}", e))
        )?;

        fs
            ::write(public_key_path, public_buffer)
            .map_err(|e|
                AttestorError::KeySaveError(format!("Failed to write public key to file: {}", e))
            )?;

        info!("Generated and saved all keys");
        info!("Client key (PRIVATE): {}", client_key_path);
        info!("Server key: {}", server_key_path);
        info!("Public key: {}", public_key_path);

        // Return the coordinator with the generated keys
        Ok(Self {
            client_key,
            server_key,
            config,
        })
    }

    /// Save public key to a file
    pub fn save_public_key(&self, path: &str) -> Result<()> {
        // Generate public key from client key
        let public_key = PublicKey::new(&self.client_key);

        // Maximum allowed size for serialization (1GB)
        let max_size = 1 << 40;

        // Create a buffer to hold the serialized data
        let mut buffer = Vec::new();

        // Serialize the public key
        safe_serialize(&public_key, &mut buffer, max_size).map_err(|e|
            AttestorError::KeySaveError(format!("Failed to serialize public key: {}", e))
        )?;

        // Write the buffer to file
        fs
            ::write(path, buffer)
            .map_err(|e|
                AttestorError::KeySaveError(format!("Failed to write public key to file: {}", e))
            )?;

        info!("Saved public key to {}", path);
        Ok(())
    }

    /// Save the server key to a file
    pub fn save_server_key(&self, path: &str) -> Result<()> {
        // Maximum allowed size for serialization (1GB)
        let max_size = 1 << 30;

        // Create a buffer to hold the serialized data
        let mut buffer = Vec::new();

        // Serialize the server key
        safe_serialize(&self.server_key, &mut buffer, max_size).map_err(|e|
            AttestorError::KeySaveError(format!("Failed to serialize server key: {}", e))
        )?;

        // Write the buffer to file
        fs
            ::write(path, buffer)
            .map_err(|e|
                AttestorError::KeySaveError(format!("Failed to write server key to file: {}", e))
            )?;

        info!("Saved server key to: {}", path);
        Ok(())
    }

    /// Get the client key (PRIVATE)
    pub fn get_client_key(&self) -> &ClientKey {
        &self.client_key
    }

    /// Get the server key (PUBLIC)
    pub fn get_server_key(&self) -> &ServerKey {
        &self.server_key
    }

    /// Get the config
    pub fn get_config(&self) -> &tfhe::Config {
        &self.config
    }

    /// Get the public key (generated from client key)
    pub fn get_public_key(&self) -> PublicKey {
        PublicKey::new(&self.client_key)
    }

    /// Set the server key for operations
    pub fn set_server_key_for_operations(&self) {
        // Make the server key available for global use
        set_server_key(self.server_key.clone());
    }
}
