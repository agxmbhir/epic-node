use anyhow::Result;
use tfhe::{
    boolean::backward_compatibility::public_key,
    prelude::*,
    safe_serialization::{ safe_deserialize, safe_serialize },
    ConfigBuilder,
    FheUint32,
    PublicKey,
};
use std::fs;
use tracing::{ debug, info };

use crate::types::{ Attestation, AttestationValue, AttestorError };

/// Individual attestation node
pub struct AttestorNode {
    /// Unique identifier for this attestor
    node_id: u64,
    /// Public key for encryption, loaded from file or coordinator
    public_key: PublicKey,
    /// Configuration used
    config: tfhe::Config,
}

impl AttestorNode {
    /// Create a new attestor node with a public key
    pub fn new(node_id: u64, public_key: PublicKey) -> Self {
        // Use default configuration
        let config = ConfigBuilder::default().build();

        Self {
            node_id,
            public_key,
            config,
        }
    }

    /// Create a new attestor with public key from a file
    pub fn new_from_file(node_id: u64, public_key_path: &str) -> Result<Self> {
        // Use default configuration
        let config = ConfigBuilder::default().build();

        // Read file content
        let public_key_data = fs
            ::read(public_key_path)
            .map_err(|e|
                AttestorError::KeyLoadError(format!("Failed to read public key file: {}", e))
            )?;

        // Maximum allowed size for deserialization (1GB)
        let max_size = 1 << 40;

        // Deserialize the public key using safe deserialization
        let public_key: PublicKey = safe_deserialize(&*public_key_data, max_size).map_err(|e|
            AttestorError::KeyLoadError(format!("Failed to deserialize public key: {}", e))
        )?;

        Ok(Self {
            node_id,
            public_key,
            config,
        })
    }

    /// Create an attestation from a vector of u32 values
    pub fn create_attestation(&self, values: &[u32]) -> Result<Attestation> {
        info!("Creating attestation with {} values", values.len());

        // Encrypt each value
        let encrypted_values: Vec<FheUint32> = values
            .iter()
            .map(|&value| {
                // Encrypt the value using the public key
                FheUint32::try_encrypt(value, &self.public_key).unwrap()
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
        let values: Vec<u32> = attestation_values
            .iter()
            .map(|av| av.value as u32) // Convert u64 to u32
            .collect();

        self.create_attestation(&values)
    }

    /// Save an attestation to a file
    // Serializing attestation values
    pub fn save_attestation(&self, attestation: &Attestation, path: &str) -> Result<()> {
        // Maximum allowed size for serialization (1GB)
        let max_size = 1 << 30;

        // Create a buffer to hold the serialized data
        let mut buffer = Vec::new();

        // First, serialize the number of values
        let num_values = attestation.values.len() as u32;
        buffer.extend_from_slice(&num_values.to_le_bytes());

        // Serialize each value individually
        for value in &attestation.values {
            // Create a temporary buffer for this value
            let mut value_buffer = Vec::new();

            // Serialize the value
            tfhe::safe_serialization
                ::safe_serialize(value, &mut value_buffer, max_size)
                .map_err(|e|
                    AttestorError::SerializationError(
                        format!("Failed to serialize attestation value: {}", e)
                    )
                )?;

            // Write the size of the buffer first (to know how much to read later)
            let size = value_buffer.len() as u32;
            buffer.extend_from_slice(&size.to_le_bytes());

            // Then write the actual serialized value
            buffer.extend_from_slice(&value_buffer);
        }

        // Serialize the metadata
        if let Some(metadata) = &attestation.metadata {
            // Write 1 to indicate metadata exists
            buffer.push(1);

            // Write the length of the metadata string
            let metadata_len = metadata.len() as u32;
            buffer.extend_from_slice(&metadata_len.to_le_bytes());

            // Write the metadata string as bytes
            buffer.extend_from_slice(metadata.as_bytes());
        } else {
            // Write 0 to indicate no metadata
            buffer.push(0);
        }

        // Write the buffer to file
        fs
            ::write(path, buffer)
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

        // Maximum allowed size for deserialization (1GB)
        let max_size = 1 << 30;

        // Read the number of values
        if data.len() < 4 {
            return Err(
                AttestorError::SerializationError(
                    "Corrupted attestation file: too short".to_string()
                ).into()
            );
        }

        let mut pos = 0;
        let num_values = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        pos += 4;

        // Deserialize each value
        let mut values = Vec::with_capacity(num_values);
        for _ in 0..num_values {
            // Make sure we have enough data for the size
            if pos + 4 > data.len() {
                return Err(
                    AttestorError::SerializationError(
                        "Corrupted attestation file: unexpected end".to_string()
                    ).into()
                );
            }

            // Read the size of this value
            let size = u32::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ]) as usize;
            pos += 4;

            // Make sure we have enough data for the value
            if pos + size > data.len() {
                return Err(
                    AttestorError::SerializationError(
                        "Corrupted attestation file: unexpected end".to_string()
                    ).into()
                );
            }

            // Extract the value data
            let value_data = &data[pos..pos + size];
            pos += size;

            // Deserialize the value
            let value: FheUint32 = safe_deserialize(value_data, max_size).map_err(|e|
                AttestorError::SerializationError(
                    format!("Failed to deserialize attestation value: {}", e)
                )
            )?;

            values.push(value);
        }

        // Read metadata if it exists
        let metadata = if pos < data.len() {
            let has_metadata = data[pos];
            pos += 1;

            if has_metadata == 1 {
                // Make sure we have enough data for the metadata length
                if pos + 4 > data.len() {
                    return Err(
                        AttestorError::SerializationError(
                            "Corrupted attestation file: unexpected end".to_string()
                        ).into()
                    );
                }

                // Read the length of the metadata
                let metadata_len = u32::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                ]) as usize;
                pos += 4;

                // Make sure we have enough data for the metadata
                if pos + metadata_len > data.len() {
                    return Err(
                        AttestorError::SerializationError(
                            "Corrupted attestation file: unexpected end".to_string()
                        ).into()
                    );
                }

                // Read the metadata as a string
                let metadata_str = std::str
                    ::from_utf8(&data[pos..pos + metadata_len])
                    .map_err(|e|
                        AttestorError::SerializationError(
                            format!("Invalid UTF-8 in metadata: {}", e)
                        )
                    )?;

                Some(metadata_str.to_string())
            } else {
                None
            }
        } else {
            None
        };

        info!("Loaded attestation from {} with {} values", path, values.len());
        Ok(Attestation {
            values,
            metadata,
        })
    }
}
