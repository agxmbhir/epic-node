use serde::{ Deserialize, Serialize };
use crate::homomorphic::{ BigInt, Ciphertext };

/// Common error types for the application
#[derive(thiserror::Error, Debug)]
pub enum AttestorError {
    #[error("Encryption error: {0}")] EncryptionError(String),

    #[error("Key loading error: {0}")] KeyLoadError(String),

    #[error("Key saving error: {0}")] KeySaveError(String),

    #[error("Serialization error: {0}")] SerializationError(String),

    #[error("Data fetch error: {0}")] DataFetchError(String),
}

/// An attestation value that can be encrypted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationValue {
    /// Type of the value (e.g., "balance", "reserves", etc.)
    pub value_type: String,
    /// Actual numeric value
    pub value: u64,
    /// Timestamp of when this value was recorded
    pub timestamp: u64,
    /// Any additional metadata needed for verification
    pub metadata: String,
}

/// Serializable encrypted attestation value
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedValue {
    #[serde(with = "BigIntSerde")]
    pub value: BigInt,
}

impl From<BigInt> for EncryptedValue {
    fn from(value: BigInt) -> Self {
        Self { value }
    }
}

impl From<EncryptedValue> for BigInt {
    fn from(ev: EncryptedValue) -> Self {
        ev.value
    }
}

impl From<Ciphertext> for EncryptedValue {
    fn from(c: Ciphertext) -> Self {
        Self {
            value: c.value,
        }
    }
}

// Serialization helper for BigInt
mod BigIntSerde {
    use serde::{ Deserialize, Deserializer, Serialize, Serializer };
    use crate::homomorphic::BigInt;
    use std::str::FromStr;

    pub fn serialize<S>(bigint: &BigInt, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        // Use the to_bytes method to serialize BigInt
        let bytes = bigint.to_bytes();
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigInt, D::Error>
        where D: Deserializer<'de>
    {
        // Deserialize as bytes and then convert back to BigInt
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(BigInt::from_bytes(&bytes))
    }
}

/// Serializable encrypted attestation
#[derive(Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// The encrypted values
    pub values: Vec<EncryptedValue>,
    /// Attestation metadata
    pub metadata: Option<String>,
}

/// Rules and constraint structures
#[derive(Clone, Serialize, Deserialize)]
pub struct Rules {
    pub attestations: Vec<Attestation>,
    pub constraints: Vec<Constraint>,
}

/// A constraint defining a relationship between attestations
#[derive(Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub left_index: usize,
    pub right_index: usize,
    pub operator: Operator,
}

/// Comparison operators for constraints
#[derive(Clone, Serialize, Deserialize)]
pub enum Operator {
    Equal,
    GreaterThan,
    LessThan,
}
