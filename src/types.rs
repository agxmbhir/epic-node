use serde::{ Deserialize, Serialize };
use tfhe::FheUint32;

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

/// Serializable encrypted attestation
#[derive(Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// The encrypted values
    pub values: Vec<FheUint32>,
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
