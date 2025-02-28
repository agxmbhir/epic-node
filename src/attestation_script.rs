//! A script for working with homomorphic encrypted attestations using SP1.
//!
//! This script allows you to:
//! 1. Generate encryption/decryption keys
//! 2. Create attestations with encrypted values
//! 3. Execute operations on encrypted values using SP1 program
//! 4. Verify proofs
//!
//! Run with:
//! ```shell
//! cargo run --bin attestation_script -- --generate-keys
//! cargo run --bin attestation_script -- --create-attestation --node 1 --value 1000000
//! cargo run --bin attestation_script -- --create-attestation --node 2 --value 900000
//! cargo run --bin attestation_script -- --execute --operation GreaterThan --att-file1 ./attestations/attestation_1.bin --att-file2 ./attestations/attestation_2.bin
//! ```

use clap::Parser;
use anyhow::{Result, anyhow, Context};
use std::path::{Path, PathBuf};
use std::fs;
use sp1_sdk::{ProverClient, SP1Stdin};

// Import epic-node types and functionality
use epic_node::attestor::{AttestorNode, KeyGeneration};
use epic_node::types::{Attestation, AttestationValue};
use epic_node::homomorphic::{PublicKey, PrivateKey, Ciphertext, BigInt, SimpleHomomorphic};

// Import types from fibonacci program
use fibonacci_lib::{Operation, OperationStep, Rule, EncryptionKey as ProgramEncryptionKey};

// Define paths
const KEYS_DIR: &str = "./keys";
const ATTESTATIONS_DIR: &str = "./attestations";
const PUBLIC_KEY_PATH: &str = "./keys/public.key";
const PRIVATE_KEY_PATH: &str = "./keys/private.key";

/// Command-line arguments for the attestation script
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Generate new encryption/decryption keys
    #[clap(long)]
    generate_keys: bool,

    /// Create a new attestation with encrypted value
    #[clap(long)]
    create_attestation: bool,

    /// Execute the SP1 program
    #[clap(long)]
    execute: bool,

    /// Prove the execution
    #[clap(long)]
    prove: bool,

    /// Node ID for attestation (e.g., 1 for exchange, 2 for regulator)
    #[clap(long)]
    node: Option<u64>,

    /// Value to encrypt in attestation
    #[clap(long)]
    value: Option<u64>,

    /// Path to first attestation file
    #[clap(long)]
    att_file1: Option<PathBuf>,

    /// Path to second attestation file
    #[clap(long)]
    att_file2: Option<PathBuf>,

    /// Operation to perform (Add, Multiply, GreaterThan, LessThan, Equal)
    #[clap(long)]
    operation: Option<String>,

    /// Rule ID for program execution
    #[clap(long, default_value = "attestation-rule-1")]
    rule_id: String,
}

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    dotenv::dotenv().ok();

    // Parse command line arguments
    let args = Args::parse();

    // Create directories if they don't exist
    ensure_directories_exist()?;

    if args.generate_keys {
        generate_keys()?;
    } else if args.create_attestation {
        create_attestation(&args)?;
    } else if args.execute {
        execute_program(&args)?;
    } else if args.prove {
        prove_execution(&args)?;
    } else {
        println!("No action specified. Use --help to see options.");
    }

    Ok(())
}

/// Create necessary directories
fn ensure_directories_exist() -> Result<()> {
    fs::create_dir_all(KEYS_DIR).context("Failed to create keys directory")?;
    fs::create_dir_all(ATTESTATIONS_DIR).context("Failed to create attestations directory")?;
    Ok(())
}

/// Generate encryption and decryption keys
fn generate_keys() -> Result<()> {
    println!("Generating encryption keys...");

    // Generate deterministic keys
    let seed = b"epic-node-deterministic-seed";
    let (public_key, private_key) = KeyGeneration::generate_key_pair(1024, seed);

    // Save the keys
    KeyGeneration::save_public_key(&public_key, PUBLIC_KEY_PATH)?;
    KeyGeneration::save_private_key(&private_key, PRIVATE_KEY_PATH)?;

    println!("Keys generated and saved:");
    println!("  Public key: {}", PUBLIC_KEY_PATH);
    println!("  Private key: {}", PRIVATE_KEY_PATH);
    println!("\nWARNING: Keep the private key secure!");

    Ok(())
}

/// Create an attestation with encrypted value
fn create_attestation(args: &Args) -> Result<()> {
    let node_id = args.node.ok_or_else(|| anyhow!("Node ID is required"))?;
    let value = args.value.ok_or_else(|| anyhow!("Value is required"))?;

    println!("Creating attestation for node {} with value {}", node_id, value);

    // Load the public key
    let public_key = KeyGeneration::load_public_key(PUBLIC_KEY_PATH)?;

    // Create attestor node
    let attestor = AttestorNode::new(node_id, public_key);

    // Create attestation values
    let attestation_value = AttestationValue {
        value_type: "balance".to_string(),
        value,
        timestamp: 1234567890, // Fixed timestamp for deterministic encryption
        metadata: format!("Node {}", node_id),
    };

    // Create the attestation
    let attestation = attestor.create_attestation_from_values(&[attestation_value])?;

    // Save the attestation
    let attestation_path = format!("{}/attestation_{}.bin", ATTESTATIONS_DIR, node_id);
    attestor.save_attestation(&attestation, &attestation_path)?;

    println!("Attestation created and saved to {}", attestation_path);
    println!("Encrypted {} values", attestation.values.len());

    Ok(())
}

/// Execute the SP1 program with attestations
fn execute_program(args: &Args) -> Result<()> {
    let operation = parse_operation(args.operation.as_deref().ok_or_else(|| anyhow!("Operation is required"))?)?;
    
    let att_file1 = args.att_file1.as_ref().ok_or_else(|| anyhow!("First attestation file is required"))?;
    let att_file2 = args.att_file2.as_ref().ok_or_else(|| anyhow!("Second attestation file is required"))?;

    println!("Executing SP1 program with operation: {:?}", operation);
    println!("Attestation files: {} and {}", att_file1.display(), att_file2.display());

    // Load public key
    let public_key = KeyGeneration::load_public_key(PUBLIC_KEY_PATH)?;
    
    // Load attestations
    let attestor = AttestorNode::new(0, public_key.clone());
    let attestation1 = attestor.load_attestation(att_file1.to_str().unwrap())?;
    let attestation2 = attestor.load_attestation(att_file2.to_str().unwrap())?;

    // Convert to program attestation format
    let program_attestations = convert_to_program_attestations(&[attestation1, attestation2])?;
    
    // Convert public key to program format
    let program_key = convert_to_program_encryption_key(&public_key)?;

    // Create operation step
    let op_step = OperationStep {
        operation,
        operands: vec![0, 1], // Use the first two attestations
        scalar: None,
    };

    // Create rule
    let rule = Rule {
        rule_id: args.rule_id.clone(),
        steps: vec![op_step],
    };

    // Setup prover client
    let client = ProverClient::from_env();

    // Prepare stdin
    let mut stdin = SP1Stdin::new();
    stdin.write(&rule);
    stdin.write(&program_attestations);
    stdin.write(&program_key);

    println!("Executing program with rule ID: {}", rule.rule_id);
    println!("Number of attestations: {}", program_attestations.len());

    // Hard-code the ELF path - update this to your actual path
    let elf_path = "./target/riscv32im-succinct-zkvm-elf/release/fibonacci-program";
    
    // Execute the program
    let result = client.execute_elf(elf_path, &stdin).run();
    let (output, report) = match result {
        Ok(result) => result,
        Err(err) => {
            return Err(anyhow!("Program execution failed: {}", err));
        }
    };

    println!("Program executed successfully.");

    // Read the rule ID from output (first committed value)
    if let Some(rule_id_bytes) = output.public.get(0) {
        let rule_id = String::from_utf8(rule_id_bytes.clone())
            .expect("Failed to parse rule ID");
        println!("Verified rule ID: {}", rule_id);
        assert_eq!(
            rule_id, args.rule_id,
            "Rule ID in output doesn't match expected rule ID"
        );
    } else {
        println!("Warning: No rule ID found in output");
    }

    // Read the result from output (second committed value)
    let result_bytes = match output.public.get(1) {
        Some(bytes) => bytes.clone(),
        None => {
            println!("Warning: No result found in output");
            Vec::new()
        }
    };
    
    println!("Result size: {} bytes", result_bytes.len());

    // Save the result to a file
    let result_path = PathBuf::from("result.bin");
    fs::write(&result_path, &result_bytes).expect("Failed to write result file");
    println!("Result saved to {}", result_path.display());

    // Try to decrypt the result if possible
    println!("\nAttempting to decrypt the result...");
    decrypt_result(&result_bytes)?;

    // Record the number of cycles executed
    println!("Number of cycles: {}", report.total_instruction_count());

    Ok(())
}

/// Prove the execution of the SP1 program
fn prove_execution(args: &Args) -> Result<()> {
    let operation = parse_operation(args.operation.as_deref().ok_or_else(|| anyhow!("Operation is required"))?)?;
    
    let att_file1 = args.att_file1.as_ref().ok_or_else(|| anyhow!("First attestation file is required"))?;
    let att_file2 = args.att_file2.as_ref().ok_or_else(|| anyhow!("Second attestation file is required"))?;

    println!("Proving SP1 program execution with operation: {:?}", operation);
    println!("Attestation files: {} and {}", att_file1.display(), att_file2.display());

    // Load public key
    let public_key = KeyGeneration::load_public_key(PUBLIC_KEY_PATH)?;
    
    // Load attestations
    let attestor = AttestorNode::new(0, public_key.clone());
    let attestation1 = attestor.load_attestation(att_file1.to_str().unwrap())?;
    let attestation2 = attestor.load_attestation(att_file2.to_str().unwrap())?;

    // Convert to program attestation format
    let program_attestations = convert_to_program_attestations(&[attestation1, attestation2])?;
    
    // Convert public key to program format
    let program_key = convert_to_program_encryption_key(&public_key)?;

    // Create operation step
    let op_step = OperationStep {
        operation,
        operands: vec![0, 1], // Use the first two attestations
        scalar: None,
    };

    // Create rule
    let rule = Rule {
        rule_id: args.rule_id.clone(),
        steps: vec![op_step],
    };

    // Setup prover client
    let client = ProverClient::from_env();

    // Prepare stdin
    let mut stdin = SP1Stdin::new();
    stdin.write(&rule);
    stdin.write(&program_attestations);
    stdin.write(&program_key);

    println!("Proving program execution with rule ID: {}", rule.rule_id);

    // Hard-code the ELF path - update this to your actual path
    let elf_path = "./target/riscv32im-succinct-zkvm-elf/release/fibonacci-program";
    
    // Setup the program for proving
    println!("Setting up for proving...");
    let (pk, vk) = client.setup_from_elf(elf_path);

    // Generate the proof
    println!("Generating proof...");
    let proof = client
        .prove(&pk, &stdin)
        .run()
        .expect("Failed to generate proof");

    println!("Successfully generated proof!");

    // Verify the proof
    println!("Verifying proof...");
    client.verify(&proof, &vk).expect("Failed to verify proof");
    println!("Successfully verified proof!");

    // Save proof and verification key
    let proof_path = PathBuf::from("proof.bin");
    fs::write(&proof_path, bincode::serialize(&proof)?).expect("Failed to write proof file");
    println!("Proof saved to {}", proof_path.display());

    let vk_path = PathBuf::from("verification_key.bin");
    fs::write(&vk_path, bincode::serialize(&vk)?).expect("Failed to write verification key file");
    println!("Verification key saved to {}", vk_path.display());

    Ok(())
}

/// Parse operation from string
fn parse_operation(op_str: &str) -> Result<Operation> {
    match op_str.to_lowercase().as_str() {
        "add" => Ok(Operation::Add),
        "multiply" | "mul" => Ok(Operation::Multiply),
        "scalarmultiply" | "scalar" => Ok(Operation::ScalarMultiply),
        "greaterthan" | "greater" | "gt" => Ok(Operation::GreaterThan),
        "lessthan" | "less" | "lt" => Ok(Operation::LessThan),
        "equal" | "eq" => Ok(Operation::Equal),
        _ => Err(anyhow!("Unknown operation: {}", op_str)),
    }
}

/// Convert our attestations to the program's attestation format
fn convert_to_program_attestations(attestations: &[Attestation]) -> Result<Vec<fibonacci_lib::Attestation>> {
    let mut program_attestations = Vec::new();

    for (i, attestation) in attestations.iter().enumerate() {
        if attestation.values.is_empty() {
            return Err(anyhow!("Attestation {} has no values", i));
        }

        // Use the first encrypted value
        let encrypted_value = attestation.values[0].value.to_bytes();

        program_attestations.push(fibonacci_lib::Attestation {
            attestor_id: format!("attestor{}", i + 1),
            encrypted_value,
        });
    }

    Ok(program_attestations)
}

/// Convert our public key to the program's encryption key format
fn convert_to_program_encryption_key(public_key: &PublicKey) -> Result<ProgramEncryptionKey> {
    let n_bytes = public_key.n.to_bytes();
    let nn_bytes = public_key.nn.to_bytes();

    Ok(ProgramEncryptionKey {
        n: n_bytes,
        nn: nn_bytes,
    })
}

/// Attempt to decrypt the result
fn decrypt_result(result_bytes: &[u8]) -> Result<()> {
    // Load the private key
    if !Path::new(PRIVATE_KEY_PATH).exists() {
        println!("Private key not found at {}. Cannot decrypt result.", PRIVATE_KEY_PATH);
        return Ok(());
    }

    let private_key = KeyGeneration::load_private_key(PRIVATE_KEY_PATH)?;
    
    // Try to deserialize the result as a ciphertext
    let ciphertext = Ciphertext::from_bytes(result_bytes);
    
    // Decrypt the result
    let decrypted = SimpleHomomorphic::decrypt(&private_key, &ciphertext);
    
    println!("Decrypted result: {}", decrypted);
    
    // For comparison operations, interpret the result
    println!("Interpretation: {}", 
        if decrypted == 1 { "TRUE" } 
        else if decrypted == 0 { "FALSE" } 
        else { "NUMERIC VALUE" });

    Ok(())
}