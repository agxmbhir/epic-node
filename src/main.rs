#[cfg(feature = "server")]
use anyhow::Result;
#[cfg(feature = "server")]
use epic_node::attestor::{AttestorNode, KeyGeneration};
#[cfg(feature = "server")]
use epic_node::homomorphic::{SimpleHomomorphic, PublicKey, PrivateKey, sp1_helpers};
#[cfg(feature = "server")]
use epic_node::types::{AttestationValue, Attestation};
#[cfg(feature = "server")]
use std::path::Path;
#[cfg(feature = "server")]
use std::fs;

#[cfg(feature = "server")]
fn main() -> Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: {} <command> [args...]", args[0]);
        println!("Commands:");
        println!("  generate-keys <key_size> <output_dir>");
        println!("  create-attestation <node_id> <pubkey_path> <values_file> <output_path>");
        println!("  decrypt <privkey_path> <attestation_path>");
        return Ok(());
    }
    
    match args[1].as_str() {
        "generate-keys" => {
            if args.len() < 4 {
                println!("Usage: {} generate-keys <key_size> <output_dir>", args[0]);
                return Ok(());
            }
            
            let key_size = args[2].parse::<usize>().unwrap_or(1024);
            let output_dir = &args[3];
            
            generate_keys(key_size, output_dir)?;
        },
        "create-attestation" => {
            if args.len() < 6 {
                println!("Usage: {} create-attestation <node_id> <pubkey_path> <values_file> <output_path>", args[0]);
                return Ok(());
            }
            
            let node_id = args[2].parse::<u64>().unwrap_or(0);
            let pubkey_path = &args[3];
            let values_file = &args[4];
            let output_path = &args[5];
            
            create_attestation(node_id, pubkey_path, values_file, output_path)?;
        },
        "decrypt" => {
            if args.len() < 4 {
                println!("Usage: {} decrypt <privkey_path> <attestation_path>", args[0]);
                return Ok(());
            }
            
            let privkey_path = &args[2];
            let attestation_path = &args[3];
            
            decrypt_attestation(privkey_path, attestation_path)?;
        },
        _ => {
            println!("Unknown command: {}", args[1]);
            println!("Usage: {} <command> [args...]", args[0]);
            println!("Commands:");
            println!("  generate-keys <key_size> <output_dir>");
            println!("  create-attestation <node_id> <pubkey_path> <values_file> <output_path>");
            println!("  decrypt <privkey_path> <attestation_path>");
        }
    }
    
    Ok(())
}

#[cfg(not(feature = "server"))]
fn main() {
    println!("Server feature is disabled. Please rebuild with the 'server' feature enabled.");
}

#[cfg(feature = "server")]
// Generate public and private keys for homomorphic encryption
fn generate_keys(key_size: usize, output_dir: &str) -> Result<()> {
    println!("Generating {} bit keys...", key_size);
    
    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir)?;
    
    // Generate a deterministic seed
    let seed = b"epic-node-deterministic-seed";
    
    // Generate the key pair
    let (public_key, private_key) = KeyGeneration::generate_key_pair(key_size, seed);
    
    // Save keys to files
    let public_key_path = Path::new(output_dir).join("public.key");
    let private_key_path = Path::new(output_dir).join("private.key");
    
    KeyGeneration::save_public_key(&public_key, public_key_path.to_str().unwrap())?;
    KeyGeneration::save_private_key(&private_key, private_key_path.to_str().unwrap())?;
    
    println!("Keys generated and saved to:");
    println!("  Public key: {}", public_key_path.display());
    println!("  Private key: {}", private_key_path.display());
    
    Ok(())
}

#[cfg(feature = "server")]
// Create an attestation from values in a file
fn create_attestation(node_id: u64, pubkey_path: &str, values_file: &str, output_path: &str) -> Result<()> {
    println!("Creating attestation for node {}...", node_id);
    
    // Load the public key
    let public_key = KeyGeneration::load_public_key(pubkey_path)?;
    
    // Create an attestor node
    let attestor = AttestorNode::new(node_id, public_key);
    
    // Read values from file
    let values_str = fs::read_to_string(values_file)?;
    let values: Vec<u64> = values_str
        .lines()
        .filter_map(|line| line.trim().parse::<u64>().ok())
        .collect();
    
    if values.is_empty() {
        println!("No valid values found in file: {}", values_file);
        return Ok(());
    }
    
    println!("Read {} values from {}", values.len(), values_file);
    
    // Create attestation
    let attestation = attestor.create_attestation(&values)?;
    
    // Save attestation to file
    attestor.save_attestation(&attestation, output_path)?;
    
    println!("Attestation created and saved to: {}", output_path);
    
    Ok(())
}

#[cfg(feature = "server")]
// Decrypt an attestation using a private key
fn decrypt_attestation(privkey_path: &str, attestation_path: &str) -> Result<()> {
    println!("Decrypting attestation...");
    
    // Load the private key
    let private_key = KeyGeneration::load_private_key(privkey_path)?;
    
    // Load the attestation
    let attestation_data = fs::read(attestation_path)?;
    let attestation: Attestation = bincode::deserialize(&attestation_data)?;
    
    println!("Attestation loaded with {} values", attestation.values.len());
    
    // Decrypt each value
    println!("Decrypted values:");
    for (i, encrypted_value) in attestation.values.iter().enumerate() {
        // Convert to our Ciphertext type
        let ciphertext = epic_node::homomorphic::Ciphertext {
            value: encrypted_value.value.clone(),
        };
        
        // Decrypt the value
        let decrypted = SimpleHomomorphic::decrypt(&private_key, &ciphertext);
        
        println!("  Value {}: {}", i, decrypted);
    }
    
    Ok(())
}