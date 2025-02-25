mod attestor;
mod coordinator;
mod types;

use std::fs;

use anyhow::Result;
use attestor::AttestorNode;
use coordinator::AttestationCoordinator;
use tfhe::{
    prelude::{ FheDecrypt, FheOrd },
    safe_serialization::safe_deserialize,
    set_server_key,
    ClientKey,
};

use types::{ AttestationValue, AttestorError };

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create directories if they don't exist
    fs::create_dir_all("./keys")?;
    fs::create_dir_all("./attestations")?;

    println!("==== Part 1: Generating Keys ====");

    // Generate and save keys
    let coordinator = AttestationCoordinator::generate_and_save_all_keys(
        "./keys/exchange_client.key",
        "./keys/exchange_server.key",
        "./keys/exchange_public.key"
    )?;

    println!("\n==== Part 2: Creating Attestation ====");

    println!("\n==== 2: Creating Attestation  Nodes====");
    // Create an attestor node from the coordinator's public key
    let attestor0 = AttestorNode::new_from_file(0, "./keys/exchange_public.key")?;
    let attestor1 = AttestorNode::new_from_file(1, "./keys/exchange_public.key")?;
    let attestor2 = AttestorNode::new_from_file(2, "./keys/exchange_public.key")?;

    // Create sample attestation values
    let values = vec![
        AttestationValue {
            value_type: "reserves".to_string(),
            value: 1_000_000, // 1 million units
            timestamp: std::time::SystemTime
                ::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            metadata: r#"{"asset":"USDC","source":"exchange_hot_wallet"}"#.to_string(),
        },
        AttestationValue {
            value_type: "liabilities".to_string(),
            value: 800_000, // 800,000 units
            timestamp: std::time::SystemTime
                ::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            metadata: r#"{"asset":"USDC","source":"exchange_db"}"#.to_string(),
        }
    ];

    // Create the attestation
    let attestation0 = attestor0.create_attestation_from_values(&values)?;
    let attestation1 = attestor1.create_attestation_from_values(&values)?;
    let attestation2 = attestor2.create_attestation_from_values(&values)?;

    // Save the attestation
    attestor0.save_attestation(&attestation0, "./attestations/exchange_attestation0.bin")?;
    attestor1.save_attestation(&attestation1, "./attestations/exchange_attestation1.bin")?;
    attestor2.save_attestation(&attestation2, "./attestations/exchange_attestation2.bin")?;

    println!("\n==== Part 3: Loading Keys and Attestation ====");
    let loaded_attestation0 = attestor0.load_attestation(
        "./attestations/exchange_attestation0.bin"
    )?;
    let loaded_attestation1 = attestor1.load_attestation(
        "./attestations/exchange_attestation1.bin"
    )?;
    let loaded_attestation2 = attestor2.load_attestation(
        "./attestations/exchange_attestation2.bin"
    )?;

    println!("\n==== Part 4: Performing Homomorphic Operations ====");
    set_server_key(coordinator.server_key);

    // Load the client key for decryption
    let client_key_data = fs
        ::read("./keys/exchange_client.key")
        .map_err(|e|
            AttestorError::KeyLoadError(format!("Failed to read public key file: {}", e))
        )?;

    // Maximum allowed size for deserialization (1GB)
    let max_size = 1 << 40;

    let client_key: ClientKey = safe_deserialize(&*client_key_data, max_size).map_err(|e|
        AttestorError::KeyLoadError(format!("Failed to deserialize public key: {}", e))
    )?;

    // Make sure we have at least 2 values in each attestation (reserves and liabilities)
    if
        loaded_attestation0.values.len() >= 2 &&
        loaded_attestation1.values.len() >= 2 &&
        loaded_attestation2.values.len() >= 2
    {
        // Extract reserves and liabilities from each attestation
        let reserves0 = &loaded_attestation0.values[0];
        let liabilities0 = &loaded_attestation0.values[1];

        let reserves1 = &loaded_attestation1.values[0];
        let liabilities1 = &loaded_attestation1.values[1];

        let reserves2 = &loaded_attestation2.values[0];
        let liabilities2 = &loaded_attestation2.values[1];

        println!("Performing homomorphic operations on encrypted values...");

        // 1. Sum of all reserves across attestors
        let total_reserves = reserves0.clone() + reserves1.clone() + reserves2.clone();
        println!("Homomorphic sum of all reserves computed");

        // 2. Sum of all liabilities across attestors
        let total_liabilities = liabilities0.clone() + liabilities1.clone() + liabilities2.clone();
        println!("Homomorphic sum of all liabilities computed");

        // 3. Check if total reserves > total liabilities (solvency check)
        let solvency_check = &total_reserves.gt(&total_liabilities);
        println!("Homomorphic comparison (reserves > liabilities) computed");

        // 4. Calculate surplus/deficit
        let surplus_deficit = &total_reserves - &total_liabilities;
        println!("Homomorphic calculation of surplus/deficit computed");

        let decrypted_total_reserves: u64 = total_reserves.decrypt(&client_key);
        let decrypted_total_liabilities: u64 = total_liabilities.decrypt(&client_key);
        let decrypted_solvency_check: bool = solvency_check.decrypt(&client_key);
        let decrypted_surplus_deficit: u64 = surplus_deficit.decrypt(&client_key);

        println!("\nDecrypted Results:");
        println!("Total Reserves: {}", decrypted_total_reserves);
        println!("Total Liabilities: {}", decrypted_total_liabilities);
        println!("Solvency Check (Reserves > Liabilities): {}", decrypted_solvency_check);
        println!("Surplus/Deficit: {}", decrypted_surplus_deficit);
        // Printout all the computed
        // Now decrypt the results using the client key to demonstrate correctness
        println!("\nDecrypted Results:");

        // Additional example: Homomorphic multiplication
    } else {
        println!("Error: Attestations don't have enough values for homomorphic operations");
    }

    println!("\n==== Part 4: Demonstrating Encryption Results ====");

    // For demonstration only - decrypt to show the values were properly encrypted
    // For demonstration only - decrypt to show the values were properly encrypted
    if loaded_attestation0.values.len() >= 2 {
        println!("Attestation 0 Decrypted Values:");
        let reserves0: u32 = loaded_attestation0.values[0].decrypt(&client_key);
        let liabilities0: u32 = loaded_attestation0.values[1].decrypt(&client_key);
        println!("  Reserves: {}", reserves0);
        println!("  Liabilities: {}", liabilities0);

        println!("\nAttestation 1 Decrypted Values:");
        let reserves1: u32 = loaded_attestation1.values[0].decrypt(&client_key);
        let liabilities1: u32 = loaded_attestation1.values[1].decrypt(&client_key);
        println!("  Reserves: {}", reserves1);
        println!("  Liabilities: {}", liabilities1);

        println!("\nAttestation 2 Decrypted Values:");
        let reserves2: u32 = loaded_attestation2.values[0].decrypt(&client_key);
        let liabilities2: u32 = loaded_attestation2.values[1].decrypt(&client_key);
        println!("  Reserves: {}", reserves2);
        println!("  Liabilities: {}", liabilities2);
    }

    // Load the attestation

    println!("\nAll operations completed successfully!");
    println!("Keys are stored in the ./keys directory");
    println!("Attestations are stored in the ./attestations directory");

    Ok(())
}
