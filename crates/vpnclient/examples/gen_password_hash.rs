//! Generate SoftEther password hash from username and password
//! Run: cargo run --example gen_password_hash -- <username> <password>

use mayaqua::crypto::softether_password_hash;
use base64::Engine;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 3 {
        eprintln!("Usage: {} <username> <password>", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!("  cargo run --example gen_password_hash -- myuser mypassword");
        std::process::exit(1);
    }
    
    let username = &args[1];
    let password = &args[2];
    
    // Generate hash using SoftEther method: SHA-0(password + UPPER(username))
    let hash = softether_password_hash(password, username);
    
    // Encode to base64
    let hash_b64 = base64::engine::general_purpose::STANDARD.encode(&hash);
    
    println!("✓ Password hash generated successfully");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Username: {}", username);
    println!("Password Hash (base64):");
    println!("{}", hash_b64);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("Add this to your test_config.json:");
    println!("  \"username\": \"{}\",", username);
    println!("  \"password_hash\": \"{}\"", hash_b64);
    println!();
    println!("Or test with:");
    println!("  cargo run -- --config test_config.json");
}
