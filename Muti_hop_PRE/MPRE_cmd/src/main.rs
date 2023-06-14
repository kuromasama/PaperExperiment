// main.rs
extern crate recrypt;
extern crate aes;
extern crate block_modes;
mod keys;

use std::env;
use recrypt::prelude::*;
use keys::*;
use recrypt::api::EncryptedValue;


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: cargo run <command> <name>");
        std::process::exit(1);
    }
    let command = &args[1];
    let name = &args[2];

    let recrypt = Recrypt::new();

    match command.as_str() {
        "keygen" => {
            let (sk, pk) = recrypt.generate_key_pair().unwrap();
            let sig_k = recrypt.generate_ed25519_key_pair();
            save_key_pair(name, &sk, &pk, &sig_k).unwrap();
        },
        "file_keygen" => {
            let pt = recrypt.gen_plaintext();
            store_plaintext(name, &pt).unwrap();
        },
        // "encrypt" => {
        //     let pt = load_plaintext(name).unwrap();
        //     let (alice_sk, alice_pk, alice_signing_keypair) = load_key_pair(name).unwrap();
        //     let encrypted_val = recrypt.encrypt(&pt, &alice_pk, &alice_signing_keypair).unwrap();
                    
        //     // Check the type of the encrypted value
        //     match encrypted_val {
        //         EncryptedValue::EncryptedOnceValue(eov) => {
        //             // Save the EncryptedOnceValue
        //             save_encrypted_once_value(name, &eov).unwrap();
        //         },
        //         EncryptedValue::TransformedValue(tv) => {
        //             // Save the TransformedValue
        //             // You may need to implement a separate function for this
        //             //save_transformed_value(name, &tv).unwrap();
        //         },
        //     }
        // },
        _ => println!("Unknown command!"),
    }
}


