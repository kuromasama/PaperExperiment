extern crate recrypt;
extern crate serde_json;
extern crate serde;
use recrypt::api::*;
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::{Write, Read};
use std::path::Path;

//[derive(Serialize, Deserialize)]
struct KeyPair {
    sk: PrivateKey,
    pk_x: PublicKey,
    pk_y: PublicKey,
}

pub fn keygen(username: &str) -> std::io::Result<()> {
    let recrypt = Recrypt::new();
    let plaintext = Plaintext::new([42u8; 384]);
    let signing_keypair = recrypt.generate_ed25519_key_pair();
    let (private_key, public_key) = recrypt.generate_key_pair().unwrap();

    let key_pair = KeyPair {
        sk: private_key.clone(),
        pk_x: public_key.clone(),
        pk_y: recrypt.transform_key(private_key, public_key, plaintext, signing_keypair).unwrap(),
    };

    let serialized = serde_json::to_string(&key_pair).unwrap();

    File::create(format!("{}_sk.json", username))?.write_all(serialized.as_bytes())?;

    Ok(())
}

pub fn read_keys(username: &str) -> std::io::Result<KeyPair> {
    let mut file = File::open(format!("{}_sk.json", username))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let deserialized: KeyPair = serde_json::from_str(&contents).unwrap();
    Ok(deserialized)
}
