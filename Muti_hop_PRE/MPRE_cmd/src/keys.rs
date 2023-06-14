// keys.rs

use std::fs::File;
use std::io::prelude::*;
use std::io::{self, BufReader};
use serde_json::Value;
use recrypt::api::*;


pub fn write_key_to_file(filename: &str, key: &str) -> io::Result<()> {
    let mut file = File::create(filename)?;
    file.write_all(key.as_bytes())?;
    Ok(())
}

pub fn read_key_from_file(filename: &str) -> io::Result<String> {
    let file = File::open(filename)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents)?;
    Ok(contents)
}

pub fn save_key_pair(name: &str, priv_key: &PrivateKey, pub_key: &PublicKey, sig_key: &SigningKeypair) -> io::Result<()> {
    let priv_key_str_json = serde_json::to_string(priv_key.bytes()).unwrap();
    let pub_key_str_json_x = serde_json::to_string(&pub_key.bytes_x_y().0).unwrap();
    let pub_key_str_json_y = serde_json::to_string(&pub_key.bytes_x_y().1).unwrap();
    let sig_key_str_json = serde_json::to_string(&sig_key.bytes().to_vec()).unwrap();

    write_key_to_file(&format!("{}_sk.json", name), &priv_key_str_json)?;
    write_key_to_file(&format!("{}_pk_x.json", name), &pub_key_str_json_x)?;
    write_key_to_file(&format!("{}_pk_y.json", name), &pub_key_str_json_y)?;
    write_key_to_file(&format!("{}_sig.json", name), &sig_key_str_json)?;

    Ok(())

    
}
pub fn load_key_pair(name: &str) -> Result<(PrivateKey, PublicKey, SigningKeypair), RecryptErr> {
    let priv_key_str_json = read_key_from_file(&format!("{}_sk.json", name)).unwrap();
    let from_str_bytes: Vec<u8> = serde_json::from_str(&priv_key_str_json).unwrap();
    let priv_key = PrivateKey::new_from_slice(&from_str_bytes).unwrap();

    let pub_key_str_json_x = read_key_from_file(&format!("{}_pk_x.json", name)).unwrap();
    let pub_key_str_json_y = read_key_from_file(&format!("{}_pk_y.json", name)).unwrap();
    let from_str_bytes_x: Vec<u8> = serde_json::from_str(&pub_key_str_json_x).unwrap();
    let from_str_bytes_y: Vec<u8> = serde_json::from_str(&pub_key_str_json_y).unwrap();
    let pub_key = PublicKey::new_from_slice((&from_str_bytes_x, &from_str_bytes_y)).unwrap();

    let sig_key_str_json = read_key_from_file(&format!("{}_sig.json", name)).unwrap();
    let sig_key_bytes: Vec<u8> = serde_json::from_str(&sig_key_str_json).unwrap();
    let sig_key = match SigningKeypair::from_byte_slice(&sig_key_bytes) {
        Ok(keypair) => keypair,
        Err(_) => return Err(RecryptErr::InputWrongSize("Incorrect size for SigningKeypair", sig_key_bytes.len())),
    };
    Ok((priv_key, pub_key, sig_key))
}

pub fn store_plaintext(name: &str,  pt: &Plaintext) -> io::Result<()> {
    let pt_str_json = serde_json::to_string(&pt.bytes().to_vec()).unwrap();
    write_key_to_file(&format!("{}_k.json", name), &pt_str_json)?;
    Ok(())
}

pub fn load_plaintext(name: &str) -> Result<Plaintext, RecryptErr> {
    let pt_str_json = read_key_from_file(&format!("{}_k.json", name)).unwrap();
    let pt_bytes: Vec<u8> = serde_json::from_str(&pt_str_json).unwrap();
    let pt = match Plaintext::new_from_slice(&pt_bytes) {
        Ok(plaintext) => plaintext,
        Err(_) => return Err(RecryptErr::InputWrongSize("Incorrect size for Plaintext", pt_bytes.len())),
    };
    Ok(pt)
}

// pub fn save_encrypted_once_value(name: &str, value: &EncryptedValue) -> io::Result<()> {
//     match value {
//         EncryptedValue::EncryptedOnceValue(eov) => {
//             let eph_pub_key_str_json_x = serde_json::to_string(&eov.ephemeral_public_key.bytes_x_y().0).unwrap();
//             let eph_pub_key_str_json_y = serde_json::to_string(&eov.ephemeral_public_key.bytes_x_y().1).unwrap();
//             let encrypted_message_str_json = serde_json::to_string(&eov.encrypted_message.bytes().to_vec()).unwrap();
//             let auth_hash_str_json = serde_json::to_string(&eov.auth_hash.bytes().to_vec()).unwrap();
//             let pub_signing_key_str_json = serde_json::to_string(&eov.public_signing_key.bytes().to_vec()).unwrap();
//             let signature_str_json = serde_json::to_string(&eov.signature.bytes().to_vec()).unwrap();

//             write_key_to_file(&format!("{}_ephemeral_pub_key_x.json", name), &eph_pub_key_str_json_x)?;
//             write_key_to_file(&format!("{}_ephemeral_pub_key_y.json", name), &eph_pub_key_str_json_y)?;
//             write_key_to_file(&format!("{}_encrypted_message.json", name), &encrypted_message_str_json)?;
//             write_key_to_file(&format!("{}_auth_hash.json", name), &auth_hash_str_json)?;
//             write_key_to_file(&format!("{}_public_signing_key.json", name), &pub_signing_key_str_json)?;
//             write_key_to_file(&format!("{}_signature.json", name), &signature_str_json)?;
//         },
//         EncryptedValue::TransformedValue(tv) => {
//             // handle TransformedValue here
//         },
//     }
    
//     Ok(())
// }
// pub fn load_encrypted_once_value(name: &str) -> Result<EncryptedValue, RecryptErr> {
//     let eph_pub_key_str_json_x = read_key_from_file(&format!("{}_ephemeral_pub_key_x.json", name)).unwrap();
//     let eph_pub_key_str_json_y = read_key_from_file(&format!("{}_ephemeral_pub_key_y.json", name)).unwrap();
//     let encrypted_message_str_json = read_key_from_file(&format!("{}_encrypted_message.json", name)).unwrap();
//     let auth_hash_str_json = read_key_from_file(&format!("{}_auth_hash.json", name)).unwrap();
//     let pub_signing_key_str_json = read_key_from_file(&format!("{}_public_signing_key.json", name)).unwrap();
//     let signature_str_json = read_key_from_file(&format!("{}_signature.json", name)).unwrap();

//     let eph_pub_key_bytes_x: Vec<u8> = serde_json::from_str(&eph_pub_key_str_json_x).unwrap();
//     let eph_pub_key_bytes_y: Vec<u8> = serde_json::from_str(&eph_pub_key_str_json_y).unwrap();
//     let encrypted_message_bytes: Vec<u8> = serde_json::from_str(&encrypted_message_str_json).unwrap();
//     let auth_hash_bytes: Vec<u8> = serde_json::from_str(&auth_hash_str_json).unwrap();
//     let pub_signing_key_bytes: Vec<u8> = serde_json::from_str(&pub_signing_key_str_json).unwrap();
//     let signature_bytes: Vec<u8> = serde_json::from_str(&signature_str_json).unwrap();

//     let eph_pub_key = recrypt::api::PublicKey::new_from_slice((&eph_pub_key_bytes_x, &eph_pub_key_bytes_y)).unwrap();
//     let encrypted_message = recrypt::api::EncryptedMessage::new_from_slice(&encrypted_message_bytes).unwrap();
//     let auth_hash = recrypt::api::AuthHash::new_from_slice(&auth_hash_bytes).unwrap();
//     let pub_signing_key = recrypt::api::PublicSigningKey::new_from_slice(&pub_signing_key_bytes).unwrap();
//     let signature = recrypt::api::Signature::new_from_slice(&signature_bytes).unwrap();

//     let eov = EncryptedOnceValue {
//         ephemeral_public_key: eph_pub_key,
//         encrypted_message,
//         auth_hash,
//         public_signing_key: pub_signing_key,
//         signature,
//     };

//     Ok(EncryptedValue::EncryptedOnceValue(eov))
// }

// // pub fn save_encrypted_once_value(name: &str, value: &EncryptedOnceValue) -> io::Result<()> {
// //     let eph_pub_key_str_json_x = serde_json::to_string(&value.ephemeral_public_key.bytes_x_y().0).unwrap();
// //     let eph_pub_key_str_json_y = serde_json::to_string(&value.ephemeral_public_key.bytes_x_y().1).unwrap();
// //     let encrypted_message_str_json = serde_json::to_string(&value.encrypted_message.bytes().to_vec()).unwrap();
// //     let auth_hash_str_json = serde_json::to_string(&value.auth_hash.bytes().to_vec()).unwrap();
// //     let pub_signing_key_str_json = serde_json::to_string(&value.public_signing_key.bytes().to_vec()).unwrap();
// //     let signature_str_json = serde_json::to_string(&value.signature.bytes().to_vec()).unwrap();

// //     write_key_to_file(&format!("{}_ephemeral_pub_key_x.json", name), &eph_pub_key_str_json_x)?;
// //     write_key_to_file(&format!("{}_ephemeral_pub_key_y.json", name), &eph_pub_key_str_json_y)?;
// //     write_key_to_file(&format!("{}_encrypted_message.json", name), &encrypted_message_str_json)?;
// //     write_key_to_file(&format!("{}_auth_hash.json", name), &auth_hash_str_json)?;
// //     write_key_to_file(&format!("{}_public_signing_key.json", name), &pub_signing_key_str_json)?;
// //     write_key_to_file(&format!("{}_signature.json", name), &signature_str_json)?;

// //     Ok(())
// // }

// // pub fn load_encrypted_once_value(name: &str) -> Result<recrypt::api::EncryptedValue, RecryptErr> {
// //     let eph_pub_key_str_json_x = read_key_from_file(&format!("{}_ephemeral_pub_key_x.json", name)).unwrap();
// //     let eph_pub_key_str_json_y = read_key_from_file(&format!("{}_ephemeral_pub_key_y.json", name)).unwrap();
// //     let encrypted_message_str_json = read_key_from_file(&format!("{}_encrypted_message.json", name)).unwrap();
// //     let auth_hash_str_json = read_key_from_file(&format!("{}_auth_hash.json", name)).unwrap();
// //     let pub_signing_key_str_json = read_key_from_file(&format!("{}_public_signing_key.json", name)).unwrap();
// //     let signature_str_json = read_key_from_file(&format!("{}_signature.json", name)).unwrap();

// //     let from_str_bytes_x: Vec<u8> = serde_json::from_str(&eph_pub_key_str_json_x).unwrap();
// //     let from_str_bytes_y: Vec<u8> = serde_json::from_str(&eph_pub_key_str_json_y).unwrap();
// //     let encrypted_message_bytes: Vec<u8> = serde_json::from_str(&encrypted_message_str_json).unwrap();
// //     let auth_hash_bytes: Vec<u8> = serde_json::from_str(&auth_hash_str_json).unwrap();
// //     let pub_signing_key_bytes: Vec<u8> = serde_json::from_str(&pub_signing_key_str_json).unwrap();
// //     let signature_bytes: Vec<u8> = serde_json::from_str(&signature_str_json).unwrap();

// //     let eph_pub_key = PublicKey::new_from_slice((&from_str_bytes_x, &from_str_bytes_y)).unwrap();
// //     let encrypted_message = EncryptedMessage::new_from_slice(&encrypted_message_bytes).unwrap();
// //     let auth_hash = AuthHash::new_from_slice(&auth_hash_bytes).unwrap();
// //     let pub_signing_key = PublicSigningKey::new_from_slice(&pub_signing_key_bytes).unwrap();
// //     let signature = Ed25519Signature::new_from_slice(&signature_bytes).unwrap();

// //     Ok(EncryptedOnceValue {
// //         ephemeral_public_key: eph_pub_key,
// //         encrypted_message: encrypted_message,
// //         auth_hash: auth_hash,
// //         public_signing_key: pub_signing_key,
// //         signature: signature,
// //     })

// //}





