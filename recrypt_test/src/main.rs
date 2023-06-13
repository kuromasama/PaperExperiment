//mod serialize;
extern crate recrypt;
extern crate aes;
extern crate block_modes;
use recrypt::prelude::*;
use recrypt::api::*;
use aes::Aes128;
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::Pkcs7;

// Create an alias for ECB mode with PKCS7 padding
type Aes128Ecb = Ecb<Aes128, Pkcs7>;

fn main() {
    // create a new recrypt
    let recrypt = Recrypt::new();

    // generate a plaintext to encrypt
    let pt = recrypt.gen_plaintext();

    // We only use the first 16 bytes of the Plaintext as the AES key
    let key = &pt.bytes()[0..16];

    // This is the message we want to encrypt
    let message = b"hello world";
    
    // Create a new block cipher with our key
    let cipher = Aes128Ecb::new_from_slices(key, &[]).unwrap();

    // Encrypt our message
    let cipher_text = cipher.encrypt_vec(message);

    println!("Encrypted: {:?}", cipher_text);

    // generate a public/private keypair and some signing keys
    let (alice_sk, alice_pk) = recrypt.generate_key_pair().unwrap();
    let alice_signing_keypair = recrypt.generate_ed25519_key_pair();
    // serialize::keygen("alice").unwrap();
    // let (alice_sk, alice_pk) = serialize::read_keys("alice").unwrap();
    // let alice_signing_keypair = serialize::read_keys("alice").generate_ed25519_key_pair();
    let (bob_sk, bob_pk) = recrypt.generate_key_pair().unwrap();
    let bob_signing_keypair = recrypt.generate_ed25519_key_pair();

    // encrypt!
    let encrypted_val = recrypt.encrypt(&pt, &alice_pk, &alice_signing_keypair).unwrap();
    // println!("{:?}", encrypted_val);

    // encrypt2!
    let encrypted_val_pre = recrypt.encrypt(&pt, &alice_pk, &alice_signing_keypair).unwrap();
    // println!("{:?}", encrypted_val_pre);    

    // decrypt!
    let decrypted_val = recrypt.decrypt(encrypted_val, &alice_sk).unwrap();
    println!("{:?}", decrypted_val);

    // plaintext recovered.
    assert_eq!(pt, decrypted_val);

    // rk keygen!
    let alice_to_bob_transform_key = recrypt.generate_transform_key(
        &alice_sk,
        &bob_pk,
        &alice_signing_keypair).unwrap();

    println!("rk_alice_bob: {:?}", alice_to_bob_transform_key);   

    // Transform the plaintext to be alice to the bob!
    // The data is _not_ decrypted here. Simply transformed!
    let transformed_val = recrypt.transform(
        encrypted_val_pre,
        alice_to_bob_transform_key,
        &alice_signing_keypair).unwrap();

    // decrypt the transformed value with the target private key and recover the plaintext
    let decrypted_val_pre = recrypt.decrypt(transformed_val, &bob_sk).unwrap();

    // plaintext recovered.
    assert_eq!(pt, decrypted_val_pre);

    // plaintext recovered.
    assert_eq!(decrypted_val_pre, decrypted_val);

    let keyde = &decrypted_val_pre.bytes()[0..16];
    // Create a new block cipher with our keyde
    let cipher = Aes128Ecb::new_from_slices(keyde, &[]).unwrap();

    // Decrypt our message
    let decrypted_text = cipher.decrypt_vec(&cipher_text).unwrap();

    println!("Decrypted: {:?}", decrypted_text);   
    // Decrypt our message

    let decrypted_string = String::from_utf8(decrypted_text).unwrap();

    println!("Decrypted: {:?}", decrypted_string);   
}
