use recrypt::api::*;
use recrypt::prelude::*;

// create a new recrypt
let mut recrypt = Recrypt::new();

// generate a plaintext to encrypt
let pt = recrypt.gen_plaintext();

// generate a public/private keypair and some signing keys
let (priv_key, pub_key) = recrypt.generate_key_pair().unwrap();
let signing_keypair = recrypt.generate_ed25519_key_pair();

// encrypt!
let encrypted_val = recrypt.encrypt(&pt, &pub_key, &signing_keypair).unwrap();

// decrypt!
let decrypted_val = recrypt.decrypt(encrypted_val, &priv_key).unwrap();

// plaintext recovered.
assert_eq!(pt, decrypted_val)