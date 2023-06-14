use aes::Aes128;
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::Pkcs7;
use recrypt::api::Plaintext;

// Create an alias for ECB mode with PKCS7 padding
type Aes128Ecb = Ecb<Aes128, Pkcs7>;

fn main() {
    // Initialize a plaintext key, you should replace this with your actual key
    let plaintext = Plaintext::new([0; 384]);

    // We only use the first 16 bytes of the Plaintext as the AES key
    let key = &plaintext.bytes[0..16];

    // This is the message we want to encrypt
    let message = b"hello world";

    // Create a new block cipher with our key
    let cipher = Aes128Ecb::new_var(key, Default::default()).unwrap();

    // Encrypt our message
    let cipher_text = cipher.encrypt_vec(message);

    println!("Encrypted: {:?}", cipher_text);
}
