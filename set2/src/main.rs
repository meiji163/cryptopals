use itertools::concat;
use openssl::base64;
use openssl::symm::{Cipher, Crypter, Mode};
use std::fs::File;
use std::io::{self, prelude::*, BufReader};

fn main() -> io::Result<()> {
    let file = File::open("10.txt")?;
    let reader = BufReader::new(file);

    let mut enc_bytes: Vec<u8> = vec![0; 16];
    let mut data = concat(
        reader
            .lines()
            .map(|l| base64::decode_block(&l.unwrap()).unwrap()),
    );
    enc_bytes.append(&mut data);

    let key = "YELLOW SUBMARINE".as_bytes();
    let dec_bytes = decrypt_aes_128_cbc(&enc_bytes, &key);
    let dec_str = String::from_utf8(dec_bytes).expect("invalid bytes");
    println!("{}", dec_str);

    Ok(())
}

fn encrypt_aes_128_cbc(bytes: &Vec<u8>, key: &[u8]) -> Vec<u8> {
    assert!(bytes.len() != 0);
    assert_eq!(0, bytes.len() % 16);
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
    encrypter.pad(false);

    // init vector = 00..0
    let mut encrypted = vec![0; bytes.len() + 16];
    let out_buf = &mut [0; 32];
    let block = &mut [0; 16];
    for i in (0..bytes.len()).step_by(16) {
        block.copy_from_slice(&bytes[i..i + 16]);
        for j in 0..16 {
            block[j] ^= encrypted[i + j];
        }
        let _ = encrypter.update(block, out_buf).unwrap();
        encrypted[i + 16..i + 32].copy_from_slice(&out_buf[0..16]);
    }
    encrypted
}

fn decrypt_aes_128_cbc(bytes: &Vec<u8>, key: &[u8]) -> Vec<u8> {
    assert!(bytes.len() != 0);
    assert_eq!(0, bytes.len() % 16);
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
    decrypter.pad(false);

    // bytes[0..16] is the init block
    let mut decrypted = vec![0; bytes.len() - 16];
    let out_buf = &mut [0; 32];
    let block = &mut [0; 16];
    for i in (16..bytes.len()).step_by(16) {
        block.copy_from_slice(&bytes[i..i + 16]);
        let _ = decrypter.update(block, out_buf).unwrap();
        for j in 0..16 {
            out_buf[j] ^= bytes[i - 16 + j];
        }
        decrypted[i - 16..i].copy_from_slice(&out_buf[0..16]);
    }
    decrypted
}

#[test]
fn test_cbc_inverse() {
    let data_str = "ABCDEFGHIJKLMNOPabcdefghijklmnop";
    let data = data_str.as_bytes().to_vec();
    let key = "YELLOW SUBMARINE".as_bytes();

    let enc_data = encrypt_aes_128_cbc(&data, key);
    assert_eq!(data.len() + 16, enc_data.len());

    let dec_data = decrypt_aes_128_cbc(&enc_data, &key);
    let dec_string = String::from_utf8(dec_data).expect("invalid bytes");
    assert_eq!(data_str, dec_string);
}
