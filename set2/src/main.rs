use itertools::concat;
use openssl::base64;
use openssl::rand::rand_bytes;
use openssl::symm::{encrypt, Cipher, Crypter, Mode};
use rand::{random, Rng};
use std::fs::File;
use std::io::{self, prelude::*, BufReader};

static AES_128_KEY: &str = "YELLOW SUBMARINE";

static CHALLENGE_12_STRING: &str = "\
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK";

fn main() -> io::Result<()> {
    println!("{:?}", challenge_12());
    // match challenge_10() {
    //     Ok(s) => println!("{}", s),
    //     Err(err) => println!("Error: {:?}", err),
    // }
    Ok(())
}

fn challenge_10() -> io::Result<String> {
    let file = File::open("10.txt")?;
    let reader = BufReader::new(file);

    let mut enc_bytes: Vec<u8> = vec![0; 16];
    let mut data = concat(
        reader
            .lines()
            .map(|l| base64::decode_block(&l.unwrap()).unwrap()),
    );
    enc_bytes.append(&mut data);
    let key = AES_128_KEY.as_bytes();
    let dec_bytes = decrypt_aes_128_cbc(&enc_bytes, &key);
    let dec_str = String::from_utf8(dec_bytes).expect("invalid bytes");
    Ok(dec_str)
}

fn challenge_12() -> Vec<u8> {
    let block_len = 16;

    let mut decrypted: Vec<u8> = vec![];
    let mut input_bytes = vec![0; block_len];

    for _ in 0..CHALLENGE_12_STRING.len() {
        let cipher_blocks: Vec<Vec<u8>> = (0..=255)
            .map(|b| {
                input_bytes[block_len - 1] = b;
                let mut cipher = encryption_oracle_ecb(&input_bytes);
                cipher.truncate(block_len);
                return cipher;
            })
            .collect();
        let plaintext = input_bytes[0..block_len - 1].to_vec();
        let ciphertext = encryption_oracle_ecb(&plaintext);
        let decrypted_byte = (0..=255)
            .filter(|&b| ciphertext[0..block_len].iter().eq(cipher_blocks[b].iter()))
            .next()
            .unwrap();

        decrypted.push(decrypted_byte as u8);
        input_bytes.remove(0);
        input_bytes.push(decrypted_byte as u8);
        println!("decrypted {}", decrypted_byte);
    }
    decrypted
}

fn detect_ecb(bytes: &Vec<u8>) -> bool {
    for offset in 0..16 {
        if bytes[offset..offset + 16]
            .iter()
            .eq(bytes[offset + 16..offset + 32].iter())
        {
            return true;
        }
    }
    false
}

// challenge 11 oracle
fn encryption_oracle_1(bytes: &Vec<u8>) -> Vec<u8> {
    let pfx_len = rand::thread_rng().gen_range(5..=10);
    let mut padded = vec![0; pfx_len];
    let _ = rand_bytes(&mut padded);
    let sfx_len = rand::thread_rng().gen_range(5..=10);
    let mut suffix = vec![0; sfx_len];
    let _ = rand_bytes(&mut suffix);

    padded.extend(bytes.iter());
    padded.append(&mut suffix);

    let mut key = [0; 16];
    let _ = rand_bytes(&mut key).unwrap();
    if random::<bool>() {
        let mut iv = [0; 16];
        let _ = rand_bytes(&mut iv).unwrap();
        encrypt_aes_128_cbc(&padded, &key, &iv)
    } else {
        encrypt(Cipher::aes_128_ecb(), &key, None, &padded).unwrap()
    }
}

// challenge 12 oracle
fn encryption_oracle_ecb(bytes: &Vec<u8>) -> Vec<u8> {
    let suffix = base64::decode_block(CHALLENGE_12_STRING).unwrap();
    let plaintext: Vec<u8> = bytes.iter().cloned().chain(suffix.into_iter()).collect();
    let key = AES_128_KEY.as_bytes();
    encrypt(Cipher::aes_128_ecb(), &key, None, &plaintext).unwrap()
}

fn encrypt_aes_128_cbc(bytes: &Vec<u8>, key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert!(bytes.len() != 0);
    assert_eq!(0, bytes.len() % 16);
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
    encrypter.pad(false);

    // init vector
    let mut encrypted = vec![0; bytes.len() + 16];
    encrypted[0..16].copy_from_slice(iv);

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
    let key = AES_128_KEY.as_bytes();

    let iv = &[0; 16];
    let enc_data = encrypt_aes_128_cbc(&data, key, iv);
    assert_eq!(data.len() + 16, enc_data.len());

    let dec_data = decrypt_aes_128_cbc(&enc_data, &key);
    let dec_string = String::from_utf8(dec_data).expect("invalid bytes");
    assert_eq!(data_str, dec_string);
}

// #[test]
// test_oracle() {
//     let data_str = "ABCDEFGHIJKLMNOPabcdefghijklmnop";
//     let data = data_str.as_bytes().to_vec();
// }
