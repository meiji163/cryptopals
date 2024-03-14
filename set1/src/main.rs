use itertools::concat;
use openssl::base64;
use openssl::symm::{decrypt, Cipher};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};

fn main() -> io::Result<()> {
    match challenge_7() {
        Ok(decoded) => println!("{}", decoded),
        Err(err) => println!("Error: {:?}", err),
    };

    match challenge_8() {
        Ok(s) => println!("{}", s),
        Err(err) => println!("Error: {:?}", err),
    }
    Ok(())
}

fn challenge_7() -> io::Result<String> {
    let file = File::open("7.txt")?;
    let reader = BufReader::new(file);

    let data_bytes = concat(
        reader
            .lines()
            .map(|l| base64::decode_block(&l.unwrap()).unwrap()),
    );

    let cipher = Cipher::aes_128_ecb();
    let key_str = "YELLOW SUBMARINE";

    let decipher = decrypt(cipher, key_str.as_bytes(), None, &data_bytes)?;
    let decipher_str = String::from_utf8(decipher).expect("invalid bytes");

    Ok(decipher_str)
}

fn challenge_8() -> io::Result<String> {
    let file = File::open("8.txt")?;
    let reader = BufReader::new(file);
    let mut ecb_lines = reader
        .lines()
        .map(|l| l.unwrap())
        .filter(|l| is_ecb_mode(l));
    match ecb_lines.next() {
        Some(l) => Ok(l),
        None => Ok("".to_string()),
    }
}

// check for repeated block of 16 bytes
fn is_ecb_mode(hex_str: &String) -> bool {
    let mut set = HashSet::new();
    for i in (0..hex_str.len()).step_by(32) {
        let substr = hex_str[i..i + 32].to_string();
        if set.contains(&substr) {
            return true;
        } else {
            set.insert(substr);
        }
    }
    false
}
