use std::fs::File;
use std::io::{self, prelude::*, BufReader};
use itertools::concat;
use openssl::symm::{decrypt,Cipher};
use openssl::base64;

fn main() -> io::Result<()> {
    match challenge_7() {
        Ok(decoded) => println!("{}", decoded),
        Err(err) => println!("Error: {:?}", err),
    };
    Ok(())
}

fn challenge_7() -> io::Result<String> {
    let file = File::open("7.txt")?;
    let reader = BufReader::new(file);

    let data_bytes = concat(
        reader.lines().map(|l| {
        base64::decode_block(&l.unwrap()).unwrap()
    }));

    let cipher = Cipher::aes_128_ecb();
    let key_str = "YELLOW SUBMARINE";

    let decipher = decrypt(cipher, key_str.as_bytes(), None, &data_bytes)?;
    let decipher_str = String::from_utf8(decipher).expect("invalid bytes");

    Ok(decipher_str)
}
