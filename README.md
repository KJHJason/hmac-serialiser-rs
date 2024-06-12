# hmac-serialiser-rs

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

HMAC Serialisers to cryptographically sign data like Python's ItsDangerous library but in rust.

This is mainly for developers who wants a shorter signed data compared to JSON Web Tokens (JWT) where the data might be too long for their use case.

This HMAC Serialiser is inspired by Python's ItsDangerous library and produces an output structure of `<payload>.<signature>` unlike JWT where it produces `<header>.<payload>.<signature>`.

Last but not least, the underlying HMAC and HKDF implementation is from the [ring](https://crates.io/crates/ring) crate.

## Sample Usage

```rust
use hmac_serialiser_rs::{HmacSigner, KeyInfo, Data, Encoder, algorithm::Algorithm};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct TestData {
    #[serde(with = "chrono::serde::ts_seconds_option")]
    exp: Option<DateTime<Utc>>,
    data: String,
}

impl Data for TestData {
    fn get_exp(&self) -> Option<chrono::DateTime<Utc>> {
        self.exp
    }
}

fn main() {
    // KeyInfo will expand your key to the required length based on the algorithm. Hence, the unwrap().
    let signer = HmacSigner::new(
        KeyInfo { b"secret-key".to_vec(), b"salt".to_vec(), b"app-context".to_vec() },
        Algorithm::SHA256,
        Encoder::UrlSafe,
    );
    let data = TestData {
        exp: Some(Utc::now() + Duration::hours(1)),
        data: "Hello World".to_string(),
    };

    // Error handling is usually for serde 
    // related errors when serialising the data.
    // Hence, it is usually safe to use unwrap().
    let signed_data = signer.sign(&data).unwrap();
    println!("Signed Data: {}", signed_data);

    // Note: You could also do `let data: Type = ...`
    let verified_data = match signer.unsign::<TestData>(&signed_data) {
        Ok(data) => data,
        Err(e) => {
            println!("Invalid token: {:?}", e);
            return;
        }
    };
    println!("Verified Data: {:?}", verified_data);
}
```
