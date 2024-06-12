# hmac-serialiser-rs

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

HMAC Serialisers to cryptographically sign data like Python's ItsDangerous library but in rust.

This is mainly for developers who wants a shorter signed data compared to JSON Web Tokens (JWT) where the data might be too long for their use case.

This HMAC Serialiser is inspired by Python's ItsDangerous library and produces an output structure of `<payload>.<signature>` unlike JWT where it produces `<header>.<payload>.<signature>`.

Last but not least, the underlying HMAC and HKDF implementation is from the [ring](https://crates.io/crates/ring) crate while the data serialisation and deserialisation is from the [serde](https://crates.io/crates/serde) crate.

The signed data is then encoded or decoded using the [base64](https://crates.io/crates/base64) crate.

## Sample Usage

```rust
use hmac_serialiser_rs::{HmacSigner, KeyInfo, Data, Encoder, algorithm::Algorithm};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct TestData {
    #[serde(with = "chrono::serde::ts_seconds")]
    exp: DateTime<Utc>,
    data: String,
}

impl Data for TestData {
    fn get_exp(&self) -> Option<chrono::DateTime<Utc>> {
        Some(self.exp)
    }
}

fn main() {
    // KeyInfo will expand your key to the required length based on the algorithm. Hence, the unwrap().
    let signer = HmacSigner::new(
        KeyInfo { 
            b"secret-key".to_vec(), 
            b"salt".to_vec(), 
            b"app-context".to_vec(), // Note: You can use vec![] for optional parameters. 
        },
        Algorithm::SHA256,
        Encoder::UrlSafe,
    );
    let data = TestData {
        exp: Utc::now() + Duration::hours(1),
        data: "Hello World".to_string(),
    };

    let signed_data = signer.sign(&data);;
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
