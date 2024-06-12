//! # HMAC Signer
//!
//! `hmac_serialiser_rs` is a Rust library for generating and verifying HMAC signatures for secure data transmission.
//! It uses the `ring` crate for HMAC operations and `serde` for serialising and deserialising data.
//! Moreover, it uses the `base64` crate for encoding and decoding data.
//!
//! ## License
//!
//! This library is licensed under the MIT license.
//!
//! ## Features
//!
//! - Supports various encoding schemes for signatures.
//! - Flexible HMAC signer logic for custom data types.
//! - Provides a convenient interface for signing and verifying data.
//!
//! ## Example
//!
//! ```rust
//! use hmac_serialiser_rs::{Encoder, HmacSigner, KeyInfo, SignerLogic, Algorithm};
//! use serde::{Serialize, Deserialize};
//! use std::error::Error;
//!
//! #[derive(Serialize, Deserialize, Debug)]
//! struct UserData {
//!     // Add your data fields here
//!     username: String,
//!     email: String,
//! }
//!
//! impl hmac_serialiser_rs::Data for UserData {
//!     fn get_exp(&self) -> Option<chrono::DateTime<chrono::Utc>> {
//!         // Add logic to retrieve expiration time if needed
//!         None
//!     }
//! }
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     // Define your secret key, salt, and optional info
//!     let key_info = KeyInfo {
//!         key: b"your_secret_key".to_vec(),
//!         salt: b"your_salt".to_vec(),
//!         info: vec![], // empty info
//!     };
//!
//!     // Initialize the HMAC signer
//!     let signer = HmacSigner::new(key_info, Algorithm::SHA256, Encoder::UrlSafe);
//!
//!     // Serialize your data
//!     let user_data = UserData {
//!         username: "user123".to_string(),
//!         email: "user123@example.com".to_string(),
//!     };
//!     let token = signer.sign(&user_data);
//!     println!("Token: {}", token);
//!
//!     // Verify the token
//!     let verified_data: UserData = signer.unsign(&token)?;
//!     println!("Verified data: {:?}", verified_data);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Supported Encoders
//!
//! - `Standard`: Standard base64 encoding.
//! - `UrlSafe`: URL-safe base64 encoding.
//! - `StandardNoPadding`: Standard base64 encoding without padding.
//! - `UrlSafeNoPadding`: URL-safe base64 encoding without padding.
//!
//! ## Supported HMAC Algorithms
//!
//! - `SHA1`
//! - `SHA256`
//! - `SHA384`
//! - `SHA512`
//!
//! ## Traits
//!
//! - `Data`: A trait for data structures that can be signed and verified.
//! - `SignerLogic`: A trait for defining signer logic.
//!
//! ## Errors
//!
//! Errors are represented by the `Error` enum, which includes:
//!
//! - `InvalidInput`: Invalid input data.
//! - `InvalidSignature`: Invalid signature provided.
//! - `InvalidToken`: Invalid token provided.
//! - `HkdfExpandError`: Error during key expansion.
//! - `HkdfFillError`: Error during key filling.
//! - `TokenExpired`: Token has expired.
//!
//! ## Contributing
//!
//! Contributions are welcome! Feel free to open issues and pull requests on [GitHub](https://github.com/KJHJason/hmac-serialiser-rs).
//!
//! ```

pub mod algorithm;
pub mod errors;
mod hkdf;

use algorithm::{Algorithm, HkdfAlgorithm};
use base64::{engine::general_purpose, Engine as _};
use errors::Error;
use ring::hmac;
use serde::{Deserialize, Serialize};

const DELIM: char = '.';

/// An enum for defining the encoding scheme for the payload and the signature.
#[derive(Debug, Clone)]
pub enum Encoder {
    // Standard base64 encoding
    Standard,
    // URL-safe base64 encoding
    UrlSafe,
    // Standard base64 encoding without padding
    StandardNoPadding,
    // URL-safe base64 encoding without padding
    UrlSafeNoPadding,
}

impl Encoder {
    fn get_encoder(&self) -> general_purpose::GeneralPurpose {
        match self {
            Encoder::Standard => general_purpose::STANDARD,
            Encoder::UrlSafe => general_purpose::URL_SAFE,
            Encoder::StandardNoPadding => general_purpose::STANDARD_NO_PAD,
            Encoder::UrlSafeNoPadding => general_purpose::URL_SAFE_NO_PAD,
        }
    }
}

/// A trait for custom data types that can be signed and verified.
///
/// This trait defines methods for retrieving expiration time and is used in conjunction with
/// signing and verifying operations.
///
/// If your data type does not require an expiration time, you can implement the trait as follows:
/// ```rust
/// use hmac_serialiser_rs::Data;
/// use chrono::{DateTime, Utc};
///
/// struct CustomData {
///    data: String,
/// }
///
/// impl Data for CustomData {
///    fn get_exp(&self) -> Option<DateTime<Utc>> {
///       None
///   }
/// }
///```
pub trait Data {
    fn get_exp(&self) -> Option<chrono::DateTime<chrono::Utc>>;
}

/// A struct that holds the key information required for key expansion.
///
/// The key expansion process is used to derive a new key from the main secret key. Its main purpose is to expand
/// the key to the HMAC algorithm's block size to avoid padding which can reduce the effort required for a brute force attack.
///
/// The `KeyInfo` struct contains the main secret key, salt for key expansion, and optional application-specific info.
/// - `key` field is the main secret key used for signing and verifying data.
/// - `salt` field is used for key expansion.
/// - `info` field is optional and can be used to provide application-specific information.
///
/// The `salt` and the `info` fields can help to prevent key reuse and provide additional security.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    // Main secret key
    pub key: Vec<u8>,

    // Salt for the key expansion (Optional)
    pub salt: Vec<u8>,

    // Application specific info (Optional)
    pub info: Vec<u8>,
}

/// A struct that holds the HMAC signer logic.
///
/// The `HmacSigner` struct is used for signing and verifying data using HMAC signatures.
#[derive(Debug, Clone)]
pub struct HmacSigner {
    key: hmac::Key,
    encoder: general_purpose::GeneralPurpose,
}

impl HmacSigner {
    pub fn new(key_info: KeyInfo, algo: Algorithm, encoder: Encoder) -> Self {
        if key_info.key.is_empty() {
            panic!("Key cannot be empty"); // panic if key is empty as it is usually due to developer error
        }

        let hkdf_algo = HkdfAlgorithm::from_hmac(&algo);
        let hkdf = hkdf::HkdfWrapper::new(&key_info.salt, hkdf_algo);
        let expanded_key = hkdf
            .expand(&key_info.key, &key_info.info)
            .expect("Failed to expand key");

        Self {
            key: hmac::Key::new(algo.to_hmac(), &expanded_key),
            encoder: encoder.get_encoder(),
        }
    }
    fn sign_data(&self, data: &[u8]) -> Vec<u8> {
        hmac::sign(&self.key, data).as_ref().to_vec()
    }
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        hmac::verify(&self.key, data, signature).is_ok()
    }
}

/// A trait for defining the signer logic.
pub trait SignerLogic {
    fn unsign<T: for<'de> Deserialize<'de> + Data>(&self, token: &str) -> Result<T, Error>;
    fn sign<T: Serialize + Data>(&self, data: &T) -> String;
}

impl SignerLogic for HmacSigner {
    /// Verifies the token and returns the deserialised data.
    ///
    /// Before verifying the payload, the input token is split into two parts: the encoded payload and the signature.
    /// If the token does not contain two parts, an `InvalidInput` error is returned.
    ///
    /// Afterwards, if the encoded payload is empty, an `InvalidToken` error is returned even if the signature is valid.
    ///
    /// The signature is then decoded using the provided encoder. If the decoding fails, an `InvalidSignature` error is returned.
    ///
    /// The encoded payload and the signature are then verified via HMAC. If the verification fails, an `InvalidToken` error is returned.
    ///
    /// If the encoded payload is valid, the payload is decoded and deserialised using serde.
    /// If the payload's expiration time is not provided, the deserialized data is returned.
    /// Otherwise, the expiration time is checked against the current time. If the expiration time is earlier than the current time, a `TokenExpired` error is returned.
    ///
    /// Sample Usage:
    /// ```rust
    /// use hmac_serialiser_rs::{HmacSigner, KeyInfo, Encoder, algorithm::Algorithm, errors::Error, SignerLogic, Data};
    /// use serde::{Serialize, Deserialize};
    ///
    /// #[derive(Serialize, Deserialize, Debug)]
    /// struct UserData {
    ///     username: String,
    /// }
    /// impl Data for UserData {
    ///    fn get_exp(&self) -> Option<chrono::DateTime<chrono::Utc>> {
    ///         None
    ///     }
    /// }
    ///
    /// let key_info = KeyInfo {
    ///    key: b"your_secret_key".to_vec(),
    ///    salt: b"your_salt".to_vec(),
    ///    info: vec![], // empty info
    /// };
    ///
    /// // Initialize the HMAC signer
    /// let signer = HmacSigner::new(key_info, Algorithm::SHA256, Encoder::UrlSafe);
    /// let result: Result<UserData, Error> = signer.unsign(&"token.signature");
    /// // or
    /// let result = signer.unsign::<UserData>(&"token.signature");
    /// ```
    fn unsign<T: for<'de> Deserialize<'de> + Data>(&self, token: &str) -> Result<T, Error> {
        let parts: Vec<&str> = token.split(DELIM).collect();
        if parts.len() != 2 {
            return Err(Error::InvalidInput);
        }

        let encoded_data = parts[0];
        if encoded_data.is_empty() {
            return Err(Error::InvalidToken);
        }

        let signature = match self.encoder.decode(parts[1]) {
            Ok(signature) => signature,
            Err(_) => return Err(Error::InvalidSignature),
        };

        let encoded_data = parts[0].as_bytes();
        if !self.verify(&encoded_data, &signature) {
            return Err(Error::InvalidToken);
        }

        // at this pt, the token is valid and hence we can safely unwrap
        let decoded_data = self.encoder.decode(encoded_data).unwrap();
        let data = String::from_utf8(decoded_data).unwrap();
        let deserialised_data: T = serde_json::from_str(&data).unwrap();
        if let Some(expiry) = deserialised_data.get_exp() {
            if expiry < chrono::Utc::now() {
                return Err(Error::TokenExpired);
            }
        }
        Ok(deserialised_data)
    }

    /// Signs the data and returns the token which can be sent to the client.
    ///
    /// Sample Usage:
    /// ```rust
    /// use hmac_serialiser_rs::{HmacSigner, KeyInfo, Encoder, algorithm::Algorithm, errors::Error, SignerLogic, Data};
    /// use serde::{Serialize, Deserialize};
    ///
    /// #[derive(Serialize, Deserialize, Debug)]
    /// struct UserData {
    ///     username: String,
    /// }
    /// impl Data for UserData {
    ///    fn get_exp(&self) -> Option<chrono::DateTime<chrono::Utc>> {
    ///         None
    ///     }
    /// }
    ///
    /// let key_info = KeyInfo {
    ///    key: b"your_secret_key".to_vec(),
    ///    salt: b"your_salt".to_vec(),
    ///    info: b"auth-context".to_vec(),
    /// };
    ///
    /// // Initialize the HMAC signer
    /// let signer = HmacSigner::new(key_info, Algorithm::SHA256, Encoder::UrlSafe);
    /// let user = UserData { username: "user123".to_string() };
    /// let result: String = signer.sign(&user);
    /// ```
    fn sign<T: Serialize + Data>(&self, data: &T) -> String {
        let token = serde_json::to_string(data).unwrap();
        let token = self.encoder.encode(token.as_bytes());
        let signature = self.sign_data(token.as_bytes());
        let signature = self.encoder.encode(&signature);
        format!("{}{}{}", token, DELIM, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[derive(Serialize, Deserialize, Debug)]
    struct TestClaim {
        #[serde(with = "chrono::serde::ts_seconds")]
        exp: chrono::DateTime<Utc>,
        data: String,
    }

    impl Data for TestClaim {
        fn get_exp(&self) -> Option<chrono::DateTime<Utc>> {
            Some(self.exp)
        }
    }

    fn setup(salt: Vec<u8>, info: Vec<u8>, algo: Algorithm, encoder: Encoder) -> HmacSigner {
        let key_info = KeyInfo {
            key: b"test_secret_key".to_vec(),
            salt,
            info,
        };
        HmacSigner::new(key_info, algo, encoder)
    }

    #[test]
    fn test_sign_and_unsign_valid_token() {
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );
        let claim = TestClaim {
            exp: Utc::now() + Duration::hours(1),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim);
        let verified_claim: TestClaim = signer.unsign(&token).unwrap();
        println!("Token: {}", token);
        println!("Verified claim: {:?}", verified_claim);
        assert_eq!(verified_claim.data, claim.data);
    }

    #[test]
    fn test_invalid_token() {
        let data = "tttttttttttttttttttttttttttttttttttttttttt";
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );
        let token: Result<TestClaim, Error> = signer.unsign(&data);
        assert!(matches!(token, Err(Error::InvalidInput)));
    }

    #[test]
    fn test_invalid_token_with_valid_signature() {
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );
        let claim = TestClaim {
            exp: Utc::now() + Duration::hours(1),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim);
        let valid_signature = token.split('.').collect::<Vec<&str>>()[1];
        let invalid_token = format!("{}.{}", "bad_data", valid_signature);
        println!("Invalid token: {}", invalid_token);
        println!("Valid token: {}", token);

        let result: Result<TestClaim, Error> = signer.unsign(&invalid_token);
        assert!(matches!(result, Err(Error::InvalidToken)));
    }

    #[test]
    fn test_unsign_expired_token() {
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );
        let claim = TestClaim {
            exp: Utc::now() - Duration::hours(1),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim);
        let result: Result<TestClaim, Error> = signer.unsign(&token);

        assert!(matches!(result, Err(Error::TokenExpired)));
    }

    #[test]
    fn test_unsign_invalid_signature() {
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );
        let claim = TestClaim {
            exp: Utc::now() + Duration::hours(1),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim);
        let mut invalid_token = token.clone();
        invalid_token.push_str("invalid");

        let result: Result<TestClaim, Error> = signer.unsign(&invalid_token);

        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_unsign_malformed_token() {
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );

        let malformed_token = "malformed.token";

        let result: Result<TestClaim, Error> = signer.unsign(malformed_token);

        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_unsign_invalid_base64_signature() {
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );
        let claim = TestClaim {
            exp: Utc::now() + Duration::hours(1),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim);
        let parts: Vec<&str> = token.split(DELIM).collect();
        let invalid_token = format!("{}.{}", parts[0], "invalid_base64");

        let result: Result<TestClaim, Error> = signer.unsign(&invalid_token);

        assert!(matches!(result, Err(Error::InvalidSignature)));
    }
}
