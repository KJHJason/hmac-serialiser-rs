mod algorithm;
mod errors;
mod hkdf;

use algorithm::{Algorithm, HkdfAlgorithm};
use base64::{engine::general_purpose, Engine as _};
use errors::Errors;
use ring::hmac;
use serde::{Deserialize, Serialize};

const DELIM: char = '.';

pub enum Encoder {
    Standard,
    UrlSafe,
    StandardNoPadding,
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

pub trait Data {
    fn get_exp(&self) -> Option<chrono::DateTime<chrono::Utc>>;
}

pub struct KeyInfo {
    // Main secret key
    pub key: Vec<u8>,

    // Salt for the key expansion
    pub salt: Vec<u8>,

    // Application specific info (Optional)
    pub info: Vec<u8>,
}

pub struct HmacSigner {
    key: hmac::Key,
    encoder: general_purpose::GeneralPurpose,
}

impl HmacSigner {
    pub fn new(key_info: KeyInfo, algo: Algorithm, encoder: Encoder) -> Self {
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

pub trait SignerLogic {
    fn unsign<T: for<'de> Deserialize<'de> + Data>(&self, token: &str) -> Result<T, Errors>;
    fn sign<T: Serialize + Data>(&self, data: &T) -> Result<String, Errors>;
}

impl SignerLogic for HmacSigner {
    fn unsign<T: for<'de> Deserialize<'de> + Data>(&self, token: &str) -> Result<T, Errors> {
        let parts: Vec<&str> = token.split(DELIM).collect();
        if parts.len() != 2 {
            return Err(Errors::InvalidInput);
        }

        let encoded_data = parts[0];
        if encoded_data.is_empty() {
            return Err(Errors::InvalidToken);
        }

        let signature = match self.encoder.decode(parts[1]) {
            Ok(signature) => signature,
            Err(_) => return Err(Errors::InvalidSignature),
        };

        let encoded_data = parts[0].as_bytes();
        if encoded_data.is_empty() {
            return Err(Errors::InvalidToken);
        }
        if !self.verify(&encoded_data, &signature) {
            return Err(Errors::InvalidToken);
        }

        // at this pt, the token is valid and hence we can safely unwrap
        let decoded_data = self.encoder.decode(encoded_data).unwrap();
        let data = String::from_utf8(decoded_data).unwrap();
        let deserialised_data: T = serde_json::from_str(&data).unwrap();
        if let Some(expiry) = deserialised_data.get_exp() {
            if expiry < chrono::Utc::now() {
                return Err(Errors::TokenExpired);
            }
        }
        Ok(deserialised_data)
    }

    fn sign<T: Serialize + Data>(&self, data: &T) -> Result<String, Errors> {
        let token = match serde_json::to_string(data) {
            Ok(token) => token,
            Err(_) => return Err(Errors::FailedToSignToken),
        };
        let token = general_purpose::URL_SAFE.encode(token.as_bytes());
        let signature = self.sign_data(token.as_bytes());
        let signature = general_purpose::URL_SAFE.encode(&signature);
        Ok(format!("{}{}{}", token, DELIM, signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[derive(Serialize, Deserialize, Debug)]
    struct TestClaim {
        #[serde(with = "chrono::serde::ts_seconds_option")]
        exp: Option<chrono::DateTime<Utc>>,
        data: String,
    }

    impl Data for TestClaim {
        fn get_exp(&self) -> Option<chrono::DateTime<Utc>> {
            self.exp
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
            exp: Some(Utc::now() + Duration::hours(1)),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim).unwrap();
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
        let token: Result<TestClaim, Errors> = signer.unsign(&data);
        assert!(matches!(token, Err(Errors::InvalidInput)));
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
            exp: Some(Utc::now() + Duration::hours(1)),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim).unwrap();
        let valid_signature = token.split('.').collect::<Vec<&str>>()[1];
        let invalid_token = format!("{}.{}", "bad_data", valid_signature);
        println!("Invalid token: {}", invalid_token);
        println!("Valid token: {}", token);

        let result: Result<TestClaim, Errors> = signer.unsign(&invalid_token);
        assert!(matches!(result, Err(Errors::InvalidToken)));
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
            exp: Some(Utc::now() - Duration::hours(1)),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim).unwrap();
        let result: Result<TestClaim, Errors> = signer.unsign(&token);

        assert!(matches!(result, Err(Errors::TokenExpired)));
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
            exp: Some(Utc::now() + Duration::hours(1)),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim).unwrap();
        let mut invalid_token = token.clone();
        invalid_token.push_str("invalid");

        let result: Result<TestClaim, Errors> = signer.unsign(&invalid_token);

        assert!(matches!(result, Err(Errors::InvalidSignature)));
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

        let result: Result<TestClaim, Errors> = signer.unsign(malformed_token);

        assert!(matches!(result, Err(Errors::InvalidSignature)));
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
            exp: Some(Utc::now() + Duration::hours(1)),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim).unwrap();
        let parts: Vec<&str> = token.split(DELIM).collect();
        let invalid_token = format!("{}.{}", parts[0], "invalid_base64");

        let result: Result<TestClaim, Errors> = signer.unsign(&invalid_token);

        assert!(matches!(result, Err(Errors::InvalidSignature)));
    }
}
