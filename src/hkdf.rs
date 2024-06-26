use crate::algorithm::{Algorithm, HashAlgorithm, HkdfAlgorithm};
use crate::errors::Error;
use ring::hkdf::{Prk, Salt};

pub struct HkdfWrapper {
    salt: Salt,
    algo: HkdfAlgorithm,
}

impl HkdfWrapper {
    pub fn new(salt: &[u8], algo: HkdfAlgorithm) -> Self {
        Self {
            salt: Salt::new(algo.to_hkdf(), salt),
            algo,
        }
    }

    #[inline]
    pub fn extract(&self, ikm: &[u8]) -> Prk {
        self.salt.extract(ikm)
    }

    #[inline]
    pub fn get_okm_len(&self) -> usize {
        self.algo.output_length()
    }

    pub fn expand(&self, ikm: &[u8], info: &[u8]) -> Result<Vec<u8>, Error> {
        let algo = &self.algo;
        let prk = self.extract(ikm);

        let mut okm = vec![0u8; self.get_okm_len()];
        let okm_slice = &mut okm[..];
        prk.expand(&[info], Algorithm::from_hkdf(algo).to_hmac())
            .map_err(|_| Error::HkdfExpandError)?
            .fill(okm_slice)
            .map_err(|_| Error::HkdfFillError)?;
        Ok(okm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::HkdfAlgorithm;
    use ring::rand::SecureRandom;

    macro_rules! none {
        () => {
            b""
        };
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn get_random_bytes(len: usize) -> Vec<u8> {
        let rng = ring::rand::SystemRandom::new();
        let mut bytes = vec![0u8; len];
        rng.fill(&mut bytes)
            .expect("Failed to generate random bytes");
        bytes
    }

    #[test]
    fn test_empty_key_hkdf_expand() {
        let salt = none!();
        let ikm = b"";
        let info = none!();
        let hkdf = HkdfWrapper::new(salt, HkdfAlgorithm::SHA1);
        let okm = hkdf.expand(ikm, info).unwrap();

        println!("sha1 okm: {}", bytes_to_hex(&okm));
        assert_eq!(okm.len(), hkdf.get_okm_len());
    }

    #[test]
    fn test_hdkf_expand_with_salt() {
        let salt = get_random_bytes(32);
        let ikm = b"";
        let info = none!();
        let hkdf = HkdfWrapper::new(&salt, HkdfAlgorithm::SHA256);
        let okm = hkdf.expand(ikm, info).unwrap();

        println!("sha256 okm: {}", bytes_to_hex(&okm));
        assert_eq!(okm.len(), hkdf.get_okm_len());
    }

    #[test]
    fn test_hdkf_expand_with_ikm() {
        let salt = none!();
        let ikm = b"kjhjason";
        let info = none!();
        let hkdf = HkdfWrapper::new(salt, HkdfAlgorithm::SHA384);
        let okm = hkdf.expand(ikm.as_ref(), info).unwrap();

        println!("sha384 okm: {}", bytes_to_hex(&okm));
        assert_eq!(okm.len(), hkdf.get_okm_len());
    }

    #[test]
    fn test_hdkf_expand_with_info() {
        let salt = none!();
        let ikm = b"";
        let info = b"kjhjason";
        let hkdf = HkdfWrapper::new(salt, HkdfAlgorithm::SHA512);
        let okm = hkdf.expand(ikm, info).unwrap();

        println!("sha512 okm: {}", bytes_to_hex(&okm));
        assert_eq!(okm.len(), hkdf.get_okm_len());
    }

    #[test]
    fn test_hdkf_expand_with_all() {
        let salt = b"kjhjason.com";
        let ikm = b"jason";
        let info = b"kjhjason";
        let hkdf = HkdfWrapper::new(salt, HkdfAlgorithm::SHA256);
        let okm = hkdf.expand(ikm, info).unwrap();

        println!("sha256 okm: {}", bytes_to_hex(&okm));
        assert_eq!(okm.len(), hkdf.get_okm_len());
    }
}
