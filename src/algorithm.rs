use ring::{hkdf, hmac};

#[derive(Default, Clone)]
pub enum Algorithm {
    SHA1,
    #[default]
    SHA256,
    SHA384,
    SHA512,
}

#[derive(Default, Clone)]
pub enum HkdfAlgorithm {
    SHA1,
    #[default]
    SHA256,
    SHA384,
    SHA512,
}

impl Algorithm {
    #[inline]
    pub fn to_hmac(&self) -> hmac::Algorithm {
        match self {
            Algorithm::SHA1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::SHA256 => hmac::HMAC_SHA256,
            Algorithm::SHA384 => hmac::HMAC_SHA384,
            Algorithm::SHA512 => hmac::HMAC_SHA512,
        }
    }
    #[inline]
    pub fn from_hkdf(algo: &HkdfAlgorithm) -> Self {
        match algo {
            HkdfAlgorithm::SHA1 => Algorithm::SHA1,
            HkdfAlgorithm::SHA256 => Algorithm::SHA256,
            HkdfAlgorithm::SHA384 => Algorithm::SHA384,
            HkdfAlgorithm::SHA512 => Algorithm::SHA512,
        }
    }
}

impl HkdfAlgorithm {
    #[inline]
    pub fn to_hkdf(&self) -> hkdf::Algorithm {
        match self {
            HkdfAlgorithm::SHA1 => hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
            HkdfAlgorithm::SHA256 => hkdf::HKDF_SHA256,
            HkdfAlgorithm::SHA384 => hkdf::HKDF_SHA384,
            HkdfAlgorithm::SHA512 => hkdf::HKDF_SHA512,
        }
    }
    #[inline]
    pub fn from_hmac(algo: &Algorithm) -> Self {
        match algo {
            Algorithm::SHA1 => HkdfAlgorithm::SHA1,
            Algorithm::SHA256 => HkdfAlgorithm::SHA256,
            Algorithm::SHA384 => HkdfAlgorithm::SHA384,
            Algorithm::SHA512 => HkdfAlgorithm::SHA512,
        }
    }
}

pub trait HashAlgorithm {
    fn output_length(&self) -> usize;
}

impl HashAlgorithm for Algorithm {
    #[inline]
    fn output_length(&self) -> usize {
        match self {
            Algorithm::SHA1 => 20,
            Algorithm::SHA256 => 32,
            Algorithm::SHA384 => 48,
            Algorithm::SHA512 => 64,
        }
    }
}

impl HashAlgorithm for HkdfAlgorithm {
    #[inline]
    fn output_length(&self) -> usize {
        match self {
            HkdfAlgorithm::SHA1 => 20,
            HkdfAlgorithm::SHA256 => 32,
            HkdfAlgorithm::SHA384 => 48,
            HkdfAlgorithm::SHA512 => 64,
        }
    }
}
