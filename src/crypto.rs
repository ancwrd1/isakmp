use anyhow::{anyhow, Context};
use bytes::Bytes;
use openssl::{
    bn::BigNum,
    dh::Dh,
    hash::{Hasher, MessageDigest},
    pkey::{PKey, Private},
    rsa::Padding,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
    x509::X509,
};
use serde::{Deserialize, Serialize};

// RFC2409: Oakley group 2
const G2_P: &[u8] = &[
    255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98, 139, 128, 220, 28, 209,
    41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142, 52, 4, 221, 239, 149, 25,
    179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98,
    94, 126, 198, 244, 76, 66, 233, 166, 55, 237, 107, 11, 255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90, 137,
    159, 165, 174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236, 230, 83, 129, 255, 255, 255, 255, 255, 255,
    255, 255,
];

const G14_P: &[u8] = &[
    255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98, 139, 128, 220, 28, 209,
    41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142, 52, 4, 221, 239, 149, 25,
    179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98,
    94, 126, 198, 244, 76, 66, 233, 166, 55, 237, 107, 11, 255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90, 137,
    159, 165, 174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236, 228, 91, 61, 194, 0, 124, 184, 161, 99, 191, 5,
    152, 218, 72, 54, 28, 85, 211, 154, 105, 22, 63, 168, 253, 36, 207, 95, 131, 101, 93, 35, 220, 163, 173, 150, 28,
    98, 243, 86, 32, 133, 82, 187, 158, 213, 41, 7, 112, 150, 150, 109, 103, 12, 53, 78, 74, 188, 152, 4, 241, 116,
    108, 8, 202, 24, 33, 124, 50, 144, 94, 70, 46, 54, 206, 59, 227, 158, 119, 44, 24, 14, 134, 3, 155, 39, 131, 162,
    236, 7, 162, 143, 181, 197, 93, 240, 111, 76, 82, 201, 222, 43, 203, 246, 149, 88, 23, 24, 57, 149, 73, 124, 234,
    149, 106, 229, 21, 210, 38, 24, 152, 250, 5, 16, 21, 114, 142, 90, 138, 172, 170, 104, 255, 255, 255, 255, 255,
    255, 255, 255,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DigestType {
    Sha1,
    Sha256,
}

impl From<DigestType> for MessageDigest {
    fn from(value: DigestType) -> Self {
        match value {
            DigestType::Sha1 => MessageDigest::sha1(),
            DigestType::Sha256 => MessageDigest::sha256(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CipherType {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
}

impl TryFrom<usize> for CipherType {
    type Error = anyhow::Error;

    fn try_from(key_len: usize) -> Result<Self, Self::Error> {
        match key_len {
            16 => Ok(Self::Aes128Cbc),
            24 => Ok(Self::Aes192Cbc),
            32 => Ok(Self::Aes256Cbc),
            _ => Err(anyhow!("Unsupported key len: {}", key_len)),
        }
    }
}

impl From<CipherType> for Cipher {
    fn from(value: CipherType) -> Self {
        match value {
            CipherType::Aes128Cbc => Cipher::aes_128_cbc(),
            CipherType::Aes192Cbc => Cipher::aes_192_cbc(),
            CipherType::Aes256Cbc => Cipher::aes_256_cbc(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GroupType {
    Oakley2,
    Oakley14,
}

impl TryFrom<GroupType> for Dh<Private> {
    type Error = anyhow::Error;

    fn try_from(value: GroupType) -> Result<Self, Self::Error> {
        let g = match value {
            GroupType::Oakley2 => G2_P,
            GroupType::Oakley14 => G14_P,
        };
        let p = BigNum::from_slice(g)?;
        let dh2 = Dh::from_pqg(p, None, BigNum::from_u32(2)?)?.generate_key()?;
        Ok(dh2)
    }
}

pub struct Crypto {
    dh2: Dh<Private>,
    digest: MessageDigest,
    cipher: Cipher,
    digest_type: DigestType,
    cipher_type: CipherType,
    group_type: GroupType,
}

impl Crypto {
    pub fn with_parameters(digest: DigestType, cipher: CipherType, group: GroupType) -> anyhow::Result<Self> {
        Ok(Self {
            dh2: group.try_into()?,
            digest: digest.into(),
            cipher: cipher.into(),
            digest_type: digest,
            cipher_type: cipher,
            group_type: group,
        })
    }

    pub fn public_key(&self) -> Bytes {
        self.dh2.public_key().to_vec().into()
    }

    pub fn shared_secret(&self, public_key: &[u8]) -> anyhow::Result<Bytes> {
        let bn = BigNum::from_slice(public_key)?;
        Ok(self.dh2.compute_key(&bn)?.into())
    }

    pub fn prf<I, R>(&self, key: &[u8], data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<[u8]>,
    {
        let key = PKey::hmac(key)?;

        let mut signer = Signer::new(self.digest, &key)?;
        for d in data.into_iter() {
            signer.update(d.as_ref())?;
        }

        Ok(signer.sign_to_vec()?.into())
    }

    pub fn hash<I, R>(&self, data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<[u8]>,
    {
        let mut hasher = Hasher::new(self.digest)?;
        for d in data.into_iter() {
            hasher.update(d.as_ref())?;
        }
        Ok(hasher.finish()?.to_vec().into())
    }

    fn enc_dec(&self, mode: Mode, key: &[u8], data: &[u8], iv: &[u8]) -> anyhow::Result<Bytes> {
        let mut crypter = Crypter::new(self.cipher, mode, key, Some(iv))?;
        crypter.pad(false);
        let mut out = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut out)?;
        let rest = crypter.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        Ok(out.into())
    }

    pub fn encrypt(&self, key: &[u8], data: &[u8], iv: &[u8]) -> anyhow::Result<Bytes> {
        self.enc_dec(Mode::Encrypt, key, data, iv)
    }

    pub fn decrypt(&self, key: &[u8], data: &[u8], iv: &[u8]) -> anyhow::Result<Bytes> {
        self.enc_dec(Mode::Decrypt, key, data, iv)
    }

    pub fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    pub fn key_len(&self) -> usize {
        self.cipher.key_len()
    }

    pub fn hash_len(&self) -> usize {
        self.digest.size()
    }

    pub fn digest_type(&self) -> DigestType {
        self.digest_type
    }

    pub fn cipher_type(&self) -> CipherType {
        self.cipher_type
    }

    pub fn group_type(&self) -> GroupType {
        self.group_type
    }

    pub fn verify_signature(&self, hash: &[u8], signature: &[u8], cert: &[u8]) -> anyhow::Result<()> {
        let rsa = X509::from_der(cert)?.public_key()?.rsa()?;

        let mut buf = vec![0u8; rsa.size() as usize];

        let len = rsa.public_decrypt(signature, &mut buf, Padding::PKCS1)?;

        (&buf[..len] == hash)
            .then_some(())
            .context("Signature verification failed!")
    }
}
