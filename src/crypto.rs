use bytes::Bytes;
use openssl::{
    bn::BigNum,
    dh::Dh,
    hash::{Hasher, MessageDigest},
    pkey::{PKey, Private},
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};

// RFC2409: Oakley group 2
const G2_P: &[u8] = &[
    255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98, 139,
    128, 220, 28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74,
    8, 121, 142, 52, 4, 221, 239, 149, 25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55,
    79, 225, 53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98, 94, 126, 198, 244, 76, 66, 233,
    166, 55, 237, 107, 11, 255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90, 137, 159, 165,
    174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236, 230, 83, 129, 255, 255, 255, 255,
    255, 255, 255, 255,
];

pub struct Crypto {
    dh2: Dh<Private>,
}

impl Crypto {
    pub fn new() -> anyhow::Result<Self> {
        let p = BigNum::from_slice(G2_P)?;
        let dh2 = Dh::from_pqg(p, None, BigNum::from_u32(2)?)?.generate_key()?;
        Ok(Self { dh2 })
    }

    pub fn public_key(&self) -> Bytes {
        self.dh2.public_key().to_vec().into()
    }

    pub fn private_key(&self) -> Bytes {
        self.dh2.private_key().to_vec().into()
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

        let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
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
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        for d in data.into_iter() {
            hasher.update(d.as_ref())?;
        }
        Ok(hasher.finish()?.to_vec().into())
    }

    fn enc_dec(
        &self,
        mode: Mode,
        key: &[u8],
        data: &[u8],
        iv: Option<&[u8]>,
    ) -> anyhow::Result<Bytes> {
        let cipher = Cipher::aes_256_cbc();
        let mut crypter = Crypter::new(cipher, mode, key, iv)?;
        crypter.pad(false);
        let mut out = vec![0; data.len() + cipher.block_size()];
        let count = crypter.update(data, &mut out)?;
        let rest = crypter.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        Ok(out.into())
    }

    pub fn encrypt(&self, key: &[u8], data: &[u8], iv: &[u8]) -> anyhow::Result<Bytes> {
        self.enc_dec(Mode::Encrypt, key, data, Some(iv))
    }

    pub fn decrypt(&self, key: &[u8], data: &[u8], iv: &[u8]) -> anyhow::Result<Bytes> {
        self.enc_dec(Mode::Decrypt, key, data, Some(iv))
    }

    pub fn block_size(&self) -> usize {
        Cipher::aes_256_cbc().block_size()
    }
}
