use std::path::Path;
use std::sync::Arc;

use anyhow::anyhow;
use bytes::Bytes;
use openssl::pkcs12::Pkcs12;
use openssl::rsa::Padding;
use openssl::x509::X509;
use openssl::{
    bn::BigNum,
    dh::Dh,
    hash::{Hasher, MessageDigest},
    pkey::{PKey, Private},
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};

use crate::model::Identity;

// RFC2409: Oakley group 2
const G2_P: &[u8] = &[
    255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98, 139, 128, 220, 28, 209,
    41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142, 52, 4, 221, 239, 149, 25,
    179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98,
    94, 126, 198, 244, 76, 66, 233, 166, 55, 237, 107, 11, 255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90, 137,
    159, 165, 174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236, 230, 83, 129, 255, 255, 255, 255, 255, 255,
    255, 255,
];

pub struct ClientCertificate {
    pkey: PKey<Private>,
    certs: Vec<X509>,
}

impl ClientCertificate {
    fn load(path: &Path, password: Option<&str>) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        if let Ok(pkcs12) = Pkcs12::from_der(&data) {
            let parsed = pkcs12.parse2(password.ok_or_else(|| anyhow!("No password provided for PKCS12!"))?)?;
            if let (Some(pkey), Some(cert)) = (parsed.pkey, parsed.cert) {
                let mut certs = vec![cert];
                if let Some(ca) = parsed.ca {
                    certs.extend(ca);
                }
                Ok(ClientCertificate { pkey, certs })
            } else {
                Err(anyhow!("No certificate chain found in the PKCS12!"))
            }
        } else if let (Ok(pkey), Ok(stack)) = (PKey::private_key_from_pem(&data), X509::stack_from_pem(&data)) {
            Ok(ClientCertificate {
                pkey,
                certs: stack.into_iter().map(Into::into).collect(),
            })
        } else {
            Err(anyhow!("Unknown certificate file format!"))
        }
    }

    pub fn issuer(&self) -> Bytes {
        self.certs
            .first()
            .and_then(|c| c.issuer_name().to_der().ok())
            .unwrap_or_default()
            .into()
    }

    pub fn subject(&self) -> Bytes {
        self.certs
            .first()
            .and_then(|c| c.subject_name().to_der().ok())
            .unwrap_or_default()
            .into()
    }

    pub fn certs(&self) -> Vec<Bytes> {
        self.certs.iter().flat_map(|c| c.to_der().map(|c| c.into())).collect()
    }

    pub fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let mut buf = vec![0u8; self.pkey.size()];
        let size = self.pkey.rsa()?.private_encrypt(data, &mut buf, Padding::PKCS1)?;

        Ok(Bytes::copy_from_slice(&buf[0..size]))
    }
}

pub struct Crypto {
    dh2: Dh<Private>,
    digest: MessageDigest,
    cipher: Cipher,
    client_cert: Option<Arc<ClientCertificate>>,
}

impl Crypto {
    pub fn new(identity: Identity) -> anyhow::Result<Self> {
        let client_cert = if let Identity::Certificate { path, password } = identity {
            Some(Arc::new(ClientCertificate::load(&path, password.as_deref())?))
        } else {
            None
        };

        let p = BigNum::from_slice(G2_P)?;
        let dh2 = Dh::from_pqg(p, None, BigNum::from_u32(2)?)?.generate_key()?;
        Ok(Self {
            dh2,
            digest: MessageDigest::sha256(),
            cipher: Cipher::aes_256_cbc(),
            client_cert,
        })
    }

    pub fn init_sha1(&mut self) {
        self.digest = MessageDigest::sha1();
    }

    pub fn init_sha256(&mut self) {
        self.digest = MessageDigest::sha256();
    }

    pub fn init_cipher(&mut self, key_len: usize) {
        if key_len == 16 {
            self.cipher = Cipher::aes_128_cbc()
        } else if key_len == 32 {
            self.cipher = Cipher::aes_256_cbc()
        }
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

    fn enc_dec(&self, mode: Mode, key: &[u8], data: &[u8], iv: Option<&[u8]>) -> anyhow::Result<Bytes> {
        let mut crypter = Crypter::new(self.cipher, mode, key, iv)?;
        crypter.pad(false);
        let mut out = vec![0; data.len() + self.cipher.block_size()];
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
        self.cipher.block_size()
    }

    pub fn key_len(&self) -> usize {
        self.cipher.key_len()
    }

    pub fn hash_len(&self) -> usize {
        self.digest.size()
    }

    pub fn client_certificate(&self) -> Option<Arc<ClientCertificate>> {
        self.client_cert.clone()
    }
}
