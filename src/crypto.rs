use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::anyhow;
use bytes::Bytes;
use cryptoki::error::RvError;
use cryptoki::session::Session;
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, CertificateType, KeyType},
    session::UserType,
    types::AuthPin,
};
use openssl::{
    bn::BigNum,
    dh::Dh,
    hash::{Hasher, MessageDigest},
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    rsa::Padding,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
    x509::X509,
};
use tracing::debug;

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

pub trait ClientCertificate {
    fn issuer(&self) -> Bytes;

    fn subject(&self) -> Bytes;

    fn certs(&self) -> Vec<Bytes>;

    fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes>;
}

pub struct Pkcs8Certificate {
    pkey: PKey<Private>,
    certs: Vec<X509>,
}

impl Pkcs8Certificate {
    fn from_pkcs12(path: &Path, password: &str) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        let pkcs12 = Pkcs12::from_der(&data)?;
        let parsed = pkcs12.parse2(password)?;
        if let (Some(pkey), Some(cert)) = (parsed.pkey, parsed.cert) {
            let mut certs = vec![cert];
            if let Some(ca) = parsed.ca {
                certs.extend(ca);
            }
            Ok(Self { pkey, certs })
        } else {
            Err(anyhow!("No certificate chain found in the PKCS12!"))
        }
    }

    fn from_pkcs8(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        let pkey = PKey::private_key_from_pem(&data)?;
        let stack = X509::stack_from_pem(&data)?;

        Ok(Self {
            pkey,
            certs: stack.into_iter().map(Into::into).collect(),
        })
    }
}

impl ClientCertificate for Pkcs8Certificate {
    fn issuer(&self) -> Bytes {
        self.certs
            .first()
            .and_then(|c| c.issuer_name().to_der().ok())
            .unwrap_or_default()
            .into()
    }

    fn subject(&self) -> Bytes {
        self.certs
            .first()
            .and_then(|c| c.subject_name().to_der().ok())
            .unwrap_or_default()
            .into()
    }

    fn certs(&self) -> Vec<Bytes> {
        self.certs.iter().flat_map(|c| c.to_der().map(|c| c.into())).collect()
    }

    fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let mut buf = vec![0u8; self.pkey.size()];
        let size = self.pkey.rsa()?.private_encrypt(data, &mut buf, Padding::PKCS1)?;

        Ok(Bytes::copy_from_slice(&buf[0..size]))
    }
}

struct Pkcs11Certificate {
    driver_path: PathBuf,
    pin: String,
    certs: Vec<X509>,
}
unsafe impl Sync for Pkcs11Certificate {}

impl Pkcs11Certificate {
    fn init_session(driver_path: &Path, pin: &str) -> anyhow::Result<Session> {
        debug!("Initializing PKCS11");
        let pkcs11 = Pkcs11::new(&driver_path)?;
        pkcs11.initialize(CInitializeArgs::OsThreads)?;

        let slots = pkcs11.get_slots_with_token()?;

        debug!("Total slots: {}", slots.len());
        let slot = slots.into_iter().next().ok_or_else(|| anyhow!("No slots found"))?;

        let user_pin = AuthPin::new(pin.to_owned());

        debug!("Opening r/o session");
        let session = pkcs11.open_ro_session(slot)?;

        debug!("Authenticating user with a pin");
        session.login(UserType::User, Some(&user_pin))?;

        Ok(session)
    }

    fn init(driver_path: PathBuf, pin: String) -> anyhow::Result<Self> {
        let session = Self::init_session(&driver_path, &pin)?;

        let cert_template = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::CertificateType(CertificateType::X_509),
        ];

        let mut certs = Vec::new();

        debug!("Reading certificates");

        for obj in session.find_objects(&cert_template)? {
            if let Some(Attribute::Value(value)) =
                session.get_attributes(obj, &[AttributeType::Value])?.into_iter().next()
            {
                certs.push(X509::from_der(&value)?);
            }
        }

        Ok(Self {
            driver_path,
            pin,
            certs,
        })
    }
}

impl ClientCertificate for Pkcs11Certificate {
    fn issuer(&self) -> Bytes {
        self.certs
            .first()
            .and_then(|c| c.issuer_name().to_der().ok())
            .unwrap_or_default()
            .into()
    }

    fn subject(&self) -> Bytes {
        self.certs
            .first()
            .and_then(|c| c.subject_name().to_der().ok())
            .unwrap_or_default()
            .into()
    }

    fn certs(&self) -> Vec<Bytes> {
        self.certs.iter().flat_map(|c| c.to_der().map(|c| c.into())).collect()
    }

    fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let session = Self::init_session(&self.driver_path, &self.pin)?;

        let priv_key_template = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::KeyType(KeyType::RSA),
        ];

        debug!("Looking up for private key");

        let key = session
            .find_objects(&priv_key_template)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("No private key!"))?;

        debug!("Signing data");

        match session.sign(&Mechanism::RsaPkcs, key, data) {
            Ok(data) => Ok(data.into()),
            Err(cryptoki::error::Error::Pkcs11(RvError::UserNotLoggedIn)) => {
                debug!("Trying with context-specific login");
                let user_pin = AuthPin::new(self.pin.to_owned());
                session.login(UserType::User, Some(&user_pin))?;
                session.login(UserType::ContextSpecific, Some(&user_pin))?;
                Ok(session.sign(&Mechanism::RsaPkcs, key, data)?.into())
            }
            Err(e) => Err(e.into()),
        }
    }
}

pub struct Crypto {
    dh2: Dh<Private>,
    digest: MessageDigest,
    cipher: Cipher,
    client_cert: Option<Arc<dyn ClientCertificate + Send + Sync>>,
}

impl Crypto {
    pub fn new(identity: Identity) -> anyhow::Result<Self> {
        let client_cert: Option<Arc<dyn ClientCertificate + Send + Sync>> = match identity {
            Identity::Pkcs12 { path, password } => Some(Arc::new(Pkcs8Certificate::from_pkcs12(&path, &password)?)),
            Identity::Pkcs8 { path } => Some(Arc::new(Pkcs8Certificate::from_pkcs8(&path)?)),
            Identity::Pkcs11 { driver_path, pin } => Some(Arc::new(Pkcs11Certificate::init(driver_path, pin)?)),
            Identity::None => None,
        };

        Ok(Self {
            dh2: Self::make_dh2(2)?,
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
        } else if key_len == 24 {
            self.cipher = Cipher::aes_192_cbc()
        } else if key_len == 32 {
            self.cipher = Cipher::aes_256_cbc()
        }
    }

    fn make_dh2(group: u16) -> anyhow::Result<Dh<Private>> {
        let g = match group {
            2 => G2_P,
            14 => G14_P,
            _ => return Err(anyhow!("Unsupported group")),
        };
        let p = BigNum::from_slice(g)?;
        let dh2 = Dh::from_pqg(p, None, BigNum::from_u32(2)?)?.generate_key()?;
        Ok(dh2)
    }

    pub fn init_group(&mut self, group: u16) -> anyhow::Result<()> {
        self.dh2 = Self::make_dh2(group)?;
        Ok(())
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

    pub fn client_certificate(&self) -> Option<Arc<dyn ClientCertificate + Send + Sync>> {
        self.client_cert.clone()
    }
}
