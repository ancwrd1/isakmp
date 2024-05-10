use std::path::{Path, PathBuf};

use anyhow::anyhow;
use bytes::Bytes;
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, CertificateType, KeyType},
    session::{Session, UserType},
    types::AuthPin,
};
use openssl::{
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    rsa::Padding,
    x509::X509,
};
use tracing::debug;

pub trait ClientCertificate {
    fn issuer(&self) -> Bytes;

    fn subject(&self) -> Bytes;

    fn certs(&self) -> Vec<Bytes>;

    fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes>;
}

trait CertOps {
    fn get_issuer(&self) -> Bytes {
        self.x509_certs()
            .first()
            .and_then(|c| c.issuer_name().to_der().ok())
            .unwrap_or_default()
            .into()
    }

    fn get_subject(&self) -> Bytes {
        self.x509_certs()
            .first()
            .and_then(|c| c.subject_name().to_der().ok())
            .unwrap_or_default()
            .into()
    }

    fn get_certs(&self) -> Vec<Bytes> {
        self.x509_certs()
            .iter()
            .flat_map(|c| c.to_der().map(|c| c.into()))
            .collect()
    }

    fn x509_certs(&self) -> &[X509];
}

pub(crate) struct Pkcs8Certificate {
    pkey: PKey<Private>,
    certs: Vec<X509>,
}

impl Pkcs8Certificate {
    pub fn from_pkcs12(path: &Path, password: &str) -> anyhow::Result<Self> {
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

    pub fn from_pkcs8(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        let pkey = PKey::private_key_from_pem(&data)?;
        let stack = X509::stack_from_pem(&data)?;

        Ok(Self {
            pkey,
            certs: stack.into_iter().map(Into::into).collect(),
        })
    }
}

impl CertOps for Pkcs8Certificate {
    fn x509_certs(&self) -> &[X509] {
        &self.certs
    }
}

impl ClientCertificate for Pkcs8Certificate {
    fn issuer(&self) -> Bytes {
        self.get_issuer()
    }

    fn subject(&self) -> Bytes {
        self.get_subject()
    }

    fn certs(&self) -> Vec<Bytes> {
        self.get_certs()
    }

    fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let mut buf = vec![0u8; self.pkey.size()];
        let size = self.pkey.rsa()?.private_encrypt(data, &mut buf, Padding::PKCS1)?;

        Ok(Bytes::copy_from_slice(&buf[0..size]))
    }
}

pub(crate) struct Pkcs11Certificate {
    driver_path: PathBuf,
    pin: String,
    key_id: Option<Bytes>,
    certs: Vec<X509>,
}

impl Pkcs11Certificate {
    fn init_session(driver_path: &Path, pin: &str) -> anyhow::Result<Session> {
        debug!("Initializing PKCS11");
        let pkcs11 = Pkcs11::new(driver_path)?;
        pkcs11.initialize(CInitializeArgs::OsThreads)?;

        let slots = pkcs11.get_slots_with_token()?;

        debug!("Total slots: {}", slots.len());
        let slot = slots.into_iter().next().ok_or_else(|| anyhow!("No slots found"))?;

        let user_pin = AuthPin::new(pin.to_owned());

        debug!("Opening session");
        let session = pkcs11.open_ro_session(slot)?;

        debug!("Authenticating user");
        session.login(UserType::User, Some(&user_pin))?;

        Ok(session)
    }

    pub fn new(driver_path: PathBuf, pin: String, key_id: Option<Bytes>) -> anyhow::Result<Self> {
        let session = Self::init_session(&driver_path, &pin)?;

        let mut cert_template = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::CertificateType(CertificateType::X_509),
        ];

        if let Some(ref key_id) = key_id {
            cert_template.push(Attribute::Id(key_id.to_vec()));
        }

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
            key_id,
            certs,
        })
    }
}

impl CertOps for Pkcs11Certificate {
    fn x509_certs(&self) -> &[X509] {
        &self.certs
    }
}

impl ClientCertificate for Pkcs11Certificate {
    fn issuer(&self) -> Bytes {
        self.get_issuer()
    }

    fn subject(&self) -> Bytes {
        self.get_subject()
    }

    fn certs(&self) -> Vec<Bytes> {
        self.get_certs()
    }

    fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let session = Self::init_session(&self.driver_path, &self.pin)?;

        let mut priv_key_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::KeyType(KeyType::RSA),
        ];

        if let Some(ref key_id) = self.key_id {
            priv_key_template.push(Attribute::Id(key_id.to_vec()));
        }

        debug!("Looking up for private key");

        let key = session
            .find_objects(&priv_key_template)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("No private key!"))?;

        let always_auth = matches!(
            session
                .get_attributes(key, &[AttributeType::AlwaysAuthenticate])?
                .into_iter()
                .next(),
            Some(Attribute::AlwaysAuthenticate(true))
        );

        if always_auth {
            debug!("Authenticating for additional context");
            let user_pin = AuthPin::new(self.pin.to_owned());
            session.login(UserType::ContextSpecific, Some(&user_pin))?;
        }

        debug!("Signing data");

        Ok(session.sign(&Mechanism::RsaPkcs, key, data)?.into())
    }
}
