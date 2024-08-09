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
    stack::Stack,
    x509::{store::X509StoreBuilder, X509NameRef, X509StoreContext, X509},
};
use tracing::{debug, trace};

fn from_der_or_pem(data: &[u8]) -> anyhow::Result<X509> {
    Ok(X509::from_der(data).or_else(|_| X509::from_pem(data))?)
}

pub trait ClientCertificate {
    fn issuer(&self) -> Bytes;

    fn issuer_name(&self) -> String;

    fn subject(&self) -> Bytes;

    fn subject_name(&self) -> String;

    fn certs(&self) -> Vec<Bytes>;

    fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes>;
}

fn format_x509_name(name: &X509NameRef) -> String {
    name.entries().map(|e| format!("{:?}", e)).collect::<Vec<_>>().join(",")
}

pub struct CertList(Vec<X509>);

impl CertList {
    pub fn from_ipsec(certs: &[Bytes]) -> anyhow::Result<Self> {
        let mut x509_list = Vec::new();
        for cert in certs {
            x509_list.push(from_der_or_pem(cert)?);
        }
        Ok(Self(x509_list))
    }

    pub fn verify(&self, ca_certs: &[Bytes]) -> anyhow::Result<()> {
        debug!("Validating IPSec certificate: {}", self.subject_name());

        trace!("Entity certificate: {:#?}", &self.0[0]);

        debug!("Certificate issuer: {}", self.issuer_name());

        let mut chain = Stack::new()?;

        for cert in &self.0[1..] {
            trace!("Chain certificate: {:#?}", cert);
            chain.push(cert.clone())?;
        }

        let mut store_bldr = X509StoreBuilder::new()?;

        for ca in ca_certs {
            store_bldr.add_cert(from_der_or_pem(ca)?)?;
        }

        let store = store_bldr.build();

        let mut context = X509StoreContext::new()?;
        if context.init(&store, &self.0[0], &chain, |c| c.verify_cert())? {
            debug!("IPSec certificate validation succeeded!");
            Ok(())
        } else {
            Err(anyhow!("IPSec certificate validation failed!"))
        }
    }

    fn issuer(&self) -> Bytes {
        self.0
            .first()
            .and_then(|c| c.issuer_name().to_der().ok())
            .unwrap_or_default()
            .into()
    }

    fn issuer_name(&self) -> String {
        self.0
            .first()
            .map(|c| format_x509_name(c.issuer_name()))
            .unwrap_or_default()
    }

    fn subject(&self) -> Bytes {
        self.0
            .first()
            .and_then(|c| c.subject_name().to_der().ok())
            .unwrap_or_default()
            .into()
    }

    fn subject_name(&self) -> String {
        self.0
            .first()
            .map(|c| format_x509_name(c.subject_name()))
            .unwrap_or_default()
    }

    fn certs(&self) -> Vec<Bytes> {
        self.0.iter().flat_map(|c| c.to_der().map(|c| c.into())).collect()
    }
}

pub(crate) struct Pkcs8Certificate {
    pkey: PKey<Private>,
    certs: CertList,
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
            Ok(Self {
                pkey,
                certs: CertList(certs),
            })
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
            certs: CertList(stack.into_iter().map(Into::into).collect()),
        })
    }
}

impl ClientCertificate for Pkcs8Certificate {
    fn issuer(&self) -> Bytes {
        self.certs.issuer()
    }

    fn issuer_name(&self) -> String {
        self.certs.issuer_name()
    }

    fn subject(&self) -> Bytes {
        self.certs.subject()
    }

    fn subject_name(&self) -> String {
        self.certs.subject_name()
    }

    fn certs(&self) -> Vec<Bytes> {
        self.certs.certs()
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
    certs: CertList,
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
            certs: CertList(certs),
        })
    }
}

impl ClientCertificate for Pkcs11Certificate {
    fn issuer(&self) -> Bytes {
        self.certs.issuer()
    }

    fn issuer_name(&self) -> String {
        self.certs.issuer_name()
    }

    fn subject(&self) -> Bytes {
        self.certs.subject()
    }

    fn subject_name(&self) -> String {
        self.certs.subject_name()
    }

    fn certs(&self) -> Vec<Bytes> {
        self.certs.certs()
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
