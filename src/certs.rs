use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, CertificateType, KeyType},
    session::{Session, UserType},
    types::AuthPin,
};
use openssl::{
    hash::MessageDigest,
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    rsa::Padding,
    stack::Stack,
    x509::{X509, X509NameRef, X509StoreContext, store::X509StoreBuilder},
};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, trace};

fn from_der_or_pem(data: &[u8]) -> anyhow::Result<X509> {
    Ok(X509::from_der(data).or_else(|_| X509::from_pem(data))?)
}

pub trait ClientCertificate {
    fn issuer(&self) -> Bytes;

    fn issuer_name(&self) -> String;

    fn subject(&self) -> Bytes;

    fn subject_name(&self) -> String;

    fn fingerprint(&self) -> Bytes;

    fn certs(&self) -> Vec<Bytes>;

    fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes>;
}

fn format_x509_name(name: &X509NameRef) -> String {
    name.entries().map(|e| format!("{e:?}")).collect::<Vec<_>>().join(",")
}

pub struct CertList(Vec<X509>);

impl CertList {
    pub fn from_ipsec(certs: &[&Bytes]) -> anyhow::Result<Self> {
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

    pub fn issuer(&self) -> Bytes {
        self.0
            .first()
            .and_then(|c| c.issuer_name().to_der().ok())
            .unwrap_or_default()
            .into()
    }

    pub fn issuer_name(&self) -> String {
        self.0
            .first()
            .map(|c| format_x509_name(c.issuer_name()))
            .unwrap_or_default()
    }

    pub fn subject(&self) -> Bytes {
        self.0
            .first()
            .and_then(|c| c.subject_name().to_der().ok())
            .unwrap_or_default()
            .into()
    }

    pub fn subject_name(&self) -> String {
        self.0
            .first()
            .map(|c| format_x509_name(c.subject_name()))
            .unwrap_or_default()
    }

    pub fn fingerprint(&self) -> Bytes {
        self.0
            .first()
            .map(|c| {
                c.digest(MessageDigest::sha1())
                    .map(|d| d.to_vec().into())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    pub fn certs(&self) -> Vec<Bytes> {
        self.0.iter().flat_map(|c| c.to_der().map(|c| c.into())).collect()
    }
}

pub struct Pkcs8Certificate {
    pkey: PKey<Private>,
    certs: CertList,
}

impl Pkcs8Certificate {
    pub fn from_pkcs12(data: &[u8], password: &str) -> anyhow::Result<Self> {
        let pkcs12 = Pkcs12::from_der(data)?;
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
            certs: CertList(stack.into_iter().collect()),
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

    fn fingerprint(&self) -> Bytes {
        self.certs.fingerprint()
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
    pin: SecretString,
    key_id: Option<Bytes>,
    certs: CertList,
}

impl Pkcs11Certificate {
    fn init_session(driver_path: &Path, pin: &str) -> anyhow::Result<Session> {
        debug!("Initializing PKCS11");
        let pkcs11 = Pkcs11::new(driver_path)?;
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

        let slots = pkcs11.get_slots_with_token()?;

        debug!("Total slots: {}", slots.len());
        let slot = slots.into_iter().next().context("No slots found")?;

        let user_pin = AuthPin::new(pin.to_owned().into());

        debug!("Opening session");
        let session = pkcs11.open_ro_session(slot)?;

        debug!("Authenticating user");
        session.login(UserType::User, Some(&user_pin))?;

        Ok(session)
    }

    pub fn new(driver_path: PathBuf, pin: SecretString, key_id: Option<Bytes>) -> anyhow::Result<Self> {
        let session = Self::init_session(&driver_path, pin.expose_secret())?;

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

    fn fingerprint(&self) -> Bytes {
        self.certs.fingerprint()
    }

    fn certs(&self) -> Vec<Bytes> {
        self.certs.certs()
    }

    fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let session = Self::init_session(&self.driver_path, self.pin.expose_secret())?;

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
            .context("No private key!")?;

        let always_auth = matches!(
            session
                .get_attributes(key, &[AttributeType::AlwaysAuthenticate])?
                .into_iter()
                .next(),
            Some(Attribute::AlwaysAuthenticate(true))
        );

        if always_auth {
            debug!("Authenticating for additional context");
            let user_pin = AuthPin::new(self.pin.expose_secret().to_owned().into());
            session.login(UserType::ContextSpecific, Some(&user_pin))?;
        }

        debug!("Signing data");

        Ok(session.sign(&Mechanism::RsaPkcs, key, data)?.into())
    }
}

#[cfg(windows)]
pub mod windows {
    use std::{mem, ptr, slice};

    use anyhow::anyhow;
    use bytes::Bytes;
    use openssl::x509::X509;
    use tracing::debug;
    use windows_sys::Win32::{Foundation::GetLastError, Security::Cryptography::*};

    use super::{CertList, ClientCertificate};

    const HCCE_LOCAL_MACHINE: HCERTCHAINENGINE = 0x1 as HCERTCHAINENGINE;
    const MY_ENCODING_TYPE: CERT_QUERY_ENCODING_TYPE = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

    pub struct SystemCertificate {
        cert_context: *const CERT_CONTEXT,
        key_handle: NCRYPT_KEY_HANDLE,
        certs: CertList,
    }

    unsafe impl Send for SystemCertificate {}
    unsafe impl Sync for SystemCertificate {}

    impl SystemCertificate {
        pub fn new(common_name: &str) -> anyhow::Result<Self> {
            unsafe {
                let store_name: Vec<u16> = "MY".encode_utf16().chain([0]).collect();

                debug!("Opening LocalMachine MY certificate store");

                let store = CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_W,
                    0,
                    HCRYPTPROV_LEGACY::default(),
                    (CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
                        | CERT_STORE_OPEN_EXISTING_FLAG
                        | CERT_STORE_READONLY_FLAG,
                    store_name.as_ptr() as _,
                );
                if store.is_null() {
                    return Err(win32_err("CertOpenStore"));
                }

                let pattern: Vec<u16> = common_name.encode_utf16().chain([0]).collect();

                debug!("Searching for certificate with subject containing '{}'", common_name);

                let found = CertFindCertificateInStore(
                    store,
                    MY_ENCODING_TYPE,
                    0,
                    CERT_FIND_SUBJECT_STR,
                    pattern.as_ptr() as _,
                    ptr::null(),
                );

                if found.is_null() {
                    CertCloseStore(store, 0);
                    return Err(anyhow!("No certificate matching '{}' in LocalMachine\\MY", common_name));
                }

                let cert_context = CertDuplicateCertificateContext(found);
                CertCloseStore(store, 0);

                let chain = match Self::build_chain(cert_context) {
                    Ok(c) => c,
                    Err(e) => {
                        CertFreeCertificateContext(cert_context);
                        return Err(e);
                    }
                };

                let mut x509_list = Vec::with_capacity(chain.len());
                for der in &chain {
                    match X509::from_der(der) {
                        Ok(x) => x509_list.push(x),
                        Err(e) => {
                            CertFreeCertificateContext(cert_context);
                            return Err(e.into());
                        }
                    }
                }
                let certs = CertList(x509_list);

                debug!("Acquiring CNG private key (silent)");

                let mut handle: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE = 0;
                let mut key_spec: CERT_KEY_SPEC = 0;
                let ok = CryptAcquireCertificatePrivateKey(
                    cert_context,
                    CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
                    ptr::null(),
                    &mut handle,
                    &mut key_spec,
                    ptr::null_mut(),
                );
                if ok == 0 {
                    let err = win32_err("CryptAcquireCertificatePrivateKey");
                    CertFreeCertificateContext(cert_context);
                    return Err(err);
                }

                let key_handle = handle as NCRYPT_KEY_HANDLE;

                let group = match get_string_property(key_handle, NCRYPT_ALGORITHM_GROUP_PROPERTY) {
                    Ok(g) => g,
                    Err(e) => {
                        let _ = NCryptFreeObject(key_handle);
                        CertFreeCertificateContext(cert_context);
                        return Err(e);
                    }
                };
                if group != "RSA" {
                    let _ = NCryptFreeObject(key_handle);
                    CertFreeCertificateContext(cert_context);
                    return Err(anyhow!("Private key algorithm group is not RSA: {}", group));
                }

                Ok(Self {
                    cert_context,
                    key_handle,
                    certs,
                })
            }
        }

        unsafe fn build_chain(ctx: *const CERT_CONTEXT) -> anyhow::Result<Vec<Vec<u8>>> {
            unsafe {
                let param: CERT_CHAIN_PARA = CERT_CHAIN_PARA {
                    cbSize: mem::size_of::<CERT_CHAIN_PARA>() as u32,
                    ..mem::zeroed()
                };
                let mut chain_ctx: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();

                let result = CertGetCertificateChain(
                    HCCE_LOCAL_MACHINE,
                    ctx,
                    ptr::null(),
                    ptr::null_mut(),
                    &param,
                    0,
                    ptr::null(),
                    &mut chain_ctx,
                );

                let mut out = Vec::new();

                if result != 0 && !chain_ctx.is_null() {
                    if (*chain_ctx).cChain > 0 {
                        let first = *(*chain_ctx).rgpChain;
                        let elements = slice::from_raw_parts((*first).rgpElement, (*first).cElement as usize);
                        for (idx, el) in elements.iter().enumerate() {
                            if idx != 0 && ((**el).TrustStatus.dwInfoStatus & CERT_TRUST_IS_SELF_SIGNED) != 0 {
                                break;
                            }
                            let c = (**el).pCertContext;
                            let der = slice::from_raw_parts((*c).pbCertEncoded, (*c).cbCertEncoded as usize);
                            out.push(der.to_vec());
                        }
                    }
                    CertFreeCertificateChain(chain_ctx);
                } else {
                    let der = slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize);
                    out.push(der.to_vec());
                }

                Ok(out)
            }
        }
    }

    impl Drop for SystemCertificate {
        fn drop(&mut self) {
            unsafe {
                if self.key_handle != 0 {
                    let _ = NCryptFreeObject(self.key_handle);
                }
                if !self.cert_context.is_null() {
                    CertFreeCertificateContext(self.cert_context);
                }
            }
        }
    }

    impl ClientCertificate for SystemCertificate {
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

        fn fingerprint(&self) -> Bytes {
            self.certs.fingerprint()
        }

        fn certs(&self) -> Vec<Bytes> {
            self.certs.certs()
        }

        fn sign(&self, data: &[u8]) -> anyhow::Result<Bytes> {
            unsafe {
                let flags = NCRYPT_SILENT_FLAG | NCRYPT_PAD_PKCS1_FLAG;
                let mut needed: u32 = 0;

                let status = NCryptEncrypt(
                    self.key_handle,
                    data.as_ptr(),
                    data.len() as u32,
                    ptr::null(),
                    ptr::null_mut(),
                    0,
                    &mut needed,
                    flags,
                );
                if status != 0 {
                    return Err(anyhow!("NCryptEncrypt(size) failed: 0x{:08x}", status));
                }

                let mut buf = vec![0u8; needed as usize];
                let mut written: u32 = 0;
                let status = NCryptEncrypt(
                    self.key_handle,
                    data.as_ptr(),
                    data.len() as u32,
                    ptr::null(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut written,
                    flags,
                );
                if status != 0 {
                    return Err(anyhow!("NCryptEncrypt failed: 0x{:08x}", status));
                }

                buf.truncate(written as usize);
                Ok(Bytes::from(buf))
            }
        }
    }

    fn win32_err(label: &str) -> anyhow::Error {
        let code = unsafe { GetLastError() };
        anyhow!("{} failed: 0x{:08x}", label, code)
    }

    unsafe fn get_string_property(
        key: NCRYPT_KEY_HANDLE,
        property: windows_sys::core::PCWSTR,
    ) -> anyhow::Result<String> {
        unsafe {
            let mut size: u32 = 0;
            let status = NCryptGetProperty(key, property, ptr::null_mut(), 0, &mut size, 0);
            if status != 0 {
                return Err(anyhow!("NCryptGetProperty(size) failed: 0x{:08x}", status));
            }
            let mut buf = vec![0u8; size as usize];
            let status = NCryptGetProperty(key, property, buf.as_mut_ptr(), buf.len() as u32, &mut size, 0);
            if status != 0 {
                return Err(anyhow!("NCryptGetProperty failed: 0x{:08x}", status));
            }
            let utf16 = slice::from_raw_parts(buf.as_ptr() as *const u16, buf.len() / 2);
            let len = utf16.iter().position(|&c| c == 0).unwrap_or(utf16.len());
            Ok(String::from_utf16_lossy(&utf16[..len]))
        }
    }
}
