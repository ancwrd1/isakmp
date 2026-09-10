use anyhow::{Context, anyhow};
use bytes::{Bytes, BytesMut};
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    dh::Dh,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    hash::{Hasher, MessageDigest},
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Padding,
    sign::{Signer, Verifier},
    symm::{Cipher, Crypter, Mode},
    x509::X509,
};
use serde::{Deserialize, Serialize};

use crate::ikev1::model::{IkeEncryptionAlgorithm, TransformId};

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
    Md5,  // Cryptographically broken
    Sha1, // Deprecated for signatures
    Sha256,
    Sha384,
    Sha512,
}

impl DigestType {
    pub fn is_deprecated(&self) -> bool {
        matches!(self, DigestType::Md5 | DigestType::Sha1)
    }

    /// Full (untruncated) output length in bytes.
    pub fn hash_len(&self) -> usize {
        MessageDigest::from(*self).size()
    }

    /// Truncated checksum length used by the IKEv2 integrity transforms:
    /// HMAC-MD5-96 / HMAC-SHA1-96 (RFC 2404) and the RFC 4868 SHA-2 variants,
    /// which truncate to half the digest size.
    pub fn integrity_len(&self) -> usize {
        match self {
            DigestType::Md5 | DigestType::Sha1 => 12,
            DigestType::Sha256 => 16,
            DigestType::Sha384 => 24,
            DigestType::Sha512 => 32,
        }
    }

    /// The DER `DigestInfo` that RSASSA-PKCS1-v1_5 signs (RFC 8017 §9.2): an
    /// ASN.1 prefix naming the hash algorithm, followed by the hash itself.
    ///
    /// IKEv2 AUTH method 1 signs this, where IKEv1 signs the bare hash — the
    /// difference [`Crypto::verify_rsa_signature`] exists for, seen from the
    /// signing side. It is built here rather than by an openssl `Signer`
    /// because a [`crate::certs::ClientCertificate`] may hold its private key
    /// in a token or in the Windows store, and can only PKCS#1-pad and encrypt
    /// whatever it is handed.
    pub fn digest_info(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let prefix: &[u8] = match self {
            DigestType::Md5 => &[
                0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04,
                0x10,
            ],
            DigestType::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
            ],
            DigestType::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
                0x04, 0x20,
            ],
            DigestType::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
                0x04, 0x30,
            ],
            DigestType::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
                0x04, 0x40,
            ],
        };

        let mut hasher = Hasher::new((*self).into())?;
        hasher.update(data)?;
        let hash = hasher.finish()?;

        let mut buf = BytesMut::with_capacity(prefix.len() + hash.len());
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(&hash);

        Ok(buf.freeze())
    }
}

impl From<DigestType> for MessageDigest {
    fn from(value: DigestType) -> Self {
        match value {
            DigestType::Md5 => MessageDigest::md5(),
            DigestType::Sha1 => MessageDigest::sha1(),
            DigestType::Sha256 => MessageDigest::sha256(),
            DigestType::Sha384 => MessageDigest::sha384(),
            DigestType::Sha512 => MessageDigest::sha512(),
        }
    }
}

/// Length of the AES-GCM authentication tag, which IKEv2 negotiates as three
/// distinct ENCR transforms: ENCR_AES_GCM_8/12/16 (RFC 5282).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IcvLength {
    Eight,
    Twelve,
    Sixteen,
}

impl IcvLength {
    pub fn size(&self) -> usize {
        match self {
            IcvLength::Eight => 8,
            IcvLength::Twelve => 12,
            IcvLength::Sixteen => 16,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CipherType {
    Aes128Cbc,
    Aes192Cbc,
    #[default]
    Aes256Cbc,
    DesEde3Cbc,
    Aes128Gcm(IcvLength),
    Aes192Gcm(IcvLength),
    Aes256Gcm(IcvLength),
}

impl CipherType {
    pub fn new_for_ike(enc_alg: IkeEncryptionAlgorithm, key_len: usize) -> anyhow::Result<Self> {
        match enc_alg {
            IkeEncryptionAlgorithm::AesCbc => match key_len {
                16 => Ok(Self::Aes128Cbc),
                24 => Ok(Self::Aes192Cbc),
                32 => Ok(Self::Aes256Cbc),
                _ => Err(anyhow!("Unsupported key len: {}", key_len)),
            },
            IkeEncryptionAlgorithm::DesEde3Cbc => match key_len {
                24 => Ok(Self::DesEde3Cbc),
                _ => Err(anyhow!("Unsupported key len: {}", key_len)),
            },
            _ => Err(anyhow!("Unsupported encryption algorithm: {:?}", enc_alg)),
        }
    }

    /// IKEv2 transform type 1 (ENCR) transform IDs, RFC 7296 §3.3.2.
    pub fn new_for_ikev2(transform_id: u16, key_len: usize) -> anyhow::Result<Self> {
        fn by_key_len<T>(key_len: usize, k128: T, k192: T, k256: T) -> anyhow::Result<T> {
            match key_len {
                16 => Ok(k128),
                24 => Ok(k192),
                32 => Ok(k256),
                _ => Err(anyhow!("Unsupported key len: {}", key_len)),
            }
        }

        match transform_id {
            // ENCR_3DES
            3 => match key_len {
                24 => Ok(Self::DesEde3Cbc),
                _ => Err(anyhow!("Unsupported key len: {}", key_len)),
            },
            // ENCR_AES_CBC
            12 => by_key_len(key_len, Self::Aes128Cbc, Self::Aes192Cbc, Self::Aes256Cbc),
            // ENCR_AES_GCM_8 / _12 / _16
            18..=20 => {
                let icv = match transform_id {
                    18 => IcvLength::Eight,
                    19 => IcvLength::Twelve,
                    _ => IcvLength::Sixteen,
                };
                by_key_len(
                    key_len,
                    Self::Aes128Gcm(icv),
                    Self::Aes192Gcm(icv),
                    Self::Aes256Gcm(icv),
                )
            }
            other => Err(anyhow!("Unsupported IKEv2 encryption transform: {}", other)),
        }
    }

    pub fn new_for_esp(transform_id: TransformId, key_len: usize) -> anyhow::Result<Self> {
        match transform_id {
            TransformId::EspAesCbc => match key_len {
                16 => Ok(Self::Aes128Cbc),
                24 => Ok(Self::Aes192Cbc),
                32 => Ok(Self::Aes256Cbc),
                _ => Err(anyhow!("Unsupported key len: {}", key_len)),
            },
            TransformId::Esp3Des => Ok(Self::DesEde3Cbc),
            _ => Err(anyhow!("Unsupported transform id: {:?}", transform_id)),
        }
    }

    /// Whether this cipher authenticates its own output, in which case the
    /// negotiated integrity transform is NONE and `encrypt_aead`/`decrypt_aead`
    /// must be used instead of `encrypt`/`decrypt`.
    pub fn is_aead(&self) -> bool {
        matches!(self, Self::Aes128Gcm(_) | Self::Aes192Gcm(_) | Self::Aes256Gcm(_))
    }

    /// Length of the authentication tag appended to the ciphertext, 0 for
    /// non-AEAD ciphers.
    pub fn icv_len(&self) -> usize {
        match self {
            Self::Aes128Gcm(icv) | Self::Aes192Gcm(icv) | Self::Aes256Gcm(icv) => icv.size(),
            _ => 0,
        }
    }

    /// Length of the implicit salt carried in the keying material but not on
    /// the wire (RFC 5282 §4), 0 for non-AEAD ciphers.
    pub fn salt_len(&self) -> usize {
        if self.is_aead() { 4 } else { 0 }
    }

    /// Length of the explicit IV carried in the message.
    pub fn iv_len(&self) -> usize {
        if self.is_aead() {
            8
        } else {
            Cipher::from(*self).block_size()
        }
    }

    /// Full nonce length expected by `encrypt_aead`/`decrypt_aead`: salt || IV.
    pub fn nonce_len(&self) -> usize {
        self.salt_len() + self.iv_len()
    }

    /// Length of the key proper, excluding any salt.
    pub fn key_len(&self) -> usize {
        Cipher::from(*self).key_len()
    }

    /// Number of octets of keying material to draw for this cipher: key || salt.
    pub fn key_material_len(&self) -> usize {
        self.key_len() + self.salt_len()
    }

    /// Plaintext padding boundary. GCM is a stream mode, so RFC 7296 §3.14
    /// only requires 4-octet alignment there.
    pub fn block_size(&self) -> usize {
        if self.is_aead() {
            4
        } else {
            Cipher::from(*self).block_size()
        }
    }
}

impl From<CipherType> for Cipher {
    fn from(value: CipherType) -> Self {
        match value {
            CipherType::Aes128Cbc => Cipher::aes_128_cbc(),
            CipherType::Aes192Cbc => Cipher::aes_192_cbc(),
            CipherType::Aes256Cbc => Cipher::aes_256_cbc(),
            CipherType::DesEde3Cbc => Cipher::des_ede3_cbc(),
            CipherType::Aes128Gcm(_) => Cipher::aes_128_gcm(),
            CipherType::Aes192Gcm(_) => Cipher::aes_192_gcm(),
            CipherType::Aes256Gcm(_) => Cipher::aes_256_gcm(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GroupType {
    Oakley2,
    Oakley14,
    EcP256,
    EcP384,
    EcP521,
}

impl GroupType {
    /// IKE Diffie-Hellman group number (IKEv1 group description / IKEv2
    /// transform type 4 ID).
    pub fn group_id(&self) -> u16 {
        match self {
            GroupType::Oakley2 => 2,
            GroupType::Oakley14 => 14,
            GroupType::EcP256 => 19,
            GroupType::EcP384 => 20,
            GroupType::EcP521 => 21,
        }
    }

    pub fn from_group_id(group_id: u16) -> anyhow::Result<Self> {
        match group_id {
            2 => Ok(GroupType::Oakley2),
            14 => Ok(GroupType::Oakley14),
            19 => Ok(GroupType::EcP256),
            20 => Ok(GroupType::EcP384),
            21 => Ok(GroupType::EcP521),
            other => Err(anyhow!("Unsupported Diffie-Hellman group: {}", other)),
        }
    }

    pub fn is_ecp(&self) -> bool {
        matches!(self, GroupType::EcP256 | GroupType::EcP384 | GroupType::EcP521)
    }

    /// Size of the KE payload data: the modulus length for MODP groups, or the
    /// concatenated x || y coordinates for ECP groups (RFC 5903 §7).
    pub fn public_key_len(&self) -> usize {
        match self {
            GroupType::Oakley2 => 128,
            GroupType::Oakley14 => 256,
            _ => 2 * self.field_len(),
        }
    }

    /// Size of the derived shared secret: the modulus length for MODP groups,
    /// or the single x coordinate for ECP groups.
    pub fn shared_secret_len(&self) -> usize {
        match self {
            GroupType::Oakley2 => 128,
            GroupType::Oakley14 => 256,
            _ => self.field_len(),
        }
    }

    /// Coordinate size in bytes for ECP groups.
    fn field_len(&self) -> usize {
        match self {
            GroupType::EcP256 => 32,
            GroupType::EcP384 => 48,
            GroupType::EcP521 => 66,
            _ => 0,
        }
    }

    fn nid(&self) -> anyhow::Result<Nid> {
        match self {
            GroupType::EcP256 => Ok(Nid::X9_62_PRIME256V1),
            GroupType::EcP384 => Ok(Nid::SECP384R1),
            GroupType::EcP521 => Ok(Nid::SECP521R1),
            other => Err(anyhow!("Not an elliptic curve group: {:?}", other)),
        }
    }

    fn ec_group(&self) -> anyhow::Result<EcGroup> {
        Ok(EcGroup::from_curve_name(self.nid()?)?)
    }
}

/// Ephemeral key agreement state, either finite-field (MODP) or elliptic curve.
enum KeyExchange {
    Modp(Dh<Private>),
    Ecp(PKey<Private>),
}

impl KeyExchange {
    fn generate(group: GroupType) -> anyhow::Result<Self> {
        if group.is_ecp() {
            let ec_group = group.ec_group()?;
            Ok(KeyExchange::Ecp(PKey::from_ec_key(EcKey::generate(&ec_group)?)?))
        } else {
            let p = BigNum::from_slice(match group {
                GroupType::Oakley2 => G2_P,
                GroupType::Oakley14 => G14_P,
                other => return Err(anyhow!("No MODP prime for group: {:?}", other)),
            })?;
            Ok(KeyExchange::Modp(
                Dh::from_pqg(p, None, BigNum::from_u32(2)?)?.generate_key()?,
            ))
        }
    }
}

/// Left-pad `data` with zeroes to exactly `len` octets. IKE carries both the
/// KE payload and the shared secret as fixed-width big-endian integers, but
/// `BigNum` renders them without leading zeroes.
fn left_pad(data: &[u8], len: usize) -> anyhow::Result<Bytes> {
    if data.len() > len {
        return Err(anyhow!("Value of {} bytes exceeds the expected {}", data.len(), len));
    }
    let mut out = BytesMut::zeroed(len - data.len());
    out.extend_from_slice(data);
    Ok(out.freeze())
}

pub struct Crypto {
    kex: KeyExchange,
    digest: MessageDigest,
    prf_digest: MessageDigest,
    cipher: Cipher,
    digest_type: DigestType,
    prf_type: DigestType,
    cipher_type: CipherType,
    group_type: GroupType,
}

impl Crypto {
    /// IKEv1 parameters, where a single negotiated hash algorithm serves as
    /// PRF, integrity function and hash.
    pub fn with_parameters(digest: DigestType, cipher: CipherType, group: GroupType) -> anyhow::Result<Self> {
        Ok(Self {
            kex: KeyExchange::generate(group)?,
            digest: digest.into(),
            prf_digest: digest.into(),
            cipher: cipher.into(),
            digest_type: digest,
            prf_type: digest,
            cipher_type: cipher,
            group_type: group,
        })
    }

    /// Override the PRF, which IKEv2 negotiates as a transform of its own,
    /// independently of the integrity algorithm (RFC 7296 §3.3.2).
    pub fn with_prf(mut self, prf: DigestType) -> Self {
        self.set_prf(prf);
        self
    }

    pub fn set_prf(&mut self, prf: DigestType) {
        self.prf_digest = prf.into();
        self.prf_type = prf;
    }

    /// Override the integrity/hash digest, keeping the key exchange.
    ///
    /// IKEv2 sends KEi before the responder has chosen the transforms, so the
    /// negotiated algorithms are applied to an existing key pair rather than
    /// through [`Crypto::with_parameters`], which would generate a new one and
    /// invalidate the KE payload already on the wire.
    pub fn set_digest(&mut self, digest: DigestType) {
        self.digest = digest.into();
        self.digest_type = digest;
    }

    /// Override the cipher, keeping the key exchange. See
    /// [`Crypto::set_digest`].
    pub fn set_cipher(&mut self, cipher: CipherType) {
        self.cipher = cipher.into();
        self.cipher_type = cipher;
    }

    pub fn public_key(&self) -> anyhow::Result<Bytes> {
        match &self.kex {
            KeyExchange::Modp(dh) => left_pad(&dh.public_key().to_vec(), self.group_type.public_key_len()),
            KeyExchange::Ecp(pkey) => {
                let ec_group = self.group_type.ec_group()?;
                let mut ctx = BigNumContext::new()?;
                let point =
                    pkey.ec_key()?
                        .public_key()
                        .to_bytes(&ec_group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;

                // strip the 0x04 uncompressed-point marker: IKE carries x || y
                Ok(Bytes::copy_from_slice(
                    point.get(1..).context("Malformed EC public key")?,
                ))
            }
        }
    }

    pub fn shared_secret(&self, public_key: &[u8]) -> anyhow::Result<Bytes> {
        match &self.kex {
            KeyExchange::Modp(dh) => {
                let peer = BigNum::from_slice(public_key)?;
                let one = BigNum::from_u32(1)?;

                // 1 < peer < p - 1, otherwise the shared secret is degenerate
                let mut limit = BigNum::new()?;
                limit.checked_sub(dh.prime_p(), &one)?;

                if peer <= one || peer >= limit {
                    return Err(anyhow!("Peer public key is out of range"));
                }

                left_pad(&dh.compute_key(&peer)?, self.group_type.shared_secret_len())
            }
            KeyExchange::Ecp(pkey) => {
                let expected = self.group_type.public_key_len();
                if public_key.len() != expected {
                    return Err(anyhow!(
                        "Peer public key is {} bytes, expected {}",
                        public_key.len(),
                        expected
                    ));
                }

                let ec_group = self.group_type.ec_group()?;
                let mut ctx = BigNumContext::new()?;

                let mut encoded = Vec::with_capacity(1 + public_key.len());
                encoded.push(0x04); // uncompressed point
                encoded.extend_from_slice(public_key);

                let point = EcPoint::from_bytes(&ec_group, &encoded, &mut ctx)?;
                let peer = EcKey::from_public_key(&ec_group, &point)?;
                peer.check_key().context("Peer public key is not on the curve")?;

                let peer = PKey::from_ec_key(peer)?;

                let mut deriver = Deriver::new(pkey)?;
                deriver.set_peer(&peer)?;

                // ECDH yields the x coordinate, already padded to the field size
                Ok(deriver.derive_to_vec()?.into())
            }
        }
    }

    fn hmac<I, R>(&self, digest: MessageDigest, key: &[u8], data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<[u8]>,
    {
        let key = PKey::hmac(key)?;

        let mut signer = Signer::new(digest, &key)?;
        for d in data.into_iter() {
            signer.update(d.as_ref())?;
        }

        Ok(signer.sign_to_vec()?.into())
    }

    pub fn prf<I, R>(&self, key: &[u8], data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<[u8]>,
    {
        self.hmac(self.prf_digest, key, data)
    }

    /// `prf+` key expansion, RFC 7296 §2.13:
    ///
    /// ```text
    /// prf+(K,S) = T1 | T2 | T3 | ...
    /// T1 = prf(K, S | 0x01)
    /// Tn = prf(K, T(n-1) | S | n)
    /// ```
    pub fn prf_plus(&self, key: &[u8], seed: &[u8], out_len: usize) -> anyhow::Result<Bytes> {
        let mut out = BytesMut::with_capacity(out_len);
        let mut block = Bytes::new();
        let mut counter = 0u8;

        while out.len() < out_len {
            counter = counter
                .checked_add(1)
                .context("prf+ cannot produce more than 255 blocks")?;

            block = self.prf(key, [block.as_ref(), seed, &[counter][..]])?;
            out.extend_from_slice(&block);
        }

        out.truncate(out_len);
        Ok(out.freeze())
    }

    /// Integrity checksum truncated per the negotiated integrity transform.
    pub fn integrity<I, R>(&self, key: &[u8], data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<[u8]>,
    {
        let mut mac = self.hmac(self.digest, key, data)?;
        mac.truncate(self.digest_type.integrity_len());
        Ok(mac)
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
        if self.cipher_type.is_aead() {
            return Err(anyhow!(
                "Cipher {:?} is AEAD, use encrypt_aead/decrypt_aead",
                self.cipher_type
            ));
        }

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

    /// AEAD encryption. `nonce` is the full salt || IV value; `aad` is the
    /// associated data authenticated but not encrypted. Returns
    /// `ciphertext || ICV`.
    pub fn encrypt_aead(&self, key: &[u8], data: &[u8], nonce: &[u8], aad: &[u8]) -> anyhow::Result<Bytes> {
        self.check_aead(key, nonce)?;

        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, key, Some(nonce))?;
        crypter.pad(false);
        crypter.aad_update(aad)?;

        let mut out = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut out)?;
        let rest = crypter.finalize(&mut out[count..])?;
        out.truncate(count + rest);

        let mut icv = vec![0u8; self.cipher_type.icv_len()];
        crypter.get_tag(&mut icv)?;
        out.extend_from_slice(&icv);

        Ok(out.into())
    }

    /// AEAD decryption. `data` is `ciphertext || ICV`; fails if the ICV does
    /// not authenticate both the ciphertext and `aad`.
    pub fn decrypt_aead(&self, key: &[u8], data: &[u8], nonce: &[u8], aad: &[u8]) -> anyhow::Result<Bytes> {
        self.check_aead(key, nonce)?;

        let icv_len = self.cipher_type.icv_len();
        if data.len() < icv_len {
            return Err(anyhow!("AEAD ciphertext is shorter than its ICV"));
        }
        let (ciphertext, icv) = data.split_at(data.len() - icv_len);

        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, key, Some(nonce))?;
        crypter.pad(false);
        crypter.aad_update(aad)?;

        let mut out = vec![0; ciphertext.len() + self.cipher.block_size()];
        let count = crypter.update(ciphertext, &mut out)?;
        crypter.set_tag(icv)?;
        let rest = crypter.finalize(&mut out[count..]).context("AEAD ICV mismatch")?;
        out.truncate(count + rest);

        Ok(out.into())
    }

    fn check_aead(&self, key: &[u8], nonce: &[u8]) -> anyhow::Result<()> {
        if !self.cipher_type.is_aead() {
            return Err(anyhow!("Cipher {:?} is not AEAD", self.cipher_type));
        }
        if key.len() != self.cipher_type.key_len() {
            return Err(anyhow!(
                "AEAD key is {} bytes, expected {}",
                key.len(),
                self.cipher_type.key_len()
            ));
        }
        if nonce.len() != self.cipher_type.nonce_len() {
            return Err(anyhow!(
                "AEAD nonce is {} bytes, expected {}",
                nonce.len(),
                self.cipher_type.nonce_len()
            ));
        }
        Ok(())
    }

    pub fn block_size(&self) -> usize {
        self.cipher_type.block_size()
    }

    pub fn key_len(&self) -> usize {
        self.cipher_type.key_len()
    }

    /// Keying material to draw for the cipher: key || salt.
    pub fn key_material_len(&self) -> usize {
        self.cipher_type.key_material_len()
    }

    pub fn salt_len(&self) -> usize {
        self.cipher_type.salt_len()
    }

    pub fn iv_len(&self) -> usize {
        self.cipher_type.iv_len()
    }

    pub fn icv_len(&self) -> usize {
        self.cipher_type.icv_len()
    }

    pub fn is_aead(&self) -> bool {
        self.cipher_type.is_aead()
    }

    pub fn hash_len(&self) -> usize {
        self.digest.size()
    }

    pub fn prf_len(&self) -> usize {
        self.prf_digest.size()
    }

    pub fn integrity_len(&self) -> usize {
        self.digest_type.integrity_len()
    }

    pub fn digest_type(&self) -> DigestType {
        self.digest_type
    }

    pub fn prf_type(&self) -> DigestType {
        self.prf_type
    }

    pub fn cipher_type(&self) -> CipherType {
        self.cipher_type
    }

    pub fn group_type(&self) -> GroupType {
        self.group_type
    }

    /// Verifies an IKEv2 AUTH payload of method 1 (RSA Digital Signature):
    /// RSASSA-PKCS1-v1_5 over the signed octets, *with* the DigestInfo prefix
    /// that IKEv1's raw construction in [`Crypto::verify_signature`] omits.
    ///
    /// RFC 7296 §3.8 only says implementations SHOULD support SHA-1 here, so
    /// the caller passes the hash to try; there is nothing on the wire that
    /// names it (that is what RFC 7427 method 14 added).
    pub fn verify_rsa_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        cert: &[u8],
        digest: DigestType,
    ) -> anyhow::Result<()> {
        let public_key = X509::from_der(cert)?.public_key()?;

        let mut verifier = Verifier::new(digest.into(), &public_key)?;
        verifier.update(data)?;

        verifier
            .verify(signature)?
            .then_some(())
            .context("Signature verification failed!")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto(digest: DigestType, cipher: CipherType) -> Crypto {
        Crypto::with_parameters(digest, cipher, GroupType::Oakley2).unwrap()
    }

    /// prf+ key expansion, RFC 7296 §2.13. Known answers computed independently
    /// with Python's `hmac` over the same key/seed.
    #[test]
    fn test_prf_plus_known_answers() {
        let key: Vec<u8> = (0..32).collect();
        let seed = b"IKEv2 prf+ test seed";

        for (digest, out_len, expected) in [
            (
                DigestType::Sha256,
                100,
                "59e1e7fb5d67b2849d8ba06e3615cafdf318a857729681ad3b63c957201302b00f49671912437f29ccf49907d\
                 f788b42694ff309f825732d459b2432ea3f664ef9b5981ed1ba639d0942c940a4a4f20fc83ee1adbc31bcf48b\
                 22c4feb4252428348a6b5c",
            ),
            (
                DigestType::Sha1,
                64,
                "43584c1be65ad03f8049220aebaca5b9740ea97de63a7906f065cf17d56bd2a4f05c9d1842748c91255964d1\
                 ee9fa7b54db0997a85c8a7e23e92ae6388bc9136",
            ),
            (
                DigestType::Sha512,
                32,
                "187f484f55f93b9f4d2fc344a47e17238d804c4cf0f078c42b4d60cb20dd7cca",
            ),
        ] {
            let crypto = crypto(digest, CipherType::Aes256Cbc);
            let out = crypto.prf_plus(&key, seed, out_len).unwrap();

            assert_eq!(out.len(), out_len);
            assert_eq!(hex::encode(&out), expected.replace(' ', ""), "digest {digest:?}");
        }
    }

    /// Every prefix of prf+ output is itself prf+ output: the chain does not
    /// depend on the requested length.
    #[test]
    fn test_prf_plus_is_a_prefix_chain() {
        let crypto = crypto(DigestType::Sha256, CipherType::Aes256Cbc);
        let full = crypto.prf_plus(b"key", b"seed", 128).unwrap();

        for len in [1, 31, 32, 33, 64, 96, 127] {
            assert_eq!(crypto.prf_plus(b"key", b"seed", len).unwrap(), full.slice(..len));
        }
    }

    /// The first block of prf+ is prf(K, S | 0x01), the second prf(K, T1 | S | 0x02).
    #[test]
    fn test_prf_plus_matches_manual_chaining() {
        let crypto = crypto(DigestType::Sha256, CipherType::Aes256Cbc);

        let t1 = crypto.prf(b"key", [b"seed".as_ref(), &[1]]).unwrap();
        let t2 = crypto.prf(b"key", [t1.as_ref(), b"seed".as_ref(), &[2]]).unwrap();

        let mut expected = t1.to_vec();
        expected.extend_from_slice(&t2);

        assert_eq!(crypto.prf_plus(b"key", b"seed", 64).unwrap(), expected);
    }

    #[test]
    fn test_prf_plus_rejects_overlong_output() {
        let crypto = crypto(DigestType::Sha256, CipherType::Aes256Cbc);

        assert!(crypto.prf_plus(b"key", b"seed", 255 * 32).is_ok());
        assert!(crypto.prf_plus(b"key", b"seed", 255 * 32 + 1).is_err());
    }

    /// IKEv2 negotiates the PRF independently of the integrity algorithm.
    #[test]
    fn test_prf_is_independent_of_digest() {
        let integ_only = crypto(DigestType::Sha256, CipherType::Aes256Cbc);
        let with_prf = crypto(DigestType::Sha256, CipherType::Aes256Cbc).with_prf(DigestType::Sha512);

        assert_eq!(integ_only.prf_len(), 32);
        assert_eq!(with_prf.prf_len(), 64);
        assert_eq!(with_prf.hash_len(), 32, "hash still follows the integrity digest");
        assert_eq!(with_prf.prf_type(), DigestType::Sha512);
        assert_eq!(with_prf.digest_type(), DigestType::Sha256);

        let sha512 = crypto(DigestType::Sha512, CipherType::Aes256Cbc);
        assert_eq!(
            with_prf.prf(b"key", [b"data"]).unwrap(),
            sha512.prf(b"key", [b"data"]).unwrap()
        );
    }

    /// Without `with_prf` the PRF is the negotiated digest, as IKEv1 expects.
    #[test]
    fn test_prf_defaults_to_digest() {
        let crypto = crypto(DigestType::Sha256, CipherType::Aes256Cbc);

        assert_eq!(crypto.prf_type(), crypto.digest_type());
        assert_eq!(crypto.prf_len(), crypto.hash_len());
    }

    #[test]
    fn test_integrity_is_truncated() {
        for (digest, len) in [
            (DigestType::Sha1, 12),
            (DigestType::Sha256, 16),
            (DigestType::Sha384, 24),
            (DigestType::Sha512, 32),
        ] {
            let crypto = crypto(digest, CipherType::Aes256Cbc);
            let icv = crypto.integrity(b"key", [b"data"]).unwrap();

            assert_eq!(icv.len(), len, "digest {digest:?}");
            assert_eq!(icv, crypto.prf(b"key", [b"data"]).unwrap().slice(..len));
        }
    }

    // NIST/McGrew-Viega AES-GCM test cases 4 (128-bit key) and 16 (256-bit key).
    const GCM_IV: &str = "cafebabefacedbaddecaf888";
    const GCM_AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    const GCM_PT: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                          1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";

    #[test]
    fn test_aes_gcm_known_answers() {
        let cases = [
            (
                "feffe9928665731c6d6a8f9467308308",
                CipherType::Aes128Gcm(IcvLength::Sixteen),
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                "5bc94fbc3221a5db94fae95ae7121a47",
            ),
            (
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                CipherType::Aes256Gcm(IcvLength::Sixteen),
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                 8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
                "76fc6ece0f4e1768cddf8853bb2d551b",
            ),
        ];

        for (key, cipher_type, ciphertext, icv) in cases {
            let crypto = crypto(DigestType::Sha256, cipher_type);
            let key = hex::decode(key).unwrap();
            let nonce = hex::decode(GCM_IV).unwrap();
            let aad = hex::decode(GCM_AAD).unwrap();
            let plaintext = hex::decode(GCM_PT.replace(' ', "")).unwrap();
            let expected = format!("{}{}", ciphertext.replace(' ', ""), icv);

            let encrypted = crypto.encrypt_aead(&key, &plaintext, &nonce, &aad).unwrap();
            assert_eq!(hex::encode(&encrypted), expected, "cipher {cipher_type:?}");

            let decrypted = crypto.decrypt_aead(&key, &encrypted, &nonce, &aad).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    /// ENCR_AES_GCM_8 / _12 simply truncate the 16-octet tag.
    #[test]
    fn test_aes_gcm_truncated_icv() {
        let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let nonce = hex::decode(GCM_IV).unwrap();
        let aad = hex::decode(GCM_AAD).unwrap();
        let plaintext = hex::decode(GCM_PT.replace(' ', "")).unwrap();

        for (icv_len, expected) in [
            (IcvLength::Eight, "5bc94fbc3221a5db"),
            (IcvLength::Twelve, "5bc94fbc3221a5db94fae95a"),
        ] {
            let crypto = crypto(DigestType::Sha256, CipherType::Aes128Gcm(icv_len));
            let encrypted = crypto.encrypt_aead(&key, &plaintext, &nonce, &aad).unwrap();

            assert_eq!(encrypted.len(), plaintext.len() + icv_len.size());
            assert_eq!(hex::encode(&encrypted[plaintext.len()..]), expected);
            assert_eq!(crypto.decrypt_aead(&key, &encrypted, &nonce, &aad).unwrap(), plaintext);
        }
    }

    #[test]
    fn test_aes_gcm_rejects_tampering() {
        let crypto = crypto(DigestType::Sha256, CipherType::Aes256Gcm(IcvLength::Sixteen));
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let aad = b"ikev2 header";

        let encrypted = crypto.encrypt_aead(&key, b"payload", &nonce, aad).unwrap();

        // flipping the ICV, the ciphertext, the AAD or the nonce all fail
        let mut bad_icv = encrypted.to_vec();
        *bad_icv.last_mut().unwrap() ^= 1;
        assert!(crypto.decrypt_aead(&key, &bad_icv, &nonce, aad).is_err());

        let mut bad_ct = encrypted.to_vec();
        bad_ct[0] ^= 1;
        assert!(crypto.decrypt_aead(&key, &bad_ct, &nonce, aad).is_err());

        assert!(crypto.decrypt_aead(&key, &encrypted, &nonce, b"other header").is_err());
        assert!(crypto.decrypt_aead(&key, &encrypted, &[0x12u8; 12], aad).is_err());
        assert!(crypto.decrypt_aead(&key, &encrypted[..8], &nonce, aad).is_err());
    }

    #[test]
    fn test_aead_and_cbc_apis_do_not_mix() {
        let gcm = crypto(DigestType::Sha256, CipherType::Aes256Gcm(IcvLength::Sixteen));
        assert!(gcm.encrypt(&[0x42; 32], b"payload_16bytes!", &[0x11; 16]).is_err());
        assert!(gcm.decrypt(&[0x42; 32], b"payload_16bytes!", &[0x11; 16]).is_err());

        let cbc = crypto(DigestType::Sha256, CipherType::Aes256Cbc);
        assert!(cbc.encrypt_aead(&[0x42; 32], b"payload", &[0x11; 12], b"").is_err());
        assert!(cbc.decrypt_aead(&[0x42; 32], b"payload", &[0x11; 12], b"").is_err());

        // wrong key or nonce length is caught before openssl sees it
        assert!(gcm.encrypt_aead(&[0x42; 16], b"payload", &[0x11; 12], b"").is_err());
        assert!(gcm.encrypt_aead(&[0x42; 32], b"payload", &[0x11; 8], b"").is_err());
    }

    #[test]
    fn test_cipher_geometry() {
        let gcm = CipherType::Aes256Gcm(IcvLength::Sixteen);
        assert!(gcm.is_aead());
        assert_eq!((gcm.key_len(), gcm.salt_len(), gcm.key_material_len()), (32, 4, 36));
        assert_eq!((gcm.iv_len(), gcm.nonce_len(), gcm.icv_len()), (8, 12, 16));
        assert_eq!(gcm.block_size(), 4);

        let cbc = CipherType::Aes128Cbc;
        assert!(!cbc.is_aead());
        assert_eq!((cbc.key_len(), cbc.salt_len(), cbc.key_material_len()), (16, 0, 16));
        assert_eq!((cbc.iv_len(), cbc.nonce_len(), cbc.icv_len()), (16, 16, 0));
        assert_eq!(cbc.block_size(), 16);

        assert_eq!(CipherType::DesEde3Cbc.iv_len(), 8);
    }

    #[test]
    fn test_ikev2_encr_transform_ids() {
        assert_eq!(CipherType::new_for_ikev2(3, 24).unwrap(), CipherType::DesEde3Cbc);
        assert_eq!(CipherType::new_for_ikev2(12, 32).unwrap(), CipherType::Aes256Cbc);
        assert_eq!(
            CipherType::new_for_ikev2(18, 16).unwrap(),
            CipherType::Aes128Gcm(IcvLength::Eight)
        );
        assert_eq!(
            CipherType::new_for_ikev2(19, 24).unwrap(),
            CipherType::Aes192Gcm(IcvLength::Twelve)
        );
        assert_eq!(
            CipherType::new_for_ikev2(20, 32).unwrap(),
            CipherType::Aes256Gcm(IcvLength::Sixteen)
        );

        assert!(CipherType::new_for_ikev2(12, 20).is_err());
        assert!(CipherType::new_for_ikev2(3, 16).is_err());
        assert!(CipherType::new_for_ikev2(23, 16).is_err());
    }

    #[test]
    fn test_group_ids_round_trip() {
        for group in [
            GroupType::Oakley2,
            GroupType::Oakley14,
            GroupType::EcP256,
            GroupType::EcP384,
            GroupType::EcP521,
        ] {
            assert_eq!(GroupType::from_group_id(group.group_id()).unwrap(), group);
        }

        assert!(GroupType::from_group_id(1).is_err());
    }

    /// Both peers derive the same secret, and both the KE payload and the
    /// secret are zero-padded to the group's fixed width (RFC 7296 §2.14).
    #[test]
    fn test_key_exchange_agrees_and_is_padded() {
        for group in [
            GroupType::Oakley2,
            GroupType::Oakley14,
            GroupType::EcP256,
            GroupType::EcP384,
            GroupType::EcP521,
        ] {
            let initiator = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, group).unwrap();
            let responder = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, group).unwrap();

            let ke_i = initiator.public_key().unwrap();
            let ke_r = responder.public_key().unwrap();

            assert_eq!(ke_i.len(), group.public_key_len(), "KE payload width, {group:?}");
            assert_eq!(ke_r.len(), group.public_key_len(), "KE payload width, {group:?}");

            let secret_i = initiator.shared_secret(&ke_r).unwrap();
            let secret_r = responder.shared_secret(&ke_i).unwrap();

            assert_eq!(secret_i, secret_r, "shared secret mismatch, {group:?}");
            assert_eq!(secret_i.len(), group.shared_secret_len(), "secret width, {group:?}");
        }
    }

    #[test]
    fn test_modp_rejects_degenerate_peer_keys() {
        let crypto = crypto(DigestType::Sha256, CipherType::Aes256Cbc);

        // p - 1, p, 1 and 0 all yield a degenerate or invalid shared secret
        let mut p_minus_1 = G2_P.to_vec();
        *p_minus_1.last_mut().unwrap() = 254;

        for peer in [p_minus_1, G2_P.to_vec(), vec![1], vec![0], vec![0xff; 128]] {
            assert!(crypto.shared_secret(&peer).is_err(), "accepted {}", hex::encode(&peer));
        }

        // a legitimate peer key still works
        let peer = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, GroupType::Oakley2).unwrap();
        assert!(crypto.shared_secret(&peer.public_key().unwrap()).is_ok());
    }

    #[test]
    fn test_ecp_rejects_invalid_peer_keys() {
        let crypto = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, GroupType::EcP256).unwrap();

        // wrong width, and a correctly sized point that is not on the curve
        assert!(crypto.shared_secret(&[0u8; 32]).is_err());
        assert!(crypto.shared_secret(&[0u8; 65]).is_err());
        assert!(crypto.shared_secret(&[0u8; 64]).is_err());
        assert!(crypto.shared_secret(&[0xaa; 64]).is_err());
    }

    /// The DigestInfo prefixes of RFC 8017 §9.2, pinned against the hash of an
    /// empty input, and then shown to be exactly what a standard RSASSA-PKCS1-v1_5
    /// signature is made over: a PKCS#1-padded private encryption of this blob
    /// must verify as an ordinary signature over the data.
    #[test]
    fn test_digest_info_is_an_rsa_pkcs1_signature_input() {
        assert_eq!(
            hex::encode(DigestType::Sha1.digest_info(b"").unwrap()),
            "3021300906052b0e03021a05000414da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex::encode(DigestType::Sha256.digest_info(b"").unwrap()),
            "3031300d060960864801650304020105000420\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa.clone()).unwrap();
        let data = b"InitiatorSignedOctets";

        for digest in [DigestType::Sha1, DigestType::Sha256, DigestType::Sha512] {
            let info = digest.digest_info(data).unwrap();

            // what `ClientCertificate::sign` does with the blob
            let mut signature = vec![0u8; rsa.size() as usize];
            let len = rsa.private_encrypt(&info, &mut signature, Padding::PKCS1).unwrap();
            signature.truncate(len);

            let mut verifier = Verifier::new(digest.into(), &key).unwrap();
            verifier.update(data).unwrap();
            assert!(verifier.verify(&signature).unwrap(), "{digest:?}");
        }
    }

    #[test]
    fn test_left_pad() {
        assert_eq!(left_pad(&[1, 2], 4).unwrap(), Bytes::from_static(&[0, 0, 1, 2]));
        assert_eq!(left_pad(&[1, 2], 2).unwrap(), Bytes::from_static(&[1, 2]));
        assert!(left_pad(&[1, 2, 3], 2).is_err());
    }
}
