//! Types shared by the IKEv1 and IKEv2 models.
//!
//! The two versions agree on almost no wire numbering, so each keeps its own
//! registries in [`crate::ikev1::model`] and [`crate::ikev2::model`]. What
//! lives here is what they do share: the [`registry!`] macro both are written
//! with, the attribute TLV both encode, and the version-neutral types that the
//! crypto and ESP layers consume once a negotiation has resolved its own wire
//! values.

use std::{io::Read, path::PathBuf};

use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use secrecy::SecretString;

use crate::crypto::{CipherType, DigestType};

/// Check Point vendor ID, sent by both versions to ask the gateway for its
/// proprietary extensions. The version-specific vendor IDs live in
/// [`crate::ikev1::model`].
pub const VID_CHECKPOINT: &[u8] = b"\xde\xfb\x99\xe6\x9a\x9f\x1f\x6e\x06\xf1\x50\x06\xb1\xf1\x66\xae";

/// Declares a wire registry: an enum of the values a field is known to take,
/// plus a fallback variant so unknown ones survive a decode/encode cycle
/// unchanged, and the `From` conversions in both directions.
///
/// The fallback is named `Other` unless a different name is given with `as`.
/// Attributes pass through, so `#[derive(Default)]` on the registry and
/// `#[default]` on one variant work as usual.
///
/// ```ignore
/// registry! {
///     /// Exchange types, RFC 7296 §3.1.
///     ExchangeType: u8 {
///         IkeSaInit = 34,
///         IkeAuth = 35,
///     }
/// }
/// ```
macro_rules! registry {
    (
        $(#[$meta:meta])* $name:ident : $repr:ty as $fallback:ident {
            $($(#[$vmeta:meta])* $variant:ident = $value:expr),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)*
            $fallback($repr),
        }

        impl From<$repr> for $name {
            fn from(value: $repr) -> Self {
                match value {
                    $($value => Self::$variant,)*
                    other => Self::$fallback(other),
                }
            }
        }

        impl From<$name> for $repr {
            fn from(value: $name) -> Self {
                match value {
                    $($name::$variant => $value,)*
                    $name::$fallback(other) => other,
                }
            }
        }
    };

    (
        $(#[$meta:meta])* $name:ident : $repr:ty {
            $($(#[$vmeta:meta])* $variant:ident = $value:expr),* $(,)?
        }
    ) => {
        registry! {
            $(#[$meta])* $name : $repr as Other {
                $($(#[$vmeta])* $variant = $value),*
            }
        }
    };
}

pub(crate) use registry;

/// Value of a [`DataAttribute`]: either inline in the header or appended after
/// an explicit length.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AttributeValue {
    Short(u16),
    Long(Bytes),
}

/// The attribute TLV both versions encode the same way: RFC 2408 §3.3 for
/// IKEv1 data attributes, RFC 7296 §3.3.5 for IKEv2 transform attributes. The
/// top bit of the type selects between a 2-octet value carried in the length
/// field and a length-prefixed one that follows.
///
/// The IKEv2 configuration payload uses a *different* TLV with no short form;
/// see [`crate::ikev2::payload::ConfigurationAttribute`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DataAttribute {
    pub attribute_type: u16,
    pub value: AttributeValue,
}

impl DataAttribute {
    pub fn short(attribute_type: u16, value: u16) -> Self {
        Self {
            attribute_type,
            value: AttributeValue::Short(value),
        }
    }

    pub fn long(attribute_type: u16, value: Bytes) -> Self {
        Self {
            attribute_type,
            value: AttributeValue::Long(value),
        }
    }

    pub fn as_short(&self) -> Option<u16> {
        match self.value {
            AttributeValue::Short(v) => Some(v),
            AttributeValue::Long(_) => None,
        }
    }

    pub fn as_long(&self) -> Option<&Bytes> {
        match self.value {
            AttributeValue::Short(_) => None,
            AttributeValue::Long(ref v) => Some(v),
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        match self.value {
            AttributeValue::Short(v) => {
                buf.put_u16(self.attribute_type | 0x8000);
                buf.put_u16(v);
            }
            AttributeValue::Long(ref v) => {
                buf.put_u16(self.attribute_type);
                buf.put_u16(v.len() as u16);
                buf.put_slice(v);
            }
        }
        buf.freeze()
    }

    pub fn len(&self) -> usize {
        match self.value {
            AttributeValue::Short(_) => 4,
            AttributeValue::Long(ref v) => 4 + v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let attribute_type = reader.read_u16::<BigEndian>()?;
        let length_or_value = reader.read_u16::<BigEndian>()?;

        if (attribute_type & 0x8000) != 0 {
            Ok(Self {
                attribute_type: attribute_type & 0x7fff,
                value: AttributeValue::Short(length_or_value),
            })
        } else {
            let mut data = vec![0u8; length_or_value as _];
            reader.read_exact(&mut data)?;
            Ok(Self {
                attribute_type,
                value: AttributeValue::Long(data.into()),
            })
        }
    }
}

/// How the client proves who it is, whichever version negotiates it.
#[derive(Debug, Clone, Default)]
pub enum Identity {
    #[default]
    None,
    Pkcs12 {
        data: Vec<u8>,
        password: SecretString,
        hybrid_auth: bool,
    },
    Pkcs8 {
        path: PathBuf,
        hybrid_auth: bool,
    },
    Pkcs11 {
        driver_path: PathBuf,
        pin: SecretString,
        key_id: Option<Bytes>,
        hybrid_auth: bool,
    },
    #[cfg(windows)]
    System {
        common_name: String,
    },
}

/// Integrity algorithm for an ESP SA, resolved from whichever IKE version
/// negotiated it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EspAuthentication {
    pub digest: DigestType,
    /// Truncated ICV length carried in the packet, which is not always half
    /// the digest size (HMAC-SHA1-160 keeps all 20 octets).
    pub icv_len: usize,
}

/// Keys and algorithms for one ESP SA.
///
/// Deliberately version-neutral: the negotiating session resolves its own wire
/// registry into these crypto types. The two versions cannot share a registry
/// here — [`crate::ikev1::model::EspAuthAlgorithm`] reads 5 as HMAC-SHA2-256,
/// while the same value in [`crate::ikev2::model::IntegrityAlgorithm`] is
/// AUTH_AES_XCBC_96, which is not an HMAC at all. Carrying a raw transform
/// number would silently select the wrong algorithm for one of the two.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct EspCryptMaterial {
    pub spi: u32,
    pub sk_e: Bytes,
    pub sk_a: Bytes,
    pub cipher: CipherType,
    /// `None` for an AEAD cipher, which authenticates its own output.
    pub auth: Option<EspAuthentication>,
}

impl EspCryptMaterial {
    /// ICV length appended to each ESP packet.
    pub fn icv_len(&self) -> usize {
        match self.auth {
            Some(auth) => auth.icv_len,
            None => self.cipher.icv_len(),
        }
    }
}
