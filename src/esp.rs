use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use bytes::Bytes;
use openssl::{
    pkey::PKey,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};
use pnet_macros::Packet;
use pnet_macros_support::types::u32be;
use pnet_packet::{
    MutablePacket, Packet,
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, MutableIpv4Packet, checksum},
    udp::{MutableUdpPacket, UdpPacket},
};
use tokio::time::Instant;

use crate::model::EspCryptMaterial;

#[derive(Packet)]
#[allow(unused)]
pub struct Esp {
    spi: u32be,
    seq: u32be,
    #[payload]
    payload: Vec<u8>,
}

/// Cipher for a CBC + HMAC SA, which carries its integrity key separately.
fn cbc_cipher(params: &EspCryptMaterial) -> anyhow::Result<Cipher> {
    if params.cipher.is_aead() {
        anyhow::bail!("{:?} is an AEAD cipher, not a CBC one", params.cipher);
    }
    check_key_len(params)?;

    Ok(params.cipher.into())
}

/// Cipher, key and salt for an AEAD SA. RFC 4106 §3 draws four octets of keying
/// material beyond the key proper: the salt, which never appears on the wire
/// and prefixes the explicit IV to form the nonce.
fn aead_cipher(params: &EspCryptMaterial) -> anyhow::Result<(Cipher, &[u8], &[u8])> {
    if !params.cipher.is_aead() {
        anyhow::bail!("{:?} is not an AEAD cipher", params.cipher);
    }
    check_key_len(params)?;

    let (key, salt) = params.sk_e.split_at(params.cipher.key_len());

    Ok((params.cipher.into(), key, salt))
}

fn check_key_len(params: &EspCryptMaterial) -> anyhow::Result<()> {
    let expected = params.cipher.key_material_len();
    if params.sk_e.len() != expected {
        anyhow::bail!(
            "ESP key is {} bytes, {:?} expects {}",
            params.sk_e.len(),
            params.cipher,
            expected
        );
    }

    Ok(())
}

/// ESP authenticates the SPI and sequence number along with the ciphertext: as
/// AAD for an AEAD cipher (RFC 4106 §5), and as the leading HMAC input for
/// CBC + HMAC (RFC 4303 §3.3.2).
fn aad(spi: u32, seq: u32) -> [u8; 8] {
    let mut aad = [0u8; 8];
    aad[0..4].copy_from_slice(&spi.to_be_bytes());
    aad[4..8].copy_from_slice(&seq.to_be_bytes());
    aad
}

/// ESP trailer, RFC 4303 §2.4: padding up to the cipher's alignment, the pad
/// length and the next header.
fn add_trailer(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = (block_size - ((data.len() + 2) % block_size)) % block_size;

    let mut plain = Vec::with_capacity(data.len() + pad_len + 2);
    plain.extend(data);
    plain.extend(1..=pad_len as u8);
    plain.push(pad_len as u8);
    plain.push(4); // next header: IPIP

    plain
}

fn strip_trailer(mut data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    if data.len() < 2 {
        anyhow::bail!("ESP plaintext too short");
    }
    let next_header = data[data.len() - 1];
    if next_header != 4 {
        anyhow::bail!("Invalid next header, should be IPIP");
    }
    let pad_len = data[data.len() - 2] as usize;
    if data.len() < pad_len + 2 {
        anyhow::bail!("Invalid ESP pad length");
    }
    data.truncate(data.len() - pad_len - 2);

    Ok(data)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EspEncapType {
    None,
    Udp,
}

pub struct EspCodec {
    params: HashMap<u32, (Instant, Arc<EspCryptMaterial>)>,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    seq_counter: AtomicU32,
    encap_type: EspEncapType,
    out_spi: Option<u32>,
}

impl EspCodec {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, encap_type: EspEncapType) -> Self {
        Self {
            params: HashMap::new(),
            src,
            dst,
            seq_counter: AtomicU32::new(1),
            encap_type,
            out_spi: None,
        }
    }

    pub fn add_params(&mut self, spi: u32, params: Arc<EspCryptMaterial>, ttl: Duration) {
        self.params
            .retain(|_, (timestamp, _)| (*timestamp + ttl) > Instant::now());

        self.params.insert(spi, (Instant::now(), params));
        self.out_spi = Some(spi);
        self.seq_counter.store(1, Ordering::SeqCst);
    }

    pub fn set_params(&mut self, spi: u32, params: Arc<EspCryptMaterial>) {
        self.params.clear();
        self.params.insert(spi, (Instant::now(), params));
        self.out_spi = Some(spi);
        self.seq_counter.store(1, Ordering::SeqCst);
    }

    fn current_outbound(&self) -> anyhow::Result<(u32, &Arc<EspCryptMaterial>)> {
        let spi = self.out_spi.context("No ESP parameters")?;
        let (_, params) = self.params.get(&spi).context("No ESP parameters")?;
        Ok((spi, params))
    }

    pub fn decode(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        match self.encap_type {
            EspEncapType::None => self.decode_from_esp(data),
            EspEncapType::Udp => self.decode_from_ip_udp(data),
        }
    }

    pub fn encode(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        match self.encap_type {
            EspEncapType::None => self.encode_to_esp(data),
            EspEncapType::Udp => self.encode_to_ip_udp(data),
        }
    }

    fn decode_from_ip_udp(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let ipv4 = Ipv4Packet::new(data).context("Invalid IPv4 packet")?;

        if ipv4.get_source() != self.src || ipv4.get_destination() != self.dst {
            anyhow::bail!(
                "Unexpected IP addresses: {} -> {}",
                ipv4.get_source(),
                ipv4.get_destination()
            );
        }

        let actual_checksum = checksum(&ipv4);
        let packet_checksum = ipv4.get_checksum();

        if packet_checksum != actual_checksum {
            anyhow::bail!(
                "Invalid IPv4 checksum: actual: {:x}, received: {:x}",
                actual_checksum,
                packet_checksum
            );
        }

        let udp = UdpPacket::new(ipv4.payload()).context("Invalid UDP packet")?;

        self.decode_from_esp(udp.payload())
    }

    fn decode_from_esp(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let esp = EspPacket::new(data).context("Invalid ESP packet")?;

        let spi = esp.get_spi();
        let seq = esp.get_seq();

        let (_, params) = self.params.get(&spi).context("Invalid SPI")?;

        Ok(self.open(params, spi, seq, esp.payload())?.into())
    }

    /// Authenticate and decrypt one ESP payload, which is `IV || ciphertext ||
    /// ICV` either way. The AEAD tag covers both the ciphertext and the header
    /// it is fed as AAD, while CBC + HMAC has the ICV computed separately over
    /// everything that precedes it.
    fn open(&self, params: &EspCryptMaterial, spi: u32, seq: u32, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let aad = aad(spi, seq);

        if params.cipher.is_aead() {
            return self.decrypt_aead(params, payload, &aad);
        }

        let icv_len = params.icv_len();
        if payload.len() < icv_len {
            anyhow::bail!("ESP payload shorter than ICV");
        }
        let (data, auth) = payload.split_at(payload.len() - icv_len);

        self.verify(params, &[&aad, data], auth)?;

        self.decrypt(params, data)
    }

    /// Encrypt one payload and bind it to the next sequence number, which the
    /// ICV covers and, for AEAD, the nonce is derived from. Returns that
    /// sequence number together with the ESP payload.
    fn seal(&self, params: &EspCryptMaterial, spi: u32, data: &[u8]) -> anyhow::Result<(u32, Vec<u8>)> {
        let seq = self.seq_counter.fetch_add(1, Ordering::SeqCst);
        let aad = aad(spi, seq);

        let payload = if params.cipher.is_aead() {
            self.encrypt_aead(params, seq, data, &aad)?
        } else {
            let mut payload = self.encrypt(params, data)?;
            let auth = self.authenticate(params, &[&aad, &payload])?;
            payload.extend(auth);
            payload
        };

        Ok((seq, payload))
    }

    fn encode_to_ip_udp(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let (spi, params) = self.current_outbound()?;

        let (next_seq, data) = self.seal(params, spi, data)?;

        let mut buffer = vec![
            0u8;
            Ipv4Packet::minimum_packet_size()
                + UdpPacket::minimum_packet_size()
                + EspPacket::minimum_packet_size()
                + data.len()
        ];

        let total_len = buffer.len();

        let mut ipv4 = MutableIpv4Packet::new(&mut buffer).context("Invalid IPv4 packet")?;
        ipv4.set_source(self.src);
        ipv4.set_destination(self.dst);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4.set_version(4);
        ipv4.set_flags(2);
        ipv4.set_ttl(64);
        ipv4.set_header_length(5);
        ipv4.set_total_length(total_len as u16);

        let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).context("Invalid UDP packet")?;
        udp.set_source(4500);
        udp.set_destination(4500);
        udp.set_length((data.len() + EspPacket::minimum_packet_size() + UdpPacket::minimum_packet_size()) as u16);

        let mut esp = MutableEspPacket::new(udp.payload_mut()).context("Invalid ESP packet")?;
        esp.set_spi(spi);
        esp.set_seq(next_seq);
        esp.set_payload(&data);

        ipv4.set_checksum(checksum(&ipv4.to_immutable()));

        Ok(buffer.into())
    }

    fn encode_to_esp(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let (spi, params) = self.current_outbound()?;

        let (next_seq, data) = self.seal(params, spi, data)?;

        let mut buffer = vec![0u8; data.len() + EspPacket::minimum_packet_size()];

        let mut esp = MutableEspPacket::new(&mut buffer).context("Invalid ESP packet")?;
        esp.set_spi(spi);
        esp.set_seq(next_seq);
        esp.set_payload(&data);

        Ok(buffer.into())
    }

    fn encrypt(&self, params: &EspCryptMaterial, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let cipher = cbc_cipher(params)?;

        let mut iv = vec![0u8; cipher.iv_len().unwrap_or_default()];
        rand::fill(&mut iv[..]);
        let iv = &iv[..];

        let plain = add_trailer(data, params.cipher.block_size());

        let mut out = vec![0u8; iv.len() + plain.len() + cipher.block_size()];

        out[0..iv.len()].copy_from_slice(iv);

        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &params.sk_e, Some(iv))?;
        crypter.pad(false);

        let mut count = crypter.update(&plain, &mut out[iv.len()..])?;
        count += crypter.finalize(&mut out[iv.len() + count..])?;

        out.truncate(count + iv.len());
        Ok(out)
    }

    /// RFC 4106: `IV || ciphertext || ICV`, where the nonce is the implicit
    /// salt followed by the explicit IV. The IV only has to be unique per key
    /// (§3.1), so the sequence number the packet already carries serves as the
    /// counter — the keys are freshly derived for every SA, and the counter is
    /// reset alongside them.
    fn encrypt_aead(&self, params: &EspCryptMaterial, seq: u32, data: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (cipher, key, salt) = aead_cipher(params)?;

        let iv = (seq as u64).to_be_bytes();
        let nonce = [salt, &iv[..]].concat();

        let plain = add_trailer(data, params.cipher.block_size());

        let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&nonce))?;
        crypter.pad(false);
        crypter.aad_update(aad)?;

        let mut out = vec![0u8; iv.len() + plain.len() + cipher.block_size()];
        out[0..iv.len()].copy_from_slice(&iv);

        let mut count = crypter.update(&plain, &mut out[iv.len()..])?;
        count += crypter.finalize(&mut out[iv.len() + count..])?;

        out.truncate(count + iv.len());

        let mut icv = vec![0u8; params.cipher.icv_len()];
        crypter.get_tag(&mut icv)?;
        out.extend(icv);

        Ok(out)
    }

    fn decrypt_aead(&self, params: &EspCryptMaterial, data: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (cipher, key, salt) = aead_cipher(params)?;

        let iv_len = params.cipher.iv_len();
        let icv_len = params.cipher.icv_len();

        if data.len() < iv_len + icv_len {
            anyhow::bail!("ESP payload shorter than IV and ICV");
        }

        let (data, icv) = data.split_at(data.len() - icv_len);
        let (iv, ciphertext) = data.split_at(iv_len);
        let nonce = [salt, iv].concat();

        let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(&nonce))?;
        crypter.pad(false);
        crypter.aad_update(aad)?;

        let mut out = vec![0u8; ciphertext.len() + cipher.block_size()];
        let mut count = crypter.update(ciphertext, &mut out)?;

        crypter.set_tag(icv)?;
        count += crypter
            .finalize(&mut out[count..])
            .context("Invalid packet signature")?;

        out.truncate(count);

        strip_trailer(out)
    }

    fn authenticate(&self, params: &EspCryptMaterial, parts: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
        let auth = params.auth.context("ESP SA has no integrity algorithm")?;

        let key = PKey::hmac(&params.sk_a)?;
        let mut signer = Signer::new(auth.digest.into(), &key)?;

        for part in parts {
            signer.update(part)?;
        }

        let mut hmac = signer.sign_to_vec()?;
        hmac.truncate(auth.icv_len);

        Ok(hmac)
    }

    fn verify(&self, params: &EspCryptMaterial, parts: &[&[u8]], auth: &[u8]) -> anyhow::Result<()> {
        let hmac = self.authenticate(params, parts)?;

        if openssl::memcmp::eq(&hmac, auth) {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Invalid packet signature"))
        }
    }

    fn decrypt(&self, params: &EspCryptMaterial, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let cipher = cbc_cipher(params)?;
        let iv_len = cipher.iv_len().unwrap_or_default();

        if data.len() < iv_len + cipher.block_size() {
            anyhow::bail!("ESP ciphertext too short");
        }

        let mut out = vec![0u8; data.len() - iv_len + cipher.block_size()];
        let iv = &data[0..iv_len];

        let mut crypter = Crypter::new(cipher, Mode::Decrypt, &params.sk_e, Some(iv))?;
        crypter.pad(false);

        let mut count = crypter.update(&data[iv_len..], &mut out)?;
        count += crypter.finalize(&mut out[count..])?;

        out.truncate(count);

        strip_trailer(out)
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use bytes::Bytes;
    use itertools::iproduct;
    use pnet_macros_support::packet::Packet;
    use pnet_packet::{ipv4::Ipv4Packet, udp::UdpPacket};

    use super::*;
    use crate::{
        crypto::{CipherType, DigestType, IcvLength},
        model::{EspAuthentication, EspCryptMaterial},
    };

    const SPI_EXPIRATION_TIME: Duration = Duration::from_secs(3600);

    /// Keying material for `cipher`: `key || salt`, the salt being empty for
    /// everything but AEAD.
    fn random_key(cipher: CipherType) -> Bytes {
        let mut sk_e = vec![0; cipher.key_material_len()];
        rand::fill(&mut sk_e[..]);
        sk_e.into()
    }

    fn do_test_esp_codec(encap_type: EspEncapType, params: EspCryptMaterial) {
        let params = Arc::new(params);

        let src = Ipv4Addr::new(192, 168, 0, 1);
        let dst = Ipv4Addr::new(192, 168, 0, 2);

        let mut codec = EspCodec::new(src, dst, encap_type);
        codec.add_params(0x01020304, params, SPI_EXPIRATION_TIME);

        let data = b"quick brown fox jumps over the lazy dog";

        let encoded = codec.encode_to_ip_udp(data).unwrap();
        let decoded = codec.decode_from_ip_udp(&encoded).unwrap();

        assert_eq!(decoded.as_ref(), data);

        let encoded = codec.encode_to_esp(data).unwrap();
        let decoded = codec.decode_from_esp(&encoded).unwrap();

        assert_eq!(decoded.as_ref(), data);
    }

    #[test]
    fn test_esp_codec_combinations() {
        let ciphers = [
            CipherType::DesEde3Cbc,
            CipherType::Aes128Cbc,
            CipherType::Aes192Cbc,
            CipherType::Aes256Cbc,
        ];

        // HMAC-SHA1-96, HMAC-SHA1-160 and HMAC-SHA2-256-128: the same digest
        // can carry different truncations, which is why the ICV length is
        // stored rather than derived
        let auths = [
            (
                EspAuthentication {
                    digest: DigestType::Sha1,
                    icv_len: 12,
                },
                20,
            ),
            (
                EspAuthentication {
                    digest: DigestType::Sha1,
                    icv_len: 20,
                },
                20,
            ),
            (
                EspAuthentication {
                    digest: DigestType::Sha256,
                    icv_len: 16,
                },
                32,
            ),
        ];

        for (encap, cipher, (auth, sk_a_len)) in iproduct!([EspEncapType::Udp, EspEncapType::None], ciphers, auths) {
            let mut sk_a = vec![0; sk_a_len];
            rand::fill(&mut sk_a[..]);

            do_test_esp_codec(
                encap,
                EspCryptMaterial {
                    spi: 0x01020304,
                    sk_e: random_key(cipher),
                    sk_a: sk_a.into(),
                    cipher,
                    auth: Some(auth),
                },
            );
        }
    }

    /// AES-GCM carries no integrity algorithm of its own: the ICV is the AEAD
    /// tag, whose length is one of the three ENCR_AES_GCM_* transforms.
    #[test]
    fn test_esp_gcm_codec_combinations() {
        let ciphers = iproduct!(
            [IcvLength::Eight, IcvLength::Twelve, IcvLength::Sixteen],
            [
                CipherType::Aes128Gcm as fn(IcvLength) -> CipherType,
                CipherType::Aes192Gcm,
                CipherType::Aes256Gcm,
            ]
        )
        .map(|(icv, cipher)| cipher(icv));

        for (encap, cipher) in iproduct!([EspEncapType::Udp, EspEncapType::None], ciphers) {
            do_test_esp_codec(
                encap,
                EspCryptMaterial {
                    spi: 0x01020304,
                    sk_e: random_key(cipher),
                    sk_a: Bytes::new(),
                    cipher,
                    auth: None,
                },
            );
        }
    }

    fn gcm_params(icv_len: IcvLength) -> EspCryptMaterial {
        let cipher = CipherType::Aes256Gcm(icv_len);
        EspCryptMaterial {
            spi: 0x01020304,
            sk_e: random_key(cipher),
            sk_a: Bytes::new(),
            cipher,
            auth: None,
        }
    }

    fn gcm_codec(icv_len: IcvLength) -> EspCodec {
        let mut codec = EspCodec::new(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, EspEncapType::None);
        codec.set_params(0x01020304, Arc::new(gcm_params(icv_len)));
        codec
    }

    /// The ICV of an AEAD SA is the tag, and its length comes from the cipher
    /// rather than from an integrity algorithm.
    #[test]
    fn test_gcm_packet_layout() {
        let codec = gcm_codec(IcvLength::Twelve);
        let params = gcm_params(IcvLength::Twelve);

        assert_eq!(params.icv_len(), 12);
        assert_eq!(params.cipher.salt_len(), 4);
        assert_eq!(params.sk_e.len(), 36);

        let data = b"quick brown fox";
        let encoded = codec.encode_to_esp(data).unwrap();
        let esp = EspPacket::new(&encoded).unwrap();

        // 8-octet explicit IV, then 15 octets of payload and the 2-octet
        // trailer padded up to GCM's 4-octet alignment, then the 12-octet tag
        assert_eq!(esp.payload().len(), 8 + 20 + 12);
    }

    /// RFC 4106 §3.1 only requires the IV to be unique per key; it is taken
    /// from the sequence number, so no two packets of an SA share a nonce.
    #[test]
    fn test_gcm_iv_follows_the_sequence_number() {
        let codec = gcm_codec(IcvLength::Sixteen);

        for _ in 0..4 {
            let encoded = codec.encode_to_esp(b"payload").unwrap();
            let esp = EspPacket::new(&encoded).unwrap();

            assert_eq!(esp.payload()[..8], (esp.get_seq() as u64).to_be_bytes());
            assert_eq!(codec.decode_from_esp(&encoded).unwrap().as_ref(), b"payload");
        }
    }

    /// The tag covers the SPI and sequence number as AAD, not just the
    /// ciphertext.
    #[test]
    fn test_gcm_rejects_tampering() {
        let codec = gcm_codec(IcvLength::Sixteen);

        let encoded = codec.encode_to_esp(b"payload").unwrap();

        // last octet of the sequence number, the ciphertext, and the tag
        for offset in [7, EspPacket::minimum_packet_size() + 10, encoded.len() - 1] {
            let mut tampered = encoded.to_vec();
            tampered[offset] ^= 1;
            assert!(codec.decode_from_esp(&tampered).is_err());
        }

        // and a payload that cannot even hold an IV and a tag
        let truncated = &encoded[..EspPacket::minimum_packet_size() + 8];
        assert!(codec.decode_from_esp(truncated).is_err());
    }

    /// The salt is part of the keying material, so an AEAD key of exactly the
    /// cipher's key length is one that was derived without it.
    #[test]
    fn test_gcm_key_material_length_is_checked() {
        let params = EspCryptMaterial {
            sk_e: Bytes::from(vec![0x11; 32]),
            ..gcm_params(IcvLength::Sixteen)
        };

        let codec = EspCodec::new(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, EspEncapType::None);
        assert!(codec.encrypt_aead(&params, 1, b"payload", &[]).is_err());

        // and a CBC SA never takes the AEAD path, or the other way round
        assert!(cbc_cipher(&gcm_params(IcvLength::Sixteen)).is_err());
        assert!(
            aead_cipher(&EspCryptMaterial {
                cipher: CipherType::Aes256Cbc,
                ..gcm_params(IcvLength::Sixteen)
            })
            .is_err()
        );
    }

    /// A key that does not match the negotiated cipher is caught before openssl
    /// sees it.
    #[test]
    fn test_key_length_mismatch_is_rejected() {
        let params = EspCryptMaterial {
            spi: 1,
            sk_e: Bytes::from(vec![0x11; 16]),
            sk_a: Bytes::from(vec![0x22; 32]),
            cipher: CipherType::Aes256Cbc,
            auth: Some(EspAuthentication {
                digest: DigestType::Sha256,
                icv_len: 16,
            }),
        };

        let codec = EspCodec::new(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, EspEncapType::None);
        assert!(codec.encrypt(&params, b"payload").is_err());
    }

    #[test]
    fn test_real_esp_decode() {
        let params = Arc::new(EspCryptMaterial {
            spi: 0xf47b67fe,
            sk_e: Bytes::copy_from_slice(
                &hex::decode(b"dd0dae6b733958899d8567ce341667dd61f907c5007d5daa4ed4b9600d52df98").unwrap(),
            ),
            sk_a: Bytes::copy_from_slice(
                &hex::decode(b"b8321902c9aca5b5551f941629c1250d1c55161686a4ab3a22261f3416b4528d").unwrap(),
            ),
            cipher: CipherType::Aes256Cbc,
            auth: Some(EspAuthentication {
                digest: DigestType::Sha256,
                icv_len: 16,
            }),
        });

        let mut codec = EspCodec::new(
            Ipv4Addr::new(172, 22, 1, 156),
            Ipv4Addr::new(1, 1, 1, 1),
            EspEncapType::Udp,
        );
        codec.add_params(0xf47b67fe, params, SPI_EXPIRATION_TIME);

        const DATA: &[u8] = include_bytes!("../tests/ip-udp-esp.bin");

        const TEST_PAYLOAD: &[u8] = &[
            0x0, 0x0, 0x0, 0x11, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x1, 0x94, 0xbb, 0x38, 0x4, 0x28, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0,
        ];

        let decoded = codec.decode_from_ip_udp(DATA).unwrap();
        let ipv4 = Ipv4Packet::new(&decoded).unwrap();
        let udp = UdpPacket::new(ipv4.payload()).unwrap();

        assert_eq!(udp.payload(), TEST_PAYLOAD);
    }
}
