use std::{
    collections::HashMap,
    iter,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::model::{EspAuthAlgorithm, EspCryptMaterial, TransformId};
use anyhow::Context;
use bytes::Bytes;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};
use pnet_macros::Packet;
use pnet_macros_support::types::u32be;
use pnet_packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{checksum, Ipv4Packet, MutableIpv4Packet},
    udp::{MutableUdpPacket, UdpPacket},
    MutablePacket, Packet,
};
use rand::random;
use tokio::time::Instant;

const SPI_EXPIRATION_TIME: Duration = Duration::from_secs(3600);

#[derive(Packet)]
#[allow(unused)]
pub struct Esp {
    spi: u32be,
    seq: u32be,
    #[payload]
    payload: Vec<u8>,
}

pub struct EspCodec {
    params: HashMap<u32, (Instant, Arc<EspCryptMaterial>)>,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    seq_counter: AtomicU32,
}

impl EspCodec {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        Self {
            params: HashMap::new(),
            src,
            dst,
            seq_counter: AtomicU32::new(1),
        }
    }

    pub fn add_params(&mut self, spi: u32, params: Arc<EspCryptMaterial>) {
        self.params
            .retain(|_, (timestamp, _)| (*timestamp + SPI_EXPIRATION_TIME) > Instant::now());

        self.params.insert(spi, (Instant::now(), params));
    }

    pub fn set_params(&mut self, spi: u32, params: Arc<EspCryptMaterial>) {
        self.params.clear();
        self.params.insert(spi, (Instant::now(), params));
    }

    pub fn decode_from_ip_udp(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let ipv4 = Ipv4Packet::new(data).context("Invalid IPv4 packet")?;
        let udp = UdpPacket::new(ipv4.payload()).context("Invalid UDP packet")?;
        let esp = EspPacket::new(udp.payload()).context("Invalid ESP packet")?;

        let spi = esp.get_spi();
        let seq = esp.get_seq();

        let Some((_, params)) = self.params.get(&spi) else {
            anyhow::bail!("Invalid SPI");
        };

        let payload = esp.payload();
        let auth = &payload[payload.len() - params.auth_algorithm.hash_len()..];
        let data = &payload[0..payload.len() - params.auth_algorithm.hash_len()];

        self.verify(params, &[&spi.to_be_bytes(), &seq.to_be_bytes(), data], auth)?;

        let decrypted = self.decrypt(params, data)?;
        Ok(decrypted)
    }

    pub fn encode_to_ip_udp(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let (spi, (_, params)) = self.params.iter().next().context("No ESP parameters")?;

        let mut data = self.encrypt(params, data)?;
        let next_seq = self.seq_counter.fetch_add(1, Ordering::SeqCst);
        let auth = self.authenticate(params, &[&spi.to_be_bytes(), &next_seq.to_be_bytes(), &data])?;
        data.extend(auth);

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
        esp.set_spi(*spi);
        esp.set_seq(next_seq);
        esp.set_payload(&data);

        ipv4.set_checksum(checksum(&ipv4.to_immutable()));

        Ok(buffer.into())
    }

    fn encrypt(&self, params: &EspCryptMaterial, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        match params.transform_id {
            TransformId::EspAesCbc => self.do_encrypt(params, Cipher::aes_256_cbc(), &random::<[u8; 16]>(), data),
            TransformId::Esp3Des => self.do_encrypt(params, Cipher::des_ede3_cbc(), &random::<[u8; 8]>(), data),
            _ => anyhow::bail!("Unsupported transform ID"),
        }
    }

    fn authenticate(&self, params: &EspCryptMaterial, parts: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
        let key = PKey::hmac(&params.sk_a)?;

        let digest = match params.auth_algorithm {
            EspAuthAlgorithm::HmacSha256 | EspAuthAlgorithm::HmacSha256v2 => MessageDigest::sha256(),
            EspAuthAlgorithm::HmacSha160 => MessageDigest::sha1(),
            EspAuthAlgorithm::HmacSha96 => MessageDigest::sha1(),
            _ => anyhow::bail!("Unsupported auth algorithm"),
        };

        let mut signer = Signer::new(digest, &key)?;

        for part in parts {
            signer.update(part)?;
        }

        let mut hmac = signer.sign_to_vec()?;
        hmac.truncate(params.auth_algorithm.hash_len());

        Ok(hmac)
    }

    fn verify(&self, params: &EspCryptMaterial, parts: &[&[u8]], auth: &[u8]) -> anyhow::Result<()> {
        let hmac = self.authenticate(params, parts)?;

        if hmac != auth {
            anyhow::bail!("Invalid HMAC");
        } else {
            Ok(())
        }
    }

    fn do_encrypt(&self, params: &EspCryptMaterial, cipher: Cipher, iv: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let pad_len = cipher.block_size() - ((data.len() + 2) % cipher.block_size());

        let mut plain = Vec::with_capacity(data.len() + pad_len + 2);
        plain.extend(data);
        plain.extend(iter::repeat(0).take(pad_len));
        plain.push(pad_len as u8);
        plain.push(4); // next header: IPIP

        let mut out = vec![0u8; iv.len() + plain.len() + cipher.block_size()];

        out[0..iv.len()].copy_from_slice(iv);

        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &params.sk_e, Some(iv))?;
        crypter.pad(false);

        let mut count = crypter.update(&plain, &mut out[iv.len()..])?;
        count += crypter.finalize(&mut out[iv.len() + count..])?;

        out.truncate(count + iv.len());
        Ok(out)
    }

    fn do_decrypt(
        &self,
        params: &EspCryptMaterial,
        cipher: Cipher,
        iv_len: usize,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut out = vec![0u8; data.len()];
        let iv = &data[0..iv_len];

        let mut crypter = Crypter::new(cipher, Mode::Decrypt, &params.sk_e, Some(iv))?;
        crypter.pad(false);

        let mut count = crypter.update(&data[iv_len..], &mut out)?;
        count += crypter.finalize(&mut out[count..])?;

        out.truncate(count);
        let next_header = out.pop().context("Invalid ESP packet")?;
        if next_header != 4 {
            anyhow::bail!("Invalid next header");
        }
        let pad_len = out.pop().context("Invalid ESP packet")? as usize;
        out.truncate(out.len() - pad_len);
        Ok(out)
    }

    fn decrypt(&self, params: &EspCryptMaterial, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        match params.transform_id {
            TransformId::EspAesCbc => self.do_decrypt(params, Cipher::aes_256_cbc(), 16, data),
            TransformId::Esp3Des => self.do_decrypt(params, Cipher::des_ede3_cbc(), 8, data),
            _ => anyhow::bail!("Unsupported transform ID"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use super::*;
    use bytes::Bytes;
    use pnet_macros_support::packet::Packet;
    use pnet_packet::{ipv4::Ipv4Packet, udp::UdpPacket};
    use rand::random;

    use crate::model::{EspAuthAlgorithm, EspCryptMaterial, TransformId};

    fn test_esp_codec(sk_e: &[u8], sk_a: &[u8], transform_id: TransformId, auth_algorithm: EspAuthAlgorithm) {
        let params = Arc::new(EspCryptMaterial {
            spi: 0x01020304,
            sk_e: Bytes::copy_from_slice(sk_e),
            sk_a: Bytes::copy_from_slice(sk_a),
            transform_id,
            key_length: sk_e.len(),
            auth_algorithm,
        });

        let src = Ipv4Addr::new(192, 168, 0, 1);
        let dst = Ipv4Addr::new(192, 168, 0, 2);

        let mut codec = EspCodec::new(src, dst);
        codec.add_params(0x01020304, params);

        let data = b"quick brown fox jumps over the lazy dog";

        let encoded = codec.encode_to_ip_udp(data).unwrap();
        let decoded = codec.decode_from_ip_udp(&encoded).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_esp_codec_aes_hmac_sha256() {
        test_esp_codec(
            &random::<[u8; 32]>(),
            &random::<[u8; 32]>(),
            TransformId::EspAesCbc,
            EspAuthAlgorithm::HmacSha256,
        );
    }

    #[test]
    fn test_esp_codec_aes_hmac_sha160() {
        test_esp_codec(
            &random::<[u8; 32]>(),
            &random::<[u8; 20]>(),
            TransformId::EspAesCbc,
            EspAuthAlgorithm::HmacSha160,
        );
    }

    #[test]
    fn test_esp_codec_aes_hmac_sha96() {
        test_esp_codec(
            &random::<[u8; 32]>(),
            &random::<[u8; 20]>(),
            TransformId::EspAesCbc,
            EspAuthAlgorithm::HmacSha96,
        );
    }

    #[test]
    fn test_esp_codec_3des_hmac_sha256() {
        test_esp_codec(
            &random::<[u8; 24]>(),
            &random::<[u8; 32]>(),
            TransformId::Esp3Des,
            EspAuthAlgorithm::HmacSha256,
        );
    }

    #[test]
    fn test_esp_codec_3des_hmac_sha160() {
        test_esp_codec(
            &random::<[u8; 24]>(),
            &random::<[u8; 20]>(),
            TransformId::Esp3Des,
            EspAuthAlgorithm::HmacSha160,
        );
    }

    #[test]
    fn test_esp_codec_3des_hmac_sha96() {
        test_esp_codec(
            &random::<[u8; 24]>(),
            &random::<[u8; 20]>(),
            TransformId::Esp3Des,
            EspAuthAlgorithm::HmacSha96,
        );
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
            transform_id: TransformId::EspAesCbc,
            key_length: 32,
            auth_algorithm: EspAuthAlgorithm::HmacSha256,
        });

        let mut codec = EspCodec::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0));
        codec.add_params(0xf47b67fe, params);

        let data = include_bytes!("../tests/ip-udp-esp.bin");

        let payload = [
            0x0, 0x0, 0x0, 0x11, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x1, 0x94, 0xbb, 0x38, 0x4, 0x28, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0,
        ];

        let decoded = codec.decode_from_ip_udp(data).unwrap();
        let ipv4 = Ipv4Packet::new(&decoded).unwrap();
        let udp = UdpPacket::new(ipv4.payload()).unwrap();

        assert_eq!(udp.payload(), payload);
    }
}
