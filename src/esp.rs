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

use crate::crypto::CipherType;
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
}

impl EspCodec {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, encap_type: EspEncapType) -> Self {
        Self {
            params: HashMap::new(),
            src,
            dst,
            seq_counter: AtomicU32::new(1),
            encap_type,
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

        let payload = esp.payload();
        let (data, auth) = payload.split_at(payload.len() - params.auth_algorithm.hash_len());

        self.verify(params, &[&spi.to_be_bytes(), &seq.to_be_bytes(), data], auth)?;

        let decrypted = self.decrypt(params, data)?;
        Ok(decrypted.into())
    }

    fn encode_to_ip_udp(&self, data: &[u8]) -> anyhow::Result<Bytes> {
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

    fn encode_to_esp(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let (spi, (_, params)) = self.params.iter().next().context("No ESP parameters")?;

        let mut data = self.encrypt(params, data)?;
        let next_seq = self.seq_counter.fetch_add(1, Ordering::SeqCst);
        let auth = self.authenticate(params, &[&spi.to_be_bytes(), &next_seq.to_be_bytes(), &data])?;
        data.extend(auth);

        let mut buffer = vec![0u8; data.len() + EspPacket::minimum_packet_size()];

        let mut esp = MutableEspPacket::new(&mut buffer).context("Invalid ESP packet")?;
        esp.set_spi(*spi);
        esp.set_seq(next_seq);
        esp.set_payload(&data);

        Ok(buffer.into())
    }

    fn encrypt(&self, params: &EspCryptMaterial, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let iv: &[u8] = match params.transform_id {
            TransformId::Esp3Des => &random::<[u8; 8]>(),
            TransformId::EspAesCbc => &random::<[u8; 16]>(),
            _ => anyhow::bail!("Unsupported encryption algorithm"),
        };
        self.do_encrypt(
            params,
            CipherType::new_for_esp(params.transform_id, params.sk_e.len())?.into(),
            iv,
            data,
        )
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

        if hmac == auth {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Invalid packet signature"))
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
        let mut out = vec![0u8; data.len() - iv_len + cipher.block_size()];
        let iv = &data[0..iv_len];

        let mut crypter = Crypter::new(cipher, Mode::Decrypt, &params.sk_e, Some(iv))?;
        crypter.pad(false);

        let mut count = crypter.update(&data[iv_len..], &mut out)?;
        count += crypter.finalize(&mut out[count..])?;

        out.truncate(count);
        let next_header = out[out.len() - 1];
        if next_header != 4 {
            anyhow::bail!("Invalid next header, should be IPIP");
        }
        let pad_len = out[out.len() - 2] as usize;
        out.truncate(out.len() - pad_len - 2);
        Ok(out)
    }

    fn decrypt(&self, params: &EspCryptMaterial, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let iv_len = match params.transform_id {
            TransformId::Esp3Des => 8,
            TransformId::EspAesCbc => 16,
            _ => anyhow::bail!("Unsupported encryption algorithm"),
        };
        self.do_decrypt(
            params,
            CipherType::new_for_esp(params.transform_id, params.sk_e.len())?.into(),
            iv_len,
            data,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use super::*;
    use bytes::Bytes;
    use itertools::iproduct;
    use pnet_macros_support::packet::Packet;
    use pnet_packet::{ipv4::Ipv4Packet, udp::UdpPacket};

    use crate::model::{EspAuthAlgorithm, EspCryptMaterial, TransformId};

    fn do_test_esp_codec(
        encap_type: EspEncapType,
        sk_e: &[u8],
        sk_a: &[u8],
        transform_id: TransformId,
        auth_algorithm: EspAuthAlgorithm,
    ) {
        let params = Arc::new(EspCryptMaterial {
            spi: 0x01020304,
            sk_e: Bytes::copy_from_slice(sk_e),
            sk_a: Bytes::copy_from_slice(sk_a),
            transform_id,
            auth_algorithm,
        });

        let src = Ipv4Addr::new(192, 168, 0, 1);
        let dst = Ipv4Addr::new(192, 168, 0, 2);

        let mut codec = EspCodec::new(src, dst, encap_type);
        codec.add_params(0x01020304, params);

        let data = b"quick brown fox jumps over the lazy dog";

        let encoded = codec.encode_to_ip_udp(data).unwrap();
        let decoded = codec.decode_from_ip_udp(&encoded).unwrap();

        assert_eq!(decoded.as_ref(), data);
    }

    #[test]
    fn test_esp_codec_combinations() {
        for (transform_id, key_lengths) in [
            (TransformId::Esp3Des, vec![24]),
            (TransformId::EspAesCbc, vec![16, 24, 32]),
        ] {
            let encaps = iproduct!(
                [EspEncapType::Udp, EspEncapType::None],
                key_lengths,
                [
                    (EspAuthAlgorithm::HmacSha96, 20),
                    (EspAuthAlgorithm::HmacSha160, 20),
                    (EspAuthAlgorithm::HmacSha256, 32),
                ]
            );

            for (encap, sk_e_len, (alg, sk_a_len)) in encaps {
                let mut sk_e = vec![0; sk_e_len];
                rand::fill(&mut sk_e[..]);
                let mut sk_a = vec![0; sk_a_len];
                rand::fill(&mut sk_a[..]);
                do_test_esp_codec(encap, &sk_e, &sk_a, transform_id, alg);
            }
        }
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
            auth_algorithm: EspAuthAlgorithm::HmacSha256,
        });

        let mut codec = EspCodec::new(
            Ipv4Addr::new(172, 22, 1, 156),
            Ipv4Addr::new(1, 1, 1, 1),
            EspEncapType::Udp,
        );
        codec.add_params(0xf47b67fe, params);

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
