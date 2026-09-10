use bytes::Bytes;

pub const IKEV1_VERSION: u8 = 0x10;
pub const IKEV2_VERSION: u8 = 0x20;

/// Fixed ISAKMP header size: RFC 2408 §3.1 for IKEv1, RFC 7296 §3.1 for IKEv2.
/// The two versions interpret the fields after the SPIs differently but agree
/// on the length.
pub const ISAKMP_HEADER_LEN: usize = 28;

/// Framing for one IKE version. `M` is that version's message type: the two
/// versions share nothing but the 28-byte header size, so the transport is
/// generic over the message and the codec supplies the version-specific
/// encode/decode.
pub trait IsakmpMessageCodec<M> {
    fn encode(&mut self, message: &M) -> anyhow::Result<Bytes>;

    fn decode(&mut self, data: &[u8]) -> anyhow::Result<Option<M>>;
}
