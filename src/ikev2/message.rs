use crate::{
    ikev2::{
        model::{ExchangeType, Flags, NotifyType, PayloadType},
        payload::{NotifyPayload, Payload},
    },
    transport::CheckInformational,
};

#[derive(Debug, Clone)]
pub struct Ikev2Message {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub version: u8,
    pub exchange_type: ExchangeType,
    pub flags: Flags,
    pub message_id: u32,
    pub payloads: Vec<Payload>,
}

impl Ikev2Message {
    /// Type of the payload at `index`, for the Next Payload field that
    /// precedes it. `None` past the end of the chain.
    pub fn next_payload(&self, index: usize) -> PayloadType {
        self.payloads
            .get(index)
            .map_or(PayloadType::None, |p| p.as_payload_type())
    }

    pub fn is_response(&self) -> bool {
        self.flags.contains(Flags::RESPONSE)
    }

    pub fn notifies(&self) -> impl Iterator<Item = &NotifyPayload> {
        self.payloads.iter().filter_map(|p| match p {
            Payload::Notify(n) => Some(n),
            _ => None,
        })
    }

    pub fn find_notify(&self, notify_type: NotifyType) -> Option<&NotifyPayload> {
        self.notifies().find(|n| n.notify_type == notify_type)
    }

    /// The error notify carried by this message, if any.
    pub fn error_notify(&self) -> Option<NotifyType> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Notify(n) if n.notify_type.is_error() => Some(n.notify_type),
            _ => None,
        })
    }
}

impl CheckInformational for Ikev2Message {
    /// Only INFORMATIONAL exchanges abort here. Error notifies in an
    /// IKE_SA_INIT or IKE_AUTH response are left to the exchange state machine,
    /// which has the context to act on the recoverable ones — COOKIE,
    /// INVALID_KE_PAYLOAD — by retrying rather than failing.
    fn check_informational(&self) -> anyhow::Result<()> {
        if self.exchange_type != ExchangeType::Informational {
            return Ok(());
        }

        match self.error_notify() {
            Some(notify_type) => anyhow::bail!("IKEv2 notify error {:?}", notify_type),
            None => Ok(()),
        }
    }
}
