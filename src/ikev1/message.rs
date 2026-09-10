use crate::{
    ikev1::{
        model::{ExchangeType, IsakmpFlags, NotifyMessageType, PayloadType},
        payload::Payload,
    },
    transport::CheckInformational,
};

// RFC 2408 notify message types
const NOTIFY_CONNECTED: u16 = 31;
const NOTIFY_RESPONDER_LIFETIME: u16 = 37;
const NOTIFY_CHECKPOINT_SPECIFIC: u16 = 9101;

#[derive(Debug, Clone)]
pub struct Ikev1Message {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub version: u8,
    pub exchange_type: ExchangeType,
    pub flags: IsakmpFlags,
    pub message_id: u32,
    pub payloads: Vec<Payload>,
}

impl Ikev1Message {
    /// Type of the payload at `index`, for the Next Payload field that
    /// precedes it. `None` past the end of the chain.
    pub fn next_payload(&self, index: usize) -> PayloadType {
        self.payloads
            .get(index)
            .map_or(PayloadType::None, |p| p.as_payload_type())
    }
}

impl CheckInformational for Ikev1Message {
    fn check_informational(&self) -> anyhow::Result<()> {
        if self.exchange_type != ExchangeType::Informational {
            return Ok(());
        }

        for payload in &self.payloads {
            if let Payload::Notification(notify) = payload {
                if matches!(
                    notify.message_type,
                    NotifyMessageType::Other(NOTIFY_CONNECTED | NOTIFY_RESPONDER_LIFETIME | NOTIFY_CHECKPOINT_SPECIFIC)
                ) {
                    anyhow::bail!(String::from_utf8_lossy(&notify.data).into_owned());
                } else if notify.message_type < NOTIFY_CONNECTED.into() {
                    anyhow::bail!("IKE notify error {:?}", notify.message_type);
                }
            }
        }

        Ok(())
    }
}
