use std::time::Duration;

use async_trait::async_trait;

use crate::{message::IsakmpMessage, model::ExchangeType, payload::Payload};

pub mod tcpt;
mod udp;

use crate::model::NotifyMessageType;
pub use tcpt::{TcptDataType, TcptTransport};
pub use udp::UdpTransport;

fn check_informational(msg: &IsakmpMessage) -> anyhow::Result<()> {
    if msg.exchange_type == ExchangeType::Informational {
        for payload in &msg.payloads {
            if let Payload::Notification(notify) = payload {
                if matches!(notify.message_type, NotifyMessageType::Other(31 | 37 | 9101)) {
                    anyhow::bail!(String::from_utf8_lossy(&notify.data).into_owned());
                } else if notify.message_type < 31.into() {
                    anyhow::bail!("IKE notify error {:?}", notify.message_type);
                }
            }
        }
    }
    Ok(())
}

#[async_trait]
pub trait IsakmpTransport {
    async fn send(&mut self, message: &IsakmpMessage) -> anyhow::Result<()>;

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<IsakmpMessage>;

    async fn send_receive(&mut self, message: &IsakmpMessage, timeout: Duration) -> anyhow::Result<IsakmpMessage> {
        self.send(message).await?;
        self.receive(timeout).await
    }

    fn disconnect(&mut self);
}
