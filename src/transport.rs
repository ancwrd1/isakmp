use std::{fmt, time::Duration};

use async_trait::async_trait;

pub mod tcpt;
mod udp;

pub use tcpt::{TcptDataType, TcptTransport};
pub use udp::UdpTransport;

/// A received message that may carry a fatal error notification. Each IKE
/// version decides which notifies abort the exchange, so the transport calls
/// through this rather than inspecting payloads itself.
pub trait CheckInformational {
    fn check_informational(&self) -> anyhow::Result<()>;
}

/// What a transport requires of the messages it carries.
pub trait TransportMessage: CheckInformational + fmt::Debug + Send + Sync {}

impl<T> TransportMessage for T where T: CheckInformational + fmt::Debug + Send + Sync {}

#[async_trait]
pub trait IsakmpTransport<M> {
    async fn send(&mut self, message: &M) -> anyhow::Result<()>;

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<M>;

    async fn send_receive(&mut self, message: &M, timeout: Duration) -> anyhow::Result<M>
    where
        M: Sync,
    {
        self.send(message).await?;
        self.receive(timeout).await
    }

    fn disconnect(&mut self);
}
