use std::{io::Cursor, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tracing::debug;

use crate::message::IsakmpMessage;
use crate::session::Ikev1Session;

#[async_trait]
pub trait IsakmpTransport {
    async fn send(&mut self, message: &IsakmpMessage) -> anyhow::Result<()>;

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<IsakmpMessage>;

    async fn send_receive(
        &mut self,
        message: &IsakmpMessage,
        timeout: Duration,
    ) -> anyhow::Result<IsakmpMessage> {
        self.send(message).await?;
        self.receive(timeout).await
    }

    fn parse_data(&mut self, data: &[u8]) -> anyhow::Result<Option<IsakmpMessage>>;
}

pub struct UdpTransport {
    socket: UdpSocket,
    session: Arc<RwLock<Ikev1Session>>,
    received_hashes: Vec<Bytes>,
}

impl UdpTransport {
    pub fn new(socket: UdpSocket, session: Arc<RwLock<Ikev1Session>>) -> Self {
        Self {
            socket,
            session,
            received_hashes: Vec::new(),
        }
    }
}

#[async_trait]
impl IsakmpTransport for UdpTransport {
    async fn send(&mut self, message: &IsakmpMessage) -> anyhow::Result<()> {
        let data = message.to_bytes(&mut self.session.write());
        debug!(
            "Sending ISAKMP message of size {} to {}",
            data.len(),
            self.socket.peer_addr()?
        );
        let mut send_buffer = vec![0u8, 0, 0, 0];
        send_buffer.extend(&data);

        self.socket.send(&send_buffer).await?;

        Ok(())
    }

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<IsakmpMessage> {
        let mut receive_buffer = [0u8; 65536];
        let received_message = loop {
            let (size, _) =
                tokio::time::timeout(timeout, self.socket.recv_from(&mut receive_buffer)).await??;

            match self.parse_data(&receive_buffer[4..size])? {
                None => continue,
                Some(message) => break message,
            }
        };
        Ok(received_message)
    }

    fn parse_data(&mut self, data: &[u8]) -> anyhow::Result<Option<IsakmpMessage>> {
        let hash = self.session.read().crypto.hash([&data])?;

        if self.received_hashes.contains(&hash) {
            debug!("Discarding already received message");
            Ok(None)
        } else {
            self.received_hashes.push(hash);
            debug!("Parsing ISAKMP message of size {}", data.len());
            let mut reader = Cursor::new(&data);
            Ok(Some(IsakmpMessage::parse(
                &mut reader,
                &mut self.session.write(),
            )?))
        }
    }
}
