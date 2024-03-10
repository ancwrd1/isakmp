use std::{io::Cursor, time::Duration};

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tracing::{debug, trace};

use crate::{
    message::{IsakmpMessage, IsakmpMessageCodec},
    model::ExchangeType,
    payload::Payload,
};

const NATT_PORT: u16 = 4500;

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

pub struct UdpTransport<C> {
    socket: UdpSocket,
    codec: C,
    received_hashes: Vec<Bytes>,
}

impl<C> UdpTransport<C> {
    pub fn new(socket: UdpSocket, codec: C) -> Self {
        Self {
            socket,
            codec,
            received_hashes: Vec::new(),
        }
    }
}

#[async_trait]
impl<C: IsakmpMessageCodec + Send> IsakmpTransport for UdpTransport<C> {
    async fn send(&mut self, message: &IsakmpMessage) -> anyhow::Result<()> {
        let data = self.codec.encode(message);
        debug!(
            "Sending ISAKMP message of size {} to {}",
            data.len(),
            self.socket.peer_addr()?
        );

        let port = self.socket.peer_addr()?.port();

        if port == NATT_PORT {
            let mut send_buffer = vec![0u8, 0, 0, 0];
            send_buffer.extend(&data);
            self.socket.send(&send_buffer).await?;
        } else {
            self.socket.send(&data).await?;
        }

        Ok(())
    }

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<IsakmpMessage> {
        let mut receive_buffer = [0u8; 65536];
        let received_message = loop {
            let (size, _) =
                tokio::time::timeout(timeout, self.socket.recv_from(&mut receive_buffer)).await??;

            let port = self.socket.peer_addr()?.port();

            let data = if port == NATT_PORT {
                &receive_buffer[4..size]
            } else {
                &receive_buffer[0..size]
            };

            match self.parse_data(data)? {
                None => continue,
                Some(message) => break message,
            }
        };
        Ok(received_message)
    }

    fn parse_data(&mut self, data: &[u8]) -> anyhow::Result<Option<IsakmpMessage>> {
        let hash = self.codec.compute_hash(data);

        if self.received_hashes.contains(&hash) {
            trace!("Discarding already received message");
            Ok(None)
        } else {
            self.received_hashes.push(hash);
            debug!("Parsing ISAKMP message of size {}", data.len());
            let mut reader = Cursor::new(&data);

            let msg = self.codec.decode(&mut reader)?;

            if msg.exchange_type == ExchangeType::Informational {
                for payload in &msg.payloads {
                    if let Payload::Notification(notify) = payload {
                        if notify.message_type == 31 || notify.message_type == 9101 {
                            return Err(
                                anyhow!(String::from_utf8_lossy(&notify.data).into_owned()),
                            );
                        } else if notify.message_type < 31 {
                            return Err(anyhow!("IKE notify error {}", notify.message_type));
                        }
                    }
                }
            }

            Ok(Some(msg))
        }
    }
}
