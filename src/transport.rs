use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use tokio::net::UdpSocket;
use tracing::{debug, trace};

use crate::{
    message::{IsakmpMessage, IsakmpMessageCodec},
    model::ExchangeType,
    payload::Payload,
};

const NATT_PORT: u16 = 4500;

fn check_informational(msg: &IsakmpMessage) -> anyhow::Result<()> {
    if msg.exchange_type == ExchangeType::Informational {
        for payload in &msg.payloads {
            if let Payload::Notification(notify) = payload {
                if notify.message_type == 31 || notify.message_type == 9101 {
                    return Err(anyhow!(String::from_utf8_lossy(&notify.data).into_owned()));
                } else if notify.message_type < 31 {
                    return Err(anyhow!("IKE notify error {}", notify.message_type));
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
}

pub struct UdpTransport<C> {
    socket: UdpSocket,
    codec: C,
    receive_buffer: Vec<u8>,
    message_offset: usize,
}

impl<C: IsakmpMessageCodec> UdpTransport<C> {
    pub fn new(socket: UdpSocket, codec: C) -> Self {
        let port = socket.peer_addr().map(|a| a.port()).unwrap_or_default();
        Self {
            socket,
            codec,
            receive_buffer: vec![0u8; 65536],
            message_offset: if port == NATT_PORT { 4 } else { 0 },
        }
    }
}

#[async_trait]
impl<C: IsakmpMessageCodec + Send> IsakmpTransport for UdpTransport<C> {
    async fn send(&mut self, message: &IsakmpMessage) -> anyhow::Result<()> {
        let data = self.codec.encode(message);
        debug!(
            "Sending ISAKMP message, len: {}, to: {}",
            data.len(),
            self.socket.peer_addr()?
        );

        trace!("Sending ISAKMP message: {:#?}", message);

        if self.message_offset == 4 {
            let mut send_buffer = vec![0u8, 0, 0, 0];
            send_buffer.extend(&data);
            self.socket.send(&send_buffer).await?;
        } else {
            self.socket.send(&data).await?;
        }

        Ok(())
    }

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<IsakmpMessage> {
        let received_message = loop {
            let (len, _) = tokio::time::timeout(timeout, self.socket.recv_from(&mut self.receive_buffer)).await??;

            debug!("Received ISAKMP message, len: {}", len);

            match self.codec.decode(&self.receive_buffer[self.message_offset..len])? {
                Some(msg) => {
                    check_informational(&msg)?;
                    break msg;
                }
                None => continue,
            }
        };

        trace!("Received ISAKMP message: {:#?}", received_message);

        Ok(received_message)
    }
}
