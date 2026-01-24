use std::{sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    net::UdpSocket,
    sync::mpsc::{Receiver, channel},
};
use tracing::{debug, trace};

use crate::{
    message::{IsakmpMessage, IsakmpMessageCodec},
    transport::{IsakmpTransport, check_informational},
};

const NATT_PORT: u16 = 4500;

pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    codec: Box<dyn IsakmpMessageCodec + Send + Sync>,
    message_offset: usize,
    receiver: Receiver<Bytes>,
}

impl UdpTransport {
    pub fn new(socket: UdpSocket, codec: Box<dyn IsakmpMessageCodec + Send + Sync>) -> Self {
        let port = socket.peer_addr().map(|a| a.port()).unwrap_or_default();
        let (tx, rx) = channel(16);

        let message_offset = if port == NATT_PORT { 4 } else { 0 };

        let socket = Arc::new(socket);
        let socket2 = socket.clone();

        tokio::spawn(async move {
            let mut receive_buffer = vec![0u8; 65536];

            while let Ok((len, _)) = socket2.recv_from(&mut receive_buffer).await {
                let data = receive_buffer[message_offset..len].to_vec().into();
                debug!("Received ISAKMP message, len: {}", len);
                tx.send(data).await?;
            }
            Ok::<_, anyhow::Error>(())
        });

        Self {
            socket,
            codec,
            message_offset,
            receiver: rx,
        }
    }
}

#[async_trait]
impl IsakmpTransport for UdpTransport {
    async fn send(&mut self, message: &IsakmpMessage) -> anyhow::Result<()> {
        let data = self.codec.encode(message)?;
        debug!(
            "Sending ISAKMP message, len: {}, to: {}",
            data.len(),
            self.socket.peer_addr()?
        );

        trace!("Sending ISAKMP message: {:#?}", message);

        if self.message_offset > 0 {
            let mut send_buffer = vec![0u8; self.message_offset];
            send_buffer.extend(&data);
            self.socket.send(&send_buffer).await?;
        } else {
            self.socket.send(&data).await?;
        }

        Ok(())
    }

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<IsakmpMessage> {
        let received_message = loop {
            let data = tokio::time::timeout(timeout, self.receiver.recv())
                .await?
                .context("Receive error")?;

            match self.codec.decode(&data)? {
                Some(msg) => {
                    trace!("Received ISAKMP message: {:#?}", msg);
                    check_informational(&msg)?;
                    break msg;
                }
                None => continue,
            }
        };

        Ok(received_message)
    }

    fn disconnect(&mut self) {}
}
