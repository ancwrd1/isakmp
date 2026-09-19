use std::{iter, sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    net::UdpSocket,
    sync::mpsc::{Receiver, channel},
    task::JoinHandle,
};
use tracing::{debug, trace};

use crate::{
    message::IsakmpMessageCodec,
    transport::{IsakmpTransport, TransportMessage},
};

const NATT_PORT: u16 = 4500;

pub struct UdpTransport<M> {
    socket: Arc<UdpSocket>,
    codec: Box<dyn IsakmpMessageCodec<M> + Send + Sync>,
    message_offset: usize,
    receiver: Receiver<Bytes>,
    reader: Option<JoinHandle<anyhow::Result<()>>>,
}

impl<M> UdpTransport<M> {
    pub fn new(socket: Arc<UdpSocket>, codec: Box<dyn IsakmpMessageCodec<M> + Send + Sync>) -> Self {
        let port = socket.peer_addr().map(|a| a.port()).unwrap_or_default();
        let (tx, rx) = channel(16);

        let message_offset = if port == NATT_PORT { 4 } else { 0 };

        let socket2 = socket.clone();

        let reader = tokio::spawn(async move {
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
            reader: Some(reader),
        }
    }
}

#[async_trait]
impl<M: TransportMessage> IsakmpTransport<M> for UdpTransport<M> {
    async fn send(&mut self, message: &M) -> anyhow::Result<()> {
        let data = self.codec.encode(message)?;
        debug!(
            "Sending ISAKMP message, len: {}, to: {}",
            data.len(),
            self.socket.peer_addr()?
        );

        trace!("Sending ISAKMP message: {:#?}", message);
        trace!("Sending raw bytes: {}", hex::encode(&data));

        if self.message_offset > 0 {
            let mut send_buffer = Vec::with_capacity(self.message_offset + data.len());
            send_buffer.extend(iter::repeat_n(0, self.message_offset));
            send_buffer.extend(&data);
            self.socket.send(&send_buffer).await?;
        } else {
            self.socket.send(&data).await?;
        }

        Ok(())
    }

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<M> {
        let received_message = loop {
            let data = tokio::time::timeout(timeout, self.receiver.recv())
                .await?
                .context("Receive error")?;

            trace!("Received raw bytes: {}", hex::encode(&data));

            match self.codec.decode(&data)? {
                Some(msg) => {
                    trace!("Received ISAKMP message: {:#?}", msg);
                    msg.check_informational()?;
                    break msg;
                }
                None => continue,
            }
        };

        Ok(received_message)
    }

    fn disconnect(&mut self) {}
}

impl<M> Drop for UdpTransport<M> {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            reader.abort();
        }
    }
}
