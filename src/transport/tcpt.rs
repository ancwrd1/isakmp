use std::{net::SocketAddr, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Interest},
    net::TcpStream,
};
use tracing::{debug, trace};

use crate::{
    message::{IsakmpMessage, IsakmpMessageCodec},
    transport::{check_informational, IsakmpTransport},
};

pub struct TcptTransport {
    address: SocketAddr,
    codec: Box<dyn IsakmpMessageCodec + Send>,
    stream: Option<TcpStream>,
}

impl TcptTransport {
    pub fn new(address: SocketAddr, codec: Box<dyn IsakmpMessageCodec + Send>) -> Self {
        Self {
            address,
            codec,
            stream: None,
        }
    }

    async fn get_stream(&mut self) -> anyhow::Result<&mut TcpStream> {
        match self.stream.take() {
            Some(stream) if stream.ready(Interest::READABLE | Interest::WRITABLE).await.is_ok() => {
                self.stream = Some(stream);
                Ok(self.stream.as_mut().unwrap())
            }
            _ => {
                debug!("Connecting to {}", self.address);
                let mut stream = TcpStream::connect(self.address).await?;

                debug!("Starting TCPT handshake");
                handshake(&mut stream).await?;

                self.stream = Some(stream);
                Ok(self.stream.as_mut().unwrap())
            }
        }
    }
}

async fn handshake(stream: &mut TcpStream) -> anyhow::Result<()> {
    stream
        .write_all(b"\x00\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x01")
        .await?;

    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await?;

    let size = u32::from_be_bytes(header[0..4].try_into()?);
    let cmd = u32::from_be_bytes(header[4..8].try_into()?);
    let flag = u32::from_be_bytes(header[12..16].try_into()?);

    if size != 8 || cmd != 1 || flag != 1 {
        anyhow::bail!("Handshake failed");
    }

    Ok(())
}

async fn do_send(stream: &mut TcpStream, data: &[u8]) -> anyhow::Result<()> {
    let mut buf = Vec::with_capacity(data.len() + 8);
    buf.extend((data.len() as u32).to_be_bytes());
    buf.extend(2u32.to_be_bytes());
    buf.extend(data);
    stream.write_all(&buf).await?;
    Ok(())
}

async fn do_receive(stream: &mut TcpStream, timeout: Duration) -> anyhow::Result<Bytes> {
    let mut header = [0u8; 8];

    tokio::time::timeout(timeout, stream.read_exact(&mut header)).await??;

    let size = u32::from_be_bytes(header[0..4].try_into()?);
    let cmd = u32::from_be_bytes(header[4..8].try_into()?);

    if cmd != 2 {
        anyhow::bail!("Invalid command");
    }

    let mut data = vec![0u8; size as usize];
    stream.read_exact(&mut data).await?;

    trace!("TCPT packet received: len={}, cmd={}", size, cmd);

    Ok(data.into())
}

#[async_trait]
impl IsakmpTransport for TcptTransport {
    async fn send(&mut self, message: &IsakmpMessage) -> anyhow::Result<()> {
        let data = self.codec.encode(message);

        trace!("Sending ISAKMP message: {:#?}", message);

        let stream = self.get_stream().await?;
        do_send(stream, &data).await?;

        Ok(())
    }

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<IsakmpMessage> {
        let stream = self.stream.as_mut().context("No stream")?;
        let data = do_receive(stream, timeout).await?;

        let received_message = self.codec.decode(&data)?.context("Decode error")?;

        check_informational(&received_message)?;

        trace!("Received ISAKMP message: {:#?}", received_message);

        Ok(received_message)
    }

    fn disconnect(&mut self) {
        self.stream = None;
    }
}
