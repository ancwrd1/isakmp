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

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TcptDataType {
    Ike,
    Esp,
}

impl TcptDataType {
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::Ike => 2,
            Self::Esp => 4,
        }
    }
}

impl TryFrom<u32> for TcptDataType {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::Ike),
            4 => Ok(Self::Esp),
            _ => anyhow::bail!("Unsupported TCPT data type"),
        }
    }
}

pub struct TcptTransport {
    address: SocketAddr,
    codec: Box<dyn IsakmpMessageCodec + Send + Sync>,
    stream: Option<TcpStream>,
    data_type: TcptDataType,
}

impl TcptTransport {
    pub fn new(data_type: TcptDataType, address: SocketAddr, codec: Box<dyn IsakmpMessageCodec + Send + Sync>) -> Self {
        Self {
            address,
            codec,
            stream: None,
            data_type,
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
                let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(self.address)).await??;

                debug!("Connected, starting TCPT handshake");
                self.handshake(&mut stream).await?;

                self.stream = Some(stream);
                Ok(self.stream.as_mut().unwrap())
            }
        }
    }

    async fn handshake(&self, stream: &mut TcpStream) -> anyhow::Result<()> {
        let mut data = [0u8; 20];
        let len = 12u32;
        let cmd = 1u32;
        data[0..4].copy_from_slice(&len.to_be_bytes());
        data[4..8].copy_from_slice(&cmd.to_be_bytes());
        data[8..12].copy_from_slice(&1u32.to_be_bytes());
        data[12..16].copy_from_slice(&self.data_type.as_u32().to_be_bytes());
        data[16..20].copy_from_slice(&1u32.to_be_bytes());

        stream.write_all(&data).await?;

        let mut header = [0u8; 16];
        tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut header)).await??;

        let size = u32::from_be_bytes(header[0..4].try_into()?);
        let cmd = u32::from_be_bytes(header[4..8].try_into()?);
        let flag = u32::from_be_bytes(header[12..16].try_into()?);

        if size != 8 || cmd != 1 || flag != 1 {
            anyhow::bail!("Handshake failed");
        }

        Ok(())
    }
}

async fn do_send(stream: &mut TcpStream, data: &[u8]) -> anyhow::Result<()> {
    let mut buf = Vec::with_capacity(data.len() + 8);
    buf.extend((data.len() as u32).to_be_bytes());
    buf.extend(2u32.to_be_bytes());
    buf.extend(data);
    stream.write_all(&buf).await?;
    Ok(())
}

async fn do_receive(data_type: TcptDataType, stream: &mut TcpStream, timeout: Duration) -> anyhow::Result<Bytes> {
    let mut header = [0u8; 8];

    tokio::time::timeout(timeout, stream.read_exact(&mut header)).await??;

    let size = u32::from_be_bytes(header[0..4].try_into()?);
    let cmd = u32::from_be_bytes(header[4..8].try_into()?);

    if cmd != data_type.as_u32() {
        anyhow::bail!("Invalid data type");
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
        let data = do_receive(self.data_type, stream, timeout).await?;

        let received_message = self.codec.decode(&data)?.context("Decode error")?;

        check_informational(&received_message)?;

        trace!("Received ISAKMP message: {:#?}", received_message);

        Ok(received_message)
    }

    fn disconnect(&mut self) {
        debug!("Disconnected");
        self.stream = None;
    }
}
