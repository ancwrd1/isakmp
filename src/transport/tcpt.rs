use std::{net::SocketAddr, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{StreamExt, sink::SinkExt};
use tokio::{
    io::{AsyncRead, AsyncWrite, Interest},
    net::TcpStream,
};
use tokio_util::codec::{Decoder, Encoder};

use tracing::{debug, trace};

use crate::{
    message::{IsakmpMessage, IsakmpMessageCodec},
    transport::{IsakmpTransport, check_informational},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TcptDataType {
    Cmd,
    Ike,
    Esp,
}

impl TcptDataType {
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::Cmd => 1,
            Self::Ike => 2,
            Self::Esp => 4,
        }
    }
}

impl TryFrom<u32> for TcptDataType {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Cmd),
            2 => Ok(Self::Ike),
            4 => Ok(Self::Esp),
            _ => anyhow::bail!("Unsupported TCPT data type"),
        }
    }
}

pub struct TcptTransportCodec {
    data_type: TcptDataType,
}

impl TcptTransportCodec {
    pub fn new(data_type: TcptDataType) -> Self {
        Self { data_type }
    }
}

impl Encoder<Bytes> for TcptTransportCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(item.len() + 8);
        dst.put_slice(&(item.len() as u32).to_be_bytes());
        dst.put_slice(&self.data_type.as_u32().to_be_bytes());
        dst.put_slice(&item);
        Ok(())
    }
}

impl Decoder for TcptTransportCodec {
    type Item = Bytes;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.remaining() < 8 {
            return Ok(None);
        }

        let size = u32::from_be_bytes(src[0..4].try_into()?);
        let cmd = u32::from_be_bytes(src[4..8].try_into()?);

        if src.remaining() < size as usize + 8 {
            return Ok(None);
        }

        if cmd != self.data_type.as_u32() {
            anyhow::bail!("Invalid data type");
        }

        src.advance(8);

        let data = src.split_to(size as usize);
        Ok(Some(data.freeze()))
    }
}

#[async_trait]
pub trait TcptHandshaker {
    async fn handshake(&mut self, data_type: TcptDataType) -> anyhow::Result<()>;
}

#[async_trait]
impl<T> TcptHandshaker for T
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn handshake(&mut self, data_type: TcptDataType) -> anyhow::Result<()> {
        let mut framed = TcptTransportCodec::new(TcptDataType::Cmd).framed(self);

        let mut data = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        data[4..8].copy_from_slice(&data_type.as_u32().to_be_bytes());

        framed.send(Bytes::copy_from_slice(&data)).await?;

        let data = tokio::time::timeout(HANDSHAKE_TIMEOUT, framed.next())
            .await?
            .context("No data")??;

        match data.last() {
            Some(1) => Ok(()),
            _ => anyhow::bail!("Handshake failed for {:?}", data_type),
        }
    }
}

pub struct TcptTransport {
    address: Option<SocketAddr>,
    codec: Box<dyn IsakmpMessageCodec + Send + Sync>,
    stream: Option<TcpStream>,
    data_type: TcptDataType,
}

impl TcptTransport {
    pub fn new(data_type: TcptDataType, address: SocketAddr, codec: Box<dyn IsakmpMessageCodec + Send + Sync>) -> Self {
        Self {
            address: Some(address),
            codec,
            stream: None,
            data_type,
        }
    }

    pub fn with_stream(
        data_type: TcptDataType,
        stream: TcpStream,
        codec: Box<dyn IsakmpMessageCodec + Send + Sync>,
    ) -> Self {
        Self {
            address: None,
            codec,
            stream: Some(stream),
            data_type,
        }
    }

    async fn get_stream(&mut self) -> anyhow::Result<&mut TcpStream> {
        match (self.stream.take(), self.address) {
            (Some(stream), _) if stream.ready(Interest::READABLE | Interest::WRITABLE).await.is_ok() => {
                self.stream = Some(stream);
                Ok(self.stream.as_mut().unwrap())
            }
            (None, Some(address)) => {
                debug!("Connecting to {}", address);
                let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await??;

                debug!("Connected, starting TCPT handshake");
                stream.handshake(self.data_type).await?;

                self.stream = Some(stream);
                Ok(self.stream.as_mut().unwrap())
            }
            _ => anyhow::bail!("Transport disconnected"),
        }
    }
}

async fn do_send(data_type: TcptDataType, stream: &mut TcpStream, data: &[u8]) -> anyhow::Result<()> {
    let mut framed = TcptTransportCodec::new(data_type).framed(stream);
    framed.send(Bytes::copy_from_slice(data)).await?;
    Ok(())
}

async fn do_receive(data_type: TcptDataType, stream: &mut TcpStream, timeout: Duration) -> anyhow::Result<Bytes> {
    let mut framed = TcptTransportCodec::new(data_type).framed(stream);
    let data = tokio::time::timeout(timeout, framed.next())
        .await?
        .context("No data")??;

    Ok(data)
}

#[async_trait]
impl IsakmpTransport for TcptTransport {
    async fn send(&mut self, message: &IsakmpMessage) -> anyhow::Result<()> {
        let data = self.codec.encode(message);

        trace!("Sending ISAKMP message: {:#?}", message);

        let data_type = self.data_type;
        let stream = self.get_stream().await?;

        do_send(data_type, stream, &data).await?;

        Ok(())
    }

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<IsakmpMessage> {
        let stream = self.stream.as_mut().context("No stream")?;
        loop {
            let data = do_receive(self.data_type, stream, timeout).await?;
            if let Some(received_message) = self.codec.decode(&data)? {
                check_informational(&received_message)?;

                trace!("Received ISAKMP message: {:#?}", received_message);
                return Ok(received_message);
            }
        }
    }

    fn disconnect(&mut self) {
        self.stream = None;
    }
}
