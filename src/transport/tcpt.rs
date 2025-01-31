use std::{net::SocketAddr, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::sink::SinkExt;
use futures::StreamExt;
use tokio::{io::Interest, net::TcpStream};
use tokio_util::codec::{Decoder, Encoder};

use tracing::{debug, trace};

use crate::{
    message::{IsakmpMessage, IsakmpMessageCodec},
    transport::{check_informational, IsakmpTransport},
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
                handshake(self.data_type, &mut stream).await?;

                self.stream = Some(stream);
                Ok(self.stream.as_mut().unwrap())
            }
        }
    }
}

pub async fn handshake(data_type: TcptDataType, stream: &mut TcpStream) -> anyhow::Result<()> {
    let mut framed = TcptTransportCodec {
        data_type: TcptDataType::Cmd,
    }
    .framed(stream);

    let mut data = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
    data[4..8].copy_from_slice(&data_type.as_u32().to_be_bytes());

    framed.send(Bytes::copy_from_slice(&data)).await?;

    let data = tokio::time::timeout(HANDSHAKE_TIMEOUT, framed.next())
        .await?
        .context("No data")??;

    if data.last() != Some(&1) {
        anyhow::bail!("Handshake failed");
    }

    Ok(())
}

async fn do_send(data_type: TcptDataType, stream: &mut TcpStream, data: &[u8]) -> anyhow::Result<()> {
    let mut framed = TcptTransportCodec { data_type }.framed(stream);
    framed.send(Bytes::copy_from_slice(data)).await?;
    Ok(())
}

async fn do_receive(data_type: TcptDataType, stream: &mut TcpStream, timeout: Duration) -> anyhow::Result<Bytes> {
    let mut framed = TcptTransportCodec { data_type }.framed(stream);
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
