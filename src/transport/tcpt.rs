use std::{io, net::SocketAddr, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{StreamExt, sink::SinkExt};
use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncRead, AsyncWrite, Interest},
    net::TcpStream,
};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, trace, warn};

use crate::{
    message::IsakmpMessageCodec,
    transport::{IsakmpTransport, TransportMessage},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

const TCP_KEEPALIVE: TcpKeepalive = TcpKeepalive::new()
    .with_time(Duration::from_secs(120))
    .with_interval(Duration::from_secs(10));

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

pub struct TcptTransport<M> {
    address: Option<SocketAddr>,
    codec: Box<dyn IsakmpMessageCodec<M> + Send + Sync>,
    stream: Option<TcpStream>,
    data_type: TcptDataType,
}

impl<M> TcptTransport<M> {
    pub fn new(
        data_type: TcptDataType,
        address: SocketAddr,
        codec: Box<dyn IsakmpMessageCodec<M> + Send + Sync>,
    ) -> Self {
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
        codec: Box<dyn IsakmpMessageCodec<M> + Send + Sync>,
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
                stream.set_nodelay(true)?;

                let sock_ref = SockRef::from(&stream);
                if let Err(e) = sock_ref.set_tcp_keepalive(&TCP_KEEPALIVE) {
                    warn!("Cannot set TCP keepalive timeout: {e}");
                }

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
    tokio::time::timeout(SEND_TIMEOUT, framed.send(Bytes::copy_from_slice(data))).await??;
    Ok(())
}

async fn do_receive(data_type: TcptDataType, stream: &mut TcpStream, timeout: Duration) -> anyhow::Result<Bytes> {
    let mut framed = TcptTransportCodec::new(data_type).framed(stream);
    let data = tokio::time::timeout(timeout, framed.next())
        .await?
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))??;

    Ok(data)
}

/// Errors after which the TCP connection is unusable and a fresh one may succeed, e.g. when an idle
/// connection was dropped by a NAT on the path (issue #2): the first write after that goes into the
/// socket buffer, the reset surfaces on the following read, and later writes fail with EPIPE.
fn is_connection_error(e: &anyhow::Error) -> bool {
    e.downcast_ref::<io::Error>().is_some_and(|e| {
        matches!(
            e.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::NotConnected
                | io::ErrorKind::TimedOut
                | io::ErrorKind::UnexpectedEof
        )
    })
}

#[async_trait]
impl<M: TransportMessage> IsakmpTransport<M> for TcptTransport<M> {
    async fn send(&mut self, message: &M) -> anyhow::Result<()> {
        let data = self.codec.encode(message)?;

        trace!("Sending ISAKMP message: {:#?}", message);

        let data_type = self.data_type;

        match do_send(data_type, self.get_stream().await?, &data).await {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!("{}", e);
                self.disconnect();
                if is_connection_error(&e) && self.address.is_some() {
                    debug!("Reconnecting and retrying send");
                    do_send(data_type, self.get_stream().await?, &data).await
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<M> {
        loop {
            let stream = self.stream.as_mut().context("No stream")?;
            let data = match do_receive(self.data_type, stream, timeout).await {
                Ok(data) => data,
                Err(e) => {
                    // A timeout is expected while polling for gateway requests and leaves the connection
                    // intact; anything else (reset, EOF, framing error) means it cannot be reused.
                    if !e.is::<tokio::time::error::Elapsed>() {
                        self.disconnect();
                    }
                    return Err(e);
                }
            };

            if let Some(received_message) = self.codec.decode(&data)? {
                received_message.check_informational()?;

                trace!("Received ISAKMP message: {:#?}", received_message);
                return Ok(received_message);
            }
        }
    }

    async fn send_receive(&mut self, message: &M, timeout: Duration) -> anyhow::Result<M>
    where
        M: Sync,
    {
        self.send(message).await?;
        match self.receive(timeout).await {
            Err(e) if is_connection_error(&e) && self.address.is_some() => {
                // The send into a stale connection succeeds and the reset only shows up here, so the whole
                // round trip is repeated on a new connection; the gateway treats it as a retransmission.
                warn!("{}, reconnecting and retrying request", e);
                self.send(message).await?;
                self.receive(timeout).await
            }
            result => result,
        }
    }

    fn disconnect(&mut self) {
        self.stream = None;
    }
}
