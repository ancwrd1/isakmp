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
use tokio_util::codec::{Decoder, Encoder, Framed};
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

/// The connection is kept framed for its whole lifetime: one read may return more than one frame, and
/// the read buffer must outlive a single `receive` call or the frames after the first are lost.
type FramedStream = Framed<TcpStream, TcptTransportCodec>;

pub struct TcptTransport<M> {
    address: Option<SocketAddr>,
    codec: Box<dyn IsakmpMessageCodec<M> + Send + Sync>,
    stream: Option<FramedStream>,
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
            stream: Some(TcptTransportCodec::new(data_type).framed(stream)),
            data_type,
        }
    }

    async fn get_stream(&mut self) -> anyhow::Result<&mut FramedStream> {
        match (self.stream.take(), self.address) {
            (Some(stream), _)
                if stream
                    .get_ref()
                    .ready(Interest::READABLE | Interest::WRITABLE)
                    .await
                    .is_ok() =>
            {
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

                self.stream = Some(TcptTransportCodec::new(self.data_type).framed(stream));
                Ok(self.stream.as_mut().unwrap())
            }
            _ => anyhow::bail!("Transport disconnected"),
        }
    }
}

async fn do_send(stream: &mut FramedStream, data: &Bytes) -> anyhow::Result<()> {
    tokio::time::timeout(SEND_TIMEOUT, stream.send(data.clone())).await??;
    Ok(())
}

async fn do_receive(stream: &mut FramedStream, timeout: Duration) -> anyhow::Result<Bytes> {
    let data = tokio::time::timeout(timeout, stream.next())
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

        match do_send(self.get_stream().await?, &data).await {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!("{}", e);
                self.disconnect();
                if is_connection_error(&e) && self.address.is_some() {
                    debug!("Reconnecting and retrying send");
                    do_send(self.get_stream().await?, &data).await
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<M> {
        loop {
            let stream = self.stream.as_mut().context("No stream")?;
            let data = match do_receive(stream, timeout).await {
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

#[cfg(test)]
mod tests {
    use tokio::{net::TcpListener, sync::oneshot};
    use tokio_util::codec::Framed;

    use super::*;
    use crate::transport::CheckInformational;

    const DATA_TYPE: TcptDataType = TcptDataType::Ike;
    const TIMEOUT: Duration = Duration::from_secs(5);

    #[derive(Debug, Clone, PartialEq)]
    struct TestMessage(Bytes);

    impl TestMessage {
        fn new(data: &'static [u8]) -> Self {
            Self(Bytes::from_static(data))
        }
    }

    impl CheckInformational for TestMessage {
        fn check_informational(&self) -> anyhow::Result<()> {
            if self.0 == "NOTIFY-ERROR" {
                anyhow::bail!("Error notification");
            }
            Ok(())
        }
    }

    /// Passes bodies through unchanged; an empty frame stands for a message the codec drops.
    struct TestCodec;

    impl IsakmpMessageCodec<TestMessage> for TestCodec {
        fn encode(&mut self, message: &TestMessage) -> anyhow::Result<Bytes> {
            Ok(message.0.clone())
        }

        fn decode(&mut self, data: &[u8]) -> anyhow::Result<Option<TestMessage>> {
            Ok((!data.is_empty()).then(|| TestMessage(Bytes::copy_from_slice(data))))
        }
    }

    type ServerConn = Framed<TcpStream, TcptTransportCodec>;

    async fn listen() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address)
    }

    fn transport(address: SocketAddr) -> TcptTransport<TestMessage> {
        TcptTransport::new(DATA_TYPE, address, Box::new(TestCodec))
    }

    /// Gateway side of the TCPT handshake: a Cmd frame naming the data type, answered with its last
    /// byte set to 1 (accepted) or 0 (rejected).
    async fn accept_with(listener: &TcpListener, accept: bool) -> ServerConn {
        let (stream, _) = listener.accept().await.unwrap();
        let mut cmd = TcptTransportCodec::new(TcptDataType::Cmd).framed(stream);

        let request = cmd.next().await.unwrap().unwrap();
        assert_eq!(&request[..], [0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1]);

        let mut reply = request.to_vec();
        *reply.last_mut().unwrap() = accept as u8;
        cmd.send(Bytes::from(reply)).await.unwrap();

        TcptTransportCodec::new(DATA_TYPE).framed(cmd.into_inner())
    }

    async fn accept(listener: &TcpListener) -> ServerConn {
        accept_with(listener, true).await
    }

    async fn recv(conn: &mut ServerConn) -> Bytes {
        conn.next().await.unwrap().unwrap()
    }

    async fn reply(conn: &mut ServerConn, data: &'static [u8]) {
        conn.send(Bytes::from_static(data)).await.unwrap();
    }

    /// Closes with RST instead of FIN, as a NAT or firewall that lost the connection state does.
    fn reset(conn: ServerConn) {
        let stream = conn.into_inner();
        SockRef::from(&stream).set_linger(Some(Duration::ZERO)).unwrap();
        drop(stream);
    }

    async fn assert_no_more_connections(listener: &TcpListener) {
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }

    #[test]
    fn test_codec_encode() {
        let mut dst = BytesMut::new();
        TcptTransportCodec::new(TcptDataType::Esp)
            .encode(Bytes::from_static(b"abc"), &mut dst)
            .unwrap();
        assert_eq!(&dst[..], [0, 0, 0, 3, 0, 0, 0, 4, b'a', b'b', b'c']);
    }

    #[test]
    fn test_codec_decode_partial_and_split() {
        let mut codec = TcptTransportCodec::new(TcptDataType::Ike);
        let mut src = BytesMut::from(&[0, 0, 0, 3, 0, 0][..]);
        assert!(codec.decode(&mut src).unwrap().is_none());

        src.extend_from_slice(&[0, 2, b'x', b'y']);
        assert!(codec.decode(&mut src).unwrap().is_none());
        assert_eq!(src.len(), 10);

        src.extend_from_slice(&[b'z', 0, 0, 0, 0]);
        assert_eq!(codec.decode(&mut src).unwrap().unwrap(), "xyz");
        assert_eq!(&src[..], [0, 0, 0, 0]);
    }

    #[test]
    fn test_codec_decode_wrong_data_type() {
        let mut codec = TcptTransportCodec::new(TcptDataType::Ike);
        let mut src = BytesMut::from(&[0, 0, 0, 1, 0, 0, 0, 4, 0][..]);
        assert!(codec.decode(&mut src).is_err());
    }

    #[test]
    fn test_data_type_conversion() {
        for data_type in [TcptDataType::Cmd, TcptDataType::Ike, TcptDataType::Esp] {
            assert_eq!(TcptDataType::try_from(data_type.as_u32()).unwrap(), data_type);
        }
        assert!(TcptDataType::try_from(3).is_err());
    }

    #[tokio::test]
    async fn test_send_receive() {
        let (listener, address) = listen().await;
        let server = tokio::spawn(async move {
            let mut conn = accept(&listener).await;
            assert_eq!(recv(&mut conn).await, "request1");
            reply(&mut conn, b"response1").await;
            assert_eq!(recv(&mut conn).await, "request2");
            reply(&mut conn, b"response2").await;
            assert_no_more_connections(&listener).await;
        });

        let mut transport = transport(address);
        let response = transport.send_receive(&TestMessage::new(b"request1"), TIMEOUT).await;
        assert_eq!(response.unwrap(), TestMessage::new(b"response1"));
        let response = transport.send_receive(&TestMessage::new(b"request2"), TIMEOUT).await;
        assert_eq!(response.unwrap(), TestMessage::new(b"response2"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_rejected() {
        let (listener, address) = listen().await;
        let server = tokio::spawn(async move {
            let _conn = accept_with(&listener, false).await;
        });

        let mut transport = transport(address);
        let err = transport.send(&TestMessage::new(b"request")).await.unwrap_err();
        assert!(err.to_string().contains("Handshake failed"), "{err}");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_receive_skips_undecodable_frames() {
        let (listener, address) = listen().await;
        let server = tokio::spawn(async move {
            let mut conn = accept(&listener).await;
            recv(&mut conn).await;
            reply(&mut conn, b"").await;
            reply(&mut conn, b"response").await;
        });

        let mut transport = transport(address);
        let response = transport.send_receive(&TestMessage::new(b"request"), TIMEOUT).await;
        assert_eq!(response.unwrap(), TestMessage::new(b"response"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_receive_error_notification() {
        let (listener, address) = listen().await;
        let server = tokio::spawn(async move {
            let mut conn = accept(&listener).await;
            recv(&mut conn).await;
            reply(&mut conn, b"NOTIFY-ERROR").await;
            assert_no_more_connections(&listener).await;
        });

        let mut transport = transport(address);
        let err = transport
            .send_receive(&TestMessage::new(b"request"), TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "Error notification");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_receive_timeout_keeps_connection() {
        let (listener, address) = listen().await;
        let (tx, rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut conn = accept(&listener).await;
            recv(&mut conn).await;
            rx.await.unwrap();
            reply(&mut conn, b"late response").await;
            assert_no_more_connections(&listener).await;
        });

        let mut transport = transport(address);
        transport.send(&TestMessage::new(b"request")).await.unwrap();
        let err = transport.receive(Duration::from_millis(50)).await.unwrap_err();
        assert!(err.is::<tokio::time::error::Elapsed>());

        tx.send(()).unwrap();
        let response = transport.receive(TIMEOUT).await;
        assert_eq!(response.unwrap(), TestMessage::new(b"late response"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_receive_eof_disconnects() {
        let (listener, address) = listen().await;
        let server = tokio::spawn(async move {
            let mut conn = accept(&listener).await;
            recv(&mut conn).await;
            drop(conn);

            let mut conn = accept(&listener).await;
            assert_eq!(recv(&mut conn).await, "request2");
        });

        let mut transport = transport(address);
        transport.send(&TestMessage::new(b"request1")).await.unwrap();
        let err = transport.receive(TIMEOUT).await.unwrap_err();
        assert!(is_connection_error(&err), "{err}");

        let err = transport.receive(TIMEOUT).await.unwrap_err();
        assert_eq!(err.to_string(), "No stream");

        transport.send(&TestMessage::new(b"request2")).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_send_receive_retries_after_eof() {
        let (listener, address) = listen().await;
        let server = tokio::spawn(async move {
            let mut conn = accept(&listener).await;
            assert_eq!(recv(&mut conn).await, "request");
            drop(conn);

            let mut conn = accept(&listener).await;
            assert_eq!(recv(&mut conn).await, "request");
            reply(&mut conn, b"response").await;
            assert_no_more_connections(&listener).await;
        });

        let mut transport = transport(address);
        let response = transport.send_receive(&TestMessage::new(b"request"), TIMEOUT).await;
        assert_eq!(response.unwrap(), TestMessage::new(b"response"));

        server.await.unwrap();
    }

    /// Issue #2: the request is written into a connection whose NAT state has expired, and the
    /// reset only surfaces when reading the response.
    #[tokio::test]
    async fn test_send_receive_retries_after_reset() {
        let (listener, address) = listen().await;
        let server = tokio::spawn(async move {
            let mut conn = accept(&listener).await;
            assert_eq!(recv(&mut conn).await, "request");
            reset(conn);

            let mut conn = accept(&listener).await;
            assert_eq!(recv(&mut conn).await, "request");
            reply(&mut conn, b"response").await;
        });

        let mut transport = transport(address);
        let response = transport.send_receive(&TestMessage::new(b"request"), TIMEOUT).await;
        assert_eq!(response.unwrap(), TestMessage::new(b"response"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_send_receive_retries_once() {
        let (listener, address) = listen().await;
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let mut conn = accept(&listener).await;
                recv(&mut conn).await;
                drop(conn);
            }
            assert_no_more_connections(&listener).await;
        });

        let mut transport = transport(address);
        let err = transport
            .send_receive(&TestMessage::new(b"request"), TIMEOUT)
            .await
            .unwrap_err();
        assert!(is_connection_error(&err), "{err}");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_send_retries_on_reset_connection() {
        let (listener, address) = listen().await;
        let (tx, rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut conn = accept(&listener).await;
            recv(&mut conn).await;
            reply(&mut conn, b"response").await;
            // Wait until the client has read the response, otherwise the reset discards it.
            rx.await.unwrap();
            reset(conn);

            let mut conn = accept(&listener).await;
            assert_eq!(recv(&mut conn).await, "request2");
        });

        let mut transport = transport(address);
        transport
            .send_receive(&TestMessage::new(b"request1"), TIMEOUT)
            .await
            .unwrap();
        tx.send(()).unwrap();

        // Give the RST time to arrive so that the write fails on the dead socket.
        tokio::time::sleep(Duration::from_millis(50)).await;
        transport.send(&TestMessage::new(b"request2")).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_with_stream_does_not_reconnect() {
        let (listener, address) = listen().await;
        let server = tokio::spawn(async move {
            let mut conn = accept(&listener).await;
            recv(&mut conn).await;
            drop(conn);
            assert_no_more_connections(&listener).await;
        });

        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.handshake(DATA_TYPE).await.unwrap();

        let mut transport = TcptTransport::with_stream(DATA_TYPE, stream, Box::new(TestCodec));
        let err = transport
            .send_receive(&TestMessage::new(b"request"), TIMEOUT)
            .await
            .unwrap_err();
        assert!(is_connection_error(&err), "{err}");

        let err = transport.send(&TestMessage::new(b"request")).await.unwrap_err();
        assert_eq!(err.to_string(), "Transport disconnected");

        server.await.unwrap();
    }
}
