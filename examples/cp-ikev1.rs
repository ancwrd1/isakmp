use std::{
    io::{stdin, stdout, Write},
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, Bytes};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use regex::Regex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, mpsc::Sender},
};
use tracing_subscriber::EnvFilter;

use isakmp::{
    ikev1::Ikev1, model::ConfigAttributeType, payload::AttributesPayload, session::Ikev1Session,
    transport::UdpTransport,
};

const CCC_ID: &[u8] = b"(\n\
               :clientType (TRAC)\n\
               :clientOS (Windows_7)\n\
               :oldSessionId ()\n\
               :protocolVersion (100)\n\
               :client_mode (SYMBIAN)\n\
               :selected_realm_id (vpn_Azure_Authentication))";

async fn run_otp_listener(sender: Sender<String>) -> anyhow::Result<()> {
    static OTP_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"^GET /(?<otp>[0-9a-f]{60}|[0-9A-F]{60}).*"#).unwrap());

    let tcp = TcpListener::bind("127.0.0.1:7779").await?;
    let (mut stream, _) = tcp.accept().await?;

    let mut buf = [0u8; 65];
    stream.read_exact(&mut buf).await?;

    let mut data = String::from_utf8_lossy(&buf).into_owned();

    while stream.read(&mut buf[0..1]).await.is_ok() && buf[0] != b'\n' && buf[0] != b'\r' {
        data.push(buf[0].into());
    }

    let _ = stream.shutdown().await;
    drop(stream);
    drop(tcp);

    if let Some(captures) = OTP_RE.captures(&data) {
        if let Some(otp) = captures.name("otp") {
            let _ = sender.send(otp.as_str().to_owned()).await;
        }
    }

    Ok(())
}

fn get_attribute(payload: &AttributesPayload, attr: ConfigAttributeType) -> Vec<Bytes> {
    payload
        .attributes
        .iter()
        .filter_map(|a| {
            if a.attribute_type == attr.into() {
                a.as_long().cloned()
            } else {
                None
            }
        })
        .collect()
}

async fn do_challenge_attr(
    ikev1: &mut Ikev1<UdpTransport>,
    attr: Bytes,
    identifier: u16,
    message_id: u32,
) -> anyhow::Result<AttributesPayload> {
    let parts = attr
        .split(|c| *c == b'\0')
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect::<Vec<_>>();

    let (tx, mut rx) = mpsc::channel(1);

    if parts[0].starts_with("https://") {
        tokio::spawn(run_otp_listener(tx));
        opener::open(&parts[0])?;
    } else {
        print!("{}", parts[0]);
        stdout().flush()?;
        let mut challenge = String::new();
        stdin().read_line(&mut challenge)?;
        let _ = tx.send(challenge.trim().to_owned()).await;
    }

    let password = match tokio::time::timeout(Duration::from_secs(120), rx.recv()).await {
        Ok(Some(password)) => password,
        _ => return Err(anyhow!("Timeout while acquiring password!")),
    };

    Ok(ikev1
        .send_auth_attribute(
            identifier,
            message_id,
            ConfigAttributeType::UserPassword,
            password.trim().to_owned().into(),
            Some(Duration::from_secs(120)),
        )
        .await?
        .0)
}

async fn do_user_name(
    ikev1: &mut Ikev1<UdpTransport>,
    attr_type: ConfigAttributeType,
    identifier: u16,
    message_id: u32,
) -> anyhow::Result<AttributesPayload> {
    print!("Username: ");
    stdout().flush()?;
    let mut username = String::new();
    stdin().read_line(&mut username)?;

    Ok(ikev1
        .send_auth_attribute(
            identifier,
            message_id,
            attr_type,
            Bytes::copy_from_slice(username.trim().as_bytes()),
            None,
        )
        .await?
        .0)
}

async fn handle_id_reply(
    ikev1: &mut Ikev1<UdpTransport>,
    payload: AttributesPayload,
    message_id: u32,
) -> anyhow::Result<AttributesPayload> {
    let challenge_attr = get_attribute(&payload, ConfigAttributeType::Challenge)
        .into_iter()
        .next();

    let username_attr = get_attribute(&payload, ConfigAttributeType::UserName)
        .into_iter()
        .next();

    if let Some(_) = username_attr {
        do_user_name(
            ikev1,
            ConfigAttributeType::UserName,
            payload.identifier,
            message_id,
        )
        .await
    } else if let Some(attr) = challenge_attr {
        do_challenge_attr(ikev1, attr, payload.identifier, message_id).await
    } else {
        Err(anyhow!("Unknown reply!"))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let address = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("Missing required server address"))?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(format!("{address}:4500")).await?;

    let gateway_addr = match udp.peer_addr()?.ip() {
        IpAddr::V4(v4) => v4,
        _ => return Err(anyhow!("Not an IPv4 addres")),
    };

    let my_addr = util::get_default_ip().await?.parse::<Ipv4Addr>()?;

    let session = Arc::new(RwLock::new(Ikev1Session::new()?));
    let transport = UdpTransport::new(udp, session.clone());
    let mut ikev1 = Ikev1::new(transport, session.clone())?;

    ikev1.do_sa_proposal().await?;
    ikev1.do_key_exchange(my_addr, gateway_addr).await?;

    let (mut id_reply, message_id) = ikev1
        .do_identity_protection(Bytes::from_static(CCC_ID))
        .await?;

    println!("{:#?}", id_reply);

    let status = loop {
        id_reply = handle_id_reply(&mut ikev1, id_reply, message_id).await?;
        println!("{:#?}", id_reply);
        let status = id_reply
            .attributes
            .iter()
            .find_map(|a| match a.attribute_type.into() {
                ConfigAttributeType::Status => a.as_short(),
                _ => None,
            });
        if let Some(status) = status {
            break status;
        }
    };

    if status != 1 {
        return Err(anyhow!("Authentication failed!"));
    }

    println!("Authentication succeeded!");

    ikev1
        .send_ack_response(id_reply.identifier, message_id)
        .await?;

    let om_reply = ikev1.send_om_request().await?;

    println!("{:#?}", om_reply);

    let ccc_session = get_attribute(&om_reply, ConfigAttributeType::CccSessionId)
        .into_iter()
        .next()
        .map(|v| String::from_utf8_lossy(&v).trim_matches('\0').to_string())
        .ok_or_else(|| anyhow!("No session in reply!"))?;

    let ipv4addr: Ipv4Addr = get_attribute(&om_reply, ConfigAttributeType::Ipv4Address)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("No IPv4 in reply!"))?
        .reader()
        .read_u32::<BigEndian>()?
        .into();

    let netmask: Ipv4Addr = get_attribute(&om_reply, ConfigAttributeType::Ipv4Netmask)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("No netmask in reply!"))?
        .reader()
        .read_u32::<BigEndian>()?
        .into();

    let dns: Vec<Ipv4Addr> = get_attribute(&om_reply, ConfigAttributeType::Ipv4Dns)
        .into_iter()
        .flat_map(|b| b.reader().read_u32::<BigEndian>().ok())
        .map(Into::into)
        .collect();

    let search_domains = get_attribute(&om_reply, ConfigAttributeType::InternalDomainName)
        .into_iter()
        .next()
        .map(|v| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_default();

    ikev1.do_esp_proposal(ipv4addr).await?;

    println!("CCC session: {}", ccc_session);
    println!("IPv4:        {}", ipv4addr);
    println!("Netmask:     {}", netmask);
    println!("DNS:         {:?}", dns);
    println!("Domains:     {}", search_domains);

    ikev1.delete_sa().await?;

    Ok(())
}

mod util {
    use std::{ffi::OsStr, fmt, path::Path, process::Output};

    use anyhow::anyhow;
    use tokio::process::Command;

    fn process_output(output: Output) -> anyhow::Result<String> {
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Err(anyhow!(if !stderr.is_empty() {
                stderr
            } else {
                output.status.to_string()
            }))
        }
    }

    pub async fn run_command<C, I, T>(command: C, args: I) -> anyhow::Result<String>
    where
        C: AsRef<Path> + fmt::Debug,
        I: IntoIterator<Item = T> + fmt::Debug,
        T: AsRef<OsStr>,
    {
        let mut command = Command::new(command.as_ref().as_os_str());
        command
            .envs(vec![("LANG", "C"), ("LC_ALL", "C")])
            .args(args);

        process_output(command.output().await?)
    }

    pub async fn get_default_ip() -> anyhow::Result<String> {
        let default_route =
            crate::util::run_command("ip", ["-4", "route", "show", "default"]).await?;
        let mut parts = default_route.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "dev" {
                if let Some(dev) = parts.next() {
                    let addr =
                        crate::util::run_command("ip", ["-4", "-o", "addr", "show", "dev", dev])
                            .await?;
                    let mut parts = addr.split_whitespace();
                    while let Some(part) = parts.next() {
                        if part == "inet" {
                            if let Some(ip) = parts.next() {
                                if let Some((ip, _)) = ip.split_once('/') {
                                    return Ok(ip.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(anyhow!("Cannot determine default IP!"))
    }
}
