use std::{
    io::{stdin, stdout, Write},
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    path::PathBuf,
    time::Duration,
};

use anyhow::{anyhow, Context};
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, Bytes};
use once_cell::sync::Lazy;
use regex::Regex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, mpsc::Sender},
};
use tracing_subscriber::EnvFilter;

use isakmp::{
    ikev1::{codec::Ikev1Codec, service::Ikev1Service, session::Ikev1Session},
    model::{ConfigAttributeType, EspAttributeType, Identity, IdentityRequest, IkeAttributeType},
    payload::AttributesPayload,
    session::IsakmpSession,
    transport::UdpTransport,
};

const CP_AUTH_BLOB: &[u8] = b"(\n\
               :clientType (TRAC)\n\
               :clientOS (Windows_7)\n\
               :oldSessionId ()\n\
               :protocolVersion (100)\n\
               :client_mode (endpoint_security)\n\
               :selected_realm_id (vpn_Azure_Authentication))";

async fn run_otp_listener(sender: Sender<String>) -> anyhow::Result<()> {
    static OTP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^GET /(?<otp>[0-9a-f]{60}|[0-9A-F]{60}).*").unwrap());

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
    ikev1: &mut Ikev1Service,
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

    let Ok(Some(password)) = tokio::time::timeout(Duration::from_secs(120), rx.recv()).await else {
        anyhow::bail!("Timeout while acquiring password!");
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
    ikev1: &mut Ikev1Service,
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

async fn handle_auth_reply(
    ikev1: &mut Ikev1Service,
    payload: AttributesPayload,
    message_id: u32,
) -> anyhow::Result<AttributesPayload> {
    let challenge_attr = get_attribute(&payload, ConfigAttributeType::Challenge)
        .into_iter()
        .next();

    let username_attr = get_attribute(&payload, ConfigAttributeType::UserName)
        .into_iter()
        .next();

    if username_attr.is_some() {
        do_user_name(ikev1, ConfigAttributeType::UserName, payload.identifier, message_id).await
    } else if let Some(attr) = challenge_attr {
        do_challenge_attr(ikev1, attr, payload.identifier, message_id).await
    } else {
        Err(anyhow!("Unknown reply!"))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();

    let address = args.get(1).context("Missing required server address")?;

    let identity = match args.get(2).map(|s| s.as_str()) {
        Some("pkcs12") => match args.get(3) {
            Some(arg) => Identity::Pkcs12 {
                path: arg.into(),
                password: args.get(4).map(|s| s.as_str()).unwrap_or_default().to_owned(),
            },
            None => return Err(anyhow!("Missing pkcs12 file path")),
        },
        Some("pkcs8") => match args.get(3) {
            Some(arg) => Identity::Pkcs8 { path: arg.into() },
            None => return Err(anyhow!("Missing pkcs8 pem file path")),
        },
        Some("pkcs11") => match args.get(3) {
            Some(arg) => Identity::Pkcs11 {
                driver_path: arg.into(),
                pin: args.get(4).map(|s| s.as_str()).unwrap_or_default().to_owned(),
                key_id: args.get(5).map(|s| hex::decode(s).unwrap().into()),
            },
            None => return Err(anyhow!("Missing pkcs8 pem file path")),
        },
        _ => Identity::None,
    };

    let (verify_certs, ca_certs) = if matches!(args.get(2).map(|s| s.as_str()), Some("validate")) {
        (true, vec![PathBuf::from(&args[3])])
    } else {
        (false, Vec::new())
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(format!("{address}:500")).await?;

    let IpAddr::V4(gateway_addr) = udp.peer_addr()?.ip() else {
        anyhow::bail!("Not an IPv4 addres");
    };

    let my_addr = util::get_default_ip().await?.parse::<Ipv4Addr>()?;

    let session = Ikev1Session::new(identity.clone())?;
    //let transport = UdpTransport::new(udp, Ikev1Codec::new(session.clone()));

    let socket_address = format!("{address}:443")
        .to_socket_addrs()?
        .next()
        .context("No address")?;

    let transport = Box::new(isakmp::transport::TcptTransport::new(
        socket_address,
        Box::new(Ikev1Codec::new(Box::new(session.clone()))),
    ));

    let mut service = Ikev1Service::new(transport, Box::new(session))?;

    let attributes = service.do_sa_proposal(Duration::from_secs(120)).await?;

    let lifetime = attributes
        .iter()
        .find_map(|a| match IkeAttributeType::from(a.attribute_type) {
            IkeAttributeType::LifeDuration => a.as_long().and_then(|v| {
                let data: Option<[u8; 4]> = v.as_ref().try_into().ok();
                data.map(u32::from_be_bytes)
            }),
            _ => None,
        })
        .context("No lifetime in reply!")?;

    println!("IKE lifetime: {lifetime}");

    service.do_key_exchange(my_addr, gateway_addr).await?;

    let identity_request = IdentityRequest {
        auth_blob: Bytes::from_static(CP_AUTH_BLOB),
        verify_certs,
        ca_certs,
        with_mfa: matches!(identity, Identity::None),
    };

    if let Some((mut auth_attrs, message_id)) = service.do_identity_protection(identity_request).await? {
        let status = loop {
            auth_attrs = handle_auth_reply(&mut service, auth_attrs, message_id).await?;
            println!("{auth_attrs:#?}");
            let status = auth_attrs
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
            anyhow::bail!("Authentication failed!");
        }

        service.send_ack_response(auth_attrs.identifier, message_id).await?;

        println!("Authentication succeeded!");
    }

    let om_reply = service.send_om_request().await?;

    println!("{om_reply:#?}");

    let ccc_session = get_attribute(&om_reply, ConfigAttributeType::CccSessionId)
        .into_iter()
        .next()
        .map(|v| String::from_utf8_lossy(&v).trim_matches('\0').to_string())
        .context("No session in reply!")?;

    let ipv4addr: Ipv4Addr = get_attribute(&om_reply, ConfigAttributeType::Ipv4Address)
        .into_iter()
        .next()
        .context("No IPv4 in reply!")?
        .reader()
        .read_u32::<BigEndian>()?
        .into();

    let netmask: Ipv4Addr = get_attribute(&om_reply, ConfigAttributeType::Ipv4Netmask)
        .into_iter()
        .next()
        .context("No netmask in reply!")?
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

    let attributes = service.do_esp_proposal(ipv4addr, Duration::from_secs(60)).await?;

    println!("{attributes:#?}");

    let lifetime = attributes
        .iter()
        .find_map(|a| match EspAttributeType::from(a.attribute_type) {
            EspAttributeType::LifeDuration => a.as_long().and_then(|v| {
                let data: Option<[u8; 4]> = v.as_ref().try_into().ok();
                data.map(u32::from_be_bytes)
            }),
            _ => None,
        })
        .context("No lifetime in reply!")?;

    println!("CCC session: {ccc_session}");
    println!("Lifetime:    {lifetime}");
    println!("IPv4:        {ipv4addr}");
    println!("Netmask:     {netmask}");
    println!("DNS:         {dns:?}");
    println!("Domains:     {search_domains}");

    let saved = service.session().save()?;

    drop(service);

    let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(format!("{address}:500")).await?;

    let mut session = Ikev1Session::new(identity.clone())?;
    session.load(&saved)?;

    let transport = Box::new(UdpTransport::new(
        udp,
        Box::new(Ikev1Codec::new(Box::new(session.clone()))),
    ));
    let mut service = Ikev1Service::new(transport, Box::new(session))?;

    let attributes = service.do_esp_proposal(ipv4addr, Duration::from_secs(60)).await?;

    println!("{attributes:#?}");

    service.delete_sa().await?;

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
            Err(anyhow!(if stderr.is_empty() {
                output.status.to_string()
            } else {
                stderr
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
        command.envs(vec![("LANG", "C"), ("LC_ALL", "C")]).args(args);

        process_output(command.output().await?)
    }

    pub async fn get_default_ip() -> anyhow::Result<String> {
        let default_route = crate::util::run_command("ip", ["-4", "route", "show", "default"]).await?;
        let mut parts = default_route.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "dev" {
                if let Some(dev) = parts.next() {
                    let addr = crate::util::run_command("ip", ["-4", "-o", "addr", "show", "dev", dev]).await?;
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
