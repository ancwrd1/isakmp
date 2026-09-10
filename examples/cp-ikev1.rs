use anyhow::{Context, anyhow};
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, Bytes};
use clap::{Parser, Subcommand};
use ipnet::Ipv4Net;
use isakmp::{
    ikev1::{
        model::{ConfigAttributeType, EspAttributeType, IdentityRequest},
        payload::AttributesPayload,
        service::Ikev1Service,
        session::Ikev1Session,
    },
    model::Identity,
    session::{IsakmpSession, OfficeMode, SessionType},
    transport::{TcptDataType, UdpTransport},
};
use regex::Regex;
use std::sync::Arc;
use std::{
    io::{Write, stdin, stdout},
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    path::PathBuf,
    sync::LazyLock,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, mpsc::Sender},
};
use tracing_subscriber::EnvFilter;

fn cp_auth_blob(realm: &str) -> String {
    format!(
        "(\n\
        \t:clientType (TRAC)\n\
        \t:clientOS (Windows_7)\n\
        \t:oldSessionId ()\n\
        \t:protocolVersion (100)\n\
        \t:client_mode (endpoint_security)\n\
        \t:selected_realm_id ({realm})\n\
        \t:client_logging_data (\n\
        \t\t:device_id (\"{{02374BAD-DE87-4B94-8190-8E33AEA8D5F0}}\")\n\
        \t\t:client_name (\"Endpoint Security VPN\")\n\
        \t\t:client_ver (E88.72)\n\
        \t\t:client_build_number (986105950)\n\
        \t\t:device_type (PC)\n\
        \t\t:os_name (Windows)\n\
        \t\t:os_version (11)\n\
        \t\t:os_edition (Professional)\n\
        \t\t:os_service_pack ()\n\
        \t\t:os_build (26200)\n\
        \t\t:os_bits (64bit)\n\
        \t\t:machine_domain ()\n\
        \t\t:machine_name (DESKTOP-NICFJFL)\n\
        \t\t:physical_ip (172.24.1.189)\n\
        \t\t:mac_address (\"52:54:00:63:2f:09,54:da:3e:16:99:00\")\n\
        \t)\n\
        )\n"
    )
}

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    address: String,
    realm: String,

    #[command(subcommand)]
    identity: Option<IdentityArgs>,
}

#[derive(Debug, Subcommand)]
enum IdentityArgs {
    Pkcs12 {
        path: PathBuf,
        password: Option<String>,
    },
    Pkcs8 {
        path: PathBuf,
    },
    Pkcs11 {
        driver_path: PathBuf,
        pin: Option<String>,
        #[arg(value_parser = parse_hex)]
        key_id: Option<Bytes>,
    },
}

fn parse_hex(value: &str) -> anyhow::Result<Bytes> {
    Ok(hex::decode(value)?.into())
}

impl TryFrom<IdentityArgs> for Identity {
    type Error = anyhow::Error;

    fn try_from(args: IdentityArgs) -> anyhow::Result<Self> {
        Ok(match args {
            IdentityArgs::Pkcs12 { path, password } => Identity::Pkcs12 {
                data: std::fs::read(path)?,
                password: password.unwrap_or_default().into(),
                hybrid_auth: false,
            },
            IdentityArgs::Pkcs8 { path } => Identity::Pkcs8 {
                path,
                hybrid_auth: false,
            },
            IdentityArgs::Pkcs11 {
                driver_path,
                pin,
                key_id,
            } => Identity::Pkcs11 {
                driver_path,
                pin: pin.unwrap_or_default().into(),
                key_id,
                hybrid_auth: false,
            },
        })
    }
}

async fn run_otp_listener(sender: Sender<String>) -> anyhow::Result<()> {
    static OTP_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^GET /(?<otp>[0-9a-f]{60}|[0-9A-F]{60}).*").unwrap());

    let tcp = TcpListener::bind("127.0.0.1:7779").await?;
    let mut data = String::new();

    while data.is_empty() {
        let (mut stream, _) = tcp.accept().await?;

        let mut buf = [0u8; 1];

        while let Ok(size) = stream.read(&mut buf).await
            && size > 0
            && buf[0] != b'\n'
            && buf[0] != b'\r'
        {
            data.push(buf[0].into());
        }

        let _ = stream.shutdown().await;
        drop(stream);
    }

    drop(tcp);

    if let Some(captures) = OTP_RE.captures(&data)
        && let Some(otp) = captures.name("otp")
    {
        let _ = sender.send(otp.as_str().to_owned()).await;
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
        .send_attribute(
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
        .send_attribute(
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
    let cli = Cli::parse();
    let address = &cli.address;

    let identity = cli.identity.map(Identity::try_from).transpose()?.unwrap_or_default();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(format!("{address}:500")).await?;

    let IpAddr::V4(gateway_addr) = udp.peer_addr()?.ip() else {
        anyhow::bail!("Not an IPv4 addres");
    };

    let my_addr = util::get_default_ip().await?.parse::<Ipv4Addr>()?;

    let session = Ikev1Session::new(identity.clone(), SessionType::Initiator)?;

    let socket_address = format!("{address}:443")
        .to_socket_addrs()?
        .next()
        .context("No address")?;

    let transport = Box::new(isakmp::transport::TcptTransport::new(
        TcptDataType::Ike,
        socket_address,
        session.new_codec(),
    ));

    let mut service = Ikev1Service::new(transport, session)?;

    let proposal = service.do_sa_proposal(Duration::from_secs(120)).await?;

    println!("SA proposal: {proposal}");

    service.do_key_exchange(my_addr, gateway_addr).await?;

    let identity_request = IdentityRequest {
        auth_blob: cp_auth_blob(&cli.realm),
        with_mfa: matches!(identity, Identity::None),
        internal_ca_fingerprints: Vec::new(),
    };

    if let (Some(mut auth_attrs), message_id) = service.do_identity_protection(identity_request).await? {
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

    let om_reply = service.send_om_request(None, None).await?;

    println!("OM reply: {om_reply:#?}");

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

    let office_mode = OfficeMode {
        ccc_session,
        username: "".to_string(),
        ip_address: ipv4addr,
        netmask,
        dns,
        domains: search_domains.split([',', ';']).map(ToOwned::to_owned).collect(),
    };

    println!("Lifetime: {lifetime}");
    println!("Office mode: {office_mode:#?}");

    let saved = service.session().save(&office_mode)?;

    drop(service);

    let udp = tokio::net::UdpSocket::bind("0.0.0.0:4500").await?;
    udp.connect(format!("{address}:4500")).await?;

    let session = Ikev1Session::new(identity.clone(), SessionType::Initiator)?;
    let office_mode = session.load(&saved)?;
    println!("Loaded office mode: {office_mode:#?}");

    let transport = Box::new(UdpTransport::new(Arc::new(udp), session.new_codec()));
    let mut service = Ikev1Service::new(transport, session)?;

    let om_reply = service
        .send_om_request(Some(Ipv4Net::with_netmask(ipv4addr, netmask)?), None)
        .await?;

    println!("OM reply: {om_reply:#?}");

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
            if part == "dev"
                && let Some(dev) = parts.next()
            {
                let addr = crate::util::run_command("ip", ["-4", "-o", "addr", "show", "dev", dev]).await?;
                let mut parts = addr.split_whitespace();
                while let Some(part) = parts.next() {
                    if part == "inet"
                        && let Some(ip) = parts.next()
                        && let Some((ip, _)) = ip.split_once('/')
                    {
                        return Ok(ip.to_string());
                    }
                }
            }
        }
        Err(anyhow!("Cannot determine default IP!"))
    }
}
