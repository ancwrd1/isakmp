use std::{
    io::{Write, stdin, stdout},
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, LazyLock},
    time::Duration,
};

use bytes::Bytes;
use clap::{Parser, Subcommand, ValueEnum};
use isakmp::{
    ikev2::{
        service::{Ikev2AuthRequest, Ikev2Service, Ikev2Step},
        session::Ikev2Session,
    },
    model::Identity,
    session::{IsakmpSession, SessionType},
    transport::UdpTransport,
};
use regex::Regex;
use secrecy::SecretString;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, mpsc::Sender},
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CertType {
    Machine,
    User,
}
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    address: String,
    realm: String,

    #[arg(short, long)]
    username: Option<String>,

    #[arg(long, value_enum, default_value_t = CertType::Machine, global = true)]
    cert_type: CertType,

    /// Machine name for the first authentication round, sent as IDi with a '$'
    /// appended. Required with a machine certificate.
    #[arg(long)]
    machine_name: Option<String>,

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

fn load_identity(args: Option<IdentityArgs>, cert_type: CertType) -> anyhow::Result<Identity> {
    let hybrid_auth = cert_type == CertType::Machine;

    let secret = |given: Option<String>, text| -> anyhow::Result<SecretString> {
        Ok(match given {
            Some(secret) => SecretString::from(secret),
            None => SecretString::from(prompt(text)?),
        })
    };

    Ok(match args {
        None => Identity::None,
        Some(IdentityArgs::Pkcs12 { path, password }) => Identity::Pkcs12 {
            data: std::fs::read(path)?,
            password: secret(password, "Certificate password: ")?,
            hybrid_auth,
        },
        Some(IdentityArgs::Pkcs8 { path }) => Identity::Pkcs8 { path, hybrid_auth },
        Some(IdentityArgs::Pkcs11 {
            driver_path,
            pin,
            key_id,
        }) => Identity::Pkcs11 {
            driver_path,
            pin: secret(pin, "Token PIN: ")?,
            key_id,
            hybrid_auth,
        },
    })
}

fn cp_auth_blob(realm: &str) -> String {
    format!(
        "(\n\
        \t:clientType (TRAC)\n\
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

const IKE_PORT: u16 = 4500;

fn prompt(text: &str) -> anyhow::Result<String> {
    print!("{text}");
    stdout().flush()?;

    let mut line = String::new();
    stdin().read_line(&mut line)?;

    Ok(line.trim().to_owned())
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let username = match args.username {
        Some(username) => username,
        None => prompt("Username: ")?,
    };

    let udp = tokio::net::UdpSocket::bind("0.0.0.0:4500").await?;
    udp.connect(format!("{}:{IKE_PORT}", args.address)).await?;

    let (SocketAddr::V4(local), SocketAddr::V4(gateway)) = (udp.local_addr()?, udp.peer_addr()?) else {
        anyhow::bail!("Not an IPv4 address");
    };

    let identity = load_identity(args.identity, args.cert_type)?;

    let session = Ikev2Session::new(identity, SessionType::Initiator)?;
    let transport = Box::new(UdpTransport::new(Arc::new(udp), session.new_codec()));

    let mut service = Ikev2Service::new(transport, session.clone())?;

    let sa_init = service.do_sa_init(local, gateway).await?;

    println!(
        "IKE SA established with {}, local NAT: {}, remote NAT: {}",
        gateway.ip(),
        sa_init.local_nat,
        sa_init.remote_nat
    );

    let mut step = service
        .do_auth(Ikev2AuthRequest {
            username,
            auth_blob: cp_auth_blob(&args.realm),
            address: None,
            machine_name: args.machine_name,
        })
        .await?;

    let result = loop {
        match step {
            Ikev2Step::NeedsChallenge(challenge) => {
                let text = challenge
                    .data()
                    .split(|c| *c == b'\0')
                    .next()
                    .map(|prompt| String::from_utf8_lossy(prompt).trim().to_owned())
                    .unwrap_or_default();

                if text.starts_with("https://") {
                    let (tx, mut rx) = mpsc::channel(1);
                    tokio::spawn(run_otp_listener(tx));
                    opener::open(&text)?;

                    let Ok(Some(password)) = tokio::time::timeout(Duration::from_secs(120), rx.recv()).await else {
                        anyhow::bail!("Timeout while acquiring password!");
                    };
                    step = service.step(Bytes::from(password.into_bytes())).await?;
                } else {
                    let answer = prompt(if text.is_empty() { "Password: " } else { &text })?;

                    step = service.step(Bytes::from(answer.into_bytes())).await?;
                }
            }
            Ikev2Step::Done(result) => break result,
        }
    };

    println!("Authenticated as {}", result.office_mode.username);
    println!("Address    : {}", result.office_mode.ip_address);
    println!("Netmask    : {}", result.office_mode.netmask);
    println!("DNS        : {:?}", result.office_mode.dns);
    println!("Domains    : {:?}", result.office_mode.domains);
    println!("CCC session: {}", result.office_mode.ccc_session);
    println!("Lifetime   : {:?}", session.lifetime());

    for selector in &result.ts_r {
        println!(
            "Remote net : {:?} - {:?}",
            Ipv4Addr::from(<[u8; 4]>::try_from(selector.start_address.as_ref())?),
            Ipv4Addr::from(<[u8; 4]>::try_from(selector.end_address.as_ref())?),
        );
    }

    // the child SA is keyed and ready for esp.rs to send through
    let (esp_in, esp_out) = (session.esp_in(), session.esp_out());
    println!("ESP in     : SPI {:08x}, {:?}", esp_in.spi, esp_in.cipher);
    println!("ESP out    : SPI {:08x}, {:?}", esp_out.spi, esp_out.cipher);

    Ok(())
}
