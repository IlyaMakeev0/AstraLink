use anyhow::{bail, Context, Result};
use clap::Parser;
use rand::Rng;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, Duration};

#[derive(Debug, Deserialize, Clone)]
struct ClientConfig {
    server_host: String,
    server_port: u16,
    server_name: Option<String>,
    username: String,
    psk: String,
    local_socks_host: String,
    local_socks_port: u16,
    ca_cert_path: Option<String>,
    quic_alpn: Option<String>,
    shaping: Option<ShapingConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StreamHello {
    username: String,
    psk: String,
    target: String,
}

#[derive(Debug, Deserialize, Clone)]
struct ShapingConfig {
    enabled: bool,
    min_chunk: usize,
    max_chunk: usize,
    max_delay_ms: u64,
    fragment_hello: bool,
}

impl Default for ShapingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_chunk: 256,
            max_chunk: 1400,
            max_delay_ms: 8,
            fragment_hello: true,
        }
    }
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "config/client.json")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let raw = tokio::fs::read(&args.config)
        .await
        .with_context(|| format!("read config {:?}", args.config))?;
    let conf: ClientConfig = serde_json::from_slice(&raw).context("parse client config")?;

    let bind = format!("{}:{}", conf.local_socks_host, conf.local_socks_port);
    let listener = TcpListener::bind(&bind).await?;
    println!("astralink-client (QUIC/TLS1.3) SOCKS5 listening on {bind}");

    let endpoint = build_client_endpoint(&conf)?;
    let server_addr = resolve_addr(&conf.server_host, conf.server_port)?;
    let server_name = conf
        .server_name
        .clone()
        .unwrap_or_else(|| conf.server_host.clone());

    let conn = endpoint
        .connect(server_addr, &server_name)
        .context("connect init")?
        .await
        .context("connect handshake")?;
    println!(
        "connected QUIC to {}:{} as {}",
        conf.server_host, conf.server_port, conf.username
    );
    let conn = Arc::new(conn);
    let conf = Arc::new(conf);

    loop {
        let (sock, peer) = listener.accept().await?;
        let conn = conn.clone();
        let conf = conf.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks_conn(sock, conn, conf).await {
                eprintln!("socks session {peer} failed: {e:#}");
            }
        });
    }
}

fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr> {
    let addr = format!("{host}:{port}");
    let mut addrs = addr.to_socket_addrs().context("dns resolve failed")?;
    addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses resolved"))
}

fn build_client_endpoint(conf: &ClientConfig) -> Result<Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    let ca_path = conf
        .ca_cert_path
        .clone()
        .unwrap_or_else(|| "config/transport.crt".to_string());
    let ca_pem = std::fs::read(&ca_path).with_context(|| format!("read ca cert {ca_path}"))?;
    let certs = rustls_pemfile::certs(&mut ca_pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse ca cert")?;
    if certs.is_empty() {
        bail!("no cert in ca_cert_path");
    }
    for cert in certs {
        roots.add(cert)?;
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![
        conf.quic_alpn
            .clone()
            .unwrap_or_else(|| "astralink/2".to_string())
            .into_bytes(),
    ];
    let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let client_cfg = QuinnClientConfig::new(Arc::new(client_crypto));

    let mut endpoint = Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

async fn handle_socks_conn(
    mut local: TcpStream,
    conn: Arc<quinn::Connection>,
    conf: Arc<ClientConfig>,
) -> Result<()> {
    let shaping = conf.shaping.clone().unwrap_or_default();
    let target = socks5_handshake_and_target(&mut local).await?;
    let (mut send, mut recv) = conn.open_bi().await.context("open quic stream")?;
    let hello = StreamHello {
        username: conf.username.clone(),
        psk: conf.psk.clone(),
        target,
    };
    let body = serde_json::to_vec(&hello)?;
    let mut hello_wire = Vec::with_capacity(4 + body.len());
    hello_wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
    hello_wire.extend_from_slice(&body);
    if shaping.enabled && shaping.fragment_hello {
        write_fragmented(&mut send, &hello_wire, &shaping).await?;
    } else {
        send.write_all(&hello_wire).await?;
        send.flush().await?;
    }

    let mut status = [0u8; 1];
    recv.read_exact(&mut status).await?;
    let mut err_len = [0u8; 2];
    recv.read_exact(&mut err_len).await?;
    let el = u16::from_be_bytes(err_len) as usize;
    if status[0] != 1 {
        let mut err = vec![0u8; el];
        if el > 0 {
            recv.read_exact(&mut err).await?;
        }
        let msg = String::from_utf8_lossy(&err).to_string();
        bail!("server rejected stream: {msg}");
    }

    local
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    local.flush().await?;

    let (mut lr, mut lw) = local.into_split();
    let up = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = lr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_fragmented(&mut send, &buf[..n], &shaping).await?;
        }
        send.finish()?;
        Result::<()>::Ok(())
    };
    let down = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = recv.read(&mut buf).await?;
            let Some(n) = n else {
                break;
            };
            if n == 0 {
                break;
            }
            lw.write_all(&buf[..n]).await?;
            lw.flush().await?;
        }
        lw.shutdown().await?;
        Result::<()>::Ok(())
    };
    tokio::try_join!(up, down)?;
    Ok(())
}

async fn socks5_handshake_and_target(local: &mut TcpStream) -> Result<String> {
    let mut head = [0u8; 2];
    local.read_exact(&mut head).await?;
    if head[0] != 5 {
        bail!("only socks5");
    }
    let n_methods = head[1] as usize;
    let mut methods = vec![0u8; n_methods];
    local.read_exact(&mut methods).await?;
    local.write_all(&[0x05, 0x00]).await?;
    local.flush().await?;

    let mut req = [0u8; 4];
    local.read_exact(&mut req).await?;
    if req[0] != 5 || req[1] != 1 {
        bail!("only CONNECT is supported");
    }
    let host = match req[3] {
        1 => {
            let mut ip = [0u8; 4];
            local.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        3 => {
            let mut ln = [0u8; 1];
            local.read_exact(&mut ln).await?;
            let mut s = vec![0u8; ln[0] as usize];
            local.read_exact(&mut s).await?;
            String::from_utf8(s).context("domain utf8")?
        }
        4 => {
            let mut ip = [0u8; 16];
            local.read_exact(&mut ip).await?;
            use std::net::Ipv6Addr;
            Ipv6Addr::from(ip).to_string()
        }
        _ => bail!("unknown atyp"),
    };
    let mut pb = [0u8; 2];
    local.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);
    Ok(format!("{host}:{port}"))
}

use std::net::ToSocketAddrs;

async fn write_fragmented(
    send: &mut quinn::SendStream,
    data: &[u8],
    shaping: &ShapingConfig,
) -> Result<()> {
    if !shaping.enabled || data.is_empty() {
        send.write_all(data).await?;
        send.flush().await?;
        return Ok(());
    }
    let mut idx = 0usize;
    while idx < data.len() {
        let remain = data.len() - idx;
        let lo = shaping.min_chunk.max(1);
        let hi = shaping.max_chunk.max(lo);
        let take = remain.min(rand::thread_rng().gen_range(lo..=hi));
        send.write_all(&data[idx..idx + take]).await?;
        send.flush().await?;
        idx += take;
        if idx < data.len() && shaping.max_delay_ms > 0 {
            let d = rand::thread_rng().gen_range(0..=shaping.max_delay_ms);
            if d > 0 {
                sleep(Duration::from_millis(d)).await;
            }
        }
    }
    Ok(())
}
