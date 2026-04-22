use anyhow::{bail, Context, Result};
use clap::Parser;
use rand::Rng;
use quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

#[derive(Debug, Deserialize, Clone)]
struct ServerConfig {
    listen_host: String,
    listen_port: u16,
    users: HashMap<String, String>,
    quic_cert_path: Option<String>,
    quic_key_path: Option<String>,
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
}

impl Default for ShapingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_chunk: 256,
            max_chunk: 1400,
            max_delay_ms: 8,
        }
    }
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "config/server.json")]
    config: PathBuf,
}

type SharedUsers = Arc<RwLock<HashMap<String, String>>>;
type SharedShaping = Arc<ShapingConfig>;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let raw = tokio::fs::read(&args.config)
        .await
        .with_context(|| format!("read config {:?}", args.config))?;
    let conf: ServerConfig = serde_json::from_slice(&raw).context("parse config json")?;
    if conf.users.is_empty() {
        bail!("users map is empty");
    }

    let cert_path = conf
        .quic_cert_path
        .clone()
        .unwrap_or_else(|| "config/transport.crt".to_string());
    let key_path = conf
        .quic_key_path
        .clone()
        .unwrap_or_else(|| "config/transport.key".to_string());
    let alpn = conf
        .quic_alpn
        .clone()
        .unwrap_or_else(|| "astralink/2".to_string());

    let server_config = build_server_config(&cert_path, &key_path, &alpn)?;
    let bind_addr = format!("{}:{}", conf.listen_host, conf.listen_port);
    let endpoint = Endpoint::server(server_config, bind_addr.parse().context("bad bind addr")?)?;
    println!("astralink-server (QUIC/TLS1.3) listening on {bind_addr}");

    let users: SharedUsers = Arc::new(RwLock::new(conf.users.clone()));
    {
        let users_reload = users.clone();
        let config_path = args.config.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(5)).await;
                if let Ok(raw) = tokio::fs::read(&config_path).await {
                    if let Ok(next_conf) = serde_json::from_slice::<ServerConfig>(&raw) {
                        let mut guard = users_reload.write().await;
                        if *guard != next_conf.users {
                            *guard = next_conf.users;
                            println!("[*] hot-reloaded users from config");
                        }
                    }
                }
            }
        });
    }

    let shaping: SharedShaping = Arc::new(conf.shaping.unwrap_or_default());
    while let Some(incoming) = endpoint.accept().await {
        let users = users.clone();
        let shaping = shaping.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let remote = conn.remote_address();
                    println!("[+] quic connected: {remote}");
                    if let Err(e) = handle_connection(conn, users, shaping).await {
                        eprintln!("[!] connection error {remote}: {e:#}");
                    }
                }
                Err(e) => eprintln!("[!] incoming handshake error: {e:#}"),
            }
        });
    }
    Ok(())
}

fn build_server_config(cert_path: &str, key_path: &str, alpn: &str) -> Result<QuinnServerConfig> {
    let cert_pem = std::fs::read(cert_path).with_context(|| format!("read cert {cert_path}"))?;
    let key_pem = std::fs::read(key_path).with_context(|| format!("read key {key_path}"))?;

    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse cert pem")?;
    if certs.is_empty() {
        bail!("no certs found");
    }
    let cert_chain: Vec<CertificateDer<'static>> = certs.into_iter().collect();

    let keys = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse key pem")?;
    if keys.is_empty() {
        bail!("no PKCS8 keys found");
    }
    let pk: PrivateKeyDer<'static> = keys.into_iter().next().unwrap().into();

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, pk)
        .context("build rustls server config")?;
    tls.alpn_protocols = vec![alpn.as_bytes().to_vec()];

    let mut cfg = QuinnServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).context("quic tls config")?,
    ));
    let transport = Arc::get_mut(&mut cfg.transport).expect("transport unique");
    transport.max_concurrent_bidi_streams(1024_u32.into());
    Ok(cfg)
}

async fn handle_connection(
    conn: quinn::Connection,
    users: SharedUsers,
    shaping: SharedShaping,
) -> Result<()> {
    loop {
        let stream = conn.accept_bi().await;
        let (mut send, mut recv) = match stream {
            Ok(v) => v,
            Err(_) => break,
        };
        let users = users.clone();
        let shaping = shaping.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(&mut send, &mut recv, users, shaping).await {
                let _ = send.write_all(&[0]).await;
                let err = e.to_string();
                let _ = send.write_all(&(err.len() as u16).to_be_bytes()).await;
                let _ = send.write_all(err.as_bytes()).await;
                let _ = send.finish();
            }
        });
    }
    Ok(())
}

async fn handle_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    users: SharedUsers,
    shaping: SharedShaping,
) -> Result<()> {
    let hello = read_len_prefixed_json::<StreamHello>(recv).await?;
    let expected_psk = {
        let users_snapshot = users.read().await;
        users_snapshot
            .get(&hello.username)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown user"))?
    };
    if expected_psk != hello.psk {
        bail!("bad credentials");
    }
    let (host, port_s) = hello
        .target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("bad target"))?;
    let port: u16 = port_s.parse().context("bad target port")?;
    let remote = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connect target {}", hello.target))?;

    send.write_all(&[1]).await?;
    send.write_all(&0u16.to_be_bytes()).await?;
    send.flush().await?;

    let (mut rr, mut rw) = remote.into_split();
    let uplink = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = recv.read(&mut buf).await?;
            let Some(n) = n else {
                break;
            };
            if n == 0 {
                break;
            }
            rw.write_all(&buf[..n]).await?;
        }
        rw.shutdown().await?;
        Result::<()>::Ok(())
    };
    let downlink = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = rr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_fragmented(send, &buf[..n], &shaping).await?;
        }
        send.finish()?;
        Result::<()>::Ok(())
    };
    tokio::try_join!(uplink, downlink)?;
    Ok(())
}

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

async fn read_len_prefixed_json<T: for<'a> Deserialize<'a>>(recv: &mut quinn::RecvStream) -> Result<T> {
    let mut len_b = [0u8; 4];
    recv.read_exact(&mut len_b).await?;
    let len = u32::from_be_bytes(len_b) as usize;
    if len > 64 * 1024 {
        bail!("hello too large");
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;
    let msg = serde_json::from_slice::<T>(&body).context("parse json hello")?;
    Ok(msg)
}
