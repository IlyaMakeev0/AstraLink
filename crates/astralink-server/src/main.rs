use anyhow::{bail, Context, Result};
use clap::Parser;
use quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Deserialize, Clone)]
struct ServerConfig {
    listen_host: String,
    listen_port: u16,
    users: HashMap<String, String>,
    quic_cert_path: Option<String>,
    quic_key_path: Option<String>,
    quic_alpn: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StreamHello {
    username: String,
    psk: String,
    target: String,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "config/server.json")]
    config: PathBuf,
}

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

    let users = Arc::new(conf.users);
    while let Some(incoming) = endpoint.accept().await {
        let users = users.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let remote = conn.remote_address();
                    println!("[+] quic connected: {remote}");
                    if let Err(e) = handle_connection(conn, users).await {
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

async fn handle_connection(conn: quinn::Connection, users: Arc<HashMap<String, String>>) -> Result<()> {
    loop {
        let stream = conn.accept_bi().await;
        let (mut send, mut recv) = match stream {
            Ok(v) => v,
            Err(_) => break,
        };
        let users = users.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(&mut send, &mut recv, users).await {
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
    users: Arc<HashMap<String, String>>,
) -> Result<()> {
    let hello = read_len_prefixed_json::<StreamHello>(recv).await?;
    let expected = users
        .get(&hello.username)
        .ok_or_else(|| anyhow::anyhow!("unknown user"))?;
    if expected != &hello.psk {
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
            send.write_all(&buf[..n]).await?;
            send.flush().await?;
        }
        send.finish()?;
        Result::<()>::Ok(())
    };
    tokio::try_join!(uplink, downlink)?;
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
