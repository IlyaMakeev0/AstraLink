use anyhow::{Context, Result};
use astralink_core::{
    build_server_hello, unpack_len, verify_client_hello, SecureFramer, CLOSE, DATA, OPEN, OPEN_ERR, OPEN_OK, PING,
    PONG,
};
use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[derive(Debug, Deserialize, Clone)]
struct ServerConfig {
    listen_host: String,
    listen_port: u16,
    users: HashMap<String, String>,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "config/server.json")]
    config: PathBuf,
}

type SharedWriter = Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>;
type StreamMap = Arc<Mutex<HashMap<u32, tokio::net::tcp::OwnedWriteHalf>>>;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let raw = tokio::fs::read(&args.config)
        .await
        .with_context(|| format!("read config {:?}", args.config))?;
    let conf: ServerConfig = serde_json::from_slice(&raw).context("parse config json")?;
    if conf.users.is_empty() {
        anyhow::bail!("users map is empty");
    }
    let bind = format!("{}:{}", conf.listen_host, conf.listen_port);
    let listener = TcpListener::bind(&bind).await.context("bind listener")?;
    println!("astralink-server listening on {bind}");
    let shared = Arc::new(conf);
    loop {
        let (sock, peer) = listener.accept().await?;
        let conf = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(sock, conf).await {
                eprintln!("[session {peer}] error: {e:#}");
            }
        });
    }
}

async fn handle_conn(stream: TcpStream, conf: Arc<ServerConfig>) -> Result<()> {
    let peer = stream.peer_addr().ok();
    let (mut rd, wr) = stream.into_split();
    let writer = Arc::new(Mutex::new(wr));

    let mut pref = [0u8; 4];
    rd.read_exact(&mut pref).await?;
    let len = unpack_len(pref)?;
    let mut hello = vec![0u8; len];
    rd.read_exact(&mut hello).await?;
    let parsed = verify_client_hello(&hello, &conf.users).context("verify client hello")?;
    let (server_hello, session_key) = build_server_hello(&parsed.psk, &parsed.client_nonce)?;
    {
        let mut w = writer.lock().await;
        w.write_all(&(server_hello.len() as u32).to_be_bytes()).await?;
        w.write_all(&server_hello).await?;
        w.flush().await?;
    }
    println!(
        "[+] auth ok user={} peer={}",
        parsed.username,
        peer.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string())
    );

    let streams: StreamMap = Arc::new(Mutex::new(HashMap::new()));
    let send_lock = Arc::new(Mutex::new(SecureFramer::new(session_key.clone())));

    loop {
        let mut p = [0u8; 4];
        if rd.read_exact(&mut p).await.is_err() {
            break;
        }
        let frame_len = unpack_len(p)?;
        let mut body = vec![0u8; frame_len];
        rd.read_exact(&mut body).await?;
        let frame = SecureFramer::parse_frame(&session_key, &body)?;
        match frame.frame_type {
            OPEN => {
                on_open(
                    frame.stream_id,
                    frame.payload,
                    writer.clone(),
                    send_lock.clone(),
                    streams.clone(),
                )
                .await?;
            }
            DATA => {
                let mut map = streams.lock().await;
                if let Some(remote_wr) = map.get_mut(&frame.stream_id) {
                    remote_wr.write_all(&frame.payload).await?;
                    remote_wr.flush().await?;
                }
            }
            CLOSE => {
                let mut map = streams.lock().await;
                map.remove(&frame.stream_id);
            }
            PING => {
                send_frame(writer.clone(), send_lock.clone(), PONG, frame.stream_id, &frame.payload).await?;
            }
            _ => {}
        }
    }
    println!(
        "[-] disconnected user={} peer={}",
        parsed.username,
        peer.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string())
    );
    Ok(())
}

async fn on_open(
    stream_id: u32,
    payload: Vec<u8>,
    client_writer: SharedWriter,
    framer: Arc<Mutex<SecureFramer>>,
    streams: StreamMap,
) -> Result<()> {
    let target = String::from_utf8(payload).context("open target is not utf8")?;
    let (host, port_s) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("bad target"))?;
    let port: u16 = port_s.parse().context("bad port")?;
    match TcpStream::connect((host, port)).await {
        Ok(remote) => {
            let (mut rr, rw) = remote.into_split();
            {
                let mut map = streams.lock().await;
                map.insert(stream_id, rw);
            }
            send_frame(client_writer.clone(), framer.clone(), OPEN_OK, stream_id, b"ok").await?;
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match rr.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Err(e) = send_frame(
                                client_writer.clone(),
                                framer.clone(),
                                DATA,
                                stream_id,
                                &buf[..n],
                            )
                            .await
                            {
                                eprintln!("remote->client send error stream={stream_id}: {e:#}");
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = send_frame(client_writer.clone(), framer.clone(), CLOSE, stream_id, b"").await;
                let mut map = streams.lock().await;
                map.remove(&stream_id);
            });
        }
        Err(e) => {
            let msg = e.to_string();
            send_frame(client_writer, framer, OPEN_ERR, stream_id, msg.as_bytes()).await?;
        }
    }
    Ok(())
}

async fn send_frame(
    writer: SharedWriter,
    framer: Arc<Mutex<SecureFramer>>,
    frame_type: u8,
    stream_id: u32,
    payload: &[u8],
) -> Result<()> {
    let wire = {
        let mut fr = framer.lock().await;
        fr.build_frame(frame_type, stream_id, payload)
    };
    let mut w = writer.lock().await;
    w.write_all(&wire).await?;
    w.flush().await?;
    Ok(())
}
