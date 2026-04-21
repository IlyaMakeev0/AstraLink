use anyhow::{Context, Result};
use astralink_core::{
    build_client_hello, unpack_len, verify_server_hello, SecureFramer, CLOSE, DATA, OPEN, OPEN_ERR, OPEN_OK, PING,
};
use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};

#[derive(Debug, Deserialize, Clone)]
struct ClientConfig {
    server_host: String,
    server_port: u16,
    username: String,
    psk: String,
    local_socks_host: String,
    local_socks_port: u16,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "config/client.json")]
    config: PathBuf,
}

#[derive(Debug)]
struct StreamState {
    opened: Option<tokio::sync::oneshot::Sender<Result<()>>>,
    tx: mpsc::Sender<Option<Vec<u8>>>,
}

#[derive(Debug, Clone)]
struct Core {
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    framer: Arc<Mutex<SecureFramer>>,
    streams: Arc<Mutex<HashMap<u32, StreamState>>>,
    next_id: Arc<Mutex<u32>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let raw = tokio::fs::read(&args.config)
        .await
        .with_context(|| format!("read config {:?}", args.config))?;
    let conf: ClientConfig = serde_json::from_slice(&raw).context("parse client json")?;
    let (core, session_key, mut reader) = connect_core(&conf).await?;
    println!(
        "astralink-client connected to {}:{}",
        conf.server_host, conf.server_port
    );

    let core_recv = core.clone();
    tokio::spawn(async move {
        if let Err(e) = recv_loop(&mut reader, core_recv, session_key).await {
            eprintln!("recv loop error: {e:#}");
        }
    });

    let core_keepalive = core.clone();
    tokio::spawn(async move {
        loop {
            if send_frame(core_keepalive.clone(), PING, 0, b"ping").await.is_err() {
                break;
            }
            sleep(Duration::from_secs(15)).await;
        }
    });

    let bind = format!("{}:{}", conf.local_socks_host, conf.local_socks_port);
    let listener = TcpListener::bind(&bind).await?;
    println!("local SOCKS5 listening on {bind}");
    loop {
        let (sock, peer) = listener.accept().await?;
        let core_conn = core.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks_conn(sock, core_conn).await {
                eprintln!("socks client {peer} error: {e:#}");
            }
        });
    }
}

async fn connect_core(
    conf: &ClientConfig,
) -> Result<(Core, Vec<u8>, tokio::net::tcp::OwnedReadHalf)> {
    let stream = TcpStream::connect((conf.server_host.as_str(), conf.server_port)).await?;
    let (mut rd, mut wr) = stream.into_split();
    let (hello, client_nonce) = build_client_hello(&conf.username, &conf.psk)?;
    wr.write_all(&(hello.len() as u32).to_be_bytes()).await?;
    wr.write_all(&hello).await?;
    wr.flush().await?;

    let mut pref = [0u8; 4];
    rd.read_exact(&mut pref).await?;
    let len = unpack_len(pref)?;
    let mut server_hello = vec![0u8; len];
    rd.read_exact(&mut server_hello).await?;
    let session_key = verify_server_hello(&server_hello, &conf.psk, &client_nonce)?;
    let core = Core {
        writer: Arc::new(Mutex::new(wr)),
        framer: Arc::new(Mutex::new(SecureFramer::new(session_key.clone()))),
        streams: Arc::new(Mutex::new(HashMap::new())),
        next_id: Arc::new(Mutex::new(1)),
    };
    Ok((core, session_key, rd))
}

async fn recv_loop(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    core: Core,
    session_key: Vec<u8>,
) -> Result<()> {
    loop {
        let mut p = [0u8; 4];
        if reader.read_exact(&mut p).await.is_err() {
            break;
        }
        let len = unpack_len(p)?;
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).await?;
        let frame = SecureFramer::parse_frame(&session_key, &body)?;
        let mut open_sender: Option<tokio::sync::oneshot::Sender<Result<()>>> = None;
        let mut tx_opt: Option<mpsc::Sender<Option<Vec<u8>>>> = None;
        let mut tx_payload: Option<Vec<u8>> = None;
        let mut tx_close = false;
        let mut open_err: Option<String> = None;
        {
            let mut map = core.streams.lock().await;
            if let Some(st) = map.get_mut(&frame.stream_id) {
                match frame.frame_type {
                    OPEN_OK => {
                        open_sender = st.opened.take();
                    }
                    OPEN_ERR => {
                        open_sender = st.opened.take();
                        tx_opt = Some(st.tx.clone());
                        open_err = Some(String::from_utf8_lossy(&frame.payload).to_string());
                    }
                    DATA => {
                        tx_opt = Some(st.tx.clone());
                        tx_payload = Some(frame.payload);
                    }
                    CLOSE => {
                        tx_opt = Some(st.tx.clone());
                        tx_close = true;
                    }
                    _ => {}
                }
            }
        }
        let had_open_err = open_err.is_some();
        if let Some(ch) = open_sender {
            if let Some(msg) = open_err {
                let _ = ch.send(Err(anyhow::anyhow!(msg)));
            } else {
                let _ = ch.send(Ok(()));
            }
        }
        if let Some(tx) = tx_opt {
            if let Some(payload) = tx_payload {
                let _ = tx.send(Some(payload)).await;
            }
            if tx_close || had_open_err {
                let _ = tx.send(None).await;
            }
        }
    }
    Ok(())
}

async fn next_stream_id(core: &Core) -> u32 {
    let mut id = core.next_id.lock().await;
    let out = *id;
    *id = id.wrapping_add(1);
    out
}

async fn send_frame(core: Core, frame_type: u8, stream_id: u32, payload: &[u8]) -> Result<()> {
    let wire = {
        let mut fr = core.framer.lock().await;
        fr.build_frame(frame_type, stream_id, payload)
    };
    let mut wr = core.writer.lock().await;
    wr.write_all(&wire).await?;
    wr.flush().await?;
    Ok(())
}

async fn open_stream(core: Core, target: &str) -> Result<(u32, mpsc::Receiver<Option<Vec<u8>>>)> {
    let sid = next_stream_id(&core).await;
    let (open_tx, open_rx) = tokio::sync::oneshot::channel::<Result<()>>();
    let (tx, rx) = mpsc::channel(128);
    {
        let mut map = core.streams.lock().await;
        map.insert(
            sid,
            StreamState {
                opened: Some(open_tx),
                tx,
            },
        );
    }
    send_frame(core.clone(), OPEN, sid, target.as_bytes()).await?;
    open_rx.await.context("open stream canceled")??;
    Ok((sid, rx))
}

async fn close_stream(core: Core, sid: u32) -> Result<()> {
    send_frame(core.clone(), CLOSE, sid, b"").await?;
    let mut map = core.streams.lock().await;
    map.remove(&sid);
    Ok(())
}

async fn handle_socks_conn(mut local: TcpStream, core: Core) -> Result<()> {
    let mut head = [0u8; 2];
    local.read_exact(&mut head).await?;
    if head[0] != 5 {
        anyhow::bail!("only socks5");
    }
    let n_methods = head[1] as usize;
    let mut methods = vec![0u8; n_methods];
    local.read_exact(&mut methods).await?;
    local.write_all(&[0x05, 0x00]).await?;
    local.flush().await?;

    let mut req = [0u8; 4];
    local.read_exact(&mut req).await?;
    if req[0] != 5 || req[1] != 1 {
        local.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        local.flush().await?;
        anyhow::bail!("only CONNECT");
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
        _ => anyhow::bail!("unknown atyp"),
    };
    let mut pb = [0u8; 2];
    local.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);
    let target = format!("{host}:{port}");
    let (sid, mut rx) = open_stream(core.clone(), &target).await?;
    local.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    local.flush().await?;

    let (mut lr, mut lw) = local.into_split();
    let core_up = core.clone();
    let uplink = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = lr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            send_frame(core_up.clone(), DATA, sid, &buf[..n]).await?;
        }
        close_stream(core_up, sid).await?;
        Result::<()>::Ok(())
    });

    let downlink = tokio::spawn(async move {
        while let Some(item) = rx.recv().await {
            match item {
                Some(chunk) => {
                    lw.write_all(&chunk).await?;
                    lw.flush().await?;
                }
                None => break,
            }
        }
        Result::<()>::Ok(())
    });

    let (u, d) = tokio::join!(uplink, downlink);
    u??;
    d??;
    Ok(())
}
