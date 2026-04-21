use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const OPEN: u8 = 1;
pub const OPEN_OK: u8 = 2;
pub const OPEN_ERR: u8 = 3;
pub const DATA: u8 = 4;
pub const CLOSE: u8 = 5;
pub const PING: u8 = 6;
pub const PONG: u8 = 7;
pub const TAG_SIZE: usize = 16;
pub const MAX_FRAME: usize = 2 * 1024 * 1024;
pub const HELLO_SKEW_SECONDS: i64 = 60;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub username: String,
    pub ts: i64,
    pub client_nonce: String,
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub server_nonce: String,
    pub session_id: String,
    pub proof: String,
}

#[derive(Debug, Clone)]
pub struct ParsedClientHello {
    pub username: String,
    pub psk: String,
    pub client_nonce: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FramedMessage {
    pub frame_type: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

pub fn unix_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn b64e(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
}

fn b64d(s: &str) -> Result<Vec<u8>> {
    general_purpose::STANDARD
        .decode(s.as_bytes())
        .context("invalid base64")
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

pub fn random_session_id() -> String {
    let raw = random_bytes(8);
    raw.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

pub fn build_client_hello(username: &str, psk: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let client_nonce = random_bytes(16);
    let ts = unix_ts();
    let mut input = Vec::new();
    input.extend_from_slice(username.as_bytes());
    input.extend_from_slice(b"|");
    input.extend_from_slice(&client_nonce);
    input.extend_from_slice(b"|");
    input.extend_from_slice(ts.to_string().as_bytes());
    let proof = hmac_sha256(psk.as_bytes(), &input);
    let hello = ClientHello {
        username: username.to_string(),
        ts,
        client_nonce: b64e(&client_nonce),
        proof: b64e(&proof),
    };
    Ok((serde_json::to_vec(&hello)?, client_nonce))
}

pub fn verify_client_hello(payload: &[u8], users: &HashMap<String, String>) -> Result<ParsedClientHello> {
    let hello: ClientHello = serde_json::from_slice(payload).context("bad client hello json")?;
    let now = unix_ts();
    if (now - hello.ts).abs() > HELLO_SKEW_SECONDS {
        bail!("handshake time skew too large");
    }
    let psk = users
        .get(&hello.username)
        .ok_or_else(|| anyhow!("unknown username"))?
        .clone();
    let client_nonce = b64d(&hello.client_nonce)?;
    let proof = b64d(&hello.proof)?;
    let mut input = Vec::new();
    input.extend_from_slice(hello.username.as_bytes());
    input.extend_from_slice(b"|");
    input.extend_from_slice(&client_nonce);
    input.extend_from_slice(b"|");
    input.extend_from_slice(hello.ts.to_string().as_bytes());
    let expected = hmac_sha256(psk.as_bytes(), &input);
    if proof != expected {
        bail!("client proof mismatch");
    }
    Ok(ParsedClientHello {
        username: hello.username,
        psk,
        client_nonce,
    })
}

pub fn build_server_hello(psk: &str, client_nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let server_nonce = random_bytes(16);
    let session_id = random_session_id();
    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(client_nonce);
    proof_input.extend_from_slice(b"|");
    proof_input.extend_from_slice(&server_nonce);
    proof_input.extend_from_slice(b"|");
    proof_input.extend_from_slice(session_id.as_bytes());
    let proof = hmac_sha256(psk.as_bytes(), &proof_input);
    let hello = ServerHello {
        server_nonce: b64e(&server_nonce),
        session_id,
        proof: b64e(&proof),
    };
    let key = derive_session_key(psk, client_nonce, &server_nonce);
    Ok((serde_json::to_vec(&hello)?, key))
}

pub fn verify_server_hello(payload: &[u8], psk: &str, client_nonce: &[u8]) -> Result<Vec<u8>> {
    let hello: ServerHello = serde_json::from_slice(payload).context("bad server hello json")?;
    let server_nonce = b64d(&hello.server_nonce)?;
    let proof = b64d(&hello.proof)?;
    let mut input = Vec::new();
    input.extend_from_slice(client_nonce);
    input.extend_from_slice(b"|");
    input.extend_from_slice(&server_nonce);
    input.extend_from_slice(b"|");
    input.extend_from_slice(hello.session_id.as_bytes());
    let expected = hmac_sha256(psk.as_bytes(), &input);
    if proof != expected {
        bail!("server proof mismatch");
    }
    Ok(derive_session_key(psk, client_nonce, &server_nonce))
}

fn derive_session_key(psk: &str, client_nonce: &[u8], server_nonce: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(b"astralink-session|");
    input.extend_from_slice(client_nonce);
    input.extend_from_slice(b"|");
    input.extend_from_slice(server_nonce);
    hmac_sha256(psk.as_bytes(), &input)
}

pub fn pack_message(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn unpack_len(prefix: [u8; 4]) -> Result<usize> {
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME {
        bail!("frame too large");
    }
    Ok(len)
}

fn xor_stream(key: &[u8], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter = 0u32;
    while out.len() < data.len() {
        let mut block_input = Vec::with_capacity(nonce.len() + 4);
        block_input.extend_from_slice(nonce);
        block_input.extend_from_slice(&counter.to_be_bytes());
        let block = hmac_sha256(key, &block_input);
        let remaining = data.len() - out.len();
        let take = remaining.min(block.len());
        for i in 0..take {
            out.push(data[out.len()] ^ block[i]);
        }
        counter = counter.wrapping_add(1);
    }
    out
}

#[derive(Debug, Clone)]
pub struct SecureFramer {
    key: Vec<u8>,
    send_counter: u64,
}

impl SecureFramer {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key, send_counter: 0 }
    }

    pub fn build_frame(&mut self, frame_type: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        self.send_counter = self.send_counter.wrapping_add(1);
        let counter = self.send_counter;
        let nonce = counter.to_be_bytes();
        let cipher = xor_stream(&self.key, &nonce, payload);

        let mut header = Vec::with_capacity(13);
        header.extend_from_slice(&counter.to_be_bytes());
        header.push(frame_type);
        header.extend_from_slice(&stream_id.to_be_bytes());
        let mut mac_input = Vec::with_capacity(header.len() + cipher.len());
        mac_input.extend_from_slice(&header);
        mac_input.extend_from_slice(&cipher);
        let tag = hmac_sha256(&self.key, &mac_input);

        let mut body = Vec::with_capacity(header.len() + cipher.len() + TAG_SIZE);
        body.extend_from_slice(&header);
        body.extend_from_slice(&cipher);
        body.extend_from_slice(&tag[..TAG_SIZE]);
        pack_message(&body)
    }

    pub fn parse_frame(key: &[u8], body: &[u8]) -> Result<FramedMessage> {
        if body.len() < (8 + 1 + 4 + TAG_SIZE) {
            bail!("frame too short");
        }
        let header = &body[..13];
        let cipher = &body[13..body.len() - TAG_SIZE];
        let tag = &body[body.len() - TAG_SIZE..];

        let mut mac_input = Vec::with_capacity(header.len() + cipher.len());
        mac_input.extend_from_slice(header);
        mac_input.extend_from_slice(cipher);
        let expected = hmac_sha256(key, &mac_input);
        if expected[..TAG_SIZE] != *tag {
            bail!("frame mac mismatch");
        }

        let counter = u64::from_be_bytes(header[..8].try_into().unwrap_or([0; 8]));
        let _ = counter;
        let frame_type = header[8];
        let stream_id = u32::from_be_bytes(header[9..13].try_into().unwrap_or([0; 4]));
        let nonce = u64::to_be_bytes(counter);
        let payload = xor_stream(key, &nonce, cipher);
        Ok(FramedMessage {
            frame_type,
            stream_id,
            payload,
        })
    }
}

