use anyhow::{Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use rand::RngCore;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    #[arg(long, default_value_t = 2096)]
    port: u16,
    #[arg(long, default_value = "data/panel.db")]
    db: PathBuf,
    #[arg(long, default_value = "config/server.json")]
    runtime_server_config: PathBuf,
    #[arg(long, default_value = "")]
    restart_service: String,
    #[arg(long, default_value = "127.0.0.1")]
    public_host: String,
    #[arg(long, default_value_t = 8443)]
    public_port: u16,
}

#[derive(Clone)]
struct AppState {
    db: PathBuf,
    runtime_server_config: PathBuf,
    restart_service: Option<String>,
    public_host: String,
    public_port: u16,
    // serialize config writes/reloads
    sync_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Deserialize)]
struct BootstrapReq {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct CreateUserReq {
    username: String,
    psk: Option<String>,
    profile: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ToggleReq {
    enabled: i64,
}

#[derive(Debug, Deserialize)]
struct SaveInboundReq {
    tag: String,
    listen_host: String,
    listen_port: u16,
    transport_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SubQuery {
    format: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApiUser {
    id: i64,
    username: String,
    psk: String,
    enabled: bool,
    profile: String,
    uuid: String,
}

#[derive(Debug, Serialize)]
struct ApiInbound {
    id: i64,
    tag: String,
    listen_host: String,
    listen_port: u16,
    transport_mode: String,
    enabled: bool,
}

fn unix_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn hash_password(password: &str, salt_opt: Option<[u8; 16]>) -> (String, String) {
    let salt = salt_opt.unwrap_or_else(|| {
        let mut s = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut s);
        s
    });
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    (
        general_purpose::STANDARD.encode(salt),
        general_purpose::STANDARD.encode(digest),
    )
}

fn verify_password(password: &str, salt_b64: &str, digest_b64: &str) -> bool {
    let salt = match general_purpose::STANDARD.decode(salt_b64.as_bytes()) {
        Ok(v) if v.len() == 16 => {
            let mut s = [0u8; 16];
            s.copy_from_slice(&v);
            s
        }
        _ => return false,
    };
    let (_, got) = hash_password(password, Some(salt));
    got == digest_b64
}

fn parse_cookie(headers: &HeaderMap, key: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|item| {
            let (k, v) = item.trim().split_once('=')?;
            Some((k.trim(), v.trim()))
        })
        .find_map(|(k, v)| if k == key { Some(v.to_string()) } else { None })
}

fn ensure_schema(db: &FsPath) -> Result<()> {
    if let Some(parent) = db.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(db)?;
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  admin_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  psk TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  profile TEXT NOT NULL DEFAULT 'balanced',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS inbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tag TEXT UNIQUE NOT NULL,
  listen_host TEXT NOT NULL,
  listen_port INTEGER NOT NULL,
  transport_mode TEXT NOT NULL DEFAULT 'tcp',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
"#,
    )?;
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM inbounds", [], |r| r.get(0))?;
    if count == 0 {
        conn.execute(
            "INSERT INTO inbounds(tag, listen_host, listen_port, transport_mode, enabled, created_at) VALUES (?1, ?2, ?3, 'tcp', 1, ?4)",
            params!["main", "0.0.0.0", 8443_i64, unix_ts()],
        )?;
    }
    Ok(())
}

fn random_psk() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn maybe_restart_service(service: &Option<String>) {
    if let Some(s) = service {
        let _ = Command::new("systemctl").args(["restart", s]).output();
    }
}

fn write_runtime_config(state: &AppState) -> Result<()> {
    let conn = Connection::open(&state.db)?;
    let mut listen_host = "0.0.0.0".to_string();
    let mut listen_port = 8443_u16;

    {
        let mut stmt = conn.prepare(
            "SELECT listen_host, listen_port FROM inbounds WHERE enabled=1 ORDER BY id LIMIT 1",
        )?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            listen_host = row.get::<_, String>(0)?;
            let p: i64 = row.get(1)?;
            listen_port = p.clamp(1, 65535) as u16;
        }
    }

    let mut users = HashMap::new();
    let mut stmt = conn.prepare("SELECT username, psk FROM users WHERE enabled=1 ORDER BY id")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    for r in rows {
        let (u, p) = r?;
        users.insert(u, p);
    }
    if let Some(parent) = state.runtime_server_config.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let payload = json!({
        "listen_host": listen_host,
        "listen_port": listen_port,
        "users": users
    });
    std::fs::write(
        &state.runtime_server_config,
        serde_json::to_vec_pretty(&payload)?,
    )?;
    Ok(())
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
}

fn ensure_auth(headers: &HeaderMap, state: &AppState) -> bool {
    let token = match parse_cookie(headers, "astrapanel_session") {
        Some(v) => v,
        None => return false,
    };
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let now = unix_ts();
    let res: rusqlite::Result<i64> = conn.query_row(
        "SELECT admin_id FROM sessions WHERE token=?1 AND expires_at>?2",
        params![token, now],
        |r| r.get(0),
    );
    res.is_ok()
}

async fn page_login() -> impl IntoResponse {
    Html(LOGIN_HTML)
}

async fn page_app(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    Html(APP_HTML).into_response()
}

async fn bootstrap(State(state): State<AppState>, Json(req): Json<BootstrapReq>) -> impl IntoResponse {
    if req.username.len() < 3 || req.password.len() < 8 {
        return (StatusCode::BAD_REQUEST, "username>=3, password>=8 required").into_response();
    }
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let count: i64 = match conn.query_row("SELECT COUNT(*) FROM admins", [], |r| r.get(0)) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if count > 0 {
        return (StatusCode::CONFLICT, "bootstrap already completed").into_response();
    }
    let (salt, hash) = hash_password(&req.password, None);
    if let Err(e) = conn.execute(
        "INSERT INTO admins(username, salt, password_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![req.username, salt, hash, unix_ts()],
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    (StatusCode::OK, "ok").into_response()
}

async fn login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> impl IntoResponse {
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let row: rusqlite::Result<(i64, String, String)> = conn.query_row(
        "SELECT id, salt, password_hash FROM admins WHERE username=?1",
        params![req.username],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    );
    let (admin_id, salt, pass_hash) = match row {
        Ok(v) => v,
        Err(_) => return (StatusCode::UNAUTHORIZED, "bad credentials").into_response(),
    };
    if !verify_password(&req.password, &salt, &pass_hash) {
        return (StatusCode::UNAUTHORIZED, "bad credentials").into_response();
    }
    let token = random_psk();
    let exp = unix_ts() + 14 * 24 * 3600;
    if let Err(e) = conn.execute(
        "INSERT INTO sessions(token, admin_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token, admin_id, exp],
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    let mut headers = HeaderMap::new();
    let cookie = format!("astrapanel_session={token}; HttpOnly; Path=/; Max-Age=1209600");
    if let Ok(val) = HeaderValue::from_str(&cookie) {
        headers.insert(header::SET_COOKIE, val);
    }
    (StatusCode::OK, headers, Json(json!({"ok": true}))).into_response()
}

async fn list_users(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut stmt = match conn.prepare(
        "SELECT id, username, psk, enabled, profile FROM users ORDER BY id DESC",
    ) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let rows = match stmt.query_map([], |r| {
        let username: String = r.get(1)?;
        Ok(ApiUser {
            id: r.get(0)?,
            username: username.clone(),
            psk: r.get(2)?,
            enabled: r.get::<_, i64>(3)? == 1,
            profile: r.get(4)?,
            uuid: Uuid::new_v5(&Uuid::NAMESPACE_DNS, format!("astralink:{username}").as_bytes()).to_string(),
        })
    }) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut out = Vec::new();
    for r in rows {
        match r {
            Ok(v) => out.push(v),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
    Json(out).into_response()
}

async fn create_user(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateUserReq>,
) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    if req.username.trim().len() < 2 {
        return (StatusCode::BAD_REQUEST, "username too short").into_response();
    }
    let psk = req.psk.filter(|s| !s.trim().is_empty()).unwrap_or_else(random_psk);
    let profile = req
        .profile
        .filter(|p| ["balanced", "performance", "stealth"].contains(&p.as_str()))
        .unwrap_or_else(|| "balanced".to_string());
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if let Err(e) = conn.execute(
        "INSERT INTO users(username, psk, enabled, profile, created_at) VALUES (?1, ?2, 1, ?3, ?4)",
        params![req.username.trim(), psk, profile, unix_ts()],
    ) {
        return (StatusCode::CONFLICT, e.to_string()).into_response();
    }
    {
        let _guard = state.sync_lock.lock().await;
        if let Err(e) = write_runtime_config(&state) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        maybe_restart_service(&state.restart_service);
    }
    Json(json!({"ok": true})).into_response()
}

async fn patch_user(
    headers: HeaderMap,
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(req): Json<ToggleReq>,
) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if let Err(e) = conn.execute("UPDATE users SET enabled=?1 WHERE id=?2", params![req.enabled, id]) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    {
        let _guard = state.sync_lock.lock().await;
        if let Err(e) = write_runtime_config(&state) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        maybe_restart_service(&state.restart_service);
    }
    Json(json!({"ok": true})).into_response()
}

async fn delete_user(headers: HeaderMap, Path(id): Path<i64>, State(state): State<AppState>) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if let Err(e) = conn.execute("DELETE FROM users WHERE id=?1", params![id]) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    {
        let _guard = state.sync_lock.lock().await;
        if let Err(e) = write_runtime_config(&state) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        maybe_restart_service(&state.restart_service);
    }
    Json(json!({"ok": true})).into_response()
}

async fn list_inbounds(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut stmt = match conn.prepare(
        "SELECT id, tag, listen_host, listen_port, transport_mode, enabled FROM inbounds ORDER BY id DESC",
    ) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let rows = match stmt.query_map([], |r| {
        Ok(ApiInbound {
            id: r.get(0)?,
            tag: r.get(1)?,
            listen_host: r.get(2)?,
            listen_port: r.get::<_, i64>(3)? as u16,
            transport_mode: r.get(4)?,
            enabled: r.get::<_, i64>(5)? == 1,
        })
    }) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut out = Vec::new();
    for r in rows {
        match r {
            Ok(v) => out.push(v),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
    Json(out).into_response()
}

async fn save_inbound(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<SaveInboundReq>,
) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    let tag = req.tag.trim();
    if tag.is_empty() {
        return (StatusCode::BAD_REQUEST, "tag is required").into_response();
    }
    let mode = req.transport_mode.unwrap_or_else(|| "tcp".to_string());
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let existing: rusqlite::Result<i64> = conn.query_row(
        "SELECT id FROM inbounds WHERE tag=?1",
        params![tag],
        |r| r.get(0),
    );
    let qres = if let Ok(id) = existing {
        conn.execute(
            "UPDATE inbounds SET listen_host=?1, listen_port=?2, transport_mode=?3 WHERE id=?4",
            params![req.listen_host, req.listen_port as i64, mode, id],
        )
    } else {
        conn.execute(
            "INSERT INTO inbounds(tag, listen_host, listen_port, transport_mode, enabled, created_at) VALUES (?1, ?2, ?3, ?4, 1, ?5)",
            params![tag, req.listen_host, req.listen_port as i64, mode, unix_ts()],
        )
    };
    if let Err(e) = qres {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    {
        let _guard = state.sync_lock.lock().await;
        if let Err(e) = write_runtime_config(&state) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        maybe_restart_service(&state.restart_service);
    }
    Json(json!({"ok": true})).into_response()
}

async fn patch_inbound(
    headers: HeaderMap,
    Path(id): Path<i64>,
    State(state): State<AppState>,
    Json(req): Json<ToggleReq>,
) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if let Err(e) = conn.execute("UPDATE inbounds SET enabled=?1 WHERE id=?2", params![req.enabled, id]) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    {
        let _guard = state.sync_lock.lock().await;
        if let Err(e) = write_runtime_config(&state) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        maybe_restart_service(&state.restart_service);
    }
    Json(json!({"ok": true})).into_response()
}

async fn subscription(
    Path(user_uuid): Path<String>,
    Query(q): Query<SubQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let fmt = q.format.unwrap_or_else(|| "astralink-uri".to_string());
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut stmt = match conn.prepare("SELECT username, psk, profile, enabled FROM users") {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let rows = match stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
        ))
    }) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    for row in rows {
        let (username, psk, profile, enabled) = match row {
            Ok(v) => v,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        let uid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, format!("astralink:{username}").as_bytes()).to_string();
        if uid == user_uuid && enabled == 1 {
            if fmt == "astralink-uri" {
                let raw = json!({
                    "host": state.public_host,
                    "port": state.public_port,
                    "username": username,
                    "psk": psk,
                    "profile": profile
                });
                let token = general_purpose::URL_SAFE_NO_PAD
                    .encode(serde_json::to_vec(&raw).unwrap_or_default());
                let uri = format!("astralink://{token}#{username}");
                return (StatusCode::OK, uri).into_response();
            }
            if fmt == "singbox-socks" {
                let cfg = json!({
                    "log": {"level": "warn"},
                    "outbounds": [{
                        "type": "socks",
                        "tag": "astralink-local",
                        "server": "127.0.0.1",
                        "server_port": 1080,
                        "version": "5"
                    }],
                    "route": {"auto_detect_interface": true, "final": "astralink-local"}
                });
                return Json(cfg).into_response();
            }
            return (StatusCode::BAD_REQUEST, "unknown format").into_response();
        }
    }
    (StatusCode::NOT_FOUND, "user not found").into_response()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure_schema(&args.db)?;
    let state = AppState {
        db: args.db.clone(),
        runtime_server_config: args.runtime_server_config.clone(),
        restart_service: if args.restart_service.trim().is_empty() {
            None
        } else {
            Some(args.restart_service.trim().to_string())
        },
        public_host: args.public_host,
        public_port: args.public_port,
        sync_lock: Arc::new(Mutex::new(())),
    };
    {
        let _guard = state.sync_lock.lock().await;
        write_runtime_config(&state)?;
    }
    let app = Router::new()
        .route("/", get(page_login))
        .route("/app", get(page_app))
        .route("/api/bootstrap", post(bootstrap))
        .route("/api/auth/login", post(login))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/:id", patch(patch_user).delete(delete_user))
        .route("/api/inbounds", get(list_inbounds).post(save_inbound))
        .route("/api/inbounds/:id", patch(patch_inbound))
        .route("/api/subscription/:uuid", get(subscription))
        .with_state(state);
    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .context("invalid bind addr")?;
    println!("astralink-panel listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

const LOGIN_HTML: &str = r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AstraPanel Login</title>
<style>
body { font-family: Segoe UI, sans-serif; background: linear-gradient(120deg,#f7fbff,#e7f3ff); margin: 0; }
.wrap { max-width: 420px; margin: 8vh auto; background: white; border-radius: 14px; padding: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.08); }
input { width: 100%; padding: 10px; margin: 8px 0; border-radius: 8px; border: 1px solid #d0d7de; }
button { width: 100%; padding: 10px; border: 0; border-radius: 8px; background: #0057b8; color: #fff; font-weight: 600; }
</style></head><body>
<div class="wrap">
<h1>AstraPanel</h1>
<p>First run: POST /api/bootstrap</p>
<input id="u" placeholder="username"/><input id="p" type="password" placeholder="password"/>
<button onclick="login()">Login</button><p id="msg"></p></div>
<script>
async function login(){
 const r = await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
 if(r.ok){location.href='/app';return;}
 document.getElementById('msg').innerText=await r.text();
}
</script></body></html>"#;

const APP_HTML: &str = r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AstraPanel</title>
<style>
:root { --bg:#f6f9fc; --card:#fff; --line:#d8e0ea; --accent:#0a5ccf; }
body{font-family:Segoe UI,sans-serif;background:var(--bg);margin:0}
.top{background:linear-gradient(100deg,#0b4fa8,#2086ff);color:#fff;padding:18px}
.wrap{max-width:1100px;margin:18px auto;padding:0 14px;display:grid;grid-template-columns:1fr 1fr;gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #edf2f7;padding:8px;text-align:left}
input,select{padding:8px;border:1px solid #cbd5e1;border-radius:8px;margin-right:6px;margin-bottom:6px}
button{padding:8px 10px;border:0;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer}
code{font-size:12px;word-break:break-all}.row{display:flex;gap:8px;flex-wrap:wrap}
</style></head><body>
<div class="top"><h1 style="margin:0">AstraPanel</h1><div>AstraLink control plane</div></div>
<div class="wrap">
<div class="card"><h2>Users</h2>
<div class="row"><input id="u_name" placeholder="username"/><input id="u_psk" placeholder="psk (optional)"/>
<select id="u_profile"><option value="balanced">balanced</option><option value="performance">performance</option><option value="stealth">stealth</option></select>
<button onclick="addUser()">Add</button></div><table id="users"></table></div>
<div class="card"><h2>Inbounds</h2>
<div class="row"><input id="i_tag" placeholder="tag (main)"/><input id="i_host" placeholder="listen host" value="0.0.0.0"/>
<input id="i_port" placeholder="port" value="8443"/><button onclick="addInbound()">Save</button></div><table id="inbounds"></table></div>
<div class="card" style="grid-column:1/span 2;"><h2>Subscriptions</h2><div id="subs"></div></div></div>
<script>
async function api(path,method='GET',body=null){const r=await fetch(path,{method,headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):null});if(!r.ok) throw new Error(await r.text());const ct=r.headers.get('content-type')||'';if(ct.includes('application/json'))return await r.json();return await r.text();}
async function loadAll(){const users=await api('/api/users');const inbounds=await api('/api/inbounds');
document.getElementById('users').innerHTML='<tr><th>User</th><th>PSK</th><th>Profile</th><th>Enabled</th><th>Actions</th></tr>'+users.map(u=>`<tr><td>${u.username}</td><td><code>${u.psk}</code></td><td>${u.profile}</td><td>${u.enabled?'yes':'no'}</td><td><button onclick="toggleUser(${u.id},${u.enabled?0:1})">${u.enabled?'Disable':'Enable'}</button><button onclick="delUser(${u.id})">Delete</button></td></tr>`).join('');
document.getElementById('inbounds').innerHTML='<tr><th>Tag</th><th>Listen</th><th>Mode</th><th>Enabled</th><th>Action</th></tr>'+inbounds.map(i=>`<tr><td>${i.tag}</td><td>${i.listen_host}:${i.listen_port}</td><td>${i.transport_mode}</td><td>${i.enabled?'yes':'no'}</td><td><button onclick="toggleInbound(${i.id},${i.enabled?0:1})">${i.enabled?'Disable':'Enable'}</button></td></tr>`).join('');
document.getElementById('subs').innerHTML=users.map(u=>`<div style="padding:8px;border-bottom:1px solid #edf2f7;"><b>${u.username}</b><br/><code>/api/subscription/${u.uuid}?format=astralink-uri</code><br/><code>/api/subscription/${u.uuid}?format=singbox-socks</code></div>`).join('');}
async function addUser(){await api('/api/users','POST',{username:document.getElementById('u_name').value.trim(),psk:document.getElementById('u_psk').value.trim(),profile:document.getElementById('u_profile').value});document.getElementById('u_name').value='';document.getElementById('u_psk').value='';await loadAll();}
async function delUser(id){await api('/api/users/'+id,'DELETE');await loadAll();}
async function toggleUser(id,enabled){await api('/api/users/'+id,'PATCH',{enabled});await loadAll();}
async function addInbound(){await api('/api/inbounds','POST',{tag:document.getElementById('i_tag').value.trim()||'main',listen_host:document.getElementById('i_host').value.trim()||'0.0.0.0',listen_port:Number(document.getElementById('i_port').value.trim()||'8443'),transport_mode:'tcp'});await loadAll();}
async function toggleInbound(id,enabled){await api('/api/inbounds/'+id,'PATCH',{enabled});await loadAll();}
loadAll().catch(e=>alert(e.message));
</script></body></html>"#;
