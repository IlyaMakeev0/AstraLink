use anyhow::{Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
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
use axum::extract::Request;
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
    #[arg(long, default_value = "")]
    panel_domain: String,
    #[arg(long, default_value = "")]
    subscription_domain: String,
    #[arg(long, default_value = "")]
    subscription_sub_domain: String,
}

#[derive(Clone)]
struct AppState {
    db: PathBuf,
    runtime_server_config: PathBuf,
    restart_service: Option<String>,
    public_host: String,
    public_port: u16,
    panel_port: u16,
    panel_domain: String,
    subscription_domain: String,
    subscription_sub_domain: String,
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
struct SaveSettingsReq {
    panel_domain: String,
    subscription_domain: String,
    subscription_sub_domain: String,
}

#[derive(Debug, Deserialize)]
struct IssueAccessReq {
    customer_label: String,
    days: i64,
    profile: Option<String>,
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

#[derive(Debug, Serialize)]
struct ApiSettings {
    panel_domain: String,
    subscription_domain: String,
    subscription_sub_domain: String,
}

#[derive(Debug, Serialize)]
struct ApiAccessKey {
    id: i64,
    customer_label: String,
    token: String,
    user_id: i64,
    username: String,
    enabled: bool,
    expires_at: i64,
    created_at: i64,
    sub_link: String,
}

#[derive(Debug, Serialize)]
struct ApiAuditLog {
    id: i64,
    admin_id: Option<i64>,
    event: String,
    details: String,
    ip: String,
    created_at: i64,
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

fn client_ip(headers: &HeaderMap) -> String {
    if let Some(v) = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
    {
        let ip = v.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }
    if let Some(v) = headers
        .get("x-real-ip")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim().to_string())
    {
        if !v.is_empty() {
            return v;
        }
    }
    "-".to_string()
}

fn insert_audit_log(
    conn: &Connection,
    admin_id: Option<i64>,
    event: &str,
    details: &str,
    ip: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO audit_logs(admin_id, event, details, ip, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![admin_id, event, details, ip, unix_ts()],
    )?;
    Ok(())
}

fn login_is_rate_limited(conn: &Connection, ip: &str, username: &str, now: i64) -> Result<bool> {
    let window = now - 10 * 60;
    let failed_ip: i64 = conn.query_row(
        "SELECT COUNT(*) FROM login_attempts WHERE ip=?1 AND success=0 AND created_at>?2",
        params![ip, window],
        |r| r.get(0),
    )?;
    let failed_user: i64 = conn.query_row(
        "SELECT COUNT(*) FROM login_attempts WHERE username=?1 AND success=0 AND created_at>?2",
        params![username, window],
        |r| r.get(0),
    )?;
    Ok(failed_ip >= 12 || failed_user >= 8)
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
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT UNIQUE NOT NULL,
  user_id INTEGER NOT NULL,
  customer_label TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  username TEXT NOT NULL,
  success INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_ts ON login_attempts(ip, created_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_ts ON login_attempts(username, created_at);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NULL,
  event TEXT NOT NULL,
  details TEXT NOT NULL,
  ip TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);
"#,
    )?;
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM inbounds", [], |r| r.get(0))?;
    if count == 0 {
        conn.execute(
            "INSERT INTO inbounds(tag, listen_host, listen_port, transport_mode, enabled, created_at) VALUES (?1, ?2, ?3, 'tcp', 1, ?4)",
            params!["main", "0.0.0.0", 8443_i64, unix_ts()],
        )?;
    }
    let panel_domain = get_setting_conn(&conn, "panel_domain")?.unwrap_or_default();
    if panel_domain.is_empty() {
        set_setting_conn(&conn, "panel_domain", "")?;
    }
    let sub_domain = get_setting_conn(&conn, "subscription_domain")?.unwrap_or_default();
    if sub_domain.is_empty() {
        set_setting_conn(&conn, "subscription_domain", "")?;
    }
    let sub_sub_domain = get_setting_conn(&conn, "subscription_sub_domain")?.unwrap_or_default();
    if sub_sub_domain.is_empty() {
        set_setting_conn(&conn, "subscription_sub_domain", "")?;
    }
    Ok(())
}

fn random_psk() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random_short_id() -> String {
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes).to_lowercase()
}

fn get_setting_conn(conn: &Connection, key: &str) -> Result<Option<String>> {
    let row: rusqlite::Result<String> = conn.query_row(
        "SELECT value FROM settings WHERE key=?1",
        params![key],
        |r| r.get(0),
    );
    match row {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn set_setting_conn(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO settings(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn resolve_public_base_url(state: &AppState, conn: &Connection) -> String {
    let sub_sub_domain = get_setting_conn(conn, "subscription_sub_domain")
        .ok()
        .flatten()
        .unwrap_or_default()
        .trim()
        .to_string();
    if !sub_sub_domain.is_empty() {
        return format!("https://{sub_sub_domain}");
    }
    let sub_domain = get_setting_conn(conn, "subscription_domain")
        .ok()
        .flatten()
        .unwrap_or_default()
        .trim()
        .to_string();
    if !sub_domain.is_empty() {
        return format!("https://{sub_domain}");
    }
    format!("http://{}:{}", state.public_host, state.panel_port)
}

fn apply_default_domains(state: &AppState) -> Result<()> {
    let conn = Connection::open(&state.db)?;
    if !state.panel_domain.trim().is_empty() {
        set_setting_conn(&conn, "panel_domain", state.panel_domain.trim())?;
    }
    if !state.subscription_domain.trim().is_empty() {
        set_setting_conn(&conn, "subscription_domain", state.subscription_domain.trim())?;
    }
    if !state.subscription_sub_domain.trim().is_empty() {
        set_setting_conn(
            &conn,
            "subscription_sub_domain",
            state.subscription_sub_domain.trim(),
        )?;
    }
    Ok(())
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
    let mut payload = if state.runtime_server_config.exists() {
        match std::fs::read(&state.runtime_server_config)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        {
            Some(v) if v.is_object() => v,
            _ => json!({}),
        }
    } else {
        json!({})
    };
    payload["listen_host"] = serde_json::Value::String(listen_host);
    payload["listen_port"] = serde_json::Value::Number(listen_port.into());
    payload["users"] = serde_json::to_value(users)?;
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

async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self' https://unpkg.com; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://unpkg.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    );
    resp
}

async fn page_app(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    Html(REACT_APP_HTML).into_response()
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
    let _ = insert_audit_log(&conn, Some(conn.last_insert_rowid()), "bootstrap_admin", "admin created", "-");
    (StatusCode::OK, "ok").into_response()
}

async fn login(headers: HeaderMap, State(state): State<AppState>, Json(req): Json<LoginReq>) -> impl IntoResponse {
    let ip = client_ip(&headers);
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let now = unix_ts();
    match login_is_rate_limited(&conn, &ip, &req.username, now) {
        Ok(true) => {
            let _ = insert_audit_log(
                &conn,
                None,
                "auth_rate_limited",
                &format!("username={}", req.username),
                &ip,
            );
            return (StatusCode::TOO_MANY_REQUESTS, "too many attempts, try later").into_response();
        }
        Ok(false) => {}
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
    let row: rusqlite::Result<(i64, String, String)> = conn.query_row(
        "SELECT id, salt, password_hash FROM admins WHERE username=?1",
        params![req.username],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    );
    let (admin_id, salt, pass_hash) = match row {
        Ok(v) => v,
        Err(_) => {
            let _ = conn.execute(
                "INSERT INTO login_attempts(ip, username, success, created_at) VALUES (?1, ?2, 0, ?3)",
                params![ip, req.username, now],
            );
            let _ = insert_audit_log(&conn, None, "auth_failed", "unknown username", &ip);
            return (StatusCode::UNAUTHORIZED, "bad credentials").into_response();
        }
    };
    if !verify_password(&req.password, &salt, &pass_hash) {
        let _ = conn.execute(
            "INSERT INTO login_attempts(ip, username, success, created_at) VALUES (?1, ?2, 0, ?3)",
            params![ip, req.username, now],
        );
        let _ = insert_audit_log(&conn, Some(admin_id), "auth_failed", "bad password", &ip);
        return (StatusCode::UNAUTHORIZED, "bad credentials").into_response();
    }
    let _ = conn.execute(
        "INSERT INTO login_attempts(ip, username, success, created_at) VALUES (?1, ?2, 1, ?3)",
        params![ip, req.username, now],
    );
    let token = random_psk();
    let exp = unix_ts() + 14 * 24 * 3600;
    if let Err(e) = conn.execute(
        "INSERT INTO sessions(token, admin_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token, admin_id, exp],
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    let _ = insert_audit_log(&conn, Some(admin_id), "auth_success", "login", &ip);
    let mut headers = HeaderMap::new();
    let cookie = format!(
        "astrapanel_session={token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1209600"
    );
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
    let _ = insert_audit_log(
        &conn,
        None,
        "user_created_manual",
        &format!("username={}", req.username.trim()),
        &client_ip(&headers),
    );
    {
        let _guard = state.sync_lock.lock().await;
        if let Err(e) = write_runtime_config(&state) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
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
    let _ = insert_audit_log(
        &conn,
        None,
        "user_toggled",
        &format!("user_id={}, enabled={}", id, req.enabled),
        &client_ip(&headers),
    );
    {
        let _guard = state.sync_lock.lock().await;
        if let Err(e) = write_runtime_config(&state) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
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
    let _ = insert_audit_log(
        &conn,
        None,
        "user_deleted",
        &format!("user_id={}", id),
        &client_ip(&headers),
    );
    {
        let _guard = state.sync_lock.lock().await;
        if let Err(e) = write_runtime_config(&state) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
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
    }
    Json(json!({"ok": true})).into_response()
}

async fn get_settings(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let payload = ApiSettings {
        panel_domain: get_setting_conn(&conn, "panel_domain")
            .ok()
            .flatten()
            .unwrap_or_default(),
        subscription_domain: get_setting_conn(&conn, "subscription_domain")
            .ok()
            .flatten()
            .unwrap_or_default(),
        subscription_sub_domain: get_setting_conn(&conn, "subscription_sub_domain")
            .ok()
            .flatten()
            .unwrap_or_default(),
    };
    Json(payload).into_response()
}

async fn save_settings(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<SaveSettingsReq>,
) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if let Err(e) = set_setting_conn(&conn, "panel_domain", req.panel_domain.trim()) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    if let Err(e) = set_setting_conn(&conn, "subscription_domain", req.subscription_domain.trim()) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    if let Err(e) = set_setting_conn(
        &conn,
        "subscription_sub_domain",
        req.subscription_sub_domain.trim(),
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    let _ = insert_audit_log(
        &conn,
        None,
        "settings_updated",
        &format!(
            "panel_domain={}, subscription_domain={}, subscription_sub_domain={}",
            req.panel_domain, req.subscription_domain, req.subscription_sub_domain
        ),
        &client_ip(&headers),
    );
    Json(json!({"ok": true})).into_response()
}

async fn list_audit_logs(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut stmt = match conn.prepare(
        "SELECT id, admin_id, event, details, ip, created_at FROM audit_logs ORDER BY id DESC LIMIT 300",
    ) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let rows = match stmt.query_map([], |r| {
        Ok(ApiAuditLog {
            id: r.get(0)?,
            admin_id: r.get(1)?,
            event: r.get(2)?,
            details: r.get(3)?,
            ip: r.get(4)?,
            created_at: r.get(5)?,
        })
    }) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut out = Vec::new();
    for row in rows {
        match row {
            Ok(v) => out.push(v),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
    Json(out).into_response()
}

async fn list_access_keys(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let base = resolve_public_base_url(&state, &conn);
    let mut stmt = match conn.prepare(
        r#"
SELECT k.id, k.customer_label, k.token, k.user_id, u.username, k.enabled, k.expires_at, k.created_at
FROM access_keys k
JOIN users u ON u.id = k.user_id
ORDER BY k.id DESC
"#,
    ) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let rows = match stmt.query_map([], |r| {
        Ok(ApiAccessKey {
            id: r.get(0)?,
            customer_label: r.get(1)?,
            token: r.get(2)?,
            user_id: r.get(3)?,
            username: r.get(4)?,
            enabled: r.get::<_, i64>(5)? == 1,
            expires_at: r.get(6)?,
            created_at: r.get(7)?,
            sub_link: String::new(),
        })
    }) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut out = Vec::new();
    for row in rows {
        match row {
            Ok(mut key) => {
                key.sub_link = format!("{}/s/{}?format=astralink-uri", base, key.token);
                out.push(key);
            }
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
    Json(out).into_response()
}

async fn issue_access_key(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<IssueAccessReq>,
) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    let source_ip = client_ip(&headers);
    let label = req.customer_label.trim().to_string();
    if label.is_empty() {
        return (StatusCode::BAD_REQUEST, "customer_label is required").into_response();
    }
    let days = req.days.clamp(1, 3650);
    let profile = req
        .profile
        .filter(|p| ["balanced", "performance", "stealth"].contains(&p.as_str()))
        .unwrap_or_else(|| "balanced".to_string());
    let username = format!("cl_{}", random_short_id());
    let psk = random_psk();
    let token = random_psk();
    let now = unix_ts();
    let expires_at = now + days * 24 * 3600;

    {
        let conn = match Connection::open(&state.db) {
            Ok(v) => v,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        let tx = match conn.unchecked_transaction() {
            Ok(v) => v,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        if let Err(e) = tx.execute(
            "INSERT INTO users(username, psk, enabled, profile, created_at) VALUES (?1, ?2, 1, ?3, ?4)",
            params![username, psk, profile, now],
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        let user_id = tx.last_insert_rowid();
        if let Err(e) = tx.execute(
            "INSERT INTO access_keys(token, user_id, customer_label, enabled, expires_at, created_at) VALUES (?1, ?2, ?3, 1, ?4, ?5)",
            params![token, user_id, label, expires_at, now],
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        if let Err(e) = tx.commit() {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        let _ = insert_audit_log(
            &conn,
            None,
            "access_key_issued",
            &format!("customer_label={}, username={}", label, username),
            &source_ip,
        );
    }
    {
        let _guard = state.sync_lock.lock().await;
        if let Err(e) = write_runtime_config(&state) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        maybe_restart_service(&state.restart_service);
    }
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let base = resolve_public_base_url(&state, &conn);
    Json(json!({
        "ok": true,
        "token": token,
        "customer_label": label,
        "expires_at": expires_at,
        "subscription_uri": format!("{}/s/{}?format=astralink-uri", base, token),
        "subscription_json": format!("{}/s/{}?format=singbox-socks", base, token),
        "subscription_json_download": format!("{}/s/{}?format=singbox-socks-download", base, token)
    }))
    .into_response()
}

async fn delete_access_key(
    headers: HeaderMap,
    Path(id): Path<i64>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if !ensure_auth(&headers, &state) {
        return unauthorized();
    }
    let source_ip = client_ip(&headers);
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let user_id: rusqlite::Result<i64> =
        conn.query_row("SELECT user_id FROM access_keys WHERE id=?1", params![id], |r| r.get(0));
    let uid = match user_id {
        Ok(v) => v,
        Err(_) => return (StatusCode::NOT_FOUND, "key not found").into_response(),
    };
    if let Err(e) = conn.execute("DELETE FROM access_keys WHERE id=?1", params![id]) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    let _ = conn.execute("UPDATE users SET enabled=0 WHERE id=?1", params![uid]);
    let _ = insert_audit_log(
        &conn,
        None,
        "access_key_revoked",
        &format!("access_key_id={}, user_id={}", id, uid),
        &source_ip,
    );
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

async fn subscription_by_token(
    Path(token): Path<String>,
    Query(q): Query<SubQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let fmt = q.format.unwrap_or_else(|| "astralink-uri".to_string());
    let conn = match Connection::open(&state.db) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let now = unix_ts();
    let row: rusqlite::Result<(String, String, String, i64, i64, i64)> = conn.query_row(
        r#"
SELECT u.username, u.psk, u.profile, u.enabled, k.enabled, k.expires_at
FROM access_keys k
JOIN users u ON u.id = k.user_id
WHERE k.token=?1
"#,
        params![token],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    );
    let (username, psk, profile, user_enabled, key_enabled, expires_at) = match row {
        Ok(v) => v,
        Err(_) => return (StatusCode::NOT_FOUND, "subscription not found").into_response(),
    };
    if user_enabled != 1 || key_enabled != 1 || now > expires_at {
        return (StatusCode::FORBIDDEN, "subscription expired or disabled").into_response();
    }
    if fmt == "astralink-uri" {
        let raw = json!({
            "host": state.public_host,
            "port": state.public_port,
            "username": username,
            "psk": psk,
            "profile": profile
        });
        let token = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&raw).unwrap_or_default());
        let uri = format!("astralink://{token}#{username}");
        return (StatusCode::OK, uri).into_response();
    }
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
    if fmt == "singbox-socks" {
        return Json(cfg).into_response();
    }
    if fmt == "singbox-socks-download" {
        let body = match serde_json::to_vec_pretty(&cfg) {
            Ok(v) => v,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("attachment; filename=\"astralink-{}.json\"", username))
                .unwrap_or(HeaderValue::from_static("attachment")),
        );
        return (StatusCode::OK, headers, body).into_response();
    }
    (StatusCode::BAD_REQUEST, "unknown format").into_response()
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
        panel_port: args.port,
        panel_domain: args.panel_domain,
        subscription_domain: args.subscription_domain,
        subscription_sub_domain: args.subscription_sub_domain,
        sync_lock: Arc::new(Mutex::new(())),
    };
    {
        let _guard = state.sync_lock.lock().await;
        apply_default_domains(&state)?;
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
        .route("/api/settings", get(get_settings).post(save_settings))
        .route("/api/access-keys", get(list_access_keys).post(issue_access_key))
        .route("/api/access-keys/:id", delete(delete_access_key))
        .route("/api/audit-logs", get(list_audit_logs))
        .route("/api/subscription/:uuid", get(subscription))
        .route("/s/:token", get(subscription_by_token))
        .layer(middleware::from_fn(security_headers_middleware))
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

const REACT_APP_HTML: &str = r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AstraPanel</title>
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<style>
:root{--bg:#f4f8fb;--line:#d9e2ec;--card:#fff;--text:#0f172a;--muted:#64748b;--accent:#0a5ccf;--ok:#177d3b;--danger:#b42318}
body[data-theme='dark']{--bg:#0b1220;--line:#1f2a3d;--card:#111a2b;--text:#e5edf8;--muted:#97a9c3;--accent:#3b82f6;--ok:#22c55e;--danger:#ef4444}
*{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,Segoe UI,system-ui;background:var(--bg);color:var(--text)}
.hero{background:linear-gradient(120deg,#0a418e,#1f7aff);color:#fff;padding:20px}
.hero h1{margin:0;font-size:30px}.hero p{margin:8px 0 0;opacity:.9}
.shell{max-width:1280px;margin:14px auto;padding:0 14px;display:grid;grid-template-columns:1.2fr 1fr;gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;box-shadow:0 3px 12px rgba(15,23,42,.04)}
.card h2{margin:0 0 10px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
input,select{padding:9px 10px;border:1px solid #cbd5e1;border-radius:10px;background:#fff}
button{padding:9px 12px;border:0;border-radius:10px;background:var(--accent);color:#fff;cursor:pointer;font-weight:600}
button.alt{background:#334155}button.ok{background:var(--ok)}button.danger{background:var(--danger)}
table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #edf2f7;padding:8px;text-align:left;vertical-align:top;font-size:13px}
code{font-size:12px;word-break:break-all}.muted{font-size:12px;color:var(--muted)}
.full{grid-column:1 / span 2}.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px}
.pill.ok{background:#e7f7ee;color:#106a30}.pill.off{background:#fdecec;color:#8f1f1f}
</style></head><body>
<div id="root"></div>
<script type="text/babel">
const {useEffect,useState}=React;
async function api(path,method='GET',body=null){
  const r=await fetch(path,{method,headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):null});
  if(!r.ok) throw new Error(await r.text());
  const ct=r.headers.get('content-type')||'';
  return ct.includes('application/json')?await r.json():await r.text();
}
function fmtTs(ts){try{return new Date(ts*1000).toLocaleString();}catch{return String(ts)}}
function App(){
  const [users,setUsers]=useState([]),[inbounds,setInbounds]=useState([]),[keys,setKeys]=useState([]);
  const [audits,setAudits]=useState([]);
  const [settings,setSettings]=useState({panel_domain:'',subscription_domain:'',subscription_sub_domain:''});
  const [kLabel,setKLabel]=useState(''),[kDays,setKDays]=useState(30),[kProfile,setKProfile]=useState('balanced');
  const [uName,setUName]=useState(''),[uPsk,setUPsk]=useState(''),[uProfile,setUProfile]=useState('balanced');
  const [inTag,setInTag]=useState('main'),[inHost,setInHost]=useState('0.0.0.0'),[inPort,setInPort]=useState(8443);
  const [msg,setMsg]=useState('');
  const [theme,setTheme]=useState(localStorage.getItem('astrapanel_theme')||'light');
  useEffect(()=>{document.body.setAttribute('data-theme',theme);localStorage.setItem('astrapanel_theme',theme);},[theme]);
  const load=async()=>{const [a,b,c,d,e]=await Promise.all([api('/api/users'),api('/api/inbounds'),api('/api/access-keys'),api('/api/settings'),api('/api/audit-logs')]);setUsers(a);setInbounds(b);setKeys(c);setSettings(d);setAudits(e);};
  useEffect(()=>{load().catch(e=>setMsg(e.message));},[]);
  const issue=async()=>{const r=await api('/api/access-keys','POST',{customer_label:kLabel.trim(),days:Number(kDays||30),profile:kProfile});setMsg('Issued: '+r.subscription_uri);setKLabel('');await load();};
  const saveSettings=async()=>{await api('/api/settings','POST',settings);setMsg('Settings saved');await load();};
  const addUser=async()=>{await api('/api/users','POST',{username:uName.trim(),psk:uPsk.trim(),profile:uProfile});setUName('');setUPsk('');await load();};
  const addInbound=async()=>{await api('/api/inbounds','POST',{tag:inTag||'main',listen_host:inHost||'0.0.0.0',listen_port:Number(inPort||8443),transport_mode:'tcp'});await load();};
  const cp=async t=>{await navigator.clipboard.writeText(t);setMsg('Copied');};
  return <><div className="hero"><div className="row" style={{justifyContent:'space-between'}}><div><h1>AstraPanel React</h1><p>Production control plane: domains, automated keys, export-ready links</p></div><div><button className="alt" onClick={()=>setTheme(theme==='dark'?'light':'dark')}>{theme==='dark'?'Light mode':'Dark mode'}</button></div></div></div>
  <div className="shell">
    <section className="card"><h2>Automated Key Issuing</h2>
      <div className="row"><input placeholder="Customer label" value={kLabel} onChange={e=>setKLabel(e.target.value)} style={{minWidth:260}}/>
      <input type="number" min="1" max="3650" value={kDays} onChange={e=>setKDays(e.target.value)} style={{width:100}}/>
      <select value={kProfile} onChange={e=>setKProfile(e.target.value)}><option>balanced</option><option>performance</option><option>stealth</option></select>
      <button className="ok" onClick={()=>issue().catch(e=>setMsg(e.message))}>Issue Key</button></div>
      <p className="muted">{msg}</p>
      <table><thead><tr><th>Customer</th><th>Status</th><th>Expires</th><th>Subscription</th><th>Actions</th></tr></thead><tbody>
      {keys.map(k=>{const j=k.sub_link.replace('format=astralink-uri','format=singbox-socks');const dl=j.replace('format=singbox-socks','format=singbox-socks-download');
      return <tr key={k.id}><td><b>{k.customer_label}</b><div className="muted">{k.username}</div></td><td>{k.enabled?<span className="pill ok">active</span>:<span className="pill off">disabled</span>}</td><td>{fmtTs(k.expires_at)}</td><td><code>{k.sub_link}</code></td><td className="row"><button onClick={()=>cp(k.sub_link)}>Copy URI</button><button className="alt" onClick={()=>cp(j)}>Copy JSON</button><button className="alt" onClick={()=>window.open(dl,'_blank')}>Download JSON</button><button className="danger" onClick={()=>api('/api/access-keys/'+k.id,'DELETE').then(load).catch(e=>setMsg(e.message))}>Revoke</button></td></tr>})}
      </tbody></table></section>
    <section className="card"><h2>Domains & Routing</h2>
      <div className="row"><input placeholder="panel.domain.com" value={settings.panel_domain||''} onChange={e=>setSettings({...settings,panel_domain:e.target.value})} style={{width:'100%'}}/></div>
      <div className="row"><input placeholder="subs.domain.com" value={settings.subscription_domain||''} onChange={e=>setSettings({...settings,subscription_domain:e.target.value})} style={{width:'100%'}}/></div>
      <div className="row"><input placeholder="api.subs.domain.com" value={settings.subscription_sub_domain||''} onChange={e=>setSettings({...settings,subscription_sub_domain:e.target.value})} style={{width:'100%'}}/></div>
      <div className="row"><button onClick={()=>saveSettings().catch(e=>setMsg(e.message))}>Save Domains</button></div>
      <hr style={{border:'none',borderTop:'1px solid #edf2f7',margin:'12px 0'}}/>
      <h2 style={{fontSize:18}}>Inbounds</h2>
      <div className="row"><input value={inTag} onChange={e=>setInTag(e.target.value)}/><input value={inHost} onChange={e=>setInHost(e.target.value)}/><input value={inPort} onChange={e=>setInPort(e.target.value)} style={{width:110}}/><button onClick={()=>addInbound().catch(e=>setMsg(e.message))}>Save</button></div>
      <table><thead><tr><th>Tag</th><th>Listen</th><th>Status</th><th>Action</th></tr></thead><tbody>
      {inbounds.map(i=><tr key={i.id}><td>{i.tag}</td><td>{i.listen_host}:{i.listen_port}</td><td>{i.enabled?'on':'off'}</td><td><button onClick={()=>api('/api/inbounds/'+i.id,'PATCH',{enabled:i.enabled?0:1}).then(load).catch(e=>setMsg(e.message))}>{i.enabled?'Disable':'Enable'}</button></td></tr>)}
      </tbody></table></section>
    <section className="card full"><h2>Raw Users (advanced)</h2>
      <div className="row"><input placeholder="username" value={uName} onChange={e=>setUName(e.target.value)}/><input placeholder="psk (optional)" value={uPsk} onChange={e=>setUPsk(e.target.value)}/>
      <select value={uProfile} onChange={e=>setUProfile(e.target.value)}><option>balanced</option><option>performance</option><option>stealth</option></select>
      <button className="alt" onClick={()=>addUser().catch(e=>setMsg(e.message))}>Add User</button></div>
      <table><thead><tr><th>User</th><th>PSK</th><th>Profile</th><th>Status</th><th>Action</th></tr></thead><tbody>
      {users.map(u=><tr key={u.id}><td>{u.username}</td><td><code>{u.psk}</code></td><td>{u.profile}</td><td>{u.enabled?'on':'off'}</td><td className="row"><button onClick={()=>api('/api/users/'+u.id,'PATCH',{enabled:u.enabled?0:1}).then(load).catch(e=>setMsg(e.message))}>{u.enabled?'Disable':'Enable'}</button><button className="danger" onClick={()=>api('/api/users/'+u.id,'DELETE').then(load).catch(e=>setMsg(e.message))}>Delete</button></td></tr>)}
      </tbody></table></section>
    <section className="card full"><h2>Security Audit Log</h2>
      <table><thead><tr><th>Time</th><th>Event</th><th>IP</th><th>Details</th></tr></thead><tbody>
      {audits.map(a=><tr key={a.id}><td>{fmtTs(a.created_at)}</td><td>{a.event}</td><td>{a.ip}</td><td><code>{a.details}</code></td></tr>)}
      </tbody></table>
    </section>
  </div></>;
}
ReactDOM.createRoot(document.getElementById('root')).render(<App />);
</script></body></html>"#;
