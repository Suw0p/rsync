use crate::{
    config::{self, Config, Role},
    identity, scan, state,
    wire::ReplicaSettings,
};
use anyhow::{Context, Result, ensure};
use askama::Template;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Form, Query, State},
    http::{HeaderMap, Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};

pub type ReplicaCache = Arc<Mutex<Option<ReplicaSettings>>>;

pub type UpgradeCache = Arc<Mutex<UpgradeStatus>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradePhase {
    Idle,
    Queued,
    Sending,
    Restarting,
    Success,
    Failed,
}

#[derive(Clone, Serialize)]
pub struct UpgradeStatus {
    pub phase: UpgradePhase,
    pub target: String,
    pub version: String,
    pub sent_bytes: u64,
    pub total_bytes: u64,
    pub message: String,
    #[serde(skip)]
    since: Option<Instant>,
}

impl Default for UpgradeStatus {
    fn default() -> Self {
        Self {
            phase: UpgradePhase::Idle,
            target: String::new(),
            version: String::new(),
            sent_bytes: 0,
            total_bytes: 0,
            message: String::new(),
            since: None,
        }
    }
}

fn upgrade_guard(cache: &UpgradeCache) -> std::sync::MutexGuard<'_, UpgradeStatus> {
    cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn upgrade_status(cache: &UpgradeCache) -> UpgradeStatus {
    let mut status = upgrade_guard(cache);
    if let Some(since) = status.since {
        let expired = match status.phase {
            UpgradePhase::Queued => since.elapsed() > Duration::from_secs(600),
            UpgradePhase::Restarting => since.elapsed() > Duration::from_secs(90),
            _ => false,
        };
        if expired {
            status.phase = UpgradePhase::Failed;
            status.message = if status.sent_bytes == 0 {
                "升级请求等待超时，请重试".into()
            } else {
                "从机重启后未能重新连接，请检查从机服务；旧版程序已备份".into()
            };
            status.since = None;
        }
    }
    status.clone()
}

pub fn queue_upgrade(cache: &UpgradeCache, target: SocketAddr, version: &str) -> bool {
    let mut status = upgrade_guard(cache);
    if matches!(
        status.phase,
        UpgradePhase::Queued | UpgradePhase::Sending | UpgradePhase::Restarting
    ) {
        return false;
    }
    *status = UpgradeStatus {
        phase: UpgradePhase::Queued,
        target: target.to_string(),
        version: version.into(),
        message: "升级请求已提交，等待当前文件传输结束".into(),
        since: Some(Instant::now()),
        ..UpgradeStatus::default()
    };
    true
}

pub fn set_upgrade(cache: &UpgradeCache, phase: UpgradePhase, message: impl Into<String>) {
    let mut status = upgrade_guard(cache);
    status.phase = phase;
    status.message = message.into();
    status.since = Some(Instant::now());
}

pub fn upgrade_progress(cache: &UpgradeCache, sent: u64, total: u64) {
    let mut status = upgrade_guard(cache);
    status.phase = UpgradePhase::Sending;
    status.message = "正在传送升级程序".into();
    status.sent_bytes = sent;
    status.total_bytes = total;
    status.since = Some(Instant::now());
}

pub fn upgrade_reconnected(cache: &UpgradeCache, target: SocketAddr, settings: &ReplicaSettings) {
    let mut status = upgrade_guard(cache);
    if status.phase != UpgradePhase::Restarting || status.target != target.to_string() {
        return;
    }
    if settings.version == status.version {
        status.phase = UpgradePhase::Success;
        status.message = format!("从机已升级到 {} 并重新连接", settings.version);
    } else {
        status.phase = UpgradePhase::Failed;
        status.message = format!("从机已重连，但版本仍是 {}", settings.version);
    }
    status.since = None;
}

#[derive(Default)]
pub struct TransferMeter(Mutex<TransferWindow>);

#[derive(Default)]
struct TransferWindow {
    active: bool,
    started: Option<Instant>,
    samples: VecDeque<(Instant, u64)>,
}

impl TransferMeter {
    pub fn begin(&self) {
        let mut window = self.0.lock().unwrap_or_else(|e| e.into_inner());
        window.active = true;
        window.started = Some(Instant::now());
        window.samples.clear();
    }

    pub fn record(&self, bytes: u64) {
        let mut window = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !window.active || bytes == 0 {
            return;
        }
        let now = Instant::now();
        if let Some((at, count)) = window.samples.back_mut()
            && now.duration_since(*at) < Duration::from_millis(100)
        {
            *count = count.saturating_add(bytes);
        } else {
            window.samples.push_back((now, bytes));
        }
        while window.samples.len() > 64 {
            window.samples.pop_front();
        }
    }

    pub fn finish(&self) {
        let mut window = self.0.lock().unwrap_or_else(|e| e.into_inner());
        window.active = false;
        window.started = None;
        window.samples.clear();
    }

    fn bytes_per_second(&self) -> u64 {
        let mut window = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !window.active {
            return 0;
        }
        let now = Instant::now();
        while window
            .samples
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) > Duration::from_secs(5))
        {
            window.samples.pop_front();
        }
        let elapsed = window.started.map_or(0.5, |at| {
            now.duration_since(at).as_secs_f64().clamp(0.5, 5.0)
        });
        (window
            .samples
            .iter()
            .map(|(_, bytes)| *bytes as u128)
            .sum::<u128>() as f64
            / elapsed) as u64
    }
}

pub fn set_replica(cache: &ReplicaCache, settings: Option<ReplicaSettings>) {
    *cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = settings;
}

pub fn cached_replica(cache: &ReplicaCache) -> Option<ReplicaSettings> {
    cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

#[derive(Clone)]
struct AppState {
    root: PathBuf,
    wake: mpsc::Sender<Control>,
    replica: ReplicaCache,
    upgrade: UpgradeCache,
    settings_revision: Arc<AtomicU64>,
    transfer_meter: Arc<TransferMeter>,
    scan: Arc<scan::ScanProgress>,
}

pub enum Control {
    Refresh,
    Wake,
    SyncNow,
    Reconnect,
    SetReplica {
        retention_days: u64,
        verify_interval_secs: u64,
        reply: oneshot::Sender<std::result::Result<ReplicaSettings, String>>,
    },
    Upgrade {
        target: SocketAddr,
    },
}

#[derive(Serialize)]
struct Status {
    source_version: &'static str,
    connection: String,
    target: Option<SocketAddr>,
    peer_configured: bool,
    first_sync_confirmed: bool,
    paused: bool,
    pending_files: String,
    scan: scan::ScanStatus,
    last_success: String,
    last_error: String,
    last_files: String,
    transfer_bps: u64,
    last_scan_hashed: String,
    last_scan_cached: String,
    last_scan_workers: String,
    last_scan_ms: String,
    last_transfer_ms: String,
    verify_hashed_files: String,
    verify_hashed_bytes: String,
    verify_reused_files: String,
    replica: Option<ReplicaSettings>,
    upgrade: UpgradeStatus,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct Dashboard {
    root: String,
    address: String,
    excludes: Vec<String>,
    status: Status,
    connection_label: &'static str,
    connected: bool,
    last_success_display: String,
    source: Config,
    target_value: String,
    source_ca_fingerprint: String,
    notice: String,
    replica_root: String,
    replica_addr: String,
    replica_retention_days: String,
    replica_verify_interval_secs: String,
    replica_available: bool,
    history_enabled: bool,
    replica_version: String,
    upgrade_available: bool,
}

#[derive(Deserialize)]
struct ControlForm {
    action: String,
}

#[derive(Deserialize)]
struct ExcludeForm {
    action: String,
    path: String,
}

#[derive(Deserialize)]
struct SourceSettingsForm {
    scan_interval_secs: u64,
    hash_workers: usize,
    verify_interval_secs: u64,
}

#[derive(Deserialize)]
struct SourceConnectionForm {
    addr: String,
}

#[derive(Deserialize)]
struct SourcePeerForm {
    fingerprint: String,
    certificate: String,
}

#[derive(Default, Deserialize)]
struct NoticeQuery {
    saved: Option<String>,
}

#[derive(Deserialize)]
struct ReplicaSettingsForm {
    retention_days: u64,
    verify_interval_secs: u64,
}

#[derive(Deserialize)]
struct ReplicaHistoryForm {
    enabled: bool,
}

#[derive(Deserialize)]
struct ReplicaUpgradeForm {
    target: String,
    version: String,
}

type WebResult<T> = std::result::Result<T, (StatusCode, String)>;

pub fn start(
    config: &Config,
    settings_revision: Arc<AtomicU64>,
    transfer_meter: Arc<TransferMeter>,
    scan: Arc<scan::ScanProgress>,
) -> Result<(mpsc::Receiver<Control>, ReplicaCache, UpgradeCache)> {
    ensure!(config.role == Role::Source, "web is source-only");
    let listener = std::net::TcpListener::bind(config.web_addr)
        .with_context(|| format!("bind web listener {}", config.web_addr))?;
    listener.set_nonblocking(true)?;
    let web_addr = listener.local_addr()?;
    let (wake, rx) = mpsc::channel(8);
    let replica: ReplicaCache = Arc::new(Mutex::new(None));
    let upgrade: UpgradeCache = Arc::new(Mutex::new(UpgradeStatus::default()));
    let app_state = AppState {
        root: config.root.clone(),
        wake,
        replica: replica.clone(),
        upgrade: upgrade.clone(),
        settings_revision,
        transfer_meter,
        scan,
    };
    thread::Builder::new()
        .name("rsync-web".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("web runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("web listener");
                let router = Router::new()
                    .route("/", get(index))
                    .route("/api/status", get(status))
                    .route("/api/control", post(control))
                    .route("/api/excludes", post(excludes))
                    .route("/api/source-settings", post(source_settings))
                    .route("/api/source-connection", post(source_connection))
                    .route("/api/source-peer", post(source_peer))
                    .route("/api/source-ca", get(source_ca))
                    .route("/api/replica-settings", post(replica_settings))
                    .route("/api/replica-history", post(replica_history))
                    .route("/api/replica-upgrade", post(replica_upgrade))
                    .route("/assets/app.css", get(css))
                    .route("/assets/app.js", get(js))
                    .layer(DefaultBodyLimit::max(8 * 1024))
                    .layer(middleware::from_fn(browser_request))
                    .with_state(app_state);
                if let Err(e) = axum::serve(listener, router).await {
                    eprintln!("web server stopped: {e}");
                }
            });
        })?;
    let reachable = reachable_web_addr(web_addr, config.addr);
    if !reachable.ip().is_unspecified() {
        println!("web dashboard at http://{reachable}");
    } else {
        println!("web dashboard listening on {web_addr}");
    }
    Ok((rx, replica, upgrade))
}

fn reachable_web_addr(listen: SocketAddr, replica: Option<SocketAddr>) -> SocketAddr {
    if !listen.ip().is_unspecified() {
        return listen;
    }
    let Some(replica) = replica else {
        return listen;
    };
    UdpSocket::bind(SocketAddr::new(listen.ip(), 0))
        .and_then(|socket| {
            socket.connect(replica)?;
            socket.local_addr()
        })
        .map(|local| SocketAddr::new(local.ip(), listen.port()))
        .unwrap_or(listen)
}

async fn browser_request(request: Request<axum::body::Body>, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok());
    let trusted = host.is_some_and(|h| {
        h == "localhost"
            || h == "[::1]"
            || h.parse::<IpAddr>().is_ok()
            || h.parse::<SocketAddr>().is_ok()
            || h.strip_prefix("localhost:")
                .is_some_and(|port| port.parse::<u16>().is_ok())
    });
    if !trusted {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Reject browser requests initiated by another site without a form token.
    if request.method() == Method::POST
        && request
            .headers()
            .get("sec-fetch-site")
            .is_some_and(|value| value == "cross-site")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'".parse().unwrap());
    response
}

fn internal(error: impl std::fmt::Display) -> (StatusCode, String) {
    eprintln!("web request failed: {error}");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".into())
}

fn read_status(app: &AppState) -> Result<Status> {
    // Snapshot the scan phase first: an inactive phase is published only after
    // its pending count is committed, so later SQL reads cannot return the old zero.
    let scan = app.scan.snapshot();
    let config = Config::load(app.root.clone())?;
    let db = state::open_readonly(&config)?;
    let get = |key: &str| -> Result<String> { Ok(state::get(&db, key)?.unwrap_or_default()) };
    Ok(Status {
        source_version: env!("CARGO_PKG_VERSION"),
        connection: get("connection")?,
        target: config.addr,
        peer_configured: config.peer_path().is_file(),
        first_sync_confirmed: config.first_sync_confirmed,
        paused: config.pause_path().exists(),
        pending_files: if scan.active {
            String::new()
        } else {
            get("pending_files")?
        },
        scan,
        last_success: get("last_success")?,
        last_error: get("last_error")?,
        last_files: get("last_files")?,
        transfer_bps: app.transfer_meter.bytes_per_second(),
        last_scan_hashed: get("last_scan_hashed")?,
        last_scan_cached: get("last_scan_cached")?,
        last_scan_workers: get("last_scan_workers")?,
        last_scan_ms: get("last_scan_ms")?,
        last_transfer_ms: get("last_transfer_ms")?,
        verify_hashed_files: get("verify_hashed_files")?,
        verify_hashed_bytes: get("verify_hashed_bytes")?,
        verify_reused_files: get("verify_reused_files")?,
        replica: cached_replica(&app.replica),
        upgrade: upgrade_status(&app.upgrade),
    })
}

async fn index(
    State(app): State<AppState>,
    Query(query): Query<NoticeQuery>,
) -> WebResult<Html<String>> {
    let config = Config::load(app.root.clone()).map_err(internal)?;
    let status = read_status(&app).map_err(internal)?;
    let connection_label = match status.connection.as_str() {
        _ if status.scan.active => "正在扫描",
        "idle" | "connected" => "已连接",
        "syncing" => "正在同步",
        "connecting" => "正在连接",
        "unconfigured" => "等待设置连接",
        "unpaired" => "等待证书配对",
        "approval_required" => "等待首次同步确认",
        "upgrade_required" => "从机需要升级",
        "error" => "连接异常",
        _ => "连接中断",
    };
    let connected = matches!(
        status.connection.as_str(),
        "idle" | "connected" | "syncing" | "upgrade_required"
    );
    let last_success_display = if status.last_success.is_empty() {
        "—".into()
    } else if let (Some(date), Some(time)) = (
        status.last_success.get(..10),
        status.last_success.get(11..19),
    ) {
        format!("{date} {time} UTC")
    } else {
        status.last_success.clone()
    };
    let target_value = status
        .target
        .map_or_else(String::new, |addr| addr.to_string());
    let source_ca_fingerprint = identity::ca_fingerprint(&config).map_err(internal)?;
    let notice = match query.saved.as_deref() {
        Some("source") => "主机设置已保存",
        Some("connection") => "连接目标已保存",
        Some("peer") => "从机证书已导入",
        Some("replica") => "从机设置已保存",
        Some("history") => "历史备份设置已保存",
        Some("excludes") => "排除规则已保存",
        Some("confirm") => "已确认，首次同步即将开始",
        Some("control") => "同步状态已更新",
        Some("upgrade") => "从机升级请求已提交",
        _ => "",
    };
    let replica = status.replica.as_ref();
    let page = Dashboard {
        root: config.root.display().to_string(),
        address: config
            .addr
            .map_or_else(|| "未设置".into(), |addr| addr.to_string()),
        excludes: config.excludes.clone(),
        connection_label,
        connected,
        last_success_display,
        source: config,
        target_value,
        source_ca_fingerprint,
        notice: notice.into(),
        replica_root: replica.map_or_else(|| "—".into(), |r| r.root.clone()),
        replica_addr: replica.map_or_else(|| "—".into(), |r| r.addr.to_string()),
        replica_retention_days: replica.map_or_else(String::new, |r| r.retention_days.to_string()),
        replica_verify_interval_secs: replica
            .map_or_else(String::new, |r| r.verify_interval_secs.to_string()),
        replica_available: replica.is_some(),
        history_enabled: replica.is_some_and(|r| r.retention_days > 0),
        replica_version: replica.map_or_else(
            || "—".into(),
            |r| {
                if r.version.is_empty() {
                    "旧版，需手动升级一次".into()
                } else {
                    r.version.clone()
                }
            },
        ),
        upgrade_available: replica.is_some_and(|r| r.upgrade_supported),
        status,
    };
    Ok(Html(page.render().map_err(internal)?))
}

async fn status(State(app): State<AppState>) -> WebResult<Json<Status>> {
    Ok(Json(read_status(&app).map_err(internal)?))
}

async fn source_settings(
    State(app): State<AppState>,
    Form(form): Form<SourceSettingsForm>,
) -> WebResult<Redirect> {
    config::validate_source_settings(
        form.scan_interval_secs,
        form.hash_workers,
        form.verify_interval_secs,
    )
    .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let mut config = Config::load(app.root.clone()).map_err(internal)?;
    if config.scan_interval_secs != form.scan_interval_secs
        || config.hash_workers != form.hash_workers
        || config.verify_interval_secs != form.verify_interval_secs
    {
        config.scan_interval_secs = form.scan_interval_secs;
        config.hash_workers = form.hash_workers;
        config.verify_interval_secs = form.verify_interval_secs;
        config.save().map_err(internal)?;
        app.settings_revision.fetch_add(1, Ordering::SeqCst);
        wake_source(&app, Control::Wake).await?;
    }
    Ok(Redirect::to("/?saved=source#settings-source"))
}

async fn source_connection(
    State(app): State<AppState>,
    Form(form): Form<SourceConnectionForm>,
) -> WebResult<Redirect> {
    let target = if form.addr.trim().is_empty() {
        None
    } else {
        Some(form.addr.trim().parse::<SocketAddr>().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "连接地址应为从机 IP 与端口，格式为 IP:端口".into(),
            )
        })?)
    };
    config::validate_address(Role::Source, target)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let mut config = Config::load(app.root.clone()).map_err(internal)?;
    if config.addr != target {
        config.addr = target;
        config.save().map_err(internal)?;
        app.settings_revision.fetch_add(1, Ordering::SeqCst);
        wake_source(&app, Control::Reconnect).await?;
    }
    Ok(Redirect::to("/?saved=connection#settings-connection"))
}

async fn source_peer(
    State(app): State<AppState>,
    Form(form): Form<SourcePeerForm>,
) -> WebResult<Redirect> {
    let config = Config::load(app.root.clone()).map_err(internal)?;
    identity::add_peer_pem(&config, &form.certificate, form.fingerprint.trim())
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    app.settings_revision.fetch_add(1, Ordering::SeqCst);
    wake_source(&app, Control::Reconnect).await?;
    Ok(Redirect::to("/?saved=peer#settings-peer"))
}

async fn source_ca(State(app): State<AppState>) -> WebResult<impl IntoResponse> {
    let config = Config::load(app.root.clone()).map_err(internal)?;
    let pem = std::fs::read(config.ca_path()).map_err(internal)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=rsync-source-ca.pem",
            ),
        ],
        pem,
    ))
}

async fn replica_settings(
    State(app): State<AppState>,
    Form(form): Form<ReplicaSettingsForm>,
) -> WebResult<Redirect> {
    save_replica_settings(&app, form.retention_days, form.verify_interval_secs).await?;
    Ok(Redirect::to("/?saved=replica#settings-replica"))
}

async fn replica_history(
    State(app): State<AppState>,
    Form(form): Form<ReplicaHistoryForm>,
) -> WebResult<Redirect> {
    let replica = cached_replica(&app.replica).ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Replica is disconnected".into(),
        )
    })?;
    let retention_days = if form.enabled {
        if replica.retention_days == 0 {
            7
        } else {
            replica.retention_days
        }
    } else {
        0
    };
    save_replica_settings(&app, retention_days, replica.verify_interval_secs).await?;
    Ok(Redirect::to("/?saved=history#settings-replica"))
}

async fn replica_upgrade(
    State(app): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ReplicaUpgradeForm>,
) -> WebResult<Redirect> {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let same_origin = origin == format!("http://{host}")
        || origin == format!("https://{host}")
        || headers
            .get("sec-fetch-site")
            .is_some_and(|value| value == "same-origin");
    if !same_origin {
        return Err((StatusCode::FORBIDDEN, "升级操作只能从本页面发起".into()));
    }
    let config = Config::load(app.root.clone()).map_err(internal)?;
    let target = config
        .addr
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "未设置从机连接地址".into()))?;
    let replica = cached_replica(&app.replica).ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "从机未连接，请稍后重试".into(),
    ))?;
    if !replica.upgrade_supported {
        return Err((
            StatusCode::CONFLICT,
            "从机尚不支持远程升级，需先手动安装支持升级的版本".into(),
        ));
    }
    if form.target != target.to_string() || form.version != replica.version {
        return Err((
            StatusCode::CONFLICT,
            "从机连接或版本已变化，请刷新页面后重试".into(),
        ));
    }
    upgrade_status(&app.upgrade);
    if !queue_upgrade(&app.upgrade, target, env!("CARGO_PKG_VERSION")) {
        return Err((StatusCode::CONFLICT, "已有从机升级任务正在进行".into()));
    }
    if app.wake.try_send(Control::Upgrade { target }).is_err() {
        set_upgrade(&app.upgrade, UpgradePhase::Failed, "同步进程忙，请稍后重试");
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "同步进程忙，请稍后重试".into(),
        ));
    }
    // Interrupt a long manifest pass at its next safe checkpoint so the queued upgrade runs.
    app.settings_revision.fetch_add(1, Ordering::SeqCst);
    Ok(Redirect::to("/?saved=upgrade#settings-replica"))
}

async fn save_replica_settings(
    app: &AppState,
    retention_days: u64,
    verify_interval_secs: u64,
) -> WebResult<()> {
    config::validate_replica_settings(retention_days, verify_interval_secs)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    if cached_replica(&app.replica).is_none() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Replica is disconnected".into(),
        ));
    }
    let (reply, response) = oneshot::channel();
    app.wake
        .try_send(Control::SetReplica {
            retention_days,
            verify_interval_secs,
            reply,
        })
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Replica settings queue is busy".into(),
            )
        })?;
    let result = tokio::time::timeout(Duration::from_secs(30), response)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Replica is busy; retry".into(),
            )
        })?
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Replica connection was interrupted".into(),
            )
        })?;
    result.map_err(|message| (StatusCode::BAD_GATEWAY, message))?;
    Ok(())
}

async fn control(
    State(app): State<AppState>,
    Form(form): Form<ControlForm>,
) -> WebResult<Redirect> {
    let mut config = Config::load(app.root.clone()).map_err(internal)?;
    match form.action.as_str() {
        "pause" => std::fs::write(config.pause_path(), b"1").map_err(internal)?,
        "resume" => match std::fs::remove_file(config.pause_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(internal(e)),
        },
        "sync" if config.first_sync_confirmed => {}
        "sync" => return Err((StatusCode::CONFLICT, "请先确认首次同步".into())),
        "confirm" => {
            config.first_sync_confirmed = true;
            config.save().map_err(internal)?;
            app.settings_revision.fetch_add(1, Ordering::SeqCst);
        }
        _ => return Err((StatusCode::BAD_REQUEST, "Invalid action".into())),
    }
    let event = if form.action == "sync" || form.action == "confirm" {
        Control::SyncNow
    } else {
        Control::Refresh
    };
    wake_source(&app, event).await?;
    Ok(Redirect::to(if form.action == "confirm" {
        "/?saved=confirm"
    } else {
        "/?saved=control"
    }))
}

async fn excludes(
    State(app): State<AppState>,
    Form(form): Form<ExcludeForm>,
) -> WebResult<Redirect> {
    let mut config = Config::load(app.root.clone()).map_err(internal)?;
    config::validate_excludes(std::slice::from_ref(&form.path))
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid relative path".into()))?;
    let changed = match form.action.as_str() {
        "add" => {
            if !config.excludes.contains(&form.path) {
                config.excludes.push(form.path);
                true
            } else {
                false
            }
        }
        "remove" => {
            let previous = config.excludes.len();
            config.excludes.retain(|path| path != &form.path);
            config.excludes.len() != previous
        }
        _ => return Err((StatusCode::BAD_REQUEST, "Invalid action".into())),
    };
    if changed {
        config.save().map_err(internal)?;
        app.settings_revision.fetch_add(1, Ordering::SeqCst);
        wake_source(&app, Control::Wake).await?;
    }
    Ok(Redirect::to("/?saved=excludes#settings-exclusions"))
}

async fn wake_source(app: &AppState, event: Control) -> WebResult<()> {
    tokio::time::timeout(Duration::from_secs(3), app.wake.send(event))
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "同步进程忙，请稍后查看状态并重试".into(),
            )
        })?
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "同步进程已停止".into()))
}

async fn css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../assets/app.css"),
    )
}

async fn js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../assets/app.js"),
    )
}
