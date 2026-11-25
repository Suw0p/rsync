use crate::{
    config::{self, CHUNK_SIZE, Config, ExclusionIndex, MAX_BLOCKS},
    identity,
    scan::{self, Entry, FileMeta, SMALL_BATCH_BYTES_LIMIT, SMALL_FILE_LIMIT},
    state, upgrade, web,
    wire::{self, Frame, FrameRef, ReplicaSettings},
};
use anyhow::{Context, Result, bail, ensure};
use notify::{RecursiveMode, Watcher};
use rayon::prelude::*;
use rusqlite::Connection;
use socket2::{SockRef, TcpKeepalive};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use walkdir::WalkDir;

const ENTRY_BATCH_LIMIT: usize = 512;
const MAX_PENDING_HANDSHAKES: usize = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_HEARTBEAT: Duration = Duration::from_secs(30);
const PENDING_UPDATE_INTERVAL: Duration = Duration::from_secs(1);
const VERIFIED_INITIAL_CAPACITY: usize = 128;
const MAX_WATCH_PATHS: usize = 50_000;
const SETTINGS_CHANGED: &str = "source settings changed during synchronization";

fn set_keepalive(tcp: &TcpStream) -> Result<()> {
    SockRef::from(tcp).set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(10))
            .with_retries(3),
    )?;
    Ok(())
}

fn check_revision(revision: &AtomicU64, expected: u64) -> Result<()> {
    ensure!(
        revision.load(Ordering::SeqCst) == expected,
        SETTINGS_CHANGED
    );
    Ok(())
}

struct ScanTrigger {
    manual: bool,
    full: bool,
    next_scan: tokio::time::Instant,
}

enum SyncOutcome {
    Full,
    RestartUnchanged,
    Delta,
}

#[derive(Default)]
struct DirtyPaths {
    paths: HashSet<String>,
    full: bool,
}

impl DirtyPaths {
    fn add(&mut self, path: String) {
        if self.full {
            return;
        }
        self.paths.insert(path);
        if self.paths.len() > MAX_WATCH_PATHS {
            self.paths = HashSet::new();
            self.full = true;
        }
    }

    fn merge(&mut self, changes: Self) {
        self.full |= changes.full || changes.paths.len() > MAX_WATCH_PATHS;
        if self.full {
            self.paths = HashSet::new();
            return;
        }
        if self.paths.is_empty() {
            self.paths = changes.paths;
            return;
        }
        for path in changes.paths {
            self.add(path);
            if self.full {
                return;
            }
        }
    }
}

fn exclusion_digest(paths: &[String]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    for path in paths {
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
    }
    hasher.finalize()
}

fn refresh_watch_exclusions(
    cache: &RwLock<Arc<ExclusionIndex>>,
    digest: &mut blake3::Hash,
    paths: &[String],
) {
    let next = exclusion_digest(paths);
    if next == *digest {
        return;
    }
    let replacement = Arc::new(ExclusionIndex::new(paths));
    let old = {
        let mut guard = cache.write().unwrap_or_else(|e| e.into_inner());
        std::mem::replace(&mut *guard, replacement)
    };
    // Deallocating a large rule set does not hold up the watcher callback.
    drop(old);
    *digest = next;
}

enum WatchPathChange {
    Ignore,
    Data(String),
    Full,
    Settings,
}

fn classify_watch_path(
    path: &Path,
    config_path: &Path,
    peer_path: &Path,
    private: &Path,
    root: &Path,
    exclusions: &ExclusionIndex,
) -> WatchPathChange {
    if path == config_path || path == peer_path {
        return WatchPathChange::Settings;
    }
    if path.starts_with(private) {
        return WatchPathChange::Ignore;
    }
    let Some(relative) = path.strip_prefix(root).ok().and_then(|path| path.to_str()) else {
        return WatchPathChange::Full;
    };
    if config::valid_relative(relative).is_err() {
        return WatchPathChange::Full;
    }
    if exclusions.contains(relative) {
        WatchPathChange::Ignore
    } else {
        WatchPathChange::Data(relative.to_owned())
    }
}

fn take_dirty_paths(tracker: &Mutex<DirtyPaths>) -> DirtyPaths {
    let mut pending = tracker
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::mem::take(&mut *pending)
}

fn restore_dirty_paths(tracker: &Mutex<DirtyPaths>, snapshot: DirtyPaths) {
    let mut pending = tracker
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pending.merge(snapshot);
}

struct WebControlContext<'a> {
    replica_cache: &'a web::ReplicaCache,
    upgrade_cache: &'a web::UpgradeCache,
    root: &'a Path,
    connected_target: Option<SocketAddr>,
}

struct TransferContext<'a> {
    revision: &'a AtomicU64,
    expected_revision: u64,
    meter: &'a web::TransferMeter,
}

struct SourcePass<'a> {
    full_requested: bool,
    known_changed: bool,
    changed_paths: &'a mut HashSet<String>,
    restart_check: bool,
    replica_generation: Option<u64>,
}

impl TransferContext<'_> {
    fn check(&self) -> Result<()> {
        check_revision(self.revision, self.expected_revision)
    }
}

struct Progress {
    files: u64,
    bytes: u64,
    verify_hashed_files: u64,
    verify_hashed_bytes: u64,
    verify_reused_files: u64,
    reported_files: u64,
    last_reported_at: Instant,
}

#[derive(Default)]
struct VerifyStats {
    hashed_files: u64,
    hashed_bytes: u64,
    reused_files: u64,
}

fn update_pending_files(
    db: &Connection,
    total_files: usize,
    completed_files: u64,
    reported_files: &mut u64,
    last_reported_at: &mut Instant,
) -> Result<()> {
    if completed_files == *reported_files {
        return Ok(());
    }
    let now = Instant::now();
    if now.duration_since(*last_reported_at) < PENDING_UPDATE_INTERVAL
        && completed_files as usize != total_files
    {
        return Ok(());
    }
    state::set(
        db,
        "pending_files",
        total_files
            .saturating_sub(completed_files as usize)
            .to_string(),
    )?;
    *reported_files = completed_files;
    *last_reported_at = now;
    Ok(())
}

fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn full_verify_due(db: &Connection, key: &str, interval: u64) -> Result<bool> {
    let last = state::get(db, key)?
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    Ok(unix_seconds()?.saturating_sub(last) >= interval)
}

fn supports_current_sync(settings: &ReplicaSettings) -> bool {
    settings.sync_protocol == wire::SYNC_PROTOCOL
        && settings.delta_supported
        && settings.deletions_supported
        && settings.directory_deletions_supported
}

fn source_sync_identity(config: &Config, db: &Connection) -> Result<String> {
    // A clean manifest can be reused only with the same peer, target and exclusion policy.
    // The file inventory itself is checked separately before skipping a network pass.
    let peer_certificate = fs::read(config.peer_path())?;
    let skipped = state::get(db, "skipped_symlinks")?.unwrap_or_default();
    let inputs = serde_json::to_vec(&(
        config.addr,
        blake3::hash(&peer_certificate).to_hex().to_string(),
        &config.excludes,
        skipped,
    ))?;
    Ok(blake3::hash(&inputs).to_hex().to_string())
}

fn mark_source_clean(db: &Connection, identity: &str) -> Result<()> {
    let transaction = db.unchecked_transaction()?;
    state::set(&transaction, "source_sync_identity", identity)?;
    state::set(&transaction, "source_sync_clean", "true")?;
    if let Some(generation) = state::get(&transaction, "generation")? {
        state::set(&transaction, "source_synced_generation", generation)?;
    }
    transaction.execute("DELETE FROM source_outbox", [])?;
    transaction.execute("DELETE FROM kv WHERE key='source_pending_mode'", [])?;
    transaction.commit()?;
    Ok(())
}

fn record_error(db: &Connection, err: &anyhow::Error) {
    let _ = state::set(db, "connection", "error");
    let _ = state::set(db, "last_error", format!("{}: {err:#}", now()));
    eprintln!("rsync error: {err:#}");
}

fn remote_text(text: &str) -> String {
    text.chars()
        .take(512)
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

async fn request_replica_settings<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<ReplicaSettings> {
    wire::send(stream, &Frame::ReplicaSettingsGet).await?;
    match wire::recv(stream).await? {
        Frame::ReplicaSettings { settings } => Ok(settings),
        Frame::Error { message } => bail!("replica settings: {}", remote_text(&message)),
        other => bail!("unexpected replica settings response: {}", other.kind()),
    }
}

async fn handle_web_control<S: AsyncRead + AsyncWrite + Unpin>(
    control: web::Control,
    stream: &mut S,
    context: &WebControlContext<'_>,
    trigger: &mut ScanTrigger,
    dirty: &mut bool,
) -> Result<bool> {
    match control {
        web::Control::Refresh => {}
        web::Control::Wake => {
            *dirty = true;
            trigger.full = true;
        }
        web::Control::SyncNow => {
            trigger.manual = true;
            *dirty = true;
            trigger.full = true;
        }
        web::Control::Reconnect => return Ok(true),
        web::Control::Upgrade { target } => {
            if web::upgrade_status(context.upgrade_cache).phase != web::UpgradePhase::Queued {
                return Ok(false);
            }
            if Config::load(context.root.to_path_buf())?.addr != Some(target)
                || context.connected_target != Some(target)
            {
                web::set_upgrade(
                    context.upgrade_cache,
                    web::UpgradePhase::Failed,
                    "从机连接目标已改变，请重新提交升级",
                );
                return Ok(false);
            }
            if !web::cached_replica(context.replica_cache).is_some_and(|r| r.upgrade_supported) {
                web::set_upgrade(
                    context.upgrade_cache,
                    web::UpgradePhase::Failed,
                    "从机未提供升级能力，请先手动安装新版",
                );
                return Ok(false);
            }
            web::set_upgrade(
                context.upgrade_cache,
                web::UpgradePhase::Sending,
                "准备升级程序",
            );
            let result = upgrade::send(stream, |sent, total| {
                web::upgrade_progress(context.upgrade_cache, sent, total);
            })
            .await;
            match result {
                Ok(true) => {
                    web::set_upgrade(
                        context.upgrade_cache,
                        web::UpgradePhase::Restarting,
                        "程序已安装，等待从机服务重启并重新连接",
                    );
                    return Ok(true);
                }
                Ok(false) => {
                    web::set_upgrade(
                        context.upgrade_cache,
                        web::UpgradePhase::Success,
                        "从机程序已是当前版本，无需重启",
                    );
                }
                Err(error) => {
                    web::set_upgrade(
                        context.upgrade_cache,
                        web::UpgradePhase::Failed,
                        format!("升级失败：{error:#}"),
                    );
                    return Ok(true);
                }
            }
        }
        web::Control::SetReplica {
            retention_days,
            verify_interval_secs,
            reply,
        } => {
            if reply.is_closed() {
                return Ok(false);
            }
            if Config::load(context.root.to_path_buf())?.addr != context.connected_target {
                let _ = reply.send(Err("连接目标已改变，请重新提交从机设置".into()));
                return Ok(false);
            }
            wire::send(
                stream,
                &Frame::ReplicaSettingsSet {
                    retention_days,
                    verify_interval_secs,
                },
            )
            .await?;
            match wire::recv(stream).await? {
                Frame::ReplicaSettings { settings } => {
                    web::set_replica(context.replica_cache, Some(settings.clone()));
                    let _ = reply.send(Ok(settings));
                }
                Frame::Error { message } => {
                    let _ = reply.send(Err(remote_text(&message)));
                }
                other => bail!("unexpected replica settings response: {}", other.kind()),
            }
        }
    }
    Ok(false)
}

pub async fn run_source(config: Config, db: Connection, once: bool) -> Result<()> {
    let mut db = db;
    config.check_root()?;
    if let Some(addr) = config.addr {
        println!("source connecting to replica at {addr}");
    } else {
        println!("source waiting for a connection target to be set in the web console");
    }
    let settings_revision = Arc::new(AtomicU64::new(0));
    let transfer_meter = Arc::new(web::TransferMeter::default());
    let (mut controls, replica_cache, upgrade_cache) = if once {
        (None, None, None)
    } else {
        let (rx, replica, upgrade) =
            web::start(&config, settings_revision.clone(), transfer_meter.clone())?;
        (Some(rx), Some(replica), Some(upgrade))
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
    let private = config.private_path();
    let config_path = config.config_path();
    let peer_path = config.peer_path();
    let watch_root = config.root.clone();
    let mut watch_digest = exclusion_digest(&config.excludes);
    let watch_exclusions = Arc::new(RwLock::new(Arc::new(ExclusionIndex::new(&config.excludes))));
    let callback_exclusions = watch_exclusions.clone();
    let watch_settings_revision = settings_revision.clone();
    let dirty_paths = Arc::new(Mutex::new(DirtyPaths::default()));
    let callback_dirty_paths = dirty_paths.clone();
    let mut _watcher = if once {
        None
    } else {
        match notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            let mut changes = DirtyPaths::default();
            let mut settings_changed = false;
            match event {
                Ok(event) if event.need_rescan() => {
                    changes.full = true;
                    // Settings events may have been lost along with data events.
                    settings_changed = true;
                }
                Ok(event) if !matches!(event.kind, notify::EventKind::Access(_)) => {
                    let exclusions = callback_exclusions
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    for path in event.paths {
                        match classify_watch_path(
                            &path,
                            &config_path,
                            &peer_path,
                            &private,
                            &watch_root,
                            &exclusions,
                        ) {
                            WatchPathChange::Ignore => {}
                            WatchPathChange::Data(relative) => {
                                changes.add(relative);
                            }
                            WatchPathChange::Full => changes.full = true,
                            WatchPathChange::Settings => {
                                changes.full = true;
                                settings_changed = true;
                            }
                        }
                    }
                }
                Err(_) => changes.full = true,
                _ => {}
            }
            if changes.full || !changes.paths.is_empty() {
                let mut pending = callback_dirty_paths
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                pending.merge(changes);
                drop(pending);
                if settings_changed {
                    watch_settings_revision.fetch_add(1, Ordering::SeqCst);
                }
                let _ = tx.try_send(());
            }
        }) {
            Ok(mut watcher) => match watcher.watch(&config.root, RecursiveMode::Recursive) {
                Ok(()) => Some(watcher),
                Err(e) => {
                    eprintln!("file watcher unavailable; periodic scans remain active: {e}");
                    None
                }
            },
            Err(e) => {
                eprintln!("file watcher unavailable; periodic scans remain active: {e}");
                None
            }
        }
    };
    let deadline = once.then(|| tokio::time::Instant::now() + Duration::from_secs(30));
    let mut retry_delay = Duration::from_millis(250);
    let mut last_logged_error = String::new();
    let mut last_log_time = std::time::Instant::now();
    // These flags describe this process, not the persisted manifest. After startup,
    // the restart check may avoid resending that manifest if both sides still agree.
    let mut manifest_ready = false;
    let mut resume_check_pending = !once;
    let startup_unix = unix_seconds()?;
    let mut last_full_scan = state::get(&db, "source_last_full_scan")?
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|last| {
            tokio::time::Instant::now()
                .checked_sub(Duration::from_secs(startup_unix.saturating_sub(last)))
        });
    let mut dirty = false;
    loop {
        let current = Config::load(config.root.clone())?;
        refresh_watch_exclusions(&watch_exclusions, &mut watch_digest, &current.excludes);
        if current.addr.is_none() || !current.peer_path().is_file() {
            if once {
                bail!("source target and peer certificate are required for --once");
            }
            let status = if current.addr.is_none() {
                state::set(&db, "last_error", "")?;
                "unconfigured"
            } else {
                "unpaired"
            };
            state::set(&db, "connection", status)?;
            if let Some(cache) = replica_cache.as_ref() {
                web::set_replica(cache, None);
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                _ = rx.recv(), if _watcher.is_some() => {}
                _ = async { controls.as_mut().unwrap().recv().await }, if controls.is_some() => {}
            }
            continue;
        }
        state::set(&db, "connection", "connecting")?;
        let current_peer = fs::read(current.peer_path())
            .ok()
            .map(|bytes| blake3::hash(&bytes));
        let connection = if let Some(deadline) = deadline {
            match tokio::time::timeout_at(deadline, connect_replica(&current)).await {
                Ok(connection) => connection,
                Err(_) => {
                    let error = anyhow::anyhow!("replica unavailable after 30 seconds");
                    record_error(&db, &error);
                    return Err(error);
                }
            }
        } else {
            connect_replica(&current).await
        };
        let mut tls = match connection {
            Ok(tls) => tls,
            Err(error) => {
                let message = format!("{error:#}");
                if message != last_logged_error
                    || last_log_time.elapsed() >= Duration::from_secs(60)
                {
                    record_error(&db, &error);
                    last_logged_error = message;
                    last_log_time = std::time::Instant::now();
                }
                state::set(&db, "connection", "disconnected")?;
                if deadline.is_some_and(|limit| tokio::time::Instant::now() >= limit) {
                    return Err(error.context("replica unavailable after 30 seconds"));
                }
                tokio::time::sleep(retry_delay).await;
                retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                continue;
            }
        };
        if Config::load(config.root.clone())?.addr != current.addr
            || fs::read(current.peer_path())
                .ok()
                .map(|bytes| blake3::hash(&bytes))
                != current_peer
        {
            continue;
        }
        let mut sync_compatible = true;
        let mut replica_generation = None;
        if let Some(cache) = replica_cache.as_ref() {
            match request_replica_settings(&mut tls).await {
                Ok(settings) => {
                    sync_compatible = supports_current_sync(&settings);
                    replica_generation = Some(settings.last_generation);
                    if let (Some(upgrade), Some(target)) = (upgrade_cache.as_ref(), current.addr) {
                        web::upgrade_reconnected(upgrade, target, &settings);
                    }
                    web::set_replica(cache, Some(settings));
                }
                Err(error) => {
                    record_error(&db, &error);
                    state::set(&db, "connection", "disconnected")?;
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                    continue;
                }
            }
        }
        state::set(
            &db,
            "connection",
            if sync_compatible {
                "idle"
            } else {
                "upgrade_required"
            },
        )?;
        let mut trigger = ScanTrigger {
            manual: false,
            full: !manifest_ready,
            next_scan: last_full_scan.map_or_else(tokio::time::Instant::now, |at| {
                at + Duration::from_secs(current.scan_interval_secs)
            }),
        };
        'connected: loop {
            if let (Some(controls), Some(cache)) = (controls.as_mut(), replica_cache.as_ref()) {
                while let Ok(control) = controls.try_recv() {
                    let context = WebControlContext {
                        replica_cache: cache,
                        upgrade_cache: upgrade_cache.as_ref().unwrap(),
                        root: &config.root,
                        connected_target: current.addr,
                    };
                    match handle_web_control(control, &mut tls, &context, &mut trigger, &mut dirty)
                        .await
                    {
                        Ok(true) => break 'connected,
                        Ok(false) => {}
                        Err(error) => {
                            record_error(&db, &error);
                            break 'connected;
                        }
                    }
                }
            }
            let active = Config::load(config.root.clone())?;
            refresh_watch_exclusions(&watch_exclusions, &mut watch_digest, &active.excludes);
            if active.addr != current.addr
                || fs::read(active.peer_path())
                    .ok()
                    .map(|bytes| blake3::hash(&bytes))
                    != current_peer
            {
                break 'connected;
            }
            while rx.try_recv().is_ok() {
                dirty = true;
            }
            let paused = !once && config.pause_path().exists();
            let approved = once || active.first_sync_confirmed;
            if !approved && sync_compatible {
                state::set(&db, "connection", "approval_required")?;
            }
            if sync_compatible
                && approved
                && (!paused || trigger.manual)
                && (dirty || trigger.full || tokio::time::Instant::now() >= trigger.next_scan)
            {
                let revision = settings_revision.load(Ordering::SeqCst);
                let mut changes = take_dirty_paths(&dirty_paths);
                let retry_delta =
                    state::get(&db, "source_pending_mode")?.as_deref() == Some("delta");
                // A watcher overflow or an event with no usable path loses the exact delta.
                // Fall back to a full scan so deletions cannot be silently missed.
                let full = trigger.full
                    || !manifest_ready
                    || changes.full
                    || (dirty && changes.paths.is_empty() && !retry_delta)
                    || tokio::time::Instant::now() >= trigger.next_scan;
                let known_changed = changes.full || !changes.paths.is_empty();
                let restart_check =
                    resume_check_pending && !trigger.manual && !dirty && !known_changed;
                resume_check_pending = false;
                trigger.manual = false;
                trigger.full = false;
                dirty = false;
                transfer_meter.begin();
                let ctx = TransferContext {
                    revision: &settings_revision,
                    expected_revision: revision,
                    meter: &transfer_meter,
                };
                let mut scan_committed = false;
                let result = async {
                    let outcome = source_once(
                        &active,
                        &mut db,
                        &mut tls,
                        SourcePass {
                            full_requested: full,
                            known_changed,
                            changed_paths: &mut changes.paths,
                            restart_check,
                            replica_generation,
                        },
                        &ctx,
                        &mut manifest_ready,
                        &mut scan_committed,
                    )
                    .await?;
                    if matches!(outcome, SyncOutcome::Full | SyncOutcome::RestartUnchanged) {
                        manifest_ready = true;
                        if matches!(outcome, SyncOutcome::Full) {
                            last_full_scan = Some(tokio::time::Instant::now());
                        }
                        trigger.next_scan = last_full_scan
                            .map_or_else(tokio::time::Instant::now, |at| {
                                at + Duration::from_secs(active.scan_interval_secs)
                            });
                    }
                    replica_generation = state::get(&db, "generation")?
                        .map(|value| value.parse())
                        .transpose()?;
                    Ok::<(), anyhow::Error>(())
                }
                .await;
                transfer_meter.finish();
                if result.is_err() {
                    // Unacknowledged delta tasks survive with their manifest transaction.
                    // Full passes still require full reconciliation after interruption.
                    if !scan_committed {
                        restore_dirty_paths(&dirty_paths, changes);
                    }
                    dirty = true;
                }
                match result {
                    Ok(()) => {
                        retry_delay = Duration::from_millis(250);
                        last_logged_error.clear();
                        if full
                            && let Some(cache) = replica_cache.as_ref()
                            && let Ok(settings) = request_replica_settings(&mut tls).await
                        {
                            web::set_replica(cache, Some(settings));
                        }
                        println!("{} rsync complete", now());
                        if once {
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        let settings_interrupted = e.to_string().contains(SETTINGS_CHANGED);
                        let upgrade_interrupted = upgrade_cache.as_ref().is_some_and(|upgrade| {
                            web::upgrade_status(upgrade).phase == web::UpgradePhase::Queued
                        }) && settings_interrupted;
                        if upgrade_interrupted {
                            eprintln!("rsync pass interrupted for requested replica upgrade");
                        } else if settings_interrupted {
                            eprintln!("rsync pass interrupted for settings change");
                        } else {
                            let message = format!("{e:#}");
                            if message != last_logged_error
                                || last_log_time.elapsed() >= Duration::from_secs(60)
                            {
                                record_error(&db, &e);
                                last_logged_error = message;
                                last_log_time = Instant::now();
                            }
                        }
                        if once {
                            return Err(e);
                        }
                        break;
                    }
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(IDLE_HEARTBEAT) => {
                    if wire::send(&mut tls, &Frame::Ping).await.is_err()
                        || expect_ack(&mut tls).await.is_err() {
                        break;
                    }
                    retry_delay = Duration::from_millis(250);
                }
                _ = tokio::time::sleep_until(trigger.next_scan), if sync_compatible && approved && (!paused || trigger.manual) => {}
                event = rx.recv(), if !once => {
                    if event.is_some() {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        while rx.try_recv().is_ok() {}
                        dirty = true;
                    }
                }
                control = async { controls.as_mut().unwrap().recv().await }, if controls.is_some() => {
                    if let Some(control) = control {
                        let context = WebControlContext {
                            replica_cache: replica_cache.as_ref().unwrap(),
                            upgrade_cache: upgrade_cache.as_ref().unwrap(),
                            root: &config.root,
                            connected_target: current.addr,
                        };
                        match handle_web_control(
                            control,
                            &mut tls,
                            &context,
                            &mut trigger,
                            &mut dirty,
                        ).await {
                            Ok(true) => break 'connected,
                            Ok(false) => {}
                            Err(error) => {
                                record_error(&db, &error);
                                break 'connected;
                            }
                        }
                    }
                }
            }
        }
        if let Some(cache) = replica_cache.as_ref() {
            web::set_replica(cache, None);
        }
        state::set(&db, "connection", "disconnected")?;
        tokio::time::sleep(retry_delay).await;
        retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
    }
}

async fn connect_replica(config: &Config) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let target = config.addr.context("source target is not configured")?;
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(target))
        .await
        .context("replica connection timed out")??;
    tcp.set_nodelay(true)?;
    set_keepalive(&tcp)?;
    let connector = TlsConnector::from(identity::client_config(config)?);
    let name = rustls::pki_types::ServerName::try_from("sync-node")?;
    let mut tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(name, tcp))
        .await
        .context("TLS connection timed out")??;
    tokio::time::timeout(Duration::from_secs(30), async {
        wire::send(&mut tls, &Frame::Ping).await?;
        expect_ack(&mut tls).await
    })
    .await
    .context("replica did not respond after TLS handshake")??;
    Ok(tls)
}

async fn accept_replica(
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
    let mut handshakes = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept(), if handshakes.len() < MAX_PENDING_HANDSHAKES => {
                let (tcp, peer) = accepted?;
                tcp.set_nodelay(true)?;
                set_keepalive(&tcp)?;
                let acceptor = acceptor.clone();
                handshakes.spawn(async move {
                    (peer, tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await)
                });
            }
            completed = handshakes.join_next(), if !handshakes.is_empty() => {
                match completed {
                    Some(Ok((_, Ok(Ok(tls))))) => {
                        handshakes.abort_all();
                        return Ok(tls);
                    }
                    Some(Ok((peer, Ok(Err(e))))) => eprintln!("TLS rejected {peer}: {e}"),
                    Some(Ok((peer, Err(_)))) => eprintln!("TLS handshake timed out for {peer}"),
                    Some(Err(e)) => eprintln!("TLS handshake task failed: {e}"),
                    None => {}
                }
            }
        }
    }
}

async fn source_once<S: AsyncRead + AsyncWrite + Unpin>(
    config: &Config,
    db: &mut Connection,
    stream: &mut S,
    pass: SourcePass<'_>,
    ctx: &TransferContext<'_>,
    manifest_ready: &mut bool,
    scan_committed: &mut bool,
) -> Result<SyncOutcome> {
    let SourcePass {
        full_requested,
        known_changed,
        changed_paths,
        restart_check,
        replica_generation,
    } = pass;
    state::set(db, "connection", "syncing")?;
    let previous_clean = state::get(db, "source_sync_clean")?.as_deref() == Some("true");
    let previous_identity = state::get(db, "source_sync_identity")?;
    let previous_generation =
        state::get(db, "generation")?.and_then(|value| value.parse::<u64>().ok());
    let pending_delta = state::get(db, "source_pending_mode")?.as_deref() == Some("delta");
    let synced_generation = state::get(db, "source_synced_generation")?
        .map(|value| value.parse::<u64>())
        .transpose()?;
    let current_identity = source_sync_identity(config, db)?;
    let same_base = previous_identity.as_deref() == Some(current_identity.as_str())
        && replica_generation.is_none_or(|remote| {
            synced_generation.is_some_and(|synced| remote >= synced)
                && previous_generation.is_some_and(|local| remote <= local)
        });
    // Clear the persisted success marker before touching the manifest. A crash during
    // scanning or transfer must not let the next process skip reconciliation.
    state::set(db, "source_sync_clean", "false")?;
    let full_verify = full_verify_due(db, "source_last_full_verify", config.verify_interval_secs)?;
    // A restarted process must inspect the local tree for changes made while it
    // was stopped. It can still send a delta when the durable base is intact.
    let resume_delta = full_requested
        && restart_check
        && pending_delta
        && same_base
        && !full_verify
        && !full_verify_due(db, "source_last_full_scan", config.scan_interval_secs)?;
    let mut full = (full_requested && !resume_delta)
        || full_verify
        || !same_base
        || state::get(db, "skipped_symlinks")?.is_none();
    if full {
        *manifest_ready = false;
    }
    state::set(
        db,
        "source_pending_mode",
        if full { "full" } else { "delta" },
    )?;
    let scan_started = Instant::now();
    let scan_stats = if full || resume_delta {
        let stats = scan::prepare_manifest(config, db, full_verify, known_changed, resume_delta)?;
        if !stats.reused_manifest
            && let Err(error) = state::checkpoint(db)
        {
            eprintln!("manifest checkpoint deferred: {error:#}");
        }
        if full_verify {
            state::set(db, "source_last_full_verify", unix_seconds()?.to_string())?;
        }
        stats
    } else {
        let paths: Vec<_> = changed_paths.iter().cloned().collect();
        scan::prepare_delta(config, db, &paths)?
    };
    *scan_committed = true;
    // The committed outbox now owns recovery. Release the watcher snapshot
    // before a long transfer rather than retaining tens of thousands of paths.
    *changed_paths = HashSet::new();
    state::set(
        db,
        "last_scan_ms",
        scan_started.elapsed().as_millis().to_string(),
    )?;
    state::set(db, "last_scan_hashed", scan_stats.hashed_files.to_string())?;
    state::set(db, "last_scan_cached", scan_stats.cache_hits.to_string())?;
    state::set(db, "last_scan_workers", scan_stats.workers.to_string())?;
    state::set(
        db,
        "last_scan_reused",
        if scan_stats.reused_manifest {
            "true"
        } else {
            "false"
        },
    )?;
    ctx.check()?;
    let identity = source_sync_identity(config, db)?;
    // A changed symlink inventory changes the protection policy. Reconcile it
    // using a full session rather than replaying tasks under an old policy.
    if resume_delta && identity != current_identity {
        full = true;
        state::set(db, "source_pending_mode", "full")?;
    }
    *manifest_ready = !full;
    // Restart may skip sending the full manifest only when the local inventory, sync
    // settings and replica generation all still match the last completed pass.
    if full
        && restart_check
        && previous_clean
        && previous_identity.as_deref() == Some(identity.as_str())
        && previous_generation.is_some()
        && previous_generation == replica_generation
        && !full_verify
        && !full_verify_due(db, "source_last_full_scan", config.scan_interval_secs)?
        && !scan_stats.manifest_changed
    {
        state::set(db, "pending_files", "0")?;
        state::set(db, "last_success", now())?;
        state::set(db, "last_error", "")?;
        state::set(db, "last_files", "0")?;
        state::set(db, "last_bytes", "0")?;
        state::set(db, "last_transfer_ms", "0")?;
        state::set(db, "connection", "idle")?;
        mark_source_clean(db, &identity)?;
        return Ok(SyncOutcome::RestartUnchanged);
    }
    let total_files = if resume_delta && !full {
        scan::delta_file_count(db)?
    } else {
        scan_stats.files
    };
    state::set(db, "pending_files", total_files.to_string())?;
    if !full
        && !pending_delta
        && scan::delta_entry_count(db)? == 0
        && scan::delta_delete_count(db)? == 0
        && scan::delta_delete_dir_count(db)? == 0
    {
        state::set(db, "last_success", now())?;
        state::set(db, "last_error", "")?;
        state::set(db, "last_files", "0")?;
        state::set(db, "last_bytes", "0")?;
        state::set(db, "last_transfer_ms", "0")?;
        state::set(db, "connection", "idle")?;
        mark_source_clean(db, &identity)?;
        return Ok(SyncOutcome::Delta);
    }
    let mut excludes = config.excludes.clone();
    if full {
        let skipped: Vec<String> = serde_json::from_str(
            &state::get(db, "skipped_symlinks")?.context("missing skipped symlink inventory")?,
        )?;
        excludes.extend(skipped);
    }
    config::validate_excludes(&excludes)?;
    let generation = state::get(db, "generation")?
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
        .checked_add(1)
        .context("generation overflow")?;
    state::set(db, "generation", generation.to_string())?;
    let transfer_started = Instant::now();
    wire::send(
        stream,
        &Frame::Begin {
            protocol: wire::SYNC_PROTOCOL,
            generation,
            files: total_files,
            excludes,
            delta: !full,
        },
    )
    .await?;
    expect_ack(stream).await?;
    if !full {
        let mut after_delete = String::new();
        loop {
            let paths = scan::delta_delete_page(db, &after_delete, ENTRY_BATCH_LIMIT)?;
            if paths.is_empty() {
                break;
            }
            after_delete = paths.last().expect("nonempty deletion page").clone();
            ctx.check()?;
            wire::send(stream, &FrameRef::Delete { paths: &paths }).await?;
            expect_ack(stream).await?;
            state::acknowledge_tasks(db, 1, &paths)?;
        }
        let mut after_dir = String::new();
        loop {
            let paths = scan::delta_delete_dir_page(db, &after_dir, ENTRY_BATCH_LIMIT)?;
            if paths.is_empty() {
                break;
            }
            after_dir = paths
                .last()
                .expect("nonempty directory deletion page")
                .clone();
            ctx.check()?;
            wire::send(stream, &FrameRef::DeleteDirs { paths: &paths }).await?;
            expect_ack(stream).await?;
            state::acknowledge_tasks(db, 2, &paths)?;
        }
    }
    let mut progress = Progress {
        files: 0,
        bytes: 0,
        verify_hashed_files: 0,
        verify_hashed_bytes: 0,
        verify_reused_files: 0,
        reported_files: 0,
        last_reported_at: Instant::now(),
    };
    let mut after = String::new();
    loop {
        let page = scan::manifest_page(db, &after, ENTRY_BATCH_LIMIT, !full)?;
        if page.is_empty() {
            break;
        }
        after = page.last().expect("nonempty manifest page").0.clone();
        let entries: Vec<Entry> = page.into_iter().map(|(_, entry)| entry).collect();
        let (files, bytes, verify) = send_entries_batch(config, stream, &entries, ctx).await?;
        if !full {
            let paths: Vec<_> = entries
                .iter()
                .map(|entry| match entry {
                    Entry::Dir { path } => path.clone(),
                    Entry::File { meta } => meta.path.clone(),
                })
                .collect();
            state::acknowledge_tasks(db, 0, &paths)?;
        }
        progress.files += files;
        progress.bytes += bytes;
        progress.verify_hashed_files += verify.hashed_files;
        progress.verify_hashed_bytes += verify.hashed_bytes;
        progress.verify_reused_files += verify.reused_files;
        let before_report = progress.reported_files;
        update_pending_files(
            db,
            total_files,
            progress.files,
            &mut progress.reported_files,
            &mut progress.last_reported_at,
        )?;
        if progress.reported_files != before_report {
            write_verify_progress(db, &progress)?;
        }
    }
    ctx.check()?;
    wire::send(stream, &Frame::End).await?;
    expect_ack(stream).await?;
    ctx.check()?;
    state::set(db, "last_success", now())?;
    state::set(db, "last_error", "")?;
    state::set(db, "last_files", progress.files.to_string())?;
    state::set(db, "last_bytes", progress.bytes.to_string())?;
    state::set(
        db,
        "last_transfer_ms",
        transfer_started.elapsed().as_millis().to_string(),
    )?;
    write_verify_progress(db, &progress)?;
    state::set(db, "connection", "idle")?;
    if full {
        state::set(db, "source_last_full_scan", unix_seconds()?.to_string())?;
    }
    mark_source_clean(db, &identity)?;
    Ok(if full {
        SyncOutcome::Full
    } else {
        SyncOutcome::Delta
    })
}

async fn expect_ack<S: AsyncRead + Unpin>(stream: &mut S) -> Result<()> {
    match wire::recv(stream).await? {
        Frame::Ack => Ok(()),
        Frame::Error { message } => bail!("replica rejected operation: {}", remote_text(&message)),
        other => bail!("unexpected response: {}", other.kind()),
    }
}

fn write_verify_progress(db: &Connection, progress: &Progress) -> Result<()> {
    state::set(
        db,
        "verify_hashed_files",
        progress.verify_hashed_files.to_string(),
    )?;
    state::set(
        db,
        "verify_hashed_bytes",
        progress.verify_hashed_bytes.to_string(),
    )?;
    state::set(
        db,
        "verify_reused_files",
        progress.verify_reused_files.to_string(),
    )?;
    Ok(())
}

async fn send_entries_batch<S: AsyncRead + AsyncWrite + Unpin>(
    config: &Config,
    stream: &mut S,
    entries: &[Entry],
    ctx: &TransferContext<'_>,
) -> Result<(u64, u64, VerifyStats)> {
    ctx.check()?;
    ensure!(
        !entries.is_empty() && entries.len() <= ENTRY_BATCH_LIMIT,
        "invalid entry batch"
    );
    wire::send(stream, &FrameRef::Entries { entries }).await?;
    let (indices, verify) = match wire::recv(stream).await? {
        Frame::EntriesNeed {
            indices,
            hashed_files,
            hashed_bytes,
            reused_files,
        } => (
            indices,
            VerifyStats {
                hashed_files,
                hashed_bytes,
                reused_files,
            },
        ),
        Frame::Error { message } => {
            bail!("replica rejected entries: {}", remote_text(&message))
        }
        other => bail!("unexpected entries response: {}", other.kind()),
    };
    let mut small_payloads = Vec::new();
    let mut small_bytes = 0usize;
    let mut previous = None;
    let prepare = (|| -> Result<()> {
        for &index in &indices {
            ctx.check()?;
            ensure!(
                index < entries.len() && previous.is_none_or(|p| index > p),
                "invalid entry request"
            );
            previous = Some(index);
            let Entry::File { meta } = &entries[index] else {
                bail!("replica requested a directory");
            };
            if meta.size > SMALL_FILE_LIMIT {
                continue;
            }
            // The file may grow after scanning. Read at most one byte beyond
            // the expected size so a stale small-file entry cannot exhaust RAM.
            let mut content = Vec::with_capacity(meta.size as usize + 1);
            File::open(config.root.join(&meta.path))?
                .take(meta.size + 1)
                .read_to_end(&mut content)?;
            ensure!(
                content.len() as u64 == meta.size,
                "source file changed: {}",
                meta.path
            );
            ensure!(
                hex::encode(blake3::hash(&content).as_bytes()) == meta.hash,
                "source file changed: {}",
                meta.path
            );
            small_bytes = small_bytes
                .checked_add(content.len())
                .context("small entry batch overflow")?;
            ensure!(
                small_bytes <= SMALL_BATCH_BYTES_LIMIT,
                "small entry batch too large"
            );
            small_payloads.push((index, content));
        }
        Ok(())
    })();
    if let Err(error) = prepare {
        let _ = wire::send(
            stream,
            &Frame::FileAbort {
                reason: format!("{error:#}"),
            },
        )
        .await;
        return Err(error);
    }
    ctx.check()?;
    let file_count = entries
        .iter()
        .filter(|entry| matches!(entry, Entry::File { .. }))
        .count() as u64;
    let mut sent = 0u64;
    if !indices.is_empty() {
        wire::send(stream, &Frame::EntriesReady).await?;
        let mut next_small = small_payloads.into_iter().peekable();
        for index in indices {
            let Entry::File { meta } = &entries[index] else {
                unreachable!()
            };
            if meta.size <= SMALL_FILE_LIMIT {
                let (got, content) = next_small.next().context("missing prepared small file")?;
                ensure!(got == index, "small entry order changed");
                tokio::time::timeout(wire::IO_TIMEOUT, stream.write_all(&content))
                    .await
                    .context("small-file send timed out")??;
                sent += content.len() as u64;
                ctx.meter.record(content.len() as u64);
            } else {
                sent += send_file(config, stream, meta, ctx).await?;
            }
        }
    }
    wire::send(stream, &Frame::EntriesDone).await?;
    expect_ack(stream).await?;
    Ok((file_count, sent, verify))
}

async fn send_file<S: AsyncRead + AsyncWrite + Unpin>(
    config: &Config,
    stream: &mut S,
    meta: &FileMeta,
    ctx: &TransferContext<'_>,
) -> Result<u64> {
    ctx.check()?;
    wire::send(stream, &FrameRef::File { meta }).await?;
    let indices = match wire::recv(stream).await? {
        Frame::Need { indices } => indices,
        Frame::Error { message } => {
            bail!("replica rejected {}: {}", meta.path, remote_text(&message))
        }
        other => bail!("unexpected response: {}", other.kind()),
    };
    if indices.is_empty() {
        wire::send(stream, &Frame::FileDone).await?;
        expect_ack(stream).await?;
        return Ok(0);
    }
    let mut source = File::open(config.root.join(&meta.path))?;
    let mut buf = Vec::new();
    let mut sent = 0u64;
    let mut previous = None;
    for index in indices {
        ctx.check()?;
        ensure!(
            index < meta.blocks.len() && previous.is_none_or(|p| index > p),
            "invalid block request"
        );
        previous = Some(index);
        let size = block_len(meta.size, index)?;
        buf.resize(size, 0);
        source.seek(SeekFrom::Start(index as u64 * CHUNK_SIZE as u64))?;
        source.read_exact(&mut buf[..size])?;
        if hex::encode(blake3::hash(&buf[..size]).as_bytes()) != meta.blocks[index] {
            wire::send(
                stream,
                &Frame::FileAbort {
                    reason: "source file changed during transfer".into(),
                },
            )
            .await?;
            bail!("source file changed during transfer: {}", meta.path);
        }
        wire::send(stream, &Frame::Chunk { index, size }).await?;
        tokio::time::timeout(wire::IO_TIMEOUT, async {
            stream.write_all(&buf[..size]).await?;
            stream.flush().await
        })
        .await
        .context("chunk send timed out")??;
        ctx.meter.record(size as u64);
        sent += size as u64;
    }
    wire::send(stream, &Frame::FileDone).await?;
    expect_ack(stream).await?;
    Ok(sent)
}

fn block_len(size: u64, index: usize) -> Result<usize> {
    let start = (index as u64)
        .checked_mul(CHUNK_SIZE as u64)
        .context("block index overflow")?;
    ensure!(start < size, "block index out of range");
    Ok((size - start).min(CHUNK_SIZE as u64) as usize)
}

// Replica listener, session handling and filesystem ownership.

struct RequestedFile {
    index: usize,
    checked_stamp: Option<Vec<u8>>,
}

const MAX_MANIFEST_ENTRIES: usize = 2_000_000;

struct ReceiveBatchContext<'a> {
    remaining_files: usize,
    remaining_entries: usize,
    excludes: &'a ExclusionIndex,
    verify_round: Option<i64>,
    verified: &'a mut Vec<state::VerifiedUpdate>,
    last_path: &'a mut String,
    full_session: bool,
    small_sync_pool: &'a mut Option<rayon::ThreadPool>,
}

pub async fn run_replica(config: Config, db: Connection) -> Result<()> {
    config.check_root()?;
    let address = config
        .addr
        .context("replica listen address is not configured")?;
    let listener = TcpListener::bind(address).await?;
    let acceptor = TlsAcceptor::from(identity::server_config(&config)?);
    state::set(&db, "connection", "listening")?;
    println!("replica listening for source on {address}");
    loop {
        let mut stream = accept_replica(&listener, &acceptor).await?;
        state::set(&db, "connection", "connected")?;
        let mut completed_session = false;
        let mut started_session = false;
        let result: Result<()> = async {
            let mut first_frame = true;
            loop {
                let frame = if first_frame {
                    tokio::time::timeout(Duration::from_secs(30), wire::recv_idle(&mut stream))
                        .await
                        .context("source did not send first frame within 30 seconds")??
                } else {
                    wire::recv_idle(&mut stream).await?
                };
                first_frame = false;
                match frame {
                    Frame::Ping => wire::send(&mut stream, &Frame::Ack).await?,
                    Frame::ReplicaSettingsGet => {
                        let current = Config::load(config.root.clone())?;
                        wire::send(
                            &mut stream,
                            &Frame::ReplicaSettings {
                                settings: replica_settings(&current, &db)?,
                            },
                        )
                        .await?;
                    }
                    Frame::ReplicaSettingsSet {
                        retention_days,
                        verify_interval_secs,
                    } => {
                        let update = (|| -> Result<ReplicaSettings> {
                            config::validate_replica_settings(
                                retention_days,
                                verify_interval_secs,
                            )?;
                            let mut current = Config::load(config.root.clone())?;
                            current.retention_days = retention_days;
                            current.verify_interval_secs = verify_interval_secs;
                            current.save()?;
                            replica_settings(&current, &db)
                        })();
                        match update {
                            Ok(settings) => {
                                wire::send(&mut stream, &Frame::ReplicaSettings { settings })
                                    .await?
                            }
                            Err(error) => {
                                wire::send(
                                    &mut stream,
                                    &Frame::Error {
                                        message: format!("{error:#}"),
                                    },
                                )
                                .await?
                            }
                        }
                    }
                    Frame::UpgradeBegin {
                        version,
                        size,
                        digest,
                    } => {
                        let result = upgrade::receive(&mut stream, version, size, digest).await;
                        match result {
                            Ok(true) => {
                                println!("replica upgrade installed; exiting for systemd restart");
                                std::process::exit(0);
                            }
                            Ok(false) => {}
                            Err(error) => {
                                let _ = send_error(&mut stream, &error).await;
                                return Err(error);
                            }
                        }
                    }
                    begin @ Frame::Begin { .. } => {
                        let current = Config::load(config.root.clone())?;
                        started_session = true;
                        receive_session(&current, &db, &mut stream, begin).await?;
                        started_session = false;
                        completed_session = true;
                        state::set(&db, "connection", "connected")?;
                    }
                    other => bail!("expected begin or ping, got {}", other.kind()),
                }
            }
        }
        .await;
        if let Err(e) = result {
            let expected_close = e.downcast_ref::<std::io::Error>().is_some_and(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                )
            });
            if started_session || !completed_session || !expected_close {
                record_error(&db, &e);
            }
        }
        state::set(&db, "connection", "listening")?;
    }
}

fn replica_settings(config: &Config, db: &Connection) -> Result<ReplicaSettings> {
    Ok(ReplicaSettings {
        root: config.root.display().to_string(),
        addr: config.addr.expect("validated replica address"),
        retention_days: config.retention_days,
        verify_interval_secs: config.verify_interval_secs,
        version: env!("CARGO_PKG_VERSION").into(),
        upgrade_supported: upgrade::replica_supported(),
        sync_protocol: wire::SYNC_PROTOCOL,
        delta_supported: true,
        deletions_supported: true,
        directory_deletions_supported: true,
        last_deleted_files: state::get(db, "last_deleted_files")?
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        last_deleted_dirs: state::get(db, "last_deleted_dirs")?
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        last_generation: state::get(db, "generation")?
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
    })
}

async fn receive_session<S: AsyncRead + AsyncWrite + Unpin>(
    config: &Config,
    db: &Connection,
    stream: &mut S,
    begin: Frame,
) -> Result<()> {
    config.check_root()?;
    let (generation, expected_files, excludes, delta) = match begin {
        Frame::Begin {
            protocol: wire::SYNC_PROTOCOL,
            generation,
            files,
            excludes,
            delta,
        } => (generation, files, excludes, delta),
        Frame::Begin { protocol, .. } => {
            wire::send(
                stream,
                &Frame::Error {
                    message: format!("unsupported protocol version {protocol}; update both nodes"),
                },
            )
            .await?;
            bail!("unsupported protocol version {protocol}");
        }
        other => bail!("expected begin, got {}", other.kind()),
    };
    config::validate_excludes(&excludes)?;
    let exclusion_index = ExclusionIndex::new(&excludes);
    ensure!(expected_files <= 1_000_000, "too many files");
    let last = state::get(db, "generation")?
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    if generation < last {
        wire::send(
            stream,
            &Frame::Error {
                message: "stale generation".into(),
            },
        )
        .await?;
        bail!("stale source generation {generation} < {last}");
    }
    // Complete any rename whose ownership transaction was interrupted before
    // accepting a new manifest or reconciling source deletions.
    recover_publications(config, db)?;
    let verify_round = if delta {
        None
    } else {
        state::begin_verify_round(
            db,
            full_verify_due(db, "replica_last_full_verify", config.verify_interval_secs)?,
        )?
    };
    if !delta {
        db.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS source_seen(path TEXT PRIMARY KEY);
             DELETE FROM temp.source_seen;",
        )?;
    }
    wire::send(stream, &Frame::Ack).await?;
    state::set(db, "pending_files", expected_files.to_string())?;
    let mut files = 0u64;
    let mut reported_files = 0u64;
    let mut last_reported_at = Instant::now();
    let mut bytes = 0u64;
    let mut entries = 0usize;
    let mut last_path = String::new();
    let mut last_delete_path = String::new();
    let mut last_delete_dir_path = String::new();
    let mut deleted_files = 0u64;
    let mut deleted_dirs = 0u64;
    let mut deletion_entries = 0usize;
    let mut verified = Vec::with_capacity(VERIFIED_INITIAL_CAPACITY);
    let mut small_sync_pool = None;
    loop {
        match wire::recv(stream).await? {
            Frame::Entries { entries: batch } => {
                let result = receive_entries_batch(
                    config,
                    db,
                    stream,
                    &batch,
                    ReceiveBatchContext {
                        remaining_files: expected_files.saturating_sub(files as usize),
                        remaining_entries: MAX_MANIFEST_ENTRIES.saturating_sub(entries),
                        excludes: &exclusion_index,
                        verify_round,
                        verified: &mut verified,
                        last_path: &mut last_path,
                        full_session: !delta,
                        small_sync_pool: &mut small_sync_pool,
                    },
                )
                .await;
                match result {
                    Ok((batch_files, batch_bytes)) => {
                        files += batch_files;
                        bytes += batch_bytes;
                        entries += batch.len();
                        update_pending_files(
                            db,
                            expected_files,
                            files,
                            &mut reported_files,
                            &mut last_reported_at,
                        )?;
                        wire::send(stream, &Frame::Ack).await?;
                    }
                    Err(e) => {
                        send_error(stream, &e).await?;
                        return Err(e);
                    }
                }
            }
            Frame::Delete { paths } if delta && entries == 0 => {
                let result = receive_delete_batch(
                    config,
                    db,
                    &exclusion_index,
                    &paths,
                    &mut last_delete_path,
                    MAX_MANIFEST_ENTRIES.saturating_sub(deletion_entries),
                );
                match result {
                    Ok(count) => {
                        deleted_files += count;
                        deletion_entries += paths.len();
                        wire::send(stream, &Frame::Ack).await?;
                    }
                    Err(error) => {
                        send_error(stream, &error).await?;
                        return Err(error);
                    }
                }
            }
            Frame::DeleteDirs { paths } if delta && entries == 0 => {
                let result = receive_delete_dirs_batch(
                    config,
                    db,
                    &exclusion_index,
                    &paths,
                    &mut last_delete_dir_path,
                    MAX_MANIFEST_ENTRIES.saturating_sub(deletion_entries),
                );
                match result {
                    Ok(count) => {
                        deleted_dirs += count;
                        deletion_entries += paths.len();
                        wire::send(stream, &Frame::Ack).await?;
                    }
                    Err(error) => {
                        send_error(stream, &error).await?;
                        return Err(error);
                    }
                }
            }
            Frame::End => {
                if files as usize != expected_files {
                    let e = anyhow::anyhow!(
                        "incomplete manifest: received {files} of {expected_files} files"
                    );
                    send_error(stream, &e).await?;
                    return Err(e);
                }
                state::flush_verified(db, &mut verified)?;
                // A successful delta also completes all outstanding source tasks.
                // Drop abandoned stages (for example a new file deleted mid-transfer)
                // instead of keeping them until the next daily full reconciliation.
                if let Err(e) = cleanup_staging(config, db) {
                    send_error(stream, &e).await?;
                    return Err(e);
                }
                if !delta {
                    match reconcile_deleted_files(config, db, &exclusion_index) {
                        Ok(count) => deleted_files += count,
                        Err(error) => {
                            send_error(stream, &error).await?;
                            return Err(error);
                        }
                    }
                    match reconcile_deleted_dirs(config, db, &exclusion_index) {
                        Ok(count) => deleted_dirs += count,
                        Err(error) => {
                            send_error(stream, &error).await?;
                            return Err(error);
                        }
                    }
                }
                state::set(db, "generation", generation.to_string())?;
                state::set(db, "last_success", now())?;
                state::set(db, "last_error", "")?;
                state::set(db, "last_files", files.to_string())?;
                state::set(db, "last_bytes", bytes.to_string())?;
                state::set(db, "last_deleted_files", deleted_files.to_string())?;
                state::set(db, "last_deleted_dirs", deleted_dirs.to_string())?;
                if verify_round.is_some() {
                    state::finish_verify_round(db, unix_seconds()?)?;
                }
                state::set(db, "pending_files", "0")?;
                if !delta {
                    if let Err(e) = cleanup_history(config) {
                        eprintln!("history cleanup failed: {e:#}");
                    }
                    if let Err(e) = state::checkpoint(db) {
                        eprintln!("state checkpoint failed: {e:#}");
                    }
                }
                wire::send(stream, &Frame::Ack).await?;
                return Ok(());
            }
            other => bail!("unexpected command: {}", other.kind()),
        }
    }
}

async fn send_error<S: AsyncWrite + Unpin>(stream: &mut S, error: &anyhow::Error) -> Result<()> {
    wire::send(
        stream,
        &Frame::Error {
            message: format!("{error:#}"),
        },
    )
    .await
}

async fn receive_entries_batch<S: AsyncRead + AsyncWrite + Unpin>(
    config: &Config,
    db: &Connection,
    stream: &mut S,
    entries: &[Entry],
    context: ReceiveBatchContext<'_>,
) -> Result<(u64, u64)> {
    ensure!(
        !entries.is_empty()
            && entries.len() <= ENTRY_BATCH_LIMIT
            && entries.len() <= context.remaining_entries,
        "invalid entry batch size"
    );
    let mut previous = context.last_path.as_str();
    let mut batch_files = 0usize;
    for entry in entries {
        let path = match entry {
            Entry::Dir { path } => path,
            Entry::File { meta } => {
                validate_meta(meta)?;
                batch_files += 1;
                &meta.path
            }
        };
        config::valid_relative(path)?;
        ensure!(
            path.as_str() > previous,
            "duplicate or out-of-order manifest path: {path}"
        );
        previous = path;
        ensure!(
            !context.excludes.contains(path),
            "excluded entry sent: {path}"
        );
        if matches!(entry, Entry::File { .. }) {
            ensure!(
                !context.excludes.protects_parent(path),
                "file conflicts with excluded descendant: {path}"
            );
        }
    }
    ensure!(
        batch_files <= context.remaining_files,
        "too many files received"
    );
    let final_path = previous.to_owned();

    let mut needed = Vec::new();
    let mut verify = VerifyStats::default();
    for (index, entry) in entries.iter().enumerate() {
        match entry {
            Entry::Dir { path } => {
                if !is_symlink_protected(config, path)? {
                    // Delta sessions already carry type-change deletions. A full
                    // manifest must also handle replacements made while offline.
                    if context.full_session
                        && fs::symlink_metadata(config.root.join(path))
                            .is_ok_and(|meta| meta.is_file())
                    {
                        let transaction = db.unchecked_transaction()?;
                        let mut parents = HashSet::new();
                        delete_managed_file(
                            config,
                            &transaction,
                            path,
                            context.excludes,
                            &mut parents,
                        )?;
                        for parent in parents {
                            File::open(parent)?.sync_all()?;
                        }
                        transaction.commit()?;
                    }
                    ensure_directory(config, path)?;
                }
            }
            Entry::File { meta } => {
                if is_symlink_protected(config, &meta.path)? {
                    continue;
                }
                let target = config.root.join(&meta.path);
                match fs::symlink_metadata(&target) {
                    Ok(existing) => {
                        ensure!(
                            !existing.file_type().is_symlink(),
                            "symlink at {}",
                            target.display()
                        );
                        if existing.is_dir() && contains_symlink_descendant(&target)? {
                            continue;
                        }
                        if existing.is_dir() && context.full_session {
                            remove_managed_directory_for_file(
                                config,
                                db,
                                &meta.path,
                                context.excludes,
                            )?;
                            needed.push(RequestedFile {
                                index,
                                checked_stamp: None,
                            });
                            continue;
                        }
                        ensure!(
                            existing.is_file(),
                            "replica path conflicts with source file; existing entry preserved: {}",
                            target.display()
                        );
                        if existing.len() != meta.size {
                            needed.push(RequestedFile {
                                index,
                                checked_stamp: None,
                            });
                        } else {
                            let check = existing_file_matches(
                                db,
                                &target,
                                meta,
                                context.verify_round,
                                context.verified,
                                &mut verify,
                            )?;
                            if let FileCheck::Different { stamp } = check {
                                needed.push(RequestedFile {
                                    index,
                                    checked_stamp: Some(stamp),
                                });
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        needed.push(RequestedFile {
                            index,
                            checked_stamp: None,
                        });
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    wire::send(
        stream,
        &Frame::EntriesNeed {
            indices: needed.iter().map(|file| file.index).collect(),
            hashed_files: verify.hashed_files,
            hashed_bytes: verify.hashed_bytes,
            reused_files: verify.reused_files,
        },
    )
    .await?;
    let mut received = 0u64;
    if !needed.is_empty() {
        match wire::recv(stream).await? {
            Frame::EntriesReady => {}
            Frame::FileAbort { reason } => {
                bail!("source aborted entry batch: {}", remote_text(&reason))
            }
            other => bail!("expected entries_ready, got {}", other.kind()),
        }
    }
    let mut small_buf = Vec::new();
    let mut small_files = SmallFileBatch::new(context.small_sync_pool);
    let transfer_result: Result<()> = async {
        for RequestedFile {
            index,
            checked_stamp,
        } in needed
        {
            let Entry::File { meta } = &entries[index] else {
                unreachable!()
            };
            if meta.size <= SMALL_FILE_LIMIT {
                let size = meta.size as usize;
                small_buf.resize(size, 0);
                tokio::time::timeout(wire::IO_TIMEOUT, stream.read_exact(&mut small_buf[..size]))
                    .await
                    .context("small-file read timed out")??;
                if small_files.stage(index, config, meta, &small_buf[..size])? {
                    small_files.flush(
                        config,
                        db,
                        entries,
                        context.verify_round,
                        context.verified,
                    )?;
                }
                received += meta.size;
            } else {
                small_files.flush(config, db, entries, context.verify_round, context.verified)?;
                match wire::recv(stream).await? {
                    Frame::File { meta: sent } if sent == *meta => {}
                    Frame::FileAbort { reason } => {
                        bail!("source aborted {}: {}", meta.path, remote_text(&reason))
                    }
                    other => bail!("expected matching file, got {}", other.kind()),
                }
                received += receive_file(
                    config,
                    db,
                    stream,
                    meta,
                    ReceiveFileContext {
                        verify_round: context.verify_round,
                        verified: context.verified,
                        verify: &mut verify,
                        checked_stamp: checked_stamp.as_deref(),
                    },
                )
                .await?;
            }
        }
        small_files.flush(config, db, entries, context.verify_round, context.verified)?;
        Ok(())
    }
    .await;
    // Preserve successful publications even when a later file or frame fails.
    // Unpublished small stages are removed by their Drop implementation.
    small_files.sync_published()?;
    state::flush_verified(db, context.verified)?;
    transfer_result?;
    match wire::recv(stream).await? {
        Frame::EntriesDone => {}
        Frame::FileAbort { reason } => {
            bail!("source aborted entry batch: {}", remote_text(&reason))
        }
        other => bail!("expected entries_done, got {}", other.kind()),
    }
    let transaction = db.unchecked_transaction()?;
    {
        let mut seen = if context.full_session {
            Some(
                transaction
                    .prepare_cached("INSERT OR IGNORE INTO temp.source_seen(path) VALUES(?1)")?,
            )
        } else {
            None
        };
        let mut managed = transaction
            .prepare_cached("INSERT OR IGNORE INTO managed_dirs(path,depth) VALUES(?1,?2)")?;
        for entry in entries {
            let path = match entry {
                Entry::Dir { path } => path,
                Entry::File { meta } => &meta.path,
            };
            if let Some(seen) = seen.as_mut() {
                seen.execute([path])?;
            }
            if matches!(entry, Entry::Dir { .. })
                && !is_symlink_protected(config, path)?
                && fs::symlink_metadata(config.root.join(path))?.is_dir()
            {
                managed.execute(rusqlite::params![
                    path,
                    path.bytes().filter(|b| *b == b'/').count() as i64 + 1
                ])?;
            }
        }
    }
    transaction.commit()?;
    *context.last_path = final_path;
    Ok((batch_files as u64, received))
}

fn is_symlink_protected(config: &Config, relative: &str) -> Result<bool> {
    let mut path = config.root.clone();
    for component in config::valid_relative(relative)?.components() {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

// replica_files contains only files previously received or verified from the source.
// It is also the ownership boundary for deletion: replica-only files have no row.
fn delete_managed_file(
    config: &Config,
    db: &Connection,
    relative: &str,
    excludes: &ExclusionIndex,
    changed_parents: &mut HashSet<PathBuf>,
) -> Result<bool> {
    config::valid_relative(relative)?;
    let managed: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM replica_files WHERE path=?1)",
        [relative],
        |row| row.get(0),
    )?;
    if !managed {
        return Ok(false);
    }
    // Keep the ownership record while the path is protected. If the rule or
    // symlink is removed later, a full reconciliation can still clean it.
    if excludes.contains(relative) || is_symlink_protected(config, relative)? {
        return Ok(false);
    }
    let mut removed = false;
    {
        let target = config.root.join(relative);
        match fs::symlink_metadata(&target) {
            Ok(meta) if meta.is_file() => {
                if config.retention_days > 0 {
                    archive_file(config, &target)?;
                }
                fs::remove_file(&target)?;
                changed_parents
                    .insert(target.parent().context("file has no parent")?.to_path_buf());
                removed = true;
            }
            Ok(_) => {} // A local directory or special file is not a managed file anymore.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    db.execute("DELETE FROM replica_files WHERE path=?1", [relative])?;
    state::clear_staging(db, relative)?;
    let stage = config
        .tmp_path()
        .join(hex::encode(blake3::hash(relative.as_bytes()).as_bytes()) + ".part");
    match fs::remove_file(stage) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(removed)
}

// Explicit source directories and parents of published files are owned. An
// empty-only removal preserves every replica-only file or directory below it.
fn delete_managed_dir(
    config: &Config,
    db: &Connection,
    relative: &str,
    excludes: &ExclusionIndex,
) -> Result<bool> {
    config::valid_relative(relative)?;
    let managed: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM managed_dirs WHERE path=?1)",
        [relative],
        |row| row.get(0),
    )?;
    if !managed {
        return Ok(false);
    }
    if excludes.contains(relative) || is_symlink_protected(config, relative)? {
        return Ok(false);
    }
    // A protected owned descendant may be skipped in this pass. Keep its
    // ancestors owned until that descendant can be reconciled too.
    let descendant_start = format!("{relative}/");
    let descendant_end = format!("{relative}0");
    let owned_descendant: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM replica_files WHERE path>=?1 AND path<?2)
             OR EXISTS(SELECT 1 FROM managed_dirs WHERE path>=?1 AND path<?2)",
        rusqlite::params![descendant_start, descendant_end],
        |row| row.get(0),
    )?;
    if owned_descendant {
        return Ok(false);
    }
    let mut removed = false;
    {
        let target = config.root.join(relative);
        match fs::symlink_metadata(&target) {
            Ok(meta) if meta.is_dir() => match fs::remove_dir(&target) {
                Ok(()) => {
                    File::open(target.parent().context("directory has no parent")?)?.sync_all()?;
                    removed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                Err(error) => return Err(error.into()),
            },
            Ok(_) => {} // A local file or symlink is preserved.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    db.execute("DELETE FROM managed_dirs WHERE path=?1", [relative])?;
    Ok(removed)
}

fn receive_delete_dirs_batch(
    config: &Config,
    db: &Connection,
    excludes: &ExclusionIndex,
    paths: &[String],
    last_path: &mut String,
    remaining: usize,
) -> Result<u64> {
    ensure!(
        !paths.is_empty() && paths.len() <= ENTRY_BATCH_LIMIT && paths.len() <= remaining,
        "invalid directory deletion batch size"
    );
    let mut previous = last_path.as_str();
    for path in paths {
        config::valid_relative(path)?;
        ensure!(
            previous.is_empty()
                || (path.chars().count(), path.as_str()) < (previous.chars().count(), previous),
            "duplicate or out-of-order directory deletion path"
        );
        ensure!(!excludes.contains(path), "excluded deletion path: {path}");
        previous = path;
    }
    let transaction = db.unchecked_transaction()?;
    let mut removed = 0u64;
    for path in paths {
        removed += u64::from(delete_managed_dir(config, &transaction, path, excludes)?);
    }
    transaction.commit()?;
    *last_path = paths
        .last()
        .expect("nonempty directory deletion batch")
        .clone();
    Ok(removed)
}

fn receive_delete_batch(
    config: &Config,
    db: &Connection,
    excludes: &ExclusionIndex,
    paths: &[String],
    last_path: &mut String,
    remaining: usize,
) -> Result<u64> {
    ensure!(
        !paths.is_empty() && paths.len() <= ENTRY_BATCH_LIMIT && paths.len() <= remaining,
        "invalid deletion batch size"
    );
    let mut previous = last_path.as_str();
    for path in paths {
        config::valid_relative(path)?;
        ensure!(
            path.as_str() > previous,
            "duplicate or out-of-order deletion path"
        );
        ensure!(!excludes.contains(path), "excluded deletion path: {path}");
        previous = path;
    }
    let transaction = db.unchecked_transaction()?;
    let mut changed_parents = HashSet::new();
    let mut removed = 0u64;
    for path in paths {
        removed += u64::from(delete_managed_file(
            config,
            &transaction,
            path,
            excludes,
            &mut changed_parents,
        )?);
    }
    for parent in changed_parents {
        File::open(parent)?.sync_all()?;
    }
    transaction.commit()?;
    *last_path = paths.last().expect("nonempty deletion batch").clone();
    Ok(removed)
}

fn reconcile_deleted_files(
    config: &Config,
    db: &Connection,
    excludes: &ExclusionIndex,
) -> Result<u64> {
    let mut after = String::new();
    let mut removed = 0u64;
    loop {
        let paths: Vec<String> = db
            .prepare(
                "SELECT cache.path FROM replica_files AS cache
                 WHERE cache.path>?1 AND NOT EXISTS
                 (SELECT 1 FROM temp.source_seen AS seen WHERE seen.path=cache.path)
                 ORDER BY cache.path LIMIT ?2",
            )?
            .query_map(rusqlite::params![after, ENTRY_BATCH_LIMIT as i64], |row| {
                row.get(0)
            })?
            .collect::<rusqlite::Result<_>>()?;
        if paths.is_empty() {
            break;
        }
        after = paths.last().expect("nonempty reconciliation page").clone();
        let transaction = db.unchecked_transaction()?;
        let mut changed_parents = HashSet::new();
        for path in paths {
            removed += u64::from(delete_managed_file(
                config,
                &transaction,
                &path,
                excludes,
                &mut changed_parents,
            )?);
        }
        for parent in changed_parents {
            File::open(parent)?.sync_all()?;
        }
        transaction.commit()?;
    }
    Ok(removed)
}

fn reconcile_deleted_dirs(
    config: &Config,
    db: &Connection,
    excludes: &ExclusionIndex,
) -> Result<u64> {
    let mut after_depth = i64::MAX;
    let mut after_path = String::new();
    let mut removed = 0u64;
    loop {
        let paths: Vec<(String, i64)> = db
            .prepare(
                "SELECT dirs.path,dirs.depth FROM managed_dirs AS dirs
                 WHERE (dirs.depth<?1 OR (dirs.depth=?1 AND dirs.path<?2))
                 AND NOT EXISTS (SELECT 1 FROM temp.source_seen AS seen WHERE seen.path=dirs.path)
                 ORDER BY dirs.depth DESC,dirs.path DESC LIMIT ?3",
            )?
            .query_map(
                rusqlite::params![after_depth, after_path, ENTRY_BATCH_LIMIT as i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?
            .collect::<rusqlite::Result<_>>()?;
        if paths.is_empty() {
            break;
        }
        (after_path, after_depth) = paths
            .last()
            .expect("nonempty directory reconciliation page")
            .clone();
        let transaction = db.unchecked_transaction()?;
        for (path, _) in paths {
            removed += u64::from(delete_managed_dir(config, &transaction, &path, excludes)?);
        }
        transaction.commit()?;
    }
    Ok(removed)
}

// A full manifest has no deletion frames before its entries. Resolve an owned
// directory -> file replacement here, without touching replica-only contents.
fn remove_managed_directory_for_file(
    config: &Config,
    db: &Connection,
    relative: &str,
    excludes: &ExclusionIndex,
) -> Result<()> {
    let target = config.root.join(relative);
    {
        let mut owned_file =
            db.prepare_cached("SELECT EXISTS(SELECT 1 FROM replica_files WHERE path=?1)")?;
        let mut owned_dir =
            db.prepare_cached("SELECT EXISTS(SELECT 1 FROM managed_dirs WHERE path=?1)")?;
        // Check the complete subtree before deleting anything. An independent
        // file, empty directory or excluded descendant blocks the replacement.
        for entry in WalkDir::new(&target).follow_links(false) {
            let entry = entry?;
            let path = entry
                .path()
                .strip_prefix(&config.root)?
                .to_str()
                .context("non-UTF8 replica path is unsupported")?;
            config::valid_relative(path)?;
            let owned = if entry.file_type().is_file() {
                owned_file.query_row([path], |row| row.get::<_, bool>(0))?
            } else if entry.file_type().is_dir() {
                owned_dir.query_row([path], |row| row.get::<_, bool>(0))?
            } else {
                false
            };
            ensure!(
                owned && !excludes.contains(path),
                "replica directory contains independent or protected contents; existing entry preserved: {path}"
            );
        }
    }
    let start = format!("{relative}/");
    let end = format!("{relative}0");
    let mut after = start.clone();
    loop {
        let paths: Vec<String> = db
            .prepare_cached(
                "SELECT path FROM replica_files WHERE path>=?1 AND path<?2 AND path>?3
             ORDER BY path LIMIT ?4",
            )?
            .query_map(
                rusqlite::params![start, end, after, ENTRY_BATCH_LIMIT as i64],
                |row| row.get(0),
            )?
            .collect::<rusqlite::Result<_>>()?;
        let Some(last) = paths.last() else { break };
        after = last.clone();
        let transaction = db.unchecked_transaction()?;
        let mut parents = HashSet::new();
        for path in paths {
            delete_managed_file(config, &transaction, &path, excludes, &mut parents)?;
        }
        for parent in parents {
            File::open(parent)?.sync_all()?;
        }
        transaction.commit()?;
    }
    // Reverse lexical order puts every descendant before its parent and uses
    // the existing primary-key index. Keep only one bounded page in memory.
    after = end.clone();
    loop {
        let paths: Vec<String> = db
            .prepare_cached(
                "SELECT path FROM managed_dirs WHERE path>=?1 AND path<?2 AND path<?3
             ORDER BY path DESC LIMIT ?4",
            )?
            .query_map(
                rusqlite::params![start, end, after, ENTRY_BATCH_LIMIT as i64],
                |row| row.get(0),
            )?
            .collect::<rusqlite::Result<_>>()?;
        let Some(last) = paths.last() else { break };
        after = last.clone();
        let transaction = db.unchecked_transaction()?;
        for path in paths {
            delete_managed_dir(config, &transaction, &path, excludes)?;
        }
        transaction.commit()?;
    }
    delete_managed_dir(config, db, relative, excludes)?;
    match fs::symlink_metadata(&target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => bail!(
            "replica directory changed during replacement; existing entry preserved: {}",
            target.display()
        ),
    }
}

fn contains_symlink_descendant(path: &Path) -> Result<bool> {
    for entry in WalkDir::new(path).follow_links(false).min_depth(1) {
        if entry?.file_type().is_symlink() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_safe_ancestors(config: &Config, path: &Path) -> Result<()> {
    let relative = path.strip_prefix(&config.root)?;
    let mut current = config.root.clone();
    for component in relative.components() {
        current.push(component);
        if let Ok(meta) = fs::symlink_metadata(&current) {
            ensure!(
                !meta.file_type().is_symlink(),
                "symlink at {}",
                current.display()
            );
        }
    }
    Ok(())
}

fn ensure_parent_dirs(config: &Config, path: &Path) -> Result<()> {
    let parent = path.parent().context("target has no parent")?;
    let relative = parent.strip_prefix(&config.root)?;
    let mut current = config.root.clone();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.is_dir() => {}
            Ok(meta) if meta.file_type().is_symlink() => bail!("symlink at {}", current.display()),
            Ok(_) => bail!(
                "replica path conflicts with source directory; existing entry preserved: {}",
                current.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                sync_parent(&current)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn ensure_directory(config: &Config, relative: &str) -> Result<()> {
    let path = config.root.join(crate::config::valid_relative(relative)?);
    ensure_parent_dirs(config, &path)?;
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_dir() => {}
        Ok(meta) if meta.file_type().is_symlink() => bail!("symlink at {}", path.display()),
        Ok(_) => bail!(
            "replica path conflicts with source directory; existing entry preserved: {}",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&path)?;
            sync_parent(&path)?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn history_destination(config: &Config, target: &Path) -> Result<PathBuf> {
    ensure_safe_ancestors(config, target)?;
    let relative = target.strip_prefix(&config.root)?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    for counter in 0..1000 {
        let batch = config.history_path().join(format!("{stamp}-{counter}"));
        match fs::create_dir(&batch) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
        let dest = batch.join(relative);
        fs::create_dir_all(dest.parent().context("history parent missing")?)?;
        return Ok(dest);
    }
    bail!("could not create unique history entry")
}

fn archive_file(config: &Config, target: &Path) -> Result<PathBuf> {
    let dest = history_destination(config, target)?;
    if fs::hard_link(target, &dest).is_err() {
        fs::copy(target, &dest)?;
    }
    File::open(&dest)?.sync_all()?;
    sync_parent(&dest)?;
    Ok(dest)
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn cleanup_history(config: &Config) -> Result<()> {
    if config.retention_days == 0 {
        return Ok(());
    }
    let cutoff = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .saturating_sub(config.retention_days as u128 * 86_400_000);
    for entry in fs::read_dir(config.history_path())? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(stamp) = name
            .to_str()
            .and_then(|s| s.split('-').next())
            .and_then(|s| s.parse::<u128>().ok())
        else {
            continue;
        };
        if stamp < cutoff && entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

fn cleanup_staging(config: &Config, db: &Connection) -> Result<()> {
    for entry in fs::read_dir(config.tmp_path())? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(stem) = name.to_str().and_then(|name| name.strip_suffix(".part")) else {
            continue;
        };
        if stem.len() == 64 && stem.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            let file_type = entry.file_type()?;
            if file_type.is_file() || file_type.is_symlink() {
                fs::remove_file(entry.path())?;
            }
        }
    }
    state::clear_all_staging(db)?;
    Ok(())
}

// File staging, block reuse and durable publication.

const SMALL_SYNC_BATCH: usize = 32;
const SMALL_SYNC_WORKERS: usize = 2;
const RECOVERY_BATCH: usize = 128;

struct StagedSmall {
    index: usize,
    file: File,
    stage: PathBuf,
}

impl Drop for StagedSmall {
    fn drop(&mut self) {
        // An interrupted batch has no resume bitmap for small files. Remove
        // its unpublished stage so repeated failures cannot fill tmp/.
        let _ = fs::remove_file(&self.stage);
    }
}

struct SmallFileBatch<'a> {
    staged: Vec<StagedSmall>,
    changed_parents: HashSet<PathBuf>,
    pool: &'a mut Option<rayon::ThreadPool>,
}

struct ReceiveFileContext<'a> {
    verify_round: Option<i64>,
    verified: &'a mut Vec<state::VerifiedUpdate>,
    verify: &'a mut VerifyStats,
    checked_stamp: Option<&'a [u8]>,
}

enum FileCheck {
    Matches,
    Different { stamp: Vec<u8> },
}

fn recover_publications(config: &Config, db: &Connection) -> Result<()> {
    let mut after = String::new();
    loop {
        let page = state::staging_page(db, &after, RECOVERY_BATCH)?;
        if page.is_empty() {
            return Ok(());
        }
        let mut recovered = Vec::with_capacity(page.len());
        for (path, hash) in &page {
            crate::config::valid_relative(path)?;
            if is_symlink_protected(config, path)? {
                continue;
            }
            let target = config.root.join(path);
            match fs::symlink_metadata(&target) {
                Ok(meta) if meta.is_file() => {}
                Ok(_) => continue,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
            // A journal row alone must never claim a replica-only file. Only a
            // stable target matching the intended content can be adopted.
            let before = scan::file_stamp(&target)?;
            if scan::file_hash(&target)? != *hash {
                continue;
            }
            let after_stamp = scan::file_stamp(&target)?;
            ensure!(
                before == after_stamp,
                "replica file changed during publication recovery: {path}"
            );
            File::open(&target)?.sync_all()?;
            sync_parent(&target)?;
            recovered.push(state::VerifiedUpdate {
                path: path.clone(),
                stamp: after_stamp,
                hash: hash.clone(),
                round: None,
            });
        }
        after = page.last().context("empty recovery page")?.0.clone();
        state::flush_verified(db, &mut recovered)?;
    }
}

fn validate_meta(meta: &FileMeta) -> Result<()> {
    crate::config::valid_relative(&meta.path)?;
    let count = meta.size.div_ceil(CHUNK_SIZE as u64);
    ensure!(
        count <= MAX_BLOCKS && meta.blocks.len() as u64 == count,
        "invalid block count"
    );
    ensure!(hex::decode(&meta.hash)?.len() == 32, "invalid file hash");
    for hash in &meta.blocks {
        ensure!(hex::decode(hash)?.len() == 32, "invalid block hash");
    }
    Ok(())
}

fn existing_file_matches(
    db: &Connection,
    target: &Path,
    meta: &FileMeta,
    verify_round: Option<i64>,
    verified: &mut Vec<state::VerifiedUpdate>,
    verify: &mut VerifyStats,
) -> Result<FileCheck> {
    let before = scan::file_stamp(target)?;
    if let Some((cached, round)) = state::replica_cached_file(db, &meta.path, &before)? {
        // An unchanged old file with a different cached hash already needs
        // replacement. Block reuse and final stage verification still read it.
        if cached != meta.hash {
            return Ok(FileCheck::Different { stamp: before });
        }
        if verify_round.is_none() {
            return Ok(FileCheck::Matches);
        }
        if round == verify_round {
            verify.reused_files += 1;
            return Ok(FileCheck::Matches);
        }
    }
    verify.hashed_files += 1;
    verify.hashed_bytes += meta.size;
    let matches = scan::file_hash(target)? == meta.hash;
    let after = scan::file_stamp(target)?;
    ensure!(
        before == after,
        "replica file changed during verification: {}",
        target.display()
    );
    if matches {
        verified.push(state::VerifiedUpdate {
            path: meta.path.clone(),
            stamp: after,
            hash: meta.hash.clone(),
            round: verify_round,
        });
        Ok(FileCheck::Matches)
    } else {
        Ok(FileCheck::Different { stamp: after })
    }
}

fn stage_small_file(
    index: usize,
    config: &Config,
    meta: &FileMeta,
    content: &[u8],
) -> Result<StagedSmall> {
    ensure!(
        content.len() as u64 == meta.size,
        "small-file size mismatch: {}",
        meta.path
    );
    let hash = hex::encode(blake3::hash(content).as_bytes());
    ensure!(hash == meta.hash, "small-file hash mismatch: {}", meta.path);
    if !content.is_empty() {
        ensure!(
            meta.blocks.len() == 1 && meta.blocks[0] == hash,
            "small-file block mismatch: {}",
            meta.path
        );
    }
    let stage = config
        .tmp_path()
        .join(hex::encode(blake3::hash(meta.path.as_bytes()).as_bytes()) + ".part");
    let temp = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&stage)?;
    let mut staged = StagedSmall {
        index,
        file: temp,
        stage,
    };
    staged.file.write_all(content)?;
    Ok(staged)
}

impl SmallFileBatch<'_> {
    fn new(pool: &mut Option<rayon::ThreadPool>) -> SmallFileBatch<'_> {
        SmallFileBatch {
            staged: Vec::with_capacity(SMALL_SYNC_BATCH),
            changed_parents: HashSet::new(),
            pool,
        }
    }

    fn stage(
        &mut self,
        index: usize,
        config: &Config,
        meta: &FileMeta,
        content: &[u8],
    ) -> Result<bool> {
        self.staged
            .push(stage_small_file(index, config, meta, content)?);
        Ok(self.staged.len() == SMALL_SYNC_BATCH)
    }

    fn sync_published(&mut self) -> Result<()> {
        for parent in &self.changed_parents {
            File::open(parent)?.sync_all()?;
        }
        self.changed_parents.clear();
        Ok(())
    }

    fn flush(
        &mut self,
        config: &Config,
        db: &Connection,
        entries: &[Entry],
        verify_round: Option<i64>,
        verified: &mut Vec<state::VerifiedUpdate>,
    ) -> Result<()> {
        if self.staged.is_empty() {
            return Ok(());
        }
        // Create workers only after a full batch is queued. Their count and the
        // number of simultaneously open stage files stay bounded for the session.
        if self.staged.len() >= SMALL_SYNC_BATCH && self.pool.is_none() {
            *self.pool = Some(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(SMALL_SYNC_WORKERS)
                    .build()?,
            );
        }
        if let Some(pool) = self.pool.as_ref() {
            let results = pool.install(|| {
                self.staged
                    .par_iter()
                    .map(|item| item.file.sync_all())
                    .collect::<Vec<_>>()
            });
            for result in results {
                result?;
            }
        } else {
            for item in self.staged.iter() {
                item.file.sync_all()?;
            }
        }
        // Save intent before the first rename. A crash can then recover files
        // already published even when the batch acknowledgement was never sent.
        let publications = self
            .staged
            .iter()
            .map(|item| {
                let Entry::File { meta } = &entries[item.index] else {
                    unreachable!()
                };
                (meta.path.as_str(), meta.hash.as_str())
            })
            .collect::<Vec<_>>();
        state::begin_publications(db, &publications)?;
        for item in self.staged.drain(..) {
            let Entry::File { meta } = &entries[item.index] else {
                unreachable!()
            };
            publish_stage(config, meta, &item.stage, false, verify_round, verified)?;
            self.changed_parents.insert(
                config
                    .root
                    .join(&meta.path)
                    .parent()
                    .context("small file has no parent")?
                    .to_path_buf(),
            );
        }
        self.sync_published()?;
        state::flush_verified(db, verified)?;
        Ok(())
    }
}

async fn receive_file<S: AsyncRead + AsyncWrite + Unpin>(
    config: &Config,
    db: &Connection,
    stream: &mut S,
    meta: &FileMeta,
    context: ReceiveFileContext<'_>,
) -> Result<u64> {
    let ReceiveFileContext {
        verify_round,
        verified,
        verify,
        checked_stamp,
    } = context;
    validate_meta(meta)?;
    let target = config.root.join(&meta.path);
    ensure_safe_ancestors(config, &target)?;
    if let Ok(existing) = fs::symlink_metadata(&target) {
        ensure!(
            !existing.file_type().is_symlink(),
            "symlink at {}",
            target.display()
        );
        ensure!(
            existing.is_file(),
            "replica path conflicts with source file; existing entry preserved: {}",
            target.display()
        );
        // Recheck content only if the target changed after EntriesNeed was sent.
        // The final stage hash also guards against concurrent edits while copying.
        let already_checked = match checked_stamp {
            Some(stamp) if existing.len() == meta.size => {
                scan::file_stamp(&target)?.as_slice() == stamp
            }
            _ => false,
        };
        if existing.len() == meta.size
            && !already_checked
            && matches!(
                existing_file_matches(db, &target, meta, verify_round, verified, verify)?,
                FileCheck::Matches
            )
        {
            wire::send(stream, &Frame::Need { indices: vec![] }).await?;
            match wire::recv(stream).await? {
                Frame::FileDone => {
                    state::flush_verified(db, verified)?;
                    wire::send(stream, &Frame::Ack).await?;
                    return Ok(0);
                }
                other => bail!("expected file_done, got {}", other.kind()),
            }
        }
    }
    let stage = config
        .tmp_path()
        .join(hex::encode(blake3::hash(meta.path.as_bytes()).as_bytes()) + ".part");
    let mut bitmap = match state::staging(db, &meta.path)? {
        Some((hash, bits))
            if hash == meta.hash && bits.len() == meta.blocks.len() && stage.is_file() =>
        {
            bits
        }
        _ => {
            let _ = fs::remove_file(&stage);
            vec![0; meta.blocks.len()]
        }
    };
    let mut temp = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&stage)?;
    temp.set_len(meta.size)?;
    let mut buf = Vec::new();
    for (index, bit) in bitmap.iter_mut().enumerate() {
        if *bit == 1 && !file_block_matches(&mut temp, meta, index, &mut buf)? {
            *bit = 0;
        }
    }
    if let Ok(existing) = fs::symlink_metadata(&target)
        && existing.is_file()
    {
        let mut old = File::open(&target)?;
        for (index, bit) in bitmap.iter_mut().enumerate() {
            if *bit == 0 && file_block_matches(&mut old, meta, index, &mut buf)? {
                let size = block_len(meta.size, index)?;
                temp.seek(SeekFrom::Start(index as u64 * CHUNK_SIZE as u64))?;
                temp.write_all(&buf[..size])?;
                *bit = 1;
            }
        }
    }
    // A resumed stage verifies every recorded block before it is reused, so a
    // crash between this checkpoint and a disk flush cannot publish bad data.
    state::set_staging(db, &meta.path, &meta.hash, &bitmap)?;
    let needed: Vec<_> = bitmap
        .iter()
        .enumerate()
        .filter_map(|(i, bit)| (*bit == 0).then_some(i))
        .collect();
    wire::send(stream, &FrameRef::Need { indices: &needed }).await?;
    let mut received = 0u64;
    let mut uncheckpointed = 0u64;
    for index in needed {
        let size = block_len(meta.size, index)?;
        match wire::recv(stream).await? {
            Frame::Chunk {
                index: got,
                size: got_size,
            } if got == index && got_size == size => {}
            Frame::FileAbort { reason } => {
                bail!("source aborted {}: {}", meta.path, remote_text(&reason))
            }
            other => bail!("unexpected chunk header: {}", other.kind()),
        }
        buf.resize(size, 0);
        tokio::time::timeout(wire::IO_TIMEOUT, stream.read_exact(&mut buf[..size]))
            .await
            .context("chunk read timed out")??;
        ensure!(
            hex::encode(blake3::hash(&buf[..size]).as_bytes()) == meta.blocks[index],
            "block hash mismatch: {} block {index}",
            meta.path
        );
        temp.seek(SeekFrom::Start(index as u64 * CHUNK_SIZE as u64))?;
        temp.write_all(&buf[..size])?;
        bitmap[index] = 1;
        received += size as u64;
        uncheckpointed += size as u64;
        if uncheckpointed >= 32 * 1024 * 1024 {
            temp.sync_data()?;
            state::set_staging(db, &meta.path, &meta.hash, &bitmap)?;
            uncheckpointed = 0;
        }
    }
    if uncheckpointed > 0 {
        // The final sync_all below makes the stage durable before publication.
        // On an interrupted transfer, the next session verifies these bits.
        state::set_staging(db, &meta.path, &meta.hash, &bitmap)?;
    }
    match wire::recv(stream).await? {
        Frame::FileDone => {}
        Frame::FileAbort { reason } => {
            bail!("source aborted {}: {}", meta.path, remote_text(&reason))
        }
        other => bail!("expected file_done, got {}", other.kind()),
    }
    ensure!(
        scan::file_hash(&stage)? == meta.hash,
        "whole-file hash mismatch: {}",
        meta.path
    );
    temp.sync_all()?;
    drop(temp);
    publish_stage(config, meta, &stage, true, verify_round, verified)?;
    state::flush_verified(db, verified)?;
    wire::send(stream, &Frame::Ack).await?;
    Ok(received)
}

fn publish_stage(
    config: &Config,
    meta: &FileMeta,
    stage: &Path,
    sync_directory: bool,
    verify_round: Option<i64>,
    verified: &mut Vec<state::VerifiedUpdate>,
) -> Result<()> {
    let target = config.root.join(&meta.path);
    ensure_parent_dirs(config, &target)?;
    match fs::symlink_metadata(&target) {
        Ok(existing) if existing.is_file() => {
            if config.retention_days > 0 {
                archive_file(config, &target)?;
            }
        }
        Ok(_) => bail!(
            "replica path conflicts with source file; existing entry preserved: {}",
            target.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    fs::rename(stage, &target)?;
    if sync_directory {
        sync_parent(&target)?;
    }
    // flush_verified clears the journal in the same transaction as ownership.
    verified.push(state::VerifiedUpdate {
        path: meta.path.clone(),
        stamp: scan::file_stamp(&target)?,
        hash: meta.hash.clone(),
        round: verify_round,
    });
    Ok(())
}

fn file_block_matches(
    file: &mut File,
    meta: &FileMeta,
    index: usize,
    buf: &mut Vec<u8>,
) -> Result<bool> {
    let size = block_len(meta.size, index)?;
    buf.resize(size, 0);
    file.seek(SeekFrom::Start(index as u64 * CHUNK_SIZE as u64))?;
    if file.read_exact(&mut buf[..size]).is_err() {
        return Ok(false);
    }
    Ok(hex::encode(blake3::hash(&buf[..size]).as_bytes()) == meta.blocks[index])
}
