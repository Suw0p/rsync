use crate::scan::{Entry, FileMeta};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{io, net::SocketAddr, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_CONTROL: usize = 16 * 1024 * 1024;
pub const IO_TIMEOUT: Duration = Duration::from_secs(120);
pub const SYNC_PROTOCOL: u32 = 5;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaSettings {
    pub root: String,
    pub addr: SocketAddr,
    pub retention_days: u64,
    pub verify_interval_secs: u64,
    pub version: String,
    pub upgrade_supported: bool,
    pub sync_protocol: u32,
    pub delta_supported: bool,
    pub deletions_supported: bool,
    pub directory_deletions_supported: bool,
    pub last_deleted_files: u64,
    pub last_deleted_dirs: u64,
    pub last_generation: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum Frame {
    Begin {
        protocol: u32,
        generation: u64,
        files: usize,
        excludes: Vec<String>,
        delta: bool,
    },
    Entries {
        entries: Vec<Entry>,
    },
    EntriesNeed {
        indices: Vec<usize>,
        hashed_files: u64,
        hashed_bytes: u64,
        reused_files: u64,
    },
    EntriesReady,
    EntriesDone,
    Delete {
        paths: Vec<String>,
    },
    DeleteDirs {
        paths: Vec<String>,
    },
    File {
        meta: FileMeta,
    },
    Need {
        indices: Vec<usize>,
    },
    Chunk {
        index: usize,
        size: usize,
    },
    FileDone,
    FileAbort {
        reason: String,
    },
    Ack,
    Ping,
    ReplicaSettingsGet,
    ReplicaSettingsSet {
        retention_days: u64,
        verify_interval_secs: u64,
    },
    ReplicaSettings {
        settings: ReplicaSettings,
    },
    UpgradeBegin {
        version: String,
        size: u64,
        digest: String,
    },
    UpgradeChunk {
        size: usize,
    },
    UpgradeEnd,
    UpgradeResult {
        changed: bool,
    },
    End,
    Error {
        message: String,
    },
}

// The receive side owns decoded values. Large outbound fields can borrow the
// existing batch instead of cloning every path and block hash across an await.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FrameRef<'a> {
    Entries { entries: &'a [Entry] },
    File { meta: &'a FileMeta },
    Need { indices: &'a [usize] },
    Delete { paths: &'a [String] },
    DeleteDirs { paths: &'a [String] },
}

impl Frame {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Begin { .. } => "begin",
            Self::Entries { .. } => "entries",
            Self::EntriesNeed { .. } => "entries_need",
            Self::EntriesReady => "entries_ready",
            Self::EntriesDone => "entries_done",
            Self::Delete { .. } => "delete",
            Self::DeleteDirs { .. } => "delete_dirs",
            Self::File { .. } => "file",
            Self::Need { .. } => "need",
            Self::Chunk { .. } => "chunk",
            Self::FileDone => "file_done",
            Self::FileAbort { .. } => "file_abort",
            Self::Ack => "ack",
            Self::Ping => "ping",
            Self::ReplicaSettingsGet => "replica_settings_get",
            Self::ReplicaSettingsSet { .. } => "replica_settings_set",
            Self::ReplicaSettings { .. } => "replica_settings",
            Self::UpgradeBegin { .. } => "upgrade_begin",
            Self::UpgradeChunk { .. } => "upgrade_chunk",
            Self::UpgradeEnd => "upgrade_end",
            Self::UpgradeResult { .. } => "upgrade_result",
            Self::End => "end",
            Self::Error { .. } => "error",
        }
    }
}

struct ControlBuffer(Vec<u8>);

impl io::Write for ControlBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let needed = self
            .0
            .len()
            .checked_add(bytes.len())
            .filter(|&size| size <= MAX_CONTROL)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "control frame too large")
            })?;
        if needed > self.0.capacity() {
            // Geometric growth keeps small writes cheap, with an explicit ceiling
            // so even a rejected oversized frame cannot allocate beyond the limit.
            let capacity = needed.max(self.0.capacity().max(64) * 2).min(MAX_CONTROL);
            self.0
                .try_reserve_exact(capacity - self.0.len())
                .map_err(io::Error::other)?;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub async fn send<W: AsyncWrite + Unpin, T: Serialize>(writer: &mut W, frame: &T) -> Result<()> {
    let mut buffer = ControlBuffer(Vec::new());
    serde_json::to_writer(&mut buffer, frame)?;
    let body = buffer.0;
    tokio::time::timeout(IO_TIMEOUT, async {
        writer.write_u32(body.len() as u32).await?;
        writer.write_all(&body).await?;
        writer.flush().await
    })
    .await
    .context("control send timed out")??;
    Ok(())
}

pub async fn recv<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    recv_with_timeout(reader, IO_TIMEOUT).await
}

pub async fn recv_idle<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    recv_with_timeout(reader, Duration::from_secs(3600)).await
}

async fn recv_with_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    header_timeout: Duration,
) -> Result<Frame> {
    let len = tokio::time::timeout(header_timeout, reader.read_u32())
        .await
        .context("control read timed out")?? as usize;
    ensure!(len > 0 && len <= MAX_CONTROL, "invalid control frame size");
    let mut body = vec![0; len];
    tokio::time::timeout(IO_TIMEOUT, reader.read_exact(&mut body))
        .await
        .context("control body timed out")??;
    Ok(serde_json::from_slice(&body)?)
}
