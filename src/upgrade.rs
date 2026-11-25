use crate::wire::{self, Frame};
use anyhow::{Context, Result, bail, ensure};
use std::{
    env, fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tempfile::Builder;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_UPGRADE_BYTES: u64 = 128 * 1024 * 1024;
const UPGRADE_CHUNK: usize = 1024 * 1024;
const PROGRAM_NAME: &str = env!("CARGO_PKG_NAME");

fn replica_executable() -> Result<PathBuf> {
    ensure!(
        env::var_os("INVOCATION_ID").is_some(),
        "replica upgrade requires a systemd managed service"
    );
    let path = env::current_exe().context("locate running rsync executable")?;
    ensure!(
        path.file_name().is_some_and(|name| name == PROGRAM_NAME),
        "replica executable must be named {PROGRAM_NAME}"
    );
    ensure!(
        fs::symlink_metadata(&path)?.file_type().is_file(),
        "replica executable is not a regular file"
    );
    ensure!(
        path.parent().is_some_and(Path::is_dir),
        "replica executable directory is unavailable"
    );
    Ok(path)
}

pub fn replica_supported() -> bool {
    replica_executable().is_ok()
}

fn hash_file(file: &mut fs::File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0; UPGRADE_CHUNK];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(hasher.finalize().to_hex().to_string())
}

fn remote_error(message: &str) -> String {
    message
        .chars()
        .take(512)
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

pub async fn send<S, F>(stream: &mut S, mut progress: F) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(u64, u64),
{
    // Read the exact binary running this source process. No web request can choose a file.
    let mut executable = fs::File::open("/proc/self/exe").context("read source executable")?;
    let size = executable.metadata()?.len();
    ensure!(
        (1..=MAX_UPGRADE_BYTES).contains(&size),
        "source executable exceeds upgrade size limit"
    );
    let digest = hash_file(&mut executable)?;
    progress(0, size);
    wire::send(
        stream,
        &Frame::UpgradeBegin {
            version: env!("CARGO_PKG_VERSION").into(),
            size,
            digest,
        },
    )
    .await?;
    match wire::recv(stream).await? {
        Frame::Ack => {}
        Frame::Error { message } => bail!("replica rejected upgrade: {}", remote_error(&message)),
        other => bail!("unexpected upgrade response: {}", other.kind()),
    }
    let mut buffer = vec![0; UPGRADE_CHUNK];
    let mut sent = 0u64;
    loop {
        let n = executable.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        wire::send(stream, &Frame::UpgradeChunk { size: n }).await?;
        tokio::time::timeout(wire::IO_TIMEOUT, async {
            stream.write_all(&buffer[..n]).await?;
            stream.flush().await
        })
        .await
        .context("upgrade data send timed out")??;
        sent += n as u64;
        progress(sent, size);
    }
    ensure!(sent == size, "source executable changed during upgrade");
    wire::send(stream, &Frame::UpgradeEnd).await?;
    match wire::recv(stream).await? {
        Frame::UpgradeResult { changed } => Ok(changed),
        Frame::Error { message } => bail!("replica rejected upgrade: {}", remote_error(&message)),
        other => bail!("unexpected upgrade result: {}", other.kind()),
    }
}

fn validate_header(version: &str, size: u64, digest: &str) -> Result<()> {
    ensure!(
        !version.is_empty()
            && version.len() <= 64
            && version
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || b".+-".contains(&ch)),
        "invalid upgrade version"
    );
    ensure!(
        (1..=MAX_UPGRADE_BYTES).contains(&size),
        "invalid upgrade size"
    );
    ensure!(
        digest.len() == 64 && digest.bytes().all(|ch| ch.is_ascii_hexdigit()),
        "invalid upgrade digest"
    );
    Ok(())
}

async fn check_candidate(path: &Path, version: &str) -> Result<()> {
    let expected = format!("{PROGRAM_NAME} {version}\n");
    let mut child = tokio::process::Command::new(path)
        .arg("--version")
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().context("missing candidate stdout")?;
    let stderr = child.stderr.take().context("missing candidate stderr")?;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        // Drain both pipes concurrently. A broken candidate must not fill RAM
        // or deadlock because its other output pipe was left unread.
        let (stdout, stderr, status) = tokio::try_join!(
            candidate_output(stdout, expected.len()),
            candidate_output(stderr, 512),
            async { child.wait().await.map_err(anyhow::Error::from) },
        )?;
        ensure!(
            status.success() && stdout == expected.as_bytes(),
            "candidate executable failed version check: {}",
            remote_error(&String::from_utf8_lossy(&stderr))
        );
        Ok(())
    })
    .await
    .context("candidate executable check timed out")
    .and_then(|result| result);
    if result.is_err() {
        // Also reap a rejected child while the runtime is still alive.
        let _ = child.kill().await;
    }
    result
}

async fn candidate_output(reader: impl AsyncRead + Unpin, limit: usize) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(limit + 1);
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut output)
        .await?;
    ensure!(
        output.len() <= limit,
        "candidate executable output too large"
    );
    Ok(output)
}

fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

pub async fn receive<S>(stream: &mut S, version: String, size: u64, digest: String) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    validate_header(&version, size, &digest)?;
    let target = replica_executable()?;
    let parent = target.parent().context("missing executable directory")?;
    let original = fs::metadata(&target)?;
    // Stage beside the running executable so the final rename stays on one filesystem.
    // The live process continues from its old inode until systemd restarts it.
    let mut staged = Builder::new()
        .prefix(".rsync-upgrade-")
        .tempfile_in(parent)
        .context("create upgrade staging file beside executable")?;
    wire::send(stream, &Frame::Ack).await?;

    let mut hasher = blake3::Hasher::new();
    let mut received = 0u64;
    let mut buffer = vec![0; UPGRADE_CHUNK];
    loop {
        match wire::recv(stream).await? {
            Frame::UpgradeChunk { size: chunk } => {
                ensure!(
                    chunk > 0 && chunk <= UPGRADE_CHUNK && received + chunk as u64 <= size,
                    "invalid upgrade chunk size"
                );
                tokio::time::timeout(wire::IO_TIMEOUT, stream.read_exact(&mut buffer[..chunk]))
                    .await
                    .context("upgrade data read timed out")??;
                staged.write_all(&buffer[..chunk])?;
                hasher.update(&buffer[..chunk]);
                received += chunk as u64;
            }
            Frame::UpgradeEnd => break,
            other => bail!("unexpected upgrade frame: {}", other.kind()),
        }
    }
    ensure!(received == size, "incomplete upgrade executable");
    ensure!(
        hasher
            .finalize()
            .to_hex()
            .to_string()
            .eq_ignore_ascii_case(&digest),
        "upgrade executable digest mismatch"
    );
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o700))?;
    staged.as_file().sync_all()?;
    // Linux refuses to execute a file that is still open for writing (ETXTBSY).
    let staged_path = staged.into_temp_path();
    check_candidate(&staged_path, &version).await?;

    // Abort if another actor replaced the executable while this payload was received.
    let current = fs::metadata(&target)?;
    ensure!(
        current.dev() == original.dev() && current.ino() == original.ino(),
        "replica executable changed during upgrade"
    );
    let mut running = fs::File::open(&target)?;
    if hash_file(&mut running)?.eq_ignore_ascii_case(&digest) {
        wire::send(stream, &Frame::UpgradeResult { changed: false }).await?;
        return Ok(false);
    }

    // Keep one previous executable for a manual rollback if the new service fails to start.
    let mut backup = Builder::new()
        .prefix(".rsync-backup-")
        .tempfile_in(parent)?;
    running.seek(SeekFrom::Start(0))?;
    std::io::copy(&mut running, backup.as_file_mut())?;
    backup
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o700))?;
    backup.as_file().sync_all()?;
    let backup_path = target.with_extension("previous");
    backup.persist(&backup_path)?;
    sync_directory(parent)?;

    fs::set_permissions(&staged_path, fs::Permissions::from_mode(0o755))?;
    fs::File::open(&staged_path)?.sync_all()?;
    staged_path.persist(&target)?;
    if let Err(error) = sync_directory(parent) {
        eprintln!("upgrade installed but executable directory sync failed: {error:#}");
    }
    // A broken connection after the rename must not leave the old process running forever.
    let _ = wire::send(stream, &Frame::UpgradeResult { changed: true }).await;
    Ok(true)
}
