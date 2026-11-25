use crate::config::{CHUNK_SIZE, Config, ExclusionIndex, MAX_BLOCKS, PRIVATE_DIR};
use anyhow::{Context, Result, ensure};
use rayon::prelude::*;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
use walkdir::{DirEntry, WalkDir};

const SCAN_BATCH: usize = 64;
const LARGE_FILE: u64 = 256 * 1024 * 1024;
pub const SMALL_FILE_LIMIT: u64 = 64 * 1024;
pub const SMALL_BATCH_BYTES_LIMIT: usize = 8 * 1024 * 1024;
const HASH_READ_SIZE: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileMeta {
    pub path: String,
    pub size: u64,
    pub hash: String,
    pub blocks: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Entry {
    Dir { path: String },
    File { meta: FileMeta },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FileStamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl FileStamp {
    fn from_metadata(meta: &fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        }
    }
}

enum Pending {
    Dir(String),
    Cached {
        path: String,
    },
    Hash {
        path: PathBuf,
        relative: String,
        size: u64,
    },
}

#[derive(Default)]
pub struct ScanStats {
    pub files: usize,
    pub cache_hits: usize,
    pub hashed_files: usize,
    pub workers: usize,
    pub reused_manifest: bool,
    pub manifest_changed: bool,
}

fn inventory_hasher(config: &Config) -> Result<blake3::Hasher> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&serde_json::to_vec(&config.excludes)?);
    Ok(hasher)
}

fn hash_entry(hasher: &mut blake3::Hasher, relative: &str, kind: u8, stamp: Option<&FileStamp>) {
    hasher.update(&(relative.len() as u64).to_le_bytes());
    hasher.update(relative.as_bytes());
    hasher.update(&[kind]);
    if let Some(stamp) = stamp {
        for value in [stamp.dev, stamp.ino, stamp.size] {
            hasher.update(&value.to_le_bytes());
        }
        for value in [stamp.mtime, stamp.mtime_nsec, stamp.ctime, stamp.ctime_nsec] {
            hasher.update(&value.to_le_bytes());
        }
    }
}

fn include_source_entry(entry: &DirEntry, config: &Config, exclusions: &ExclusionIndex) -> bool {
    if entry.path() == config.root {
        return true;
    }
    if entry.path() == config.private_path() {
        return false;
    }
    let Some(relative) = entry
        .path()
        .strip_prefix(&config.root)
        .ok()
        .and_then(|path| path.to_str())
    else {
        return true;
    };
    !exclusions.contains(relative)
}

fn inventory_fingerprint(config: &Config) -> Result<(String, Vec<String>)> {
    // This cheap tree walk hashes paths, types and file stamps, not file contents.
    // It is only a manifest-cache hint; scheduled verification still rehashes files.
    let exclusions = ExclusionIndex::new(&config.excludes);
    let mut hasher = inventory_hasher(config)?;
    let mut skipped_symlinks = Vec::new();
    let walk = WalkDir::new(&config.root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| include_source_entry(entry, config, &exclusions));
    for item in walk {
        let entry = item.context("scan directory")?;
        if entry.path() == config.root {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&config.root)?
            .to_str()
            .context("non-UTF8 path is unsupported")?;
        crate::config::valid_relative(relative)?;
        ensure!(
            entry.file_name() != PRIVATE_DIR,
            "nested rsync state directory is unsupported: {}",
            entry.path().display()
        );
        let kind = entry.file_type();
        if kind.is_dir() {
            hash_entry(&mut hasher, relative, 0, None);
        } else if kind.is_file() {
            ensure!(
                !exclusions.protects_parent(relative),
                "source file conflicts with excluded descendant: {relative}"
            );
            let meta = fs::symlink_metadata(entry.path())?;
            ensure!(
                meta.is_file(),
                "file changed during scan: {}",
                entry.path().display()
            );
            hash_entry(
                &mut hasher,
                relative,
                1,
                Some(&FileStamp::from_metadata(&meta)),
            );
        } else if kind.is_symlink() {
            hash_entry(&mut hasher, relative, 2, None);
            skipped_symlinks.push(relative.to_owned());
        } else {
            anyhow::bail!("unsupported source entry: {}", entry.path().display());
        }
    }
    Ok((hasher.finalize().to_hex().to_string(), skipped_symlinks))
}

pub fn file_hash(path: &Path) -> Result<String> {
    let file = fs::File::open(path)?;
    let size = file.metadata()?.len();
    let mut file = file.take(size.saturating_add(1));
    let mut hasher = blake3::Hasher::new();
    let mut total = 0u64;
    let mut buf = [0; HASH_READ_SIZE];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    ensure!(
        total == size,
        "file size changed during hashing: {}",
        path.display()
    );
    Ok(hex::encode(hasher.finalize().as_bytes()))
}

pub fn file_stamp(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(meta.is_file(), "not a regular file: {}", path.display());
    Ok(serde_json::to_vec(&FileStamp::from_metadata(&meta))?)
}

fn scan_file(path: &Path, relative: String) -> Result<(FileMeta, FileStamp)> {
    let before = fs::symlink_metadata(path)?;
    ensure!(before.is_file(), "not a regular file: {}", path.display());
    let before_stamp = FileStamp::from_metadata(&before);
    ensure!(
        before_stamp.size.div_ceil(CHUNK_SIZE as u64) <= MAX_BLOCKS,
        "file has too many blocks: {}",
        path.display()
    );
    let file = fs::File::open(path)?;
    ensure!(
        before_stamp == FileStamp::from_metadata(&file.metadata()?),
        "file replaced during scan: {}",
        path.display()
    );
    // A concurrently growing file must not keep the scan reading indefinitely
    // or grow its block list past the metadata size that was validated above.
    let mut file = file.take(before_stamp.size + 1);
    let mut hasher = blake3::Hasher::new();
    let mut blocks = Vec::new();
    let mut total = 0u64;
    let mut block_hasher = blake3::Hasher::new();
    let mut block_bytes = 0usize;
    let mut buf = [0; HASH_READ_SIZE];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        let mut offset = 0;
        while offset < n {
            let take = (CHUNK_SIZE - block_bytes).min(n - offset);
            block_hasher.update(&buf[offset..offset + take]);
            block_bytes += take;
            offset += take;
            if block_bytes == CHUNK_SIZE {
                blocks.push(hex::encode(block_hasher.finalize().as_bytes()));
                block_hasher = blake3::Hasher::new();
                block_bytes = 0;
            }
        }
        total += n as u64;
    }
    if block_bytes > 0 {
        blocks.push(hex::encode(block_hasher.finalize().as_bytes()));
    }
    let after_stamp = FileStamp::from_metadata(&fs::symlink_metadata(path)?);
    ensure!(
        before_stamp == after_stamp
            && before_stamp == FileStamp::from_metadata(&file.get_ref().metadata()?)
            && total == after_stamp.size,
        "file changed during scan: {}",
        path.display()
    );
    Ok((
        FileMeta {
            path: relative,
            size: total,
            hash: hex::encode(hasher.finalize().as_bytes()),
            blocks,
        },
        after_stamp,
    ))
}

type HashedFile = Result<(FileMeta, FileStamp)>;

fn hash_batch(
    batch: &[Pending],
    workers: usize,
    pool: &mut Option<rayon::ThreadPool>,
    stats: &mut ScanStats,
) -> Result<Vec<Option<HashedFile>>> {
    let to_hash = batch
        .iter()
        .filter(|item| matches!(item, Pending::Hash { .. }))
        .count();
    let large_to_hash = batch
        .iter()
        .filter(|item| matches!(item, Pending::Hash { size, .. } if *size >= LARGE_FILE))
        .count();
    // Keep the scan single-threaded for small deltas; create a pool only when enough
    // work can amortize its threads, including a pair of large files.
    if (to_hash >= 16 || large_to_hash >= 2) && workers > 1 && pool.is_none() {
        let active_workers = if to_hash >= 16 {
            workers
        } else {
            workers.min(4).min(to_hash)
        };
        *pool = Some(
            rayon::ThreadPoolBuilder::new()
                .num_threads(active_workers)
                .build()?,
        );
        stats.workers = active_workers;
    }
    let hash_one = |item: &Pending| match item {
        Pending::Hash { path, relative, .. } => Some(scan_file(path, relative.clone())),
        _ => None,
    };
    let results: Vec<_> = if let Some(pool) = pool.as_ref() {
        pool.install(|| batch.par_iter().map(hash_one).collect())
    } else {
        batch.iter().map(hash_one).collect()
    };
    Ok(results)
}

fn write_batch(
    db: &Connection,
    batch: &mut Vec<Pending>,
    workers: usize,
    pool: &mut Option<rayon::ThreadPool>,
    stats: &mut ScanStats,
    collect_delta: bool,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let results = hash_batch(batch, workers, pool, stats)?;
    let mut upsert_entry = db.prepare_cached(
        "INSERT INTO source_entries(kind,path,meta,stamp) VALUES(?1,?2,?3,?4) \
         ON CONFLICT(path) DO UPDATE SET
           kind=excluded.kind,meta=excluded.meta,stamp=excluded.stamp \
         WHERE source_entries.kind<>excluded.kind OR source_entries.meta IS NOT excluded.meta \
            OR source_entries.stamp IS NOT excluded.stamp",
    )?;
    let mut insert_seen = db.prepare_cached("INSERT INTO temp.scan_seen(path) VALUES(?1)")?;
    let mut previous_entry =
        db.prepare_cached("SELECT kind,meta FROM source_entries WHERE path=?1")?;
    for (item, result) in batch.drain(..).zip(results) {
        match item {
            Pending::Dir(path) => {
                insert_seen.execute([&path])?;
                if collect_delta {
                    stats.manifest_changed |= update_delta_entry(db, &path, 0, None, None)?;
                } else {
                    stats.manifest_changed |= upsert_entry.execute(params![
                        0,
                        path,
                        Option::<&[u8]>::None,
                        Option::<&[u8]>::None
                    ])? > 0;
                }
            }
            Pending::Cached { path } => {
                insert_seen.execute([&path])?;
                stats.files += 1;
                stats.cache_hits += 1;
            }
            Pending::Hash { .. } => {
                let (meta, stamp) = result.context("missing file hash result")??;
                let meta_json = serde_json::to_vec(&meta)?;
                insert_seen.execute([&meta.path])?;
                let previous: Option<(i64, Option<Vec<u8>>)> = previous_entry
                    .query_row([&meta.path], |row| Ok((row.get(0)?, row.get(1)?)))
                    .optional()?;
                stats.manifest_changed |= previous.as_ref().is_none_or(|(kind, old)| {
                    *kind != 1 || old.as_deref() != Some(meta_json.as_slice())
                });
                let stamp_json = serde_json::to_vec(&stamp)?;
                if collect_delta {
                    update_delta_entry(db, &meta.path, 1, Some(&meta_json), Some(&stamp_json))?;
                } else {
                    upsert_entry.execute(params![1, &meta.path, &meta_json, &stamp_json])?;
                }
                stats.files += 1;
                stats.hashed_files += 1;
            }
        }
    }
    Ok(())
}

pub fn prepare_manifest(
    config: &Config,
    db: &mut Connection,
    force_hash: bool,
    known_changed: bool,
    collect_delta: bool,
) -> Result<ScanStats> {
    config.check_root()?;
    // On restart, an unchanged tree can reuse the stored manifest without reading
    // every file again. Known watcher changes and full verification bypass this path.
    if !force_hash
        && !known_changed
        && let Some(previous) = crate::state::get(db, "inventory_fingerprint")?
    {
        let (fingerprint, skipped_symlinks) = inventory_fingerprint(config)?;
        if previous == fingerprint {
            crate::state::set(
                db,
                "skipped_symlinks",
                serde_json::to_string(&skipped_symlinks)?,
            )?;
            let files = manifest_file_count(db)?;
            return Ok(ScanStats {
                files,
                cache_hits: files,
                hashed_files: 0,
                workers: 1,
                reused_manifest: true,
                manifest_changed: false,
            });
        }
    }
    let transaction = db.transaction()?;
    transaction.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS scan_seen(path TEXT PRIMARY KEY);
         DELETE FROM temp.scan_seen;",
    )?;
    let mut batch = Vec::with_capacity(SCAN_BATCH);
    let mut pool = None;
    let exclusions = ExclusionIndex::new(&config.excludes);
    let mut inventory = inventory_hasher(config)?;
    let mut skipped_symlinks = Vec::new();
    let mut stats = ScanStats {
        workers: 1,
        ..ScanStats::default()
    };
    // The full scan can visit hundreds of thousands of files. Reuse the lookup
    // statement instead of preparing the same SQL once for every file.
    let mut cached_stamp_stmt =
        transaction.prepare_cached("SELECT stamp FROM source_entries WHERE path=?1 AND kind=1")?;
    let iter = WalkDir::new(&config.root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| include_source_entry(entry, config, &exclusions));
    for item in iter {
        let entry = item.context("scan directory")?;
        if entry.path() == config.root {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&config.root)?
            .to_str()
            .context("non-UTF8 path is unsupported")?
            .to_string();
        crate::config::valid_relative(&relative)?;
        if entry.file_name() == PRIVATE_DIR {
            anyhow::bail!(
                "nested rsync state directory is unsupported: {}",
                entry.path().display()
            );
        }
        let ty = entry.file_type();
        if ty.is_symlink() {
            hash_entry(&mut inventory, &relative, 2, None);
            skipped_symlinks.push(relative);
            continue;
        }
        if ty.is_dir() {
            hash_entry(&mut inventory, &relative, 0, None);
            batch.push(Pending::Dir(relative));
        } else if ty.is_file() {
            ensure!(
                !exclusions.protects_parent(&relative),
                "source file conflicts with excluded descendant: {relative}"
            );
            let path = entry.path().to_path_buf();
            let current_meta = fs::symlink_metadata(&path)?;
            ensure!(
                current_meta.is_file(),
                "file changed during scan: {}",
                path.display()
            );
            let current = FileStamp::from_metadata(&current_meta);
            hash_entry(&mut inventory, &relative, 1, Some(&current));
            let cached: Option<Vec<u8>> = if force_hash {
                None
            } else {
                cached_stamp_stmt
                    .query_row([&relative], |row| row.get::<_, Option<Vec<u8>>>(0))
                    .optional()?
                    .flatten()
            };
            let current_stamp = serde_json::to_vec(&current)?;
            batch.push(match cached {
                Some(stamp) if stamp == current_stamp => Pending::Cached { path: relative },
                _ => Pending::Hash {
                    path,
                    relative,
                    size: current.size,
                },
            });
            let large_pending = batch
                .iter()
                .filter(|item| matches!(item, Pending::Hash { size, .. } if *size >= LARGE_FILE))
                .count();
            if large_pending >= config.hash_workers.clamp(2, 4) {
                write_batch(
                    &transaction,
                    &mut batch,
                    config.hash_workers,
                    &mut pool,
                    &mut stats,
                    collect_delta,
                )?;
            }
        } else {
            anyhow::bail!("special file is unsupported: {}", entry.path().display());
        }
        if batch.len() >= SCAN_BATCH {
            write_batch(
                &transaction,
                &mut batch,
                config.hash_workers,
                &mut pool,
                &mut stats,
                collect_delta,
            )?;
        }
    }
    write_batch(
        &transaction,
        &mut batch,
        config.hash_workers,
        &mut pool,
        &mut stats,
        collect_delta,
    )?;
    if collect_delta {
        // The startup walk also catches edits made while no watcher was running.
        // Keep missing entries as tombstones before removing their metadata.
        let mut protected = config.excludes.clone();
        protected.extend(skipped_symlinks.iter().cloned());
        let protected = ExclusionIndex::new(&protected);
        let mut after = String::new();
        loop {
            let missing: Vec<(i64, String)> = transaction.prepare_cached(
                "SELECT kind,path FROM source_entries WHERE path>?1
                 AND NOT EXISTS (SELECT 1 FROM temp.scan_seen WHERE scan_seen.path=source_entries.path)
                 ORDER BY path LIMIT ?2",
            )?.query_map(params![after, SCAN_BATCH as i64], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            if missing.is_empty() {
                break;
            }
            after = missing
                .last()
                .context("nonempty missing path page")?
                .1
                .clone();
            for (kind, path) in missing {
                if !protected.contains(&path) {
                    transaction
                        .prepare_cached(
                            "INSERT OR IGNORE INTO source_outbox(kind,path) VALUES(?1,?2)",
                        )?
                        .execute(params![2 - kind, path])?;
                }
            }
        }
        // Do not replay tasks for newly protected symlinks or excluded paths.
        prune_protected_tasks(&transaction, &protected)?;
        transaction.execute(
            "DELETE FROM source_outbox WHERE kind=0 AND NOT EXISTS
             (SELECT 1 FROM temp.scan_seen WHERE scan_seen.path=source_outbox.path)",
            [],
        )?;
    }
    stats.manifest_changed |= transaction.execute(
        "DELETE FROM source_entries WHERE NOT EXISTS \
         (SELECT 1 FROM temp.scan_seen WHERE scan_seen.path=source_entries.path)",
        [],
    )? > 0;
    crate::state::set(
        &transaction,
        "skipped_symlinks",
        serde_json::to_string(&skipped_symlinks)?,
    )?;
    crate::state::set(
        &transaction,
        "inventory_fingerprint",
        inventory.finalize().to_hex(),
    )?;
    drop(cached_stamp_stmt);
    transaction.commit()?;
    Ok(stats)
}

fn remove_delta_tasks(db: &Connection, relative: &str) -> Result<()> {
    db.execute(
        "DELETE FROM source_outbox WHERE kind IN (0,1,2)
         AND (path=?1 OR (path>=?2 AND path<?3))",
        params![relative, format!("{relative}/"), format!("{relative}0")],
    )?;
    Ok(())
}

fn prune_protected_tasks(db: &Connection, exclusions: &ExclusionIndex) -> Result<()> {
    for kind in 0..=2 {
        let mut after = String::new();
        loop {
            let paths: Vec<String> = db.prepare_cached(
                "SELECT path FROM source_outbox WHERE kind=?1 AND path>?2 ORDER BY path LIMIT ?3",
            )?.query_map(params![kind, after, SCAN_BATCH as i64], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            if paths.is_empty() {
                break;
            }
            after = paths.last().context("nonempty task page")?.clone();
            for path in paths {
                if exclusions.contains(&path) {
                    db.prepare_cached("DELETE FROM source_outbox WHERE kind=?1 AND path=?2")?
                        .execute(params![kind, path])?;
                }
            }
        }
    }
    Ok(())
}

fn remove_delta_path(db: &Connection, relative: &str, send_deletion: bool) -> Result<()> {
    // Every descendant starts with "path/", which sorts before "path0". These
    // bounds let SQLite use the path indexes instead of scanning the whole table.
    let child_start = format!("{relative}/");
    let child_end = format!("{relative}0");
    if !send_deletion {
        remove_delta_tasks(db, relative)?;
    } else {
        // A symlink temporarily removes the source entry without deleting the
        // replica's managed file. When that symlink is later removed, the
        // source entry is already gone; still send its path so the replica can
        // apply its ownership check and remove the stale file promptly.
        db.execute(
            "INSERT OR IGNORE INTO source_outbox(kind,path) VALUES(1,?1)",
            [relative],
        )?;
        db.execute(
            "INSERT OR IGNORE INTO source_outbox(kind,path)
             SELECT 1,path FROM source_entries WHERE kind=1
             AND (path=?1 OR (path>=?2 AND path<?3))",
            params![relative, child_start, child_end],
        )?;
        db.execute(
            "INSERT OR IGNORE INTO source_outbox(kind,path)
             SELECT 2,path FROM source_entries WHERE kind=0
             AND (path=?1 OR (path>=?2 AND path<?3))",
            params![relative, child_start, child_end],
        )?;
    }
    db.execute(
        "DELETE FROM source_entries WHERE path=?1 OR (path>=?2 AND path<?3)",
        params![relative, child_start, child_end],
    )?;
    db.execute(
        "DELETE FROM source_outbox WHERE kind=0 AND (path=?1 OR (path>=?2 AND path<?3))",
        params![relative, child_start, child_end],
    )?;
    Ok(())
}

fn reconcile_delta_directory(
    db: &Connection,
    relative: &str,
    exclusions: &ExclusionIndex,
) -> Result<()> {
    let child_start = format!("{relative}/");
    let child_end = format!("{relative}0");
    let mut after = child_start.clone();
    loop {
        let missing: Vec<(i64, String)> = db
            .prepare(
                "SELECT kind,path FROM source_entries
                 WHERE path>=?1 AND path<?2 AND path>?3
                   AND NOT EXISTS
                     (SELECT 1 FROM temp.delta_seen WHERE delta_seen.path=source_entries.path)
                 ORDER BY path LIMIT ?4",
            )?
            .query_map(
                params![child_start, child_end, after, SCAN_BATCH as i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?
            .collect::<rusqlite::Result<_>>()?;
        if missing.is_empty() {
            break;
        }
        after = missing
            .last()
            .context("nonempty missing entry page")?
            .1
            .clone();
        for (kind, path) in missing {
            // A newly excluded path is left for the next full scan, which updates
            // the exclusion policy on both nodes before reconciling ownership.
            if exclusions.contains(&path) {
                continue;
            }
            let insert = match kind {
                0 => "INSERT OR IGNORE INTO source_outbox(kind,path) VALUES(2,?1)",
                1 => "INSERT OR IGNORE INTO source_outbox(kind,path) VALUES(1,?1)",
                _ => anyhow::bail!("invalid source entry kind"),
            };
            db.execute(insert, [&path])?;
            db.execute("DELETE FROM source_entries WHERE path=?1", [&path])?;
            db.execute(
                "DELETE FROM source_outbox WHERE kind=0 AND path=?1",
                [&path],
            )?;
        }
    }
    Ok(())
}

fn update_delta_entry(
    db: &Connection,
    relative: &str,
    kind: i64,
    meta: Option<&[u8]>,
    stamp: Option<&[u8]>,
) -> Result<bool> {
    let previous: Option<(i64, Option<Vec<u8>>)> = db
        .prepare_cached("SELECT kind,meta FROM source_entries WHERE path=?1")?
        .query_row([relative], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    let changed = previous
        .as_ref()
        .is_none_or(|(old_kind, old_meta)| *old_kind != kind || old_meta.as_deref() != meta);
    db.prepare_cached(
        "INSERT INTO source_entries(kind,path,meta,stamp) VALUES(?1,?2,?3,?4)
         ON CONFLICT(path) DO UPDATE SET
           kind=excluded.kind,meta=excluded.meta,stamp=excluded.stamp
         WHERE source_entries.kind<>excluded.kind OR source_entries.meta IS NOT excluded.meta
            OR source_entries.stamp IS NOT excluded.stamp",
    )?
    .execute(params![kind, relative, meta, stamp])?;
    if let Some((old_kind, _)) = previous.as_ref()
        && *old_kind != kind
    {
        db.prepare_cached("INSERT OR IGNORE INTO source_outbox(kind,path) VALUES(?1,?2)")?
            .execute(params![2 - old_kind, relative])?;
    }
    if changed {
        db.prepare_cached("INSERT OR IGNORE INTO source_outbox(kind,path) VALUES(0,?1)")?
            .execute([relative])?;
    }
    Ok(changed)
}

struct DeltaBatch {
    pending: Vec<Pending>,
    workers: usize,
    pool: Option<rayon::ThreadPool>,
}

impl DeltaBatch {
    fn flush(&mut self, db: &Connection, stats: &mut ScanStats) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let results = hash_batch(&self.pending, self.workers, &mut self.pool, stats)?;
        for result in results {
            let (meta, stamp) = result.context("missing delta hash result")??;
            let previous_kind: Option<i64> = db
                .prepare_cached("SELECT kind FROM source_entries WHERE path=?1")?
                .query_row([&meta.path], |row| row.get(0))
                .optional()?;
            if previous_kind == Some(0) {
                remove_delta_path(db, &meta.path, true)?;
            }
            update_delta_entry(
                db,
                &meta.path,
                1,
                Some(&serde_json::to_vec(&meta)?),
                Some(&serde_json::to_vec(&stamp)?),
            )?;
            stats.hashed_files += 1;
        }
        self.pending.clear();
        Ok(())
    }
}

enum AncestorChange {
    ProtectedBySymlink,
    Missing(String),
    Replaced(String),
}

fn source_ancestor_change(root: &Path, relative: &str) -> Result<Option<AncestorChange>> {
    let mut path = root.to_path_buf();
    let Some(parent) = Path::new(relative).parent() else {
        return Ok(None);
    };
    for component in parent.components() {
        path.push(component);
        let ancestor = || -> Result<String> {
            Ok(path
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF8 path is unsupported")?
                .to_owned())
        };
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Ok(Some(AncestorChange::ProtectedBySymlink));
            }
            Ok(meta) if !meta.is_dir() => {
                return Ok(Some(AncestorChange::Replaced(ancestor()?)));
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(Some(AncestorChange::Missing(ancestor()?)));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(None)
}

fn add_delta_entry(
    db: &Connection,
    path: &Path,
    relative: &str,
    direct_event: bool,
    stats: &mut ScanStats,
    batch: &mut DeltaBatch,
) -> Result<()> {
    crate::config::valid_relative(relative)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        remove_delta_path(db, relative, false)?;
    } else if metadata.is_dir() {
        update_delta_entry(db, relative, 0, None, None)?;
    } else if metadata.is_file() {
        // Directory notifications may include unchanged children. A direct file notification
        // is always hashed so a timestamp-only change cannot hide edited content.
        let stamp = serde_json::to_vec(&FileStamp::from_metadata(&metadata))?;
        if !direct_event {
            let cached: Option<Vec<u8>> = db
                .prepare_cached("SELECT stamp FROM source_entries WHERE path=?1 AND kind=1")?
                .query_row([relative], |row| row.get::<_, Option<Vec<u8>>>(0))
                .optional()?
                .flatten();
            if cached.as_deref() == Some(stamp.as_slice()) {
                stats.cache_hits += 1;
                return Ok(());
            }
        }
        batch.pending.push(Pending::Hash {
            path: path.to_path_buf(),
            relative: relative.to_owned(),
            size: metadata.len(),
        });
        if batch.pending.len() == SCAN_BATCH {
            batch.flush(db, stats)?;
        }
    } else {
        anyhow::bail!("unsupported source entry: {}", path.display());
    }
    Ok(())
}

/// Update only paths reported by the file watcher. The daily full scan repairs missed events.
pub fn prepare_delta(config: &Config, db: &mut Connection, paths: &[String]) -> Result<ScanStats> {
    config.check_root()?;
    let transaction = db.transaction()?;
    transaction.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS delta_seen(path TEXT PRIMARY KEY);
         CREATE TEMP TABLE IF NOT EXISTS delta_roots(path TEXT PRIMARY KEY, force_hash INTEGER NOT NULL);
         DELETE FROM temp.delta_roots;
         INSERT INTO temp.delta_roots SELECT path,0 FROM source_outbox WHERE kind=0;",
    )?;
    let exclusions = ExclusionIndex::new(&config.excludes);
    prune_protected_tasks(&transaction, &exclusions)?;
    {
        let mut insert = transaction.prepare_cached(
            "INSERT INTO temp.delta_roots(path,force_hash) VALUES(?1,1)
                             ON CONFLICT(path) DO UPDATE SET force_hash=1",
        )?;
        for relative in paths {
            crate::config::valid_relative(relative)?;
            insert.execute([relative])?;
        }
    }
    let mut stats = ScanStats {
        workers: 1,
        ..ScanStats::default()
    };
    // Sorted roots keep descendants of an ancestor together. Remember only the
    // last ancestor, even when millions of persisted tasks need refreshing.
    let mut handled_ancestor = None::<String>;
    let mut batch = DeltaBatch {
        pending: Vec::with_capacity(SCAN_BATCH),
        workers: config.hash_workers,
        pool: None,
    };
    let mut after = String::new();
    loop {
        let roots: Vec<(String, bool)> = transaction
            .prepare_cached(
                "SELECT path,force_hash FROM temp.delta_roots WHERE path>?1 ORDER BY path LIMIT ?2",
            )?
            .query_map(params![after, SCAN_BATCH as i64], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        if roots.is_empty() {
            break;
        }
        after = roots
            .last()
            .context("nonempty changed path page")?
            .0
            .clone();
        for (relative, force_hash) in roots {
            crate::config::valid_relative(&relative)?;
            if exclusions.contains(&relative) {
                remove_delta_tasks(&transaction, &relative)?;
                continue;
            }
            // A queued directory covers its descendants. Query the disk-backed roots
            // index instead of retaining an unbounded set of failed tasks in memory.
            let mut parent = relative.as_str();
            let mut covered = false;
            while let Some((prefix, _)) = parent.rsplit_once('/') {
                if transaction
                    .prepare_cached("SELECT EXISTS(SELECT 1 FROM temp.delta_roots WHERE path=?1)")?
                    .query_row([prefix], |row| row.get::<_, bool>(0))?
                {
                    covered = true;
                    break;
                }
                parent = prefix;
            }
            if covered {
                continue;
            }
            match source_ancestor_change(&config.root, &relative)? {
                Some(AncestorChange::ProtectedBySymlink) => {
                    remove_delta_path(&transaction, &relative, false)?;
                    continue;
                }
                Some(AncestorChange::Missing(ancestor)) => {
                    if handled_ancestor.as_deref() != Some(ancestor.as_str()) {
                        handled_ancestor = Some(ancestor.clone());
                        remove_delta_path(&transaction, &ancestor, true)?;
                    }
                    continue;
                }
                Some(AncestorChange::Replaced(ancestor)) => {
                    if handled_ancestor.as_deref() != Some(ancestor.as_str()) {
                        handled_ancestor = Some(ancestor.clone());
                        add_delta_entry(
                            &transaction,
                            &config.root.join(&ancestor),
                            &ancestor,
                            true,
                            &mut stats,
                            &mut batch,
                        )?;
                    }
                    continue;
                }
                None => {}
            }
            let path = config.root.join(&relative);
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_dir() => {
                    transaction.execute("DELETE FROM temp.delta_seen", [])?;
                    let walk = WalkDir::new(&path)
                        .follow_links(false)
                        .into_iter()
                        .filter_entry(|entry| {
                            let Some(child) = entry
                                .path()
                                .strip_prefix(&config.root)
                                .ok()
                                .and_then(|path| path.to_str())
                            else {
                                return true;
                            };
                            !exclusions.contains(child)
                        });
                    for item in walk {
                        let entry = item.context("scan changed directory")?;
                        let child = entry
                            .path()
                            .strip_prefix(&config.root)?
                            .to_str()
                            .context("non-UTF8 path is unsupported")?;
                        transaction.execute(
                            "INSERT OR IGNORE INTO temp.delta_seen(path) VALUES(?1)",
                            [child],
                        )?;
                        add_delta_entry(
                            &transaction,
                            entry.path(),
                            child,
                            false,
                            &mut stats,
                            &mut batch,
                        )?;
                    }
                    batch.flush(&transaction, &mut stats)?;
                    reconcile_delta_directory(&transaction, &relative, &exclusions)?;
                }
                Ok(_) => add_delta_entry(
                    &transaction,
                    &path,
                    &relative,
                    force_hash,
                    &mut stats,
                    &mut batch,
                )?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    remove_delta_path(&transaction, &relative, true)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => {
                    remove_delta_path(&transaction, &relative, true)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    batch.flush(&transaction, &mut stats)?;
    stats.files = delta_file_count(&transaction)?;
    // The fingerprint describes the last full inventory, not the updated rows.
    // Invalidate it so a restart cannot reuse it after a type change or reversion.
    transaction.execute("DELETE FROM kv WHERE key='inventory_fingerprint'", [])?;
    transaction.commit()?;
    Ok(stats)
}

pub fn delta_file_count(db: &Connection) -> Result<usize> {
    let count: i64 = db.query_row(
        "SELECT count(*) FROM source_outbox AS task
         JOIN source_entries AS entry ON entry.path=task.path
         WHERE task.kind=0 AND entry.kind=1",
        [],
        |row| row.get(0),
    )?;
    Ok(count.try_into()?)
}

pub fn delta_entry_count(db: &Connection) -> Result<usize> {
    let count: i64 = db.query_row(
        "SELECT count(*) FROM source_outbox WHERE kind=0",
        [],
        |row| row.get(0),
    )?;
    Ok(count.try_into()?)
}

pub fn delta_delete_count(db: &Connection) -> Result<usize> {
    let count: i64 = db.query_row(
        "SELECT count(*) FROM source_outbox WHERE kind=1",
        [],
        |row| row.get(0),
    )?;
    Ok(count.try_into()?)
}

pub fn delta_delete_page(db: &Connection, after: &str, limit: usize) -> Result<Vec<String>> {
    let mut statement = db.prepare(
        "SELECT path FROM source_outbox WHERE kind=1 AND path>?1 ORDER BY path LIMIT ?2",
    )?;
    Ok(statement
        .query_map(params![after, limit as i64], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn delta_delete_dir_count(db: &Connection) -> Result<usize> {
    let count: i64 = db.query_row(
        "SELECT count(*) FROM source_outbox WHERE kind=2",
        [],
        |row| row.get(0),
    )?;
    Ok(count.try_into()?)
}

pub fn delta_delete_dir_page(db: &Connection, after: &str, limit: usize) -> Result<Vec<String>> {
    let mut statement = db.prepare(
        "SELECT path FROM source_outbox
         WHERE kind=2 AND (?1='' OR length(path)<length(?1) OR (length(path)=length(?1) AND path<?1))
         ORDER BY length(path) DESC,path DESC LIMIT ?2",
    )?;
    Ok(statement
        .query_map(params![after, limit as i64], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn manifest_page(
    db: &Connection,
    after: &str,
    limit: usize,
    delta: bool,
) -> Result<Vec<(String, Entry)>> {
    let sql = if delta {
        "SELECT entry.kind,entry.path,entry.meta,coalesce(length(entry.meta),0)
         FROM source_outbox AS task JOIN source_entries AS entry ON entry.path=task.path
         WHERE task.kind=0 AND task.path>?1 ORDER BY task.path LIMIT ?2"
    } else {
        "SELECT kind,path,meta,coalesce(length(meta),0) FROM source_entries
         WHERE path>?1 ORDER BY path LIMIT ?2"
    };
    let mut stmt = db.prepare_cached(sql)?;
    let mut rows = stmt.query(params![after, limit as i64])?;
    let mut page = Vec::new();
    let mut bytes = 0usize;
    let mut small_bytes = 0usize;
    while let Some(row) = rows.next()? {
        let meta_len: usize = row.get::<_, i64>(3)?.try_into()?;
        if !page.is_empty() && bytes.saturating_add(meta_len) > 4 * 1024 * 1024 {
            break;
        }
        let kind: i64 = row.get(0)?;
        let path: String = row.get(1)?;
        let entry = match kind {
            0 => Entry::Dir { path: path.clone() },
            1 => {
                let bytes: Vec<u8> = row.get(2)?;
                let meta: FileMeta = serde_json::from_slice(&bytes)?;
                ensure!(meta.path == path, "manifest path mismatch");
                Entry::File { meta }
            }
            _ => anyhow::bail!("invalid manifest kind"),
        };
        let next_small_bytes = match &entry {
            Entry::File { meta } if meta.size <= SMALL_FILE_LIMIT => {
                small_bytes.saturating_add(meta.size as usize)
            }
            _ => small_bytes,
        };
        if !page.is_empty() && next_small_bytes > SMALL_BATCH_BYTES_LIMIT {
            break;
        }
        bytes += meta_len;
        small_bytes = next_small_bytes;
        page.push((path, entry));
    }
    Ok(page)
}

pub fn manifest_file_count(db: &Connection) -> Result<usize> {
    let count: i64 = db.query_row(
        "SELECT count(*) FROM source_entries WHERE kind=1",
        [],
        |row| row.get(0),
    )?;
    Ok(count.try_into()?)
}
