use crate::config::{Config, Role};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
};

const SCHEMA_VERSION: i64 = 1;

pub fn lock_run(config: &Config) -> Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(config.private_path().join("run.lock"))?;
    file.try_lock()
        .context("another rsync run process is active for this root")?;
    Ok(file)
}

pub fn open(config: &Config) -> Result<Connection> {
    let mut db = Connection::open(config.db_path())?;
    db.execute_batch(
        "PRAGMA journal_mode=WAL;
        PRAGMA temp_store=FILE;",
    )?;
    let version: i64 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    match version {
        0 => initialize_schema(config, &mut db)?,
        SCHEMA_VERSION => {}
        _ => anyhow::bail!("unsupported state database schema {version}"),
    }
    let required = match config.role {
        Role::Source => "source_entries",
        Role::Replica => "replica_files",
    };
    ensure!(
        table_exists(&db, required)?,
        "state database is missing {required}"
    );
    if matches!(config.role, Role::Source) {
        // Tasks contain paths only; file metadata stays in source_entries.
        // Separate kinds allow a type replacement to delete before publishing.
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS source_outbox (
                kind INTEGER NOT NULL CHECK(kind IN (0,1,2)),
                path TEXT NOT NULL,
                PRIMARY KEY(kind,path)
            ) WITHOUT ROWID;",
        )?;
    }
    Ok(db)
}

fn table_exists(db: &Connection, name: &str) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [name],
        |row| row.get(0),
    )?)
}

// Fresh roots start at schema v1.
fn initialize_schema(config: &Config, db: &mut Connection) -> Result<()> {
    let transaction = db.transaction()?;
    transaction.execute_batch("CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);")?;
    match config.role {
        Role::Source => transaction.execute_batch(
            "CREATE TABLE source_entries (
                seq INTEGER PRIMARY KEY,
                kind INTEGER NOT NULL CHECK(kind IN (0,1)),
                path TEXT NOT NULL,
                meta BLOB,
                stamp BLOB,
                CHECK((kind=0 AND meta IS NULL AND stamp IS NULL)
                   OR (kind=1 AND meta IS NOT NULL))
            );
            CREATE UNIQUE INDEX source_entries_path ON source_entries(path);",
        )?,
        Role::Replica => transaction.execute_batch(
            "CREATE TABLE replica_files (
                path TEXT PRIMARY KEY,
                stamp BLOB NOT NULL,
                hash TEXT NOT NULL,
                verified_round INTEGER
            );
            CREATE TABLE staging (path TEXT PRIMARY KEY, hash TEXT NOT NULL, bitmap BLOB NOT NULL);
            CREATE TABLE managed_dirs (path TEXT PRIMARY KEY, depth INTEGER NOT NULL);
            CREATE INDEX managed_dirs_depth_path ON managed_dirs(depth DESC, path DESC);",
        )?,
    }
    transaction.execute_batch("PRAGMA user_version=1;")?;
    transaction.commit()?;
    Ok(())
}

pub fn open_readonly(config: &Config) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        config.db_path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?)
}

pub fn get(db: &Connection, key: &str) -> Result<Option<String>> {
    Ok(db
        .query_row("SELECT value FROM kv WHERE key=?1", [key], |r| r.get(0))
        .optional()?)
}

pub fn set(db: &Connection, key: &str, value: impl AsRef<str>) -> Result<()> {
    db.execute("INSERT INTO kv(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key, value.as_ref()])?;
    Ok(())
}

pub fn acknowledge_tasks(db: &Connection, kind: i64, paths: &[String]) -> Result<()> {
    let transaction = db.unchecked_transaction()?;
    {
        let mut delete =
            transaction.prepare_cached("DELETE FROM source_outbox WHERE kind=?1 AND path=?2")?;
        for path in paths {
            delete.execute(params![kind, path])?;
        }
    }
    transaction.commit()?;
    Ok(())
}

pub fn staging(db: &Connection, path: &str) -> Result<Option<(String, Vec<u8>)>> {
    Ok(db
        .query_row(
            "SELECT hash,bitmap FROM staging WHERE path=?1",
            [path],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}

pub fn set_staging(db: &Connection, path: &str, hash: &str, bitmap: &[u8]) -> Result<()> {
    db.execute("INSERT INTO staging(path,hash,bitmap) VALUES(?1,?2,?3) ON CONFLICT(path) DO UPDATE SET hash=excluded.hash,bitmap=excluded.bitmap", params![path, hash, bitmap])?;
    Ok(())
}

// Keep publication intent until the target's ownership/cache row is committed.
// Small files need no resume bitmap, but still need recovery across a crash
// between rename() and flush_verified().
pub fn begin_publications(db: &Connection, files: &[(&str, &str)]) -> Result<()> {
    let transaction = db.unchecked_transaction()?;
    {
        let mut stage = transaction.prepare_cached(
            "INSERT INTO staging(path,hash,bitmap) VALUES(?1,?2,X'')
             ON CONFLICT(path) DO UPDATE SET hash=excluded.hash,bitmap=excluded.bitmap",
        )?;
        for (path, hash) in files {
            stage.execute(params![path, hash])?;
        }
    }
    transaction.commit()?;
    Ok(())
}

pub fn staging_page(db: &Connection, after: &str, limit: usize) -> Result<Vec<(String, String)>> {
    let mut query =
        db.prepare_cached("SELECT path,hash FROM staging WHERE path>?1 ORDER BY path LIMIT ?2")?;
    Ok(query
        .query_map(params![after, limit as i64], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn clear_staging(db: &Connection, path: &str) -> Result<()> {
    db.execute("DELETE FROM staging WHERE path=?1", [path])?;
    Ok(())
}

pub fn clear_all_staging(db: &Connection) -> Result<()> {
    db.execute("DELETE FROM staging", [])?;
    Ok(())
}

pub fn checkpoint(db: &Connection) -> Result<()> {
    let busy: i64 = db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
    ensure!(busy == 0, "state database checkpoint is busy");
    Ok(())
}

pub fn replica_cached_file(
    db: &Connection,
    path: &str,
    stamp: &[u8],
) -> Result<Option<(String, Option<i64>)>> {
    let mut query =
        db.prepare_cached("SELECT stamp,hash,verified_round FROM replica_files WHERE path=?1")?;
    let cached: Option<(Vec<u8>, String, Option<i64>)> = query
        .query_row([path], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .optional()?;
    Ok(cached
        .and_then(|(old_stamp, old_hash, round)| (old_stamp == stamp).then_some((old_hash, round))))
}

pub struct VerifiedUpdate {
    pub path: String,
    pub stamp: Vec<u8>,
    pub hash: String,
    pub round: Option<i64>,
}

pub fn begin_verify_round(db: &Connection, due: bool) -> Result<Option<i64>> {
    // Reuse an interrupted round so already verified files can be recognized after
    // a disconnect; its progress is discarded only after the full pass succeeds.
    if let Some(round) = get(db, "replica_verify_active")? {
        return Ok(Some(round.parse()?));
    }
    if !due {
        return Ok(None);
    }
    let next = get(db, "replica_verify_next")?
        .map(|value| value.parse::<i64>())
        .transpose()?
        .unwrap_or(0)
        .checked_add(1)
        .context("verification round overflow")?;
    let transaction = db.unchecked_transaction()?;
    set(&transaction, "replica_verify_next", next.to_string())?;
    set(&transaction, "replica_verify_active", next.to_string())?;
    transaction.commit()?;
    Ok(Some(next))
}

pub fn flush_verified(db: &Connection, pending: &mut Vec<VerifiedUpdate>) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let transaction = db.unchecked_transaction()?;
    {
        let mut cache = transaction.prepare(
            "INSERT INTO replica_files(path,stamp,hash,verified_round) VALUES(?1,?2,?3,?4) \
             ON CONFLICT(path) DO UPDATE SET
               stamp=excluded.stamp,hash=excluded.hash,verified_round=excluded.verified_round
             WHERE replica_files.stamp<>excluded.stamp OR replica_files.hash<>excluded.hash
                OR replica_files.verified_round IS NOT excluded.verified_round",
        )?;
        let mut published = transaction.prepare_cached("DELETE FROM staging WHERE path=?1")?;
        let mut directory = transaction
            .prepare_cached("INSERT OR IGNORE INTO managed_dirs(path,depth) VALUES(?1,?2)")?;
        let mut directories = HashSet::new();
        for update in pending.iter() {
            cache.execute(params![
                &update.path,
                &update.stamp,
                &update.hash,
                update.round
            ])?;
            // A published file also establishes its source parent directories.
            // Record them here so an interrupted entry batch can later remove
            // empty parents without claiming unrelated replica-only content.
            for (depth, (index, _)) in update.path.match_indices('/').enumerate() {
                let parent = &update.path[..index];
                if directories.insert(parent) {
                    directory.execute(params![parent, (depth + 1) as i64])?;
                }
            }
            published.execute([&update.path])?;
        }
    }
    transaction.commit()?;
    pending.clear();
    Ok(())
}

pub fn finish_verify_round(db: &Connection, completed_at: u64) -> Result<()> {
    let transaction = db.unchecked_transaction()?;
    ensure!(
        get(&transaction, "replica_verify_active")?.is_some(),
        "missing active verification round"
    );
    set(
        &transaction,
        "replica_last_full_verify",
        completed_at.to_string(),
    )?;
    transaction.execute("DELETE FROM kv WHERE key='replica_verify_active'", [])?;
    transaction.commit()?;
    Ok(())
}
