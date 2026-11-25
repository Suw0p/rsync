use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt, fs,
    io::ErrorKind,
    net::SocketAddr,
    path::{Path, PathBuf},
};

pub const PRIVATE_DIR: &str = ".rsync";
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;
pub const MAX_BLOCKS: u64 = 200_000;

fn default_hash_workers() -> usize {
    2
}

fn default_verify_interval() -> u64 {
    24 * 60 * 60
}

fn default_web_addr() -> SocketAddr {
    "0.0.0.0:8787".parse().expect("valid web address")
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Source,
    Replica,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Source => "source",
                Self::Replica => "replica",
            }
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub role: Role,
    pub root: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<SocketAddr>,
    #[serde(default = "default_web_addr")]
    pub web_addr: SocketAddr,
    pub scan_interval_secs: u64,
    pub retention_days: u64,
    #[serde(default = "default_hash_workers")]
    pub hash_workers: usize,
    #[serde(default = "default_verify_interval")]
    pub verify_interval_secs: u64,
    #[serde(default)]
    pub excludes: Vec<String>,
    #[serde(default)]
    pub first_sync_confirmed: bool,
}

impl Config {
    pub fn init(
        root: PathBuf,
        role: Role,
        addr: Option<String>,
        web_addr: Option<String>,
        start_immediately: bool,
    ) -> Result<Self> {
        let addr = addr
            .map(|value| {
                value
                    .parse::<SocketAddr>()
                    .context("address must be IP:port")
            })
            .transpose()?;
        validate_address(role, addr)?;
        let web_addr = web_addr
            .map(|value| value.parse().context("web address must be IP:port"))
            .transpose()?
            .unwrap_or_else(default_web_addr);
        ensure!(
            role == Role::Source || web_addr == default_web_addr(),
            "web address is source-only"
        );
        ensure!(
            role == Role::Source || !start_immediately,
            "start-immediately is source-only"
        );
        fs::create_dir_all(&root).context("create root")?;
        let root = fs::canonicalize(&root)?;
        ensure!(root.is_dir(), "root must be a directory");
        let private = root.join(PRIVATE_DIR);
        ensure!(!path_entry_exists(&private)?, "root already initialized");
        fs::create_dir(&private)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
        }
        let config = Self {
            role,
            root,
            addr,
            web_addr,
            scan_interval_secs: 86_400,
            retention_days: 7,
            hash_workers: default_hash_workers(),
            verify_interval_secs: default_verify_interval(),
            excludes: Vec::new(),
            first_sync_confirmed: role == Role::Replica || start_immediately,
        };
        fs::write(config.config_path(), toml::to_string_pretty(&config)?)?;
        fs::create_dir(config.tmp_path())?;
        fs::create_dir(config.history_path())?;
        Ok(config)
    }

    pub fn load(root: PathBuf) -> Result<Self> {
        let root = fs::canonicalize(root).context("root does not exist")?;
        ensure!(
            fs::symlink_metadata(root.join(PRIVATE_DIR))?
                .file_type()
                .is_dir(),
            ".rsync state path must be a directory"
        );
        let text = fs::read_to_string(root.join(PRIVATE_DIR).join("config.toml"))?;
        let config: Self = toml::from_str(&text)?;
        ensure!(
            config.root == root,
            "configured root differs from requested root"
        );
        ensure!(
            config.scan_interval_secs > 0 && config.retention_days <= 3650,
            "invalid timing settings"
        );
        ensure!(
            (1..=8).contains(&config.hash_workers),
            "hash_workers must be between 1 and 8"
        );
        ensure!(
            config.verify_interval_secs > 0,
            "verify_interval_secs must be positive"
        );
        validate_address(config.role, config.addr)?;
        ensure!(config.private_path().is_dir(), "root marker is missing");
        validate_excludes(&config.excludes)?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        validate_address(self.role, self.addr)?;
        validate_excludes(&self.excludes)?;
        let temp = self.tmp_path().join("config.toml.new");
        fs::write(&temp, toml::to_string_pretty(self)?)?;
        fs::rename(temp, self.config_path())?;
        Ok(())
    }

    pub fn private_path(&self) -> PathBuf {
        self.root.join(PRIVATE_DIR)
    }
    pub fn config_path(&self) -> PathBuf {
        self.private_path().join("config.toml")
    }
    pub fn ca_path(&self) -> PathBuf {
        self.private_path().join("ca.pem")
    }
    pub fn cert_path(&self) -> PathBuf {
        self.private_path().join("node.pem")
    }
    pub fn key_path(&self) -> PathBuf {
        self.private_path().join("node.key")
    }
    pub fn peer_path(&self) -> PathBuf {
        self.private_path().join("peer-ca.pem")
    }
    pub fn db_path(&self) -> PathBuf {
        self.private_path().join("state.db")
    }
    pub fn tmp_path(&self) -> PathBuf {
        self.private_path().join("tmp")
    }
    pub fn history_path(&self) -> PathBuf {
        self.private_path().join("history")
    }
    pub fn pause_path(&self) -> PathBuf {
        self.private_path().join("paused")
    }

    pub fn check_root(&self) -> Result<()> {
        let canonical = fs::canonicalize(&self.root).context("root unavailable")?;
        if canonical != self.root || !self.config_path().is_file() || !self.ca_path().is_file() {
            bail!("root marker is missing or root changed; refusing synchronization");
        }
        Ok(())
    }
}

fn path_entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub fn validate_address(role: Role, addr: Option<SocketAddr>) -> Result<()> {
    if role == Role::Replica {
        ensure!(addr.is_some(), "replica listen address is required");
    }
    if let Some(addr) = addr {
        ensure!(addr.port() != 0, "address port must not be zero");
        ensure!(
            role == Role::Replica || !addr.ip().is_unspecified(),
            "source target must be a reachable IP:port"
        );
    }
    Ok(())
}

pub fn validate_excludes(excludes: &[String]) -> Result<()> {
    ensure!(excludes.len() <= 10_000, "too many exclusions");
    for path in excludes {
        valid_relative(path)?;
        if let Some(name) = path.strip_prefix("**/") {
            ensure!(
                !name.is_empty() && !name.contains('/') && !name.contains('*'),
                "recursive exclusion must be **/name: {path}"
            );
        }
        ensure!(
            path.split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."),
            "exclusion must be a clean relative path: {path}"
        );
        ensure!(path.len() <= 4096, "exclusion path too long");
    }
    Ok(())
}

pub fn validate_replica_settings(retention_days: u64, verify_interval_secs: u64) -> Result<()> {
    ensure!(
        retention_days <= 3650,
        "history retention must be between 0 and 3650 days"
    );
    ensure!(
        (1..=31_536_000).contains(&verify_interval_secs),
        "verification interval must be between 1 and 31536000 seconds"
    );
    Ok(())
}

pub fn validate_source_settings(
    scan_interval_secs: u64,
    hash_workers: usize,
    verify_interval_secs: u64,
) -> Result<()> {
    ensure!(
        (1..=86_400).contains(&scan_interval_secs),
        "scan interval must be between 1 and 86400 seconds"
    );
    ensure!(
        (1..=8).contains(&hash_workers),
        "hash workers must be between 1 and 8"
    );
    ensure!(
        (1..=31_536_000).contains(&verify_interval_secs),
        "verification interval must be between 1 and 31536000 seconds"
    );
    Ok(())
}

pub struct ExclusionIndex {
    exact: HashSet<String>,
    parents: HashSet<String>,
    anywhere: HashSet<String>,
}

impl ExclusionIndex {
    pub fn new(paths: &[String]) -> Self {
        let mut exact = HashSet::new();
        let mut parents = HashSet::new();
        let mut anywhere = HashSet::new();
        for path in paths {
            if let Some(name) = path.strip_prefix("**/") {
                anywhere.insert(name.to_owned());
                continue;
            }
            exact.insert(path.clone());
            for (index, byte) in path.bytes().enumerate() {
                if byte == b'/' {
                    parents.insert(path[..index].to_owned());
                }
            }
        }
        Self {
            exact,
            parents,
            anywhere,
        }
    }

    pub fn contains(&self, path: &str) -> bool {
        if self.exact.contains(path) || path.split('/').any(|part| self.anywhere.contains(part)) {
            return true;
        }
        let mut parent = path;
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if self.exact.contains(prefix) {
                return true;
            }
            parent = prefix;
        }
        false
    }

    pub fn protects_parent(&self, path: &str) -> bool {
        self.parents.contains(path)
    }
}

pub fn valid_relative(path: &str) -> Result<&Path> {
    ensure!(
        !path.is_empty()
            && path.len() <= 4096
            && !path.contains('\\')
            && !path.chars().any(char::is_control),
        "invalid path"
    );
    ensure!(
        path.split('/')
            .all(|part| { !part.is_empty() && part != "." && part != ".." && part != PRIVATE_DIR }),
        "unsafe path: {path}"
    );
    Ok(Path::new(path))
}
