//! Trainer store: browse a remote GitHub repository, download trainer
//! packages, and install them into the local trainer directory.
//!
//! All network + install work is owned by Forge (it is the source of truth for
//! trainer state). The store is split into:
//!
//! * [`repo`] — stateless GitHub client (trees API + raw content) and catalog
//!   parsing.
//! * [`install`] — atomic, path-jailed package installation + validation.
//! * [`Store`] (this module) — catalog caching, an install job table, and the
//!   background worker thread.
//!
//! [`Store::install`] spawns a worker thread so a download never blocks the
//! engine's stdin loop or risks Relay's request timeout. The worker does only
//! network + disk + validation; the main thread performs the trainer reload
//! when a job reaches `Done` (see the `install_status` dispatch arm).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::error::{EngineError, EngineResult};
use crate::trainer::{self, InstalledTrainer};

pub mod install;
pub mod repo;

use repo::{CatalogEntry, RepoConfig, TreeResponse};

/// Monotonic install-job id counter (process-wide; there is one Store).
static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Cached catalog: the raw tree (used to enumerate a package's files on
/// install) plus the derived catalog entries.
struct CatalogCache {
    fetched: Instant,
    tree: TreeResponse,
    catalog: Vec<CatalogEntry>,
}

/// One install job's state, shared between the worker thread and the main
/// thread (which polls it via `install_status`).
#[derive(Clone)]
struct Job {
    app_id: u64,
    state: JobState,
    progress: f32,
    error: Option<String>,
    /// Whether the main thread has already hot-reloaded the trainer for this
    /// finished job (avoids reloading on every poll after `Done`).
    reloaded: bool,
}

/// Lifecycle of an install job. Surfaced to Cockpit as a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Downloading,
    Validating,
    Done,
    Failed,
}

impl JobState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Downloading => "downloading",
            Self::Validating => "validating",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }
}

/// A catalog entry annotated with local install status.
#[derive(Debug, Clone)]
pub struct CatalogItem {
    pub app_id: u64,
    pub game_name: String,
    pub trainer_name: String,
    pub version: String,
    pub author: Option<String>,
    pub file_count: usize,
    pub installed: bool,
    pub installed_version: Option<String>,
    pub update_available: bool,
}

/// Snapshot of an install job, returned by `install_status`.
#[derive(Debug, Clone)]
pub struct JobStatus {
    pub state: JobState,
    pub progress: f32,
    pub error: Option<String>,
    pub app_id: u64,
    pub reloaded: bool,
}

/// The trainer store. Cheap to clone (inner state is behind `Arc`); the clone
/// is moved into the worker thread.
#[derive(Clone)]
pub struct Store {
    cfg: RepoConfig,
    cache: Arc<Mutex<Option<CatalogCache>>>,
    jobs: Arc<Mutex<HashMap<String, Job>>>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub fn new() -> Self {
        Self::with_config(RepoConfig::from_env())
    }

    pub fn with_config(cfg: RepoConfig) -> Self {
        Self {
            cfg,
            cache: Arc::new(Mutex::new(None)),
            jobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn config(&self) -> &RepoConfig {
        &self.cfg
    }

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, Option<CatalogCache>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_jobs(&self) -> std::sync::MutexGuard<'_, HashMap<String, Job>> {
        self.jobs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Ensure the catalog cache is populated and fresh. Fetches (one trees-API
    /// call + one raw fetch per trainer for metadata) only when cold or past
    /// the TTL; otherwise returns immediately.
    fn ensure_tree(&self) -> EngineResult<()> {
        {
            let lock = self.lock_cache();
            if let Some(c) = lock.as_ref() {
                if c.fetched.elapsed() < repo::ttl() {
                    return Ok(());
                }
            }
        }
        let tree = repo::fetch_tree(&self.cfg)?;
        let catalog = repo::build_catalog(&self.cfg, &tree)?;
        let mut lock = self.lock_cache();
        *lock = Some(CatalogCache {
            fetched: Instant::now(),
            tree,
            catalog,
        });
        Ok(())
    }

    /// File list (paths relative to the package) for `app_id`, fetching the
    /// tree if needed. `RepoNotFound` if the app is not in the repository.
    fn package_files(&self, app_id: u64) -> EngineResult<Vec<String>> {
        self.ensure_tree()?;
        let lock = self.lock_cache();
        let cache = lock.as_ref().expect("cache populated by ensure_tree");
        let pkgs = repo::parse_packages(&cache.tree);
        pkgs.into_iter()
            .find(|(id, _)| *id == app_id)
            .map(|(_, files)| files)
            .ok_or(EngineError::RepoNotFound)
    }

    /// Browse the repository catalog, annotated with local install status and
    /// update availability. Blocks on the network only when the cache is cold.
    pub fn list_catalog(&self) -> EngineResult<Vec<CatalogItem>> {
        self.ensure_tree()?;
        let installed: HashMap<u64, InstalledTrainer> = trainer::installed_trainers()
            .into_iter()
            .map(|t| (t.app_id, t))
            .collect();
        let lock = self.lock_cache();
        let cache = lock.as_ref().expect("cache populated");
        let mut out = Vec::with_capacity(cache.catalog.len());
        for e in &cache.catalog {
            let inst = installed.get(&e.app_id);
            let installed_version = inst.map(|t| t.version.clone());
            let update_available = match inst {
                Some(t) => t.version != e.version,
                None => false,
            };
            out.push(CatalogItem {
                app_id: e.app_id,
                game_name: e.game_name.clone(),
                trainer_name: e.trainer_name.clone(),
                version: e.version.clone(),
                author: e.author.clone(),
                file_count: e.file_count,
                installed: inst.is_some(),
                installed_version,
                update_available,
            });
        }
        Ok(out)
    }

    /// Start installing the trainer for `app_id` in the background. Returns a
    /// job id immediately; poll with [`Store::install_status`].
    pub fn install(&self, app_id: u64) -> EngineResult<String> {
        let job_id = format!("job-{}", JOB_COUNTER.fetch_add(1, Ordering::Relaxed));
        {
            let mut jobs = self.lock_jobs();
            jobs.insert(
                job_id.clone(),
                Job {
                    app_id,
                    state: JobState::Queued,
                    progress: 0.0,
                    error: None,
                    reloaded: false,
                },
            );
        }
        let store = self.clone();
        let job_id_move = job_id.clone();
        std::thread::spawn(move || {
            store.run_install(app_id, job_id_move);
        });
        Ok(job_id)
    }

    /// Worker entry point: download → validate → swap. Runs off the main
    /// thread; updates the shared job table as it progresses. Touches no
    /// [`crate::state::EngineState`] — the main thread reloads the trainer
    /// when the job reaches `Done`.
    fn run_install(&self, app_id: u64, job_id: String) {
        self.set_job(&job_id, JobState::Downloading, 0.0, None);
        let result = (|| -> EngineResult<()> {
            let files = self.package_files(app_id)?;
            if files.is_empty() {
                return Err(EngineError::RepoNotFound);
            }
            let total = files.len();
            let staging = install::download_package(&self.cfg, app_id, &files, &|done| {
                let p = (done as f32) / (total as f32).max(1.0);
                self.set_job(&job_id, JobState::Downloading, p, None);
            })?;
            self.set_job(&job_id, JobState::Validating, 1.0, None);
            install::finalize_package(&staging, app_id)?;
            Ok(())
        })();
        match result {
            Ok(()) => self.set_job(&job_id, JobState::Done, 1.0, None),
            Err(e) => self.set_job(&job_id, JobState::Failed, 0.0, Some(e.message())),
        }
    }

    fn set_job(&self, job_id: &str, state: JobState, progress: f32, error: Option<String>) {
        let mut jobs = self.lock_jobs();
        if let Some(job) = jobs.get_mut(job_id) {
            job.state = state;
            job.progress = progress;
            job.error = error;
        }
    }

    /// Current status of an install job. `RepoJobNotFound` for an unknown id.
    pub fn install_status(&self, job_id: &str) -> EngineResult<JobStatus> {
        let jobs = self.lock_jobs();
        let job = jobs.get(job_id).ok_or(EngineError::RepoJobNotFound)?;
        Ok(JobStatus {
            state: job.state,
            progress: job.progress,
            error: job.error.clone(),
            app_id: job.app_id,
            reloaded: job.reloaded,
        })
    }

    /// Record that the main thread has hot-reloaded the trainer for a finished
    /// job, so the reload is attempted only once.
    pub fn mark_reloaded(&self, job_id: &str) {
        let mut jobs = self.lock_jobs();
        if let Some(job) = jobs.get_mut(job_id) {
            job.reloaded = true;
        }
    }

    /// Remove an installed trainer package (idempotent).
    pub fn uninstall(&self, app_id: u64) -> EngineResult<()> {
        install::uninstall_package(app_id)
    }

    /// Locally installed trainers (no network).
    pub fn list_installed(&self) -> EngineResult<Vec<InstalledTrainer>> {
        Ok(trainer::installed_trainers())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_state_strings() {
        assert_eq!(JobState::Queued.as_str(), "queued");
        assert_eq!(JobState::Downloading.as_str(), "downloading");
        assert_eq!(JobState::Validating.as_str(), "validating");
        assert_eq!(JobState::Done.as_str(), "done");
        assert_eq!(JobState::Failed.as_str(), "failed");
    }

    #[test]
    fn install_status_unknown_job() {
        let store = Store::with_config(RepoConfig {
            owner: "o".into(),
            repo: "r".into(),
            git_ref: "main".into(),
            token: None,
        });
        let err = store.install_status("nope").unwrap_err();
        assert!(matches!(err, EngineError::RepoJobNotFound));
    }
}
