//! GitHub repository client for the trainer store.
//!
//! Trainers live in a public GitHub repo under `trainers/<appid>/` (one
//! trainer package per Steam AppID, each a directory containing `trainer.json`
//! plus an optional `scripts/` tree). Discovery uses the GitHub **git trees
//! API** (one call, cached upstream) and file contents are fetched via
//! `raw.githubusercontent.com` (a CDN, not rate-limited like the API).
//!
//! This module is stateless: it holds only a [`RepoConfig`] and performs HTTP
//! + JSON parsing. Caching and install orchestration live in [`super`].

use std::collections::BTreeMap;
use std::io::Read;

use serde::Deserialize;

use crate::error::{EngineError, EngineResult};

const USER_AGENT: &str = "deckforge-engine";
const TTL_SECS: u64 = 600;

/// Repository location + optional auth. Defaults point at the public
/// `firmanjml/deckforge-trainers` repo on `main`; every field is overridable
/// via `DECKFORGE_REPO_*` env vars.
#[derive(Debug, Clone)]
pub struct RepoConfig {
    pub owner: String,
    pub repo: String,
    pub git_ref: String,
    pub token: Option<String>,
}

impl RepoConfig {
    pub fn from_env() -> Self {
        Self {
            owner: std::env::var("DECKFORGE_REPO_OWNER")
                .unwrap_or_else(|_| "firmanjml".to_string()),
            repo: std::env::var("DECKFORGE_REPO_NAME")
                .unwrap_or_else(|_| "deckforge-trainers".to_string()),
            git_ref: std::env::var("DECKFORGE_REPO_REF").unwrap_or_else(|_| "main".to_string()),
            token: std::env::var("DECKFORGE_REPO_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }

    fn api_base(&self) -> String {
        format!("https://api.github.com/repos/{}/{}/", self.owner, self.repo)
    }

    fn raw_base(&self) -> String {
        format!(
            "https://raw.githubusercontent.com/{}/{}/{}/",
            self.owner, self.repo, self.git_ref
        )
    }
}

/// Catalog cache freshness window.
pub fn ttl() -> std::time::Duration {
    std::time::Duration::from_secs(TTL_SECS)
}

// ---------------------------------------------------------------------------
// GitHub API / raw response shapes
// ---------------------------------------------------------------------------

/// `GET /repos/{owner}/{repo}/git/trees/{ref}?recursive=1` response.
#[derive(Debug, Clone, Deserialize)]
pub struct TreeResponse {
    pub tree: Vec<TreeEntry>,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TreeEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub entry_type: String, // "blob" | "tree"
}

/// One trainer package as advertised by the repository.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub app_id: u64,
    pub game_name: String,
    pub trainer_name: String,
    pub version: String,
    pub author: Option<String>,
    pub file_count: usize,
}

// Lightweight metadata parsed from a remote `trainer.json` (only the fields
// the catalog needs; does not require the full definition to be valid).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrainerMeta {
    game: MetaGame,
    trainer: MetaTrainer,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetaGame {
    #[allow(dead_code)]
    steam_app_id: u64,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetaTrainer {
    name: String,
    version: String,
    #[serde(default)]
    author: Option<String>,
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

fn http_get(cfg: &RepoConfig, url: &str, accept: &str) -> EngineResult<ureq::Response> {
    // ureq 2's `Request::set` consumes and returns `self`, so we chain.
    let req = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", accept);
    let req = if let Some(tok) = &cfg.token {
        req.set("Authorization", &format!("Bearer {tok}"))
    } else {
        req
    };
    req.call().map_err(|e| map_http_err(e, url))
}

fn get_text(cfg: &RepoConfig, url: &str, accept: &str) -> EngineResult<String> {
    let resp = http_get(cfg, url, accept)?;
    resp.into_string()
        .map_err(|e| EngineError::RepoNetworkError(format!("read body {url}: {e}")))
}

fn get_bytes(cfg: &RepoConfig, url: &str, accept: &str) -> EngineResult<Vec<u8>> {
    let resp = http_get(cfg, url, accept)?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| EngineError::RepoNetworkError(format!("read body {url}: {e}")))?;
    Ok(buf)
}

fn map_http_err(e: ureq::Error, url: &str) -> EngineError {
    match e {
        ureq::Error::Status(404, _) => EngineError::RepoNotFound,
        ureq::Error::Status(403, resp) => {
            if resp.header("x-ratelimit-remaining") == Some("0") {
                EngineError::RepoRateLimited
            } else {
                EngineError::RepoNetworkError(format!("HTTP 403 for {url}"))
            }
        }
        ureq::Error::Status(code, _) => {
            EngineError::RepoNetworkError(format!("HTTP {code} for {url}"))
        }
        ureq::Error::Transport(t) => {
            EngineError::RepoNetworkError(format!("transport error for {url}: {t}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Fetch operations
// ---------------------------------------------------------------------------

/// Fetch the full file tree (recursive). One GitHub API call.
pub fn fetch_tree(cfg: &RepoConfig) -> EngineResult<TreeResponse> {
    let url = format!("{}git/trees/{}?recursive=1", cfg.api_base(), cfg.git_ref);
    let text = get_text(cfg, &url, "application/vnd.github+json")?;
    let resp: TreeResponse = serde_json::from_str(&text)
        .map_err(|e| EngineError::RepoNetworkError(format!("parse trees API response: {e}")))?;
    if resp.truncated {
        eprintln!(
            "[store] warning: GitHub tree response was truncated; some trainers may be missing from the catalog"
        );
    }
    Ok(resp)
}

/// Fetch a single file's text content from `raw.githubusercontent.com`.
pub fn fetch_raw_text(cfg: &RepoConfig, path: &str) -> EngineResult<String> {
    let url = format!("{}{}", cfg.raw_base(), path);
    get_text(cfg, &url, "text/plain")
}

/// Fetch a single file's raw bytes from `raw.githubusercontent.com`.
pub fn fetch_raw_bytes(cfg: &RepoConfig, path: &str) -> EngineResult<Vec<u8>> {
    let url = format!("{}{}", cfg.raw_base(), path);
    get_bytes(cfg, &url, "application/octet-stream")
}

// ---------------------------------------------------------------------------
// Catalog parsing (pure, no network)
// ---------------------------------------------------------------------------

/// Group tree blob entries into trainer packages: `(app_id, [relative file
/// paths within the package])`. Files are sorted; only `trainers/<appid>/...`
/// blob paths are considered. A package with no files is omitted.
pub fn parse_packages(tree: &TreeResponse) -> Vec<(u64, Vec<String>)> {
    let mut map: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for e in &tree.tree {
        if e.entry_type != "blob" {
            continue;
        }
        let Some(rest) = e.path.strip_prefix("trainers/") else {
            continue;
        };
        let Some((appid_str, sub)) = rest.split_once('/') else {
            continue;
        };
        let Ok(app_id) = appid_str.parse::<u64>() else {
            continue;
        };
        if sub.is_empty() {
            continue;
        }
        map.entry(app_id).or_default().push(sub.to_string());
    }
    let mut out: Vec<(u64, Vec<String>)> = map
        .into_iter()
        .map(|(id, mut f)| {
            f.sort();
            (id, f)
        })
        .collect();
    out.sort_by_key(|(id, _)| *id);
    out
}

/// Build the full catalog: for every package with a `trainer.json`, fetch its
/// metadata. Packages lacking `trainer.json` are skipped.
pub fn build_catalog(cfg: &RepoConfig, tree: &TreeResponse) -> EngineResult<Vec<CatalogEntry>> {
    let pkgs = parse_packages(tree);
    let mut out = Vec::with_capacity(pkgs.len());
    for (app_id, files) in pkgs {
        if !files.iter().any(|f| f == "trainer.json") {
            continue;
        }
        let raw = fetch_raw_text(cfg, &format!("trainers/{app_id}/trainer.json"))?;
        let meta: TrainerMeta = serde_json::from_str(&raw).map_err(|e| {
            EngineError::RepoInvalidPackage(format!("app {app_id}: invalid trainer.json: {e}"))
        })?;
        out.push(CatalogEntry {
            app_id,
            game_name: meta.game.name,
            trainer_name: meta.trainer.name,
            version: meta.trainer.version,
            author: meta.trainer.author,
            file_count: files.len(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree_json(entries: &[(&str, &str)]) -> String {
        let items: Vec<String> = entries
            .iter()
            .map(|(p, t)| format!(r#"{{"path":"{p}","type":"{t}"}}"#))
            .collect();
        format!(r#"{{"tree":[{}],"truncated":false}}"#, items.join(","))
    }

    #[test]
    fn parse_packages_groups_by_appid() {
        let json = tree_json(&[
            ("trainers/1091500/trainer.json", "blob"),
            ("trainers/1091500/scripts/ih.asm", "blob"),
            ("trainers/1091500/scripts", "tree"),
            ("trainers/1245620/trainer.json", "blob"),
            ("README.md", "blob"),
            ("trainers/notanid/trainer.json", "blob"),
            ("trainers/999/empty", "tree"),
        ]);
        let tree: TreeResponse = serde_json::from_str(&json).unwrap();
        let pkgs = parse_packages(&tree);
        let ids: Vec<u64> = pkgs.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![1091500, 1245620]);
        let (_, files) = pkgs.iter().find(|(id, _)| *id == 1091500).unwrap();
        assert_eq!(files, &vec!["scripts/ih.asm".to_string(), "trainer.json".to_string()]);
    }

    #[test]
    fn repo_config_defaults() {
        // Defaults must resolve even with no env (clear to be deterministic).
        // (Other env vars may be set in CI; only assert the structure is sane.)
        let cfg = RepoConfig::from_env();
        assert!(!cfg.owner.is_empty());
        assert!(!cfg.repo.is_empty());
        assert!(!cfg.git_ref.is_empty());
        assert!(cfg.api_base().starts_with("https://api.github.com/repos/"));
        assert!(cfg.raw_base().contains("raw.githubusercontent.com"));
    }
}
