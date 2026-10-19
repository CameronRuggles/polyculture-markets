//! Media pipeline glue (spec §18): uploads land in a temp dir, the
//! isolated media-worker binary sanitizes them, only its output is kept.
//! The worker runs with a cleared environment and a hard timeout.
//!
//! Containment (Media/Content/Disputes audit CM2), in layers, stated
//! exactly as built — no layer is claimed that does not exist:
//!
//! - **Kill on timeout.** The child is spawned with
//!   `kill_on_drop(true)`: when the timeout fires and the future is
//!   dropped, Tokio kills the worker process instead of leaving it
//!   running detached.
//! - **Concurrency cap.** A process-wide semaphore admits at most
//!   `MAX_CONCURRENT_WORKERS` (2) workers at once; further uploads
//!   queue instead of multiplying memory pressure.
//! - **Per-job scratch.** Each job works in a fresh directory under
//!   the pipeline tmp dir, deleted when the job ends. In the sandbox
//!   that directory alone is bound at `/work`, so a worker can never
//!   see another job's input or output.
//! - **Optional sandbox wrapper.** When the deployment sets
//!   `MEDIA_WORKER_SANDBOX=bwrap` and provides bubblewrap, each
//!   worker runs inside it: no network namespace, a tmpfs root with
//!   only the system library dirs, the worker binary, its input
//!   file and its scratch dir visible, dies with the parent. The
//!   wrapper is opt-in because it needs a deployment-provided
//!   bubblewrap; without the env var the worker runs as a plain
//!   child (the two layers above still apply). If the env var is
//!   set but bwrap is missing, the spawn fails closed
//!   (WorkerFailed) rather than silently running unwrapped.
//! - **Not in code:** a per-worker memory cap is a deployment
//!   measure (the systemd unit's `MemoryMax=` bounds the app,
//!   workers included); this module does not set rlimits. The
//!   threat model (§T6) says exactly this.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Semaphore;

/// CM2: at most this many media workers run at once, process-wide.
pub const MAX_CONCURRENT_WORKERS: usize = 2;

fn worker_slots() -> &'static Semaphore {
    static SLOTS: OnceLock<Semaphore> = OnceLock::new();
    SLOTS.get_or_init(|| Semaphore::new(MAX_CONCURRENT_WORKERS))
}

#[derive(Clone)]
pub struct MediaPipeline {
    pub worker_path: PathBuf,
    pub media_dir: PathBuf,
    pub tmp_dir: PathBuf,
}

#[derive(Debug)]
pub enum MediaError {
    TooLarge,
    Rejected,
    WorkerFailed,
}

impl MediaPipeline {
    pub fn from_env() -> MediaPipeline {
        let base = std::env::var("MEDIA_DIR").unwrap_or_else(|_| "media".into());
        MediaPipeline {
            worker_path: std::env::var("MEDIA_WORKER")
                .unwrap_or_else(|_| "target/debug/media-worker".into())
                .into(),
            media_dir: PathBuf::from(&base),
            tmp_dir: PathBuf::from(format!("{base}/tmp")),
        }
    }

    /// Directory holding images of taken-down listings (task CM1):
    /// files move here on takedown so the served folder never holds
    /// them, and back on restore.
    pub fn quarantine_dir(&self) -> PathBuf {
        self.media_dir.join("quarantine")
    }

    /// Move one stored file between the served folder and the
    /// quarantine folder (best-effort: a missing file is not an
    /// error — the database check in the serve path is the actual
    /// access boundary; this is the on-disk half of the takedown).
    pub async fn set_quarantined(&self, stored_ref: &str, quarantined: bool) {
        let (from, to) = if quarantined {
            (self.media_dir.join(stored_ref), self.quarantine_dir().join(stored_ref))
        } else {
            (self.quarantine_dir().join(stored_ref), self.media_dir.join(stored_ref))
        };
        if quarantined {
            let _ = tokio::fs::create_dir_all(self.quarantine_dir()).await;
        }
        let _ = tokio::fs::rename(&from, &to).await;
    }

    /// Sanitize raw upload bytes. On success returns (stored_ref, width, height).
    pub async fn sanitize(&self, bytes: &[u8]) -> Result<(String, i32, i32), MediaError> {
        self.sanitize_with_timeout(bytes, Duration::from_secs(10)).await
    }

    /// `sanitize` with an explicit worker timeout (the 10 s default
    /// lives in `sanitize`; tests use shorter ones).
    pub async fn sanitize_with_timeout(
        &self,
        bytes: &[u8],
        timeout: Duration,
    ) -> Result<(String, i32, i32), MediaError> {
        if bytes.len() > 5 * 1024 * 1024 {
            return Err(MediaError::TooLarge);
        }
        tokio::fs::create_dir_all(&self.tmp_dir).await.map_err(|_| MediaError::WorkerFailed)?;
        tokio::fs::create_dir_all(&self.media_dir).await.map_err(|_| MediaError::WorkerFailed)?;
        let stem = crate::db::public_id("");
        // CM2 (fix verification): one scratch directory per job. The
        // worker sees only its own job's files — in the sandbox this
        // directory alone is bound at /work — and the whole directory
        // is deleted when the job ends, on every exit path.
        let job_dir = self.tmp_dir.join(&stem);
        tokio::fs::create_dir_all(&job_dir).await.map_err(|_| MediaError::WorkerFailed)?;
        let result = self.run_worker(&job_dir, &stem, bytes, timeout).await;
        let _ = tokio::fs::remove_dir_all(&job_dir).await;
        result
    }

    /// Run one worker job inside its private scratch directory
    /// (`job_dir`, created by the caller; deleted by the caller).
    async fn run_worker(
        &self,
        job_dir: &std::path::Path,
        stem: &str,
        bytes: &[u8],
        timeout: Duration,
    ) -> Result<(String, i32, i32), MediaError> {
        let in_path = job_dir.join("in");
        let out_path = job_dir.join("out");
        tokio::fs::write(&in_path, bytes).await.map_err(|_| MediaError::WorkerFailed)?;

        // CM2: never more than MAX_CONCURRENT_WORKERS workers alive.
        let _permit = worker_slots()
            .acquire()
            .await
            .map_err(|_| MediaError::WorkerFailed)?;

        let mut cmd = build_worker_command(&self.worker_path, &in_path, &out_path);
        // CM2: a worker past its timeout is KILLED when the output
        // future is dropped below — not left running detached.
        cmd.kill_on_drop(true);
        let run = cmd.output();
        let output = match tokio::time::timeout(timeout, run).await {
            Ok(Ok(o)) => o,
            _ => return Err(MediaError::WorkerFailed),
        };
        if !output.status.success() {
            return Err(MediaError::Rejected);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let (w, h) = stdout
            .trim()
            .split_once('x')
            .and_then(|(a, b)| Some((a.parse::<i32>().ok()?, b.parse::<i32>().ok()?)))
            .ok_or(MediaError::WorkerFailed)?;

        // Keep the sanitized file under a random ref with the true format's
        // extension (worker output follows the input format).
        let is_png = bytes.starts_with(b"\x89PNG");
        let ext = if is_png { "png" } else { "jpg" };
        let stored_ref = format!("{stem}.{ext}");
        tokio::fs::rename(&out_path, self.media_dir.join(&stored_ref))
            .await
            .map_err(|_| MediaError::WorkerFailed)?;
        Ok((stored_ref, w, h))
    }

    pub fn path_of(&self, stored_ref: &str) -> PathBuf {
        // stored_ref is server-generated (hex + extension); never user input.
        self.media_dir.join(stored_ref)
    }

    /// Where a stored file actually lives: the served folder, or the
    /// quarantine folder when the file has been quarantined.
    pub fn existing_path_of(&self, stored_ref: &str) -> PathBuf {
        let served = self.path_of(stored_ref);
        if served.exists() {
            return served;
        }
        let q = self.quarantine_dir().join(stored_ref);
        if q.exists() {
            return q;
        }
        served
    }
}

/// Build the worker invocation. Plain by default; wrapped in
/// bubblewrap when the deployment opted in via
/// `MEDIA_WORKER_SANDBOX=bwrap` (see the module comment).
fn build_worker_command(
    worker_path: &std::path::Path,
    in_path: &std::path::Path,
    out_path: &std::path::Path,
) -> tokio::process::Command {
    if std::env::var("MEDIA_WORKER_SANDBOX").as_deref() == Ok("bwrap") {
        // Inside the sandbox the worker sees: /usr, /lib, /lib64
        // (read-only, for the dynamic loader), /dev, its own binary
        // at /worker, the input at /in, and the job's OWN scratch dir
        // at /work (the output's parent — one directory per job, so
        // concurrent workers cannot see each other's files). No
        // network.
        // /lib64 is bound with --ro-bind-try (fix verification CM2):
        // some distributions have no /lib64 at all, and a plain
        // --ro-bind of a missing source fails the whole spawn.
        let scratch = out_path.parent().unwrap_or(std::path::Path::new("/"));
        let out_name = out_path.file_name().unwrap_or_default();
        let mut cmd = tokio::process::Command::new("bwrap");
        cmd.arg("--unshare-net")
            .arg("--die-with-parent")
            .arg("--tmpfs").arg("/")
            .arg("--ro-bind").arg("/usr").arg("/usr")
            .arg("--ro-bind").arg("/lib").arg("/lib")
            .arg("--ro-bind-try").arg("/lib64").arg("/lib64")
            .arg("--dev").arg("/dev")
            .arg("--ro-bind").arg(worker_path).arg("/worker")
            .arg("--ro-bind").arg(in_path).arg("/in")
            .arg("--bind").arg(scratch).arg("/work")
            .arg("--")
            .arg("/worker")
            .arg("/in")
            .arg(std::path::Path::new("/work").join(out_name));
        cmd.env_clear();
        return cmd;
    }
    let mut cmd = tokio::process::Command::new(worker_path);
    cmd.arg(in_path).arg(out_path).env_clear();
    cmd
}
