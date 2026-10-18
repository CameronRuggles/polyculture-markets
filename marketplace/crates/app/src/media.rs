//! Media pipeline glue (spec §18): uploads land in a temp dir, the
//! isolated media-worker binary sanitizes them, only its output is kept.
//! The worker runs with a cleared environment and a hard timeout.

use std::path::PathBuf;
use std::time::Duration;

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

    /// Sanitize raw upload bytes. On success returns (stored_ref, width, height).
    pub async fn sanitize(&self, bytes: &[u8]) -> Result<(String, i32, i32), MediaError> {
        if bytes.len() > 5 * 1024 * 1024 {
            return Err(MediaError::TooLarge);
        }
        tokio::fs::create_dir_all(&self.tmp_dir).await.map_err(|_| MediaError::WorkerFailed)?;
        tokio::fs::create_dir_all(&self.media_dir).await.map_err(|_| MediaError::WorkerFailed)?;
        let stem = crate::db::public_id("");
        let in_path = self.tmp_dir.join(format!("{stem}.in"));
        let out_path = self.tmp_dir.join(format!("{stem}.out"));
        tokio::fs::write(&in_path, bytes).await.map_err(|_| MediaError::WorkerFailed)?;

        let run = tokio::process::Command::new(&self.worker_path)
            .arg(&in_path)
            .arg(&out_path)
            .env_clear()
            .output();
        let output = match tokio::time::timeout(Duration::from_secs(10), run).await {
            Ok(Ok(o)) => o,
            _ => {
                let _ = tokio::fs::remove_file(&in_path).await;
                return Err(MediaError::WorkerFailed);
            }
        };
        let _ = tokio::fs::remove_file(&in_path).await;
        if !output.status.success() {
            let _ = tokio::fs::remove_file(&out_path).await;
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
}
