//! Bundle directory layout and I/O for meta / summary / timeline.
//!
//! Bundles are stored in `$WFX_HOME/bundles/` (default `~/.wifi-forensic/bundles/`).

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Storage root: the `WFX_HOME` environment variable, otherwise `~/.wifi-forensic`.
pub fn home_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("WFX_HOME").filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join(".wifi-forensic")
}

/// Directory that holds the bundles.
pub fn bundles_dir() -> PathBuf {
    home_dir().join("bundles")
}

/// Makes an SSID safe for a directory name (anything outside `[A-Za-z0-9._-]` becomes `_`).
pub fn sanitize_ssid(ssid: &str) -> String {
    let s: String = ssid
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
        .collect();
    if s.is_empty() {
        "_".into()
    } else {
        s
    }
}

/// Bundle directory name `<YYYYmmdd-HHMMSS>_<ssid>_<run_id>`.
pub fn bundle_name(timestamp: &str, ssid: &str, run_id: &str) -> String {
    format!("{timestamp}_{}_{run_id}", sanitize_ssid(ssid))
}

/// Per-run unique run id (6 hex digits). From `/dev/urandom`, or from pid + time if that cannot be read.
pub fn new_run_id() -> String {
    let mut buf = [0u8; 3];
    let ok = std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf)).is_ok();
    if ok {
        return format_run_id(u32::from_be_bytes([0, buf[0], buf[1], buf[2]]));
    }
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    format_run_id(nanos ^ std::process::id().wrapping_mul(2654435761))
}

/// Formats the low 24 bits as 6 hex digits.
pub fn format_run_id(n: u32) -> String {
    format!("{:06x}", n & 0xff_ffff)
}

/// Current epoch seconds (fractional).
pub fn epoch_now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Whether the process with the given pid is alive (`kill(pid, 0)`; EPERM means a live process owned by another user, so it counts as alive).
pub fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 only checks existence and sends nothing.
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Takes the per-device exclusive lock (`$WFX_HOME/locks/<dev>.lock`) without blocking.
///
/// Returns `Ok(None)` if it is held (another capture is running). The fd is returned with `FD_CLOEXEC` set.
/// To hand it to the worker, the caller clears CLOEXEC in the child process.
pub fn acquire_device_lock(device: &str) -> anyhow::Result<Option<std::fs::File>> {
    let dir = home_dir().join("locks");
    std::fs::create_dir_all(&dir)?;
    try_lock(&dir.join(format!("{}.lock", sanitize_ssid(device))))
}

/// Takes an exclusive flock on `path` without blocking.
fn try_lock(path: &Path) -> anyhow::Result<Option<std::fs::File>> {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(path)?;
    // SAFETY: flock on a valid fd.
    let r = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if r == 0 {
        return Ok(Some(f));
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(None)
    } else {
        Err(err.into())
    }
}

/// Run parameters for `capture`. Written by the foreground, read by the worker (never includes the password).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub wfx_version: String,
    pub ssid: String,
    /// SSID to restore to. `None` leaves it to auto-join of preferred networks
    pub restore_ssid: Option<String>,
    pub dhcp_wait: u64,
    pub no_pcap: bool,
    /// Wi-Fi device (e.g. `en0`)
    pub device: String,
    pub started_at: String,
    /// Start time in the format passed to `log show --start` (`%Y-%m-%d %H:%M:%S`)
    pub started_log: String,
    pub host_os: String,
    pub bundle: String,
    pub args: Vec<String>,
    /// Unique id of this run (matched against the summary)
    #[serde(default)]
    pub run_id: String,
    /// Lifetime of the tcpdump supervisor (seconds). `None` without pcap
    #[serde(default)]
    pub tcpdump_secs: Option<u64>,
}

/// `summary.json`. Written atomically by the worker at the very end (the completion marker).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub schema_version: u32,
    pub ssid: String,
    pub started_at: String,
    pub finished_at: String,
    /// `ok` / `failed`
    pub join: String,
    pub join_error: Option<String>,
    /// How the IP was obtained: `dhcp` (lease present in getpacket) / `manual` (manually configured). `None` if no IP
    #[serde(default)]
    pub ip_source: Option<String>,
    /// Seconds until the IP was obtained via DHCP (only when `ip_source == "dhcp"`)
    pub ip_acquired_after_sec: Option<f64>,
    /// Whether a 169.254.* self-assigned address was observed
    pub link_local_seen: bool,
    pub first_failure: Option<String>,
    /// `ok` / `failed` (`skipped` is not emitted currently)
    pub restore: String,
    pub restore_ssid: Option<String>,
    /// Reason the worker left its normal flow, e.g. panic / SIGTERM
    pub aborted: Option<String>,
    pub bundle: String,
    /// Unique id of this run (the foreground matches it against meta)
    #[serde(default)]
    pub run_id: String,
    /// Our MAC at join time (including Private Wi-Fi Address; analyze uses it to attribute the pcap)
    #[serde(default)]
    pub our_mac: Option<String>,
    /// `complete` / `still_recording` / `none` (no pcap)
    #[serde(default)]
    pub pcap: Option<String>,
}

/// Writes JSON to a file atomically (write to tmp, then rename).
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    // Include the pid in the tmp name so concurrent writers do not collide
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Reads a JSON file.
pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> anyhow::Result<T> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("cannot parse {}: {e}", path.display()))
}

/// Appends to `timeline.jsonl` (one event per line).
#[derive(Clone)]
pub struct Timeline {
    path: PathBuf,
}

impl Timeline {
    pub fn new(bundle: &Path) -> Self {
        Timeline { path: bundle.join("timeline.jsonl") }
    }

    /// Appends one event line. Write failures are swallowed (recording must not stop the main flow).
    pub fn event(&self, event: &str, detail: serde_json::Value) {
        let line = serde_json::json!({ "t": crate::collect::now_iso8601(), "epoch": epoch_now(), "event": event, "detail": detail });
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(f, "{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssid_is_sanitized_for_dir_name() {
        assert_eq!(sanitize_ssid("Example Cafe/1"), "Example_Cafe_1");
        assert_eq!(sanitize_ssid("Hotspot-6a_x.1"), "Hotspot-6a_x.1");
        assert_eq!(sanitize_ssid("カフェ"), "___");
        assert_eq!(sanitize_ssid(""), "_");
        assert_eq!(bundle_name("20261001-120000", "a b", "0a1b2c"), "20261001-120000_a_b_0a1b2c");
        assert_eq!(format_run_id(0xff12_3456), "123456");
        assert_eq!(new_run_id().len(), 6);
    }

    #[test]
    fn atomic_write_roundtrip() {
        let dir = std::env::temp_dir().join(format!("wfx-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.json");
        write_json_atomic(&p, &serde_json::json!({"a": 1})).unwrap();
        let v: serde_json::Value = read_json(&p).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no tmp file is left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_is_exclusive_until_released() {
        let p = std::env::temp_dir().join(format!("wfx-lock-{}.lock", std::process::id()));
        let first = try_lock(&p).unwrap();
        assert!(first.is_some());
        assert!(try_lock(&p).unwrap().is_none(), "a second lock cannot be taken");
        drop(first);
        assert!(try_lock(&p).unwrap().is_some(), "can be taken after release");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn pid_liveness() {
        assert!(pid_alive(std::process::id() as i32));
        assert!(!pid_alive(0));
        assert!(!pid_alive(i32::MAX));
    }
}
