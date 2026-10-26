//! Foreground side of `wfx capture` (preflight / sudo / tcpdump launch / worker detach / result display) and
//! `wfx bundles`.
//!
//! The actual Wi-Fi switching is done by the detached worker (`worker.rs`).
//! These functions do not change Wi-Fi state (changes happen only after the worker starts).

use crate::bundle::*;
use crate::collect;
use crate::model::HelperReport;
use std::fmt::Write;
use std::fs::OpenOptions;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Total worker budget (seconds): DHCP wait + join 30 + snapshot 30 + log 60 + restore 120 + slack 30.
///
/// Used as the foreground wait limit and the tcpdump supervisor's max lifetime (= how long the pcap covers, through restore).
pub fn worker_budget_secs(dhcp_wait: u64) -> u64 {
    dhcp_wait + 30 + 30 + 60 + 120 + 30
}

/// Extracts the APs of the target SSID from the `scan` JSON.
pub fn target_aps(scan: &serde_json::Value, ssid: &str) -> Vec<serde_json::Value> {
    scan["networks"]
        .as_array()
        .map(|a| a.iter().filter(|n| n["ssid"].as_str() == Some(ssid)).cloned().collect())
        .unwrap_or_default()
}

/// Human-readable result display.
pub fn render_summary(s: &Summary) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Capture result\n────────────────────────");
    let _ = writeln!(out, "SSID        {}", s.ssid);
    let join = match &s.join_error {
        Some(e) => format!("{} ({e})", s.join),
        None => s.join.clone(),
    };
    let _ = writeln!(out, "join        {join}");
    let ip = match (s.ip_source.as_deref(), s.ip_acquired_after_sec) {
        (Some("dhcp"), Some(v)) => format!("obtained via DHCP in {v:.1}s"),
        (Some("manual"), _) => "manually configured (not using DHCP)".into(),
        _ => "not obtained".into(),
    };
    let ll = if s.link_local_seen { " (169.254 self-assigned address seen)" } else { "" };
    let _ = writeln!(out, "IP          {ip}{ll}");
    let _ = writeln!(out, "Diagnosis   {}", s.first_failure.as_deref().map(|l| format!("first failure: {l}")).unwrap_or_else(|| "no failures".into()));
    let _ = writeln!(out, "Restore     {} ({})", s.restore, s.restore_ssid.as_deref().unwrap_or("auto-join"));
    if let Some(p) = s.pcap.as_deref().filter(|p| *p != "complete" && *p != "none") {
        let _ = writeln!(out, "pcap        {p} (pcap may be incomplete)");
    }
    if let Some(a) = &s.aborted {
        let _ = writeln!(out, "Aborted     {a}");
    }
    let _ = writeln!(out, "Bundle      {}", s.bundle);
    let _ = writeln!(out, "\nDetailed analysis: wfx analyze {}", s.bundle);
    out
}

/// Manual recovery instructions.
fn recovery_instructions(restore_ssid: Option<&str>, device: &str) -> String {
    let target = restore_ssid.unwrap_or("<original SSID>");
    format!(
        "\x1b[1;31m!! Automatic Wi-Fi restore failed. Please restore it manually !!\x1b[0m\n  \
         networksetup -setairportpower {device} off && networksetup -setairportpower {device} on\n  \
         networksetup -setairportnetwork {device} \"{target}\"\n  \
         (You can also pick it from the Wi-Fi menu bar. If the IP is still manual: networksetup -setdhcp Wi-Fi)"
    )
}

fn current_date(fmt: &str) -> String {
    collect::stdout_of("date", &[fmt]).map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Arguments for `capture`.
pub struct CaptureArgs {
    pub ssid: String,
    pub restore: Option<String>,
    pub dhcp_wait: u64,
    pub no_pcap: bool,
    pub no_wait: bool,
    pub json: bool,
}

/// Script for the tcpdump supervisor (a root `sh`). Args: `$1` bundle / `$2` device / `$3` max seconds / `$4` user / `$5` filter.
///
/// Starts tcpdump in the background and stops it with SIGINT on whichever comes first: the max seconds elapsing,
/// `tcpdump.stop` appearing, or tcpdump exiting on its own. It always stops by the max seconds even if the foreground
/// or worker dies, and the user never needs to kill a root process (stopping is signaled via a file).
///
/// The supervisor never opens a path in the bundle itself: the pid goes to stdout and tcpdump's log to stderr,
/// both files opened by the user beforehand. A root `>` into the user-owned bundle would follow a planted symlink
/// and truncate any file on the system. `dhcp.pcap` is safe because tcpdump opens it after `-Z` drops root.
const TCPDUMP_SUPERVISOR: &str = r#"
tcpdump -i "$2" -n -U -w "$1/dhcp.pcap" -Z "$4" "$5" &
p=$!
echo $p
i=0
while [ $i -lt "$3" ] && [ ! -e "$1/tcpdump.stop" ] && kill -0 $p 2>/dev/null; do sleep 1; i=$((i+1)); done
kill -INT $p 2>/dev/null
wait $p
"#;

/// Launches tcpdump through the supervisor with `sudo -n`, in its own session detached from the foreground.
fn spawn_tcpdump(bundle: &Path, device: &str, secs: u64) -> anyhow::Result<Child> {
    let user = std::env::var("USER").unwrap_or_else(|_| "nobody".into());
    // create_new (O_EXCL) refuses an existing path, including a planted symlink
    let pid_file = OpenOptions::new().write(true).create_new(true).open(bundle.join("tcpdump.pid"))?;
    let log_file = OpenOptions::new().write(true).create_new(true).open(bundle.join("tcpdump.log"))?;
    let mut cmd = Command::new("sudo");
    cmd.args(["-n", "/bin/sh", "-c", TCPDUMP_SUPERVISOR, "wfx-tcpdump"])
        .arg(bundle)
        .arg(device)
        .arg(secs.to_string())
        .arg(user)
        .arg("(port 67 or port 68) or arp or icmp")
        .stdin(Stdio::null())
        .stdout(pid_file)
        .stderr(log_file);
    // SAFETY: only calls setsid between fork and exec (async-signal-safe).
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn().map_err(|e| anyhow::anyhow!("cannot start tcpdump: {e}"))
}

/// Tells the tcpdump supervisor to stop (creates `tcpdump.stop`; no sudo needed).
fn request_tcpdump_stop(bundle: &Path) {
    let _ = std::fs::write(bundle.join("tcpdump.stop"), "");
}

/// Launches the worker detached in a new session. stdout / stderr go to `worker.log`.
///
/// The exclusive lock on `lock_fd` is handed to the worker (`FD_CLOEXEC` is cleared only in the child; the fd number is passed via an environment variable).
fn spawn_worker(bundle: &Path, lock_fd: Option<i32>) -> anyhow::Result<Child> {
    let exe = std::env::current_exe()?;
    let log = std::fs::File::create(bundle.join("worker.log"))?;
    let mut cmd = Command::new(exe);
    cmd.arg("__capture-worker").arg(bundle).stdin(Stdio::null()).stdout(log.try_clone()?).stderr(log);
    if let Some(fd) = lock_fd {
        cmd.env("WFX_LOCK_FD", fd.to_string());
    }
    // SAFETY: only calls fcntl / setsid between fork and exec (async-signal-safe).
    // Detaches from terminal SIGHUP and parent death, and lets the lock fd be inherited.
    unsafe {
        cmd.pre_exec(move || {
            if let Some(fd) = lock_fd {
                libc::fcntl(fd, libc::F_SETFD, 0);
            }
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn().map_err(|e| anyhow::anyhow!("cannot start worker: {e}"))
}

/// Entry point of `wfx capture`. Returns the exit code (0 done / 1 pre-flight error or wait timed out / 2 restore failed).
pub fn run(args: CaptureArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run_inner(args: CaptureArgs) -> anyhow::Result<i32> {
    use std::os::unix::io::AsRawFd;
    let device = collect::wifi_device();

    // 0. Per-device exclusive lock (before preflight; handed to the worker)
    let lock = match acquire_device_lock(&device)? {
        Some(l) => l,
        None => anyhow::bail!("another capture is running (cannot take the lock for {device}); wait for it to finish"),
    };

    // 1. preflight: SSID to restore to, and whether the target SSID is visible
    eprintln!("preflight: checking current connection and scanning...");
    let current_raw = collect::helper_raw("current").map_err(|e| anyhow::anyhow!("helper(current): {e}"))?;
    let current: serde_json::Value = serde_json::from_str(&current_raw).unwrap_or(serde_json::Value::Null);
    let report: HelperReport = serde_json::from_str(&current_raw).unwrap_or_default();
    let authorized = report.authorization.as_deref() == Some("authorized");
    if !authorized && args.restore.is_none() {
        anyhow::bail!(
            "Location access is not authorized, so the current SSID (restore target) cannot be read. \
             Grant access, or specify the restore target with `--restore <SSID>`"
        );
    }
    let restore_ssid = args.restore.clone().or_else(|| report.interface.and_then(|i| i.ssid));
    if restore_ssid.is_none() {
        eprintln!("warn: restore SSID is unknown (not connected); restore will rely on auto-join of preferred networks");
    }
    let scan_raw = collect::helper_raw("scan");
    let scan: serde_json::Value = scan_raw.as_deref().ok().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(serde_json::Value::Null);
    let aps = target_aps(&scan, &args.ssid);
    if aps.is_empty() {
        eprintln!("warn: `{}` is not visible in the scan (hidden SSID or out of range?); continuing", args.ssid);
    }

    // Create the bundle. The name includes the run id, and a collision is an error (create_dir)
    let started_at = collect::now_iso8601();
    let run_id = new_run_id();
    let name = bundle_name(&current_date("+%Y%m%d-%H%M%S"), &args.ssid, &run_id);
    let bundle: PathBuf = bundles_dir().join(name);
    // 0700: bundles hold SSIDs, BSSIDs, MACs and pcaps, and the default umask would let other local users read them
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(bundles_dir())?;
    std::fs::DirBuilder::new().mode(0o700).create(&bundle).map_err(|e| anyhow::anyhow!("cannot create bundle ({}): {e}", bundle.display()))?;
    std::fs::create_dir(bundle.join("commands"))?;
    write_json_atomic(
        &bundle.join("preflight.json"),
        &serde_json::json!({
            "current": current,
            "scan_error": scan_raw.as_ref().err(),
            "target_visible": !aps.is_empty(),
            "target_aps": aps,
            "restore_ssid": restore_ssid,
        }),
    )?;
    let budget = worker_budget_secs(args.dhcp_wait);
    let meta = Meta {
        wfx_version: env!("CARGO_PKG_VERSION").into(),
        ssid: args.ssid.clone(),
        restore_ssid: restore_ssid.clone(),
        dhcp_wait: args.dhcp_wait,
        no_pcap: args.no_pcap,
        device: device.clone(),
        started_at,
        started_log: current_date("+%Y-%m-%d %H:%M:%S"),
        host_os: collect::stdout_of("sw_vers", &["-productVersion"]).unwrap_or_default().trim().into(),
        bundle: bundle.display().to_string(),
        args: std::env::args().skip(1).collect(),
        run_id: run_id.clone(),
        tcpdump_secs: (!args.no_pcap).then_some(budget),
    };
    write_json_atomic(&bundle.join("meta.json"), &meta)?;

    // 2-3. sudo and the tcpdump supervisor (fail before touching Wi-Fi)
    if !args.no_pcap {
        eprintln!("Enter your sudo password for tcpdump (Wi-Fi has not been switched yet)");
        let ok = Command::new("sudo").arg("-v").status().map(|s| s.success()).unwrap_or(false);
        if !ok {
            anyhow::bail!("sudo authentication failed; Wi-Fi was not touched (use --no-pcap if you do not need a pcap)");
        }
        let mut child = spawn_tcpdump(&bundle, &device, budget)?;
        std::thread::sleep(Duration::from_secs(1));
        let pid: Option<i32> = std::fs::read_to_string(bundle.join("tcpdump.pid")).ok().and_then(|t| t.trim().parse().ok());
        let died = matches!(child.try_wait(), Ok(Some(_)));
        if !tcpdump_started(died, pid.map(pid_alive)) {
            request_tcpdump_stop(&bundle);
            let log = std::fs::read_to_string(bundle.join("tcpdump.log")).unwrap_or_default();
            anyhow::bail!("tcpdump failed to start; Wi-Fi was not touched\n{log}");
        }
    }

    // 4. Detach the worker (stop tcpdump on failure)
    let mut worker = match spawn_worker(&bundle, Some(lock.as_raw_fd())) {
        Ok(w) => w,
        Err(e) => {
            request_tcpdump_stop(&bundle);
            return Err(e);
        }
    };
    eprintln!("Worker started (pid {}). Bundle: {}", worker.id(), bundle.display());
    if args.no_wait {
        println!("{}", bundle.display());
        return Ok(0);
    }

    // 5. Wait for summary.json (bounded by the worker budget)
    eprintln!("Wi-Fi will switch temporarily. Waiting for completion...");
    let summary_path = bundle.join("summary.json");
    let cap = Duration::from_secs(budget);
    let t0 = Instant::now();
    let mut worker_dead_at: Option<Instant> = None;
    while !summary_path.exists() && t0.elapsed() < cap {
        if worker_dead_at.is_none() && matches!(worker.try_wait(), Ok(Some(_))) {
            worker_dead_at = Some(Instant::now());
        }
        if worker_dead_at.is_some_and(|t| t.elapsed() > Duration::from_secs(2)) {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    if !summary_path.exists() && matches!(worker.try_wait(), Ok(None)) {
        // The wait timed out but the worker is still alive; distinguish this from a restore failure
        eprintln!(
            "The worker is still running. Do not touch Wi-Fi. Check later with `wfx bundles`: {}",
            bundle.display()
        );
        return Ok(1);
    }
    let summary: Summary = match read_json(&summary_path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("{}", recovery_instructions(restore_ssid.as_deref(), &device));
            anyhow::bail!("summary.json was not written; check {}/worker.log", bundle.display());
        }
    };
    if summary.run_id != run_id {
        anyhow::bail!("run_id in summary.json does not match (it may belong to another run): {}", bundle.display());
    }
    if args.json {
        println!("{}", std::fs::read_to_string(&summary_path)?);
    } else {
        print!("{}", render_summary(&summary));
    }
    if summary.restore != "ok" {
        eprintln!("{}", recovery_instructions(restore_ssid.as_deref(), &device));
        return Ok(2);
    }
    Ok(0)
}

/// Whether the tcpdump supervisor started: sudo has not exited immediately, and the pid in the pid file is alive.
pub fn tcpdump_started(sudo_exited: bool, pid_alive: Option<bool>) -> bool {
    !sudo_exited && pid_alive == Some(true)
}

// ---------------------------------------------------------------- bundles

/// One row of `bundles`.
#[derive(Debug, PartialEq)]
pub struct Row {
    pub name: String,
    pub ssid: String,
    pub started_at: String,
    pub join: String,
    pub first_failure: String,
    pub restore: String,
}

/// Builds a display row from one bundle. Without summary.json it is treated as incomplete and filled from meta.
pub fn row_for(dir: &Path) -> Row {
    let name = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let summary: Option<Summary> = read_json(&dir.join("summary.json")).ok();
    let meta: Option<Meta> = read_json(&dir.join("meta.json")).ok();
    let dash = || "—".to_string();
    match summary {
        Some(s) => Row {
            name,
            ssid: s.ssid,
            started_at: s.started_at,
            join: s.join,
            first_failure: s.first_failure.unwrap_or_else(dash),
            restore: s.restore,
        },
        None => Row {
            name,
            ssid: meta.as_ref().map(|m| m.ssid.clone()).unwrap_or_else(dash),
            started_at: meta.map(|m| m.started_at).unwrap_or_else(dash),
            join: dash(),
            first_failure: dash(),
            restore: "incomplete".into(),
        },
    }
}

/// `wfx bundles`: lists saved bundles, newest first.
pub fn list_bundles() -> anyhow::Result<()> {
    let dir = bundles_dir();
    let mut dirs: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect(),
        Err(_) => Vec::new(),
    };
    // Names start with the timestamp, so descending name order = newest first
    dirs.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
    if dirs.is_empty() {
        println!("No bundles found ({})", dir.display());
        return Ok(());
    }
    println!("{:<34} {:<18} {:<6} {:<14} {}", "BUNDLE", "STARTED", "JOIN", "FIRST_FAILURE", "RESTORE");
    for d in dirs {
        let r = row_for(&d);
        let started: String = r.started_at.chars().take(16).collect();
        println!("{:<34} {:<18} {:<6} {:<14} {}   [{}]", r.name, started, r.join, r.first_failure, r.restore, r.ssid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_budget_covers_every_phase() {
        assert_eq!(worker_budget_secs(45), 45 + 30 + 30 + 60 + 120 + 30);
    }

    #[test]
    fn tcpdump_start_requires_live_pid_and_live_sudo() {
        assert!(tcpdump_started(false, Some(true)));
        assert!(!tcpdump_started(true, Some(true)));
        assert!(!tcpdump_started(false, Some(false)));
        assert!(!tcpdump_started(false, None));
    }

    #[test]
    fn supervisor_script_stops_on_file_or_timeout_and_uses_positional_args() {
        assert!(TCPDUMP_SUPERVISOR.contains("tcpdump.stop"));
        assert!(TCPDUMP_SUPERVISOR.contains("kill -INT"));
        // The path comes in as $1 (does not break on paths with spaces)
        assert!(TCPDUMP_SUPERVISOR.contains("\"$1/dhcp.pcap\""));
    }

    #[test]
    fn supervisor_script_never_redirects_into_the_bundle_as_root() {
        assert!(!TCPDUMP_SUPERVISOR.contains(">\"$1"));
        assert!(!TCPDUMP_SUPERVISOR.contains("> \"$1"));
        assert!(!TCPDUMP_SUPERVISOR.contains("tcpdump.pid"));
        assert!(!TCPDUMP_SUPERVISOR.contains("tcpdump.log"));
    }

    #[test]
    fn target_aps_filters_by_ssid() {
        let scan = serde_json::json!({"networks": [
            {"ssid": "A", "bssid": "1"}, {"ssid": "B", "bssid": "2"}, {"ssid": "A", "bssid": "3"}]});
        assert_eq!(target_aps(&scan, "A").len(), 2);
        assert!(target_aps(&scan, "Z").is_empty());
        assert!(target_aps(&serde_json::Value::Null, "A").is_empty());
    }

    #[test]
    fn incomplete_bundle_row() {
        let dir = std::env::temp_dir().join(format!("wfx-rows-{}", std::process::id())).join("20260101-000000_x");
        std::fs::create_dir_all(&dir).unwrap();
        let r = row_for(&dir);
        assert_eq!(r.restore, "incomplete");
        assert_eq!(r.name, "20260101-000000_x");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn summary_rendering_mentions_failure_and_restore() {
        let s = Summary {
            schema_version: 1,
            ssid: "ExampleCafe".into(),
            started_at: "t".into(),
            finished_at: "t".into(),
            join: "ok".into(),
            join_error: None,
            ip_source: None,
            ip_acquired_after_sec: None,
            link_local_seen: true,
            first_failure: Some("ip_address".into()),
            restore: "ok".into(),
            restore_ssid: Some("ExampleHotspot".into()),
            aborted: None,
            bundle: "/b".into(),
            run_id: "abc".into(),
            our_mac: None,
            pcap: Some("still_recording".into()),
        };
        let t = render_summary(&s);
        assert!(t.contains("not obtained") && t.contains("169.254") && t.contains("ip_address") && t.contains("ExampleHotspot") && t.contains("still_recording"));
    }
}
