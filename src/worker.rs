//! `wfx __capture-worker <bundle>`: the detached body of capture.
//!
//! join -> wait for IP -> snapshot -> unified log -> **always restore** -> wait for pcap to finish -> summary.json (completion marker).
//! Detached with setsid so it runs to the end even if the foreground terminal or parent process goes away.
//! SIGTERM / SIGINT / SIGHUP all set a flag meaning "proceed to restore at the next checkpoint" (restore itself is never interrupted).

use crate::bundle::*;
use crate::collect;
use crate::exec;
use crate::model::{IpMethod, SCHEMA_VERSION};
use crate::restore::{self, RealOps};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Whether an abort signal was received.
static TERMINATED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    TERMINATED.store(true, Ordering::SeqCst);
}

/// Turns SIGTERM / SIGINT / SIGHUP into a flag (does not ignore them).
fn install_signals() {
    // SAFETY: the signal handler only stores to an AtomicBool (async-signal-safe).
    unsafe {
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::signal(sig, on_signal as *const () as libc::sighandler_t);
        }
    }
}

fn terminated() -> bool {
    TERMINATED.load(Ordering::SeqCst)
}

/// Restores `FD_CLOEXEC` on the exclusive lock fd inherited from the foreground.
///
/// The worker itself keeps holding the lock, but external commands it launches must not inherit it.
fn protect_lock_fd() {
    if let Some(fd) = std::env::var("WFX_LOCK_FD").ok().and_then(|v| v.parse::<i32>().ok()) {
        // SAFETY: only sets flags on the inherited fd.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
}

/// Whether this is a valid IPv4 address that is not 169.254.* (for `ipconfig getifaddr` output).
pub fn is_usable_ip(out: &str) -> bool {
    let ip = out.trim();
    !ip.is_empty() && ip.parse::<std::net::Ipv4Addr>().is_ok() && !collect::is_link_local(ip)
}

/// How the IP was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpSource {
    /// DHCP (getpacket has a server_identifier = an ACK was received on this link)
    Dhcp,
    /// Manually configured (no DHCP acquisition time is recorded)
    Manual,
}

impl IpSource {
    fn as_str(self) -> &'static str {
        match self {
            IpSource::Dhcp => "dhcp",
            IpSource::Manual => "manual",
        }
    }
}

/// Whether the IP can be considered "obtained".
///
/// Requires a valid IPv4 address (not self-assigned). Then:
/// - Manual if the IP method is manual
/// - Otherwise `ipconfig getpacket` must show a DHCP server (so a leftover IP from before the switch is not mistaken for one)
pub fn decide_acquired(method: Option<IpMethod>, ip: &str, lease_server: Option<&str>) -> Option<IpSource> {
    if !is_usable_ip(ip) {
        return None;
    }
    match method {
        Some(IpMethod::Manual | IpMethod::ManualWithDhcpRouter) => Some(IpSource::Manual),
        _ => lease_server.filter(|s| !s.is_empty()).map(|_| IpSource::Dhcp),
    }
}

/// Execution state of the restore.
#[derive(Debug, PartialEq, Clone, Copy)]
enum RestoreState {
    Pending,
    /// Running (a Drop in this state means a panic happened mid-restore)
    Running,
    Done(bool),
}

/// Guard that runs the restore exactly once. It also runs on `Drop`, so restore happens even on an early `?` return or a panic.
struct RestoreGuard {
    device: String,
    restore_ssid: Option<String>,
    bundle: PathBuf,
    timeline: Timeline,
    state: RestoreState,
}

impl RestoreGuard {
    /// If not yet run, restores and writes `restore.json`. Later calls return the previous result.
    fn run(&mut self) -> bool {
        match self.state {
            RestoreState::Done(ok) => return ok,
            // Do not recurse on re-entry (e.g. after a panic during restore)
            RestoreState::Running => return false,
            RestoreState::Pending => {}
        }
        self.state = RestoreState::Running;
        // Timeline write failures are swallowed (restore must not depend on them)
        self.timeline.event("restore_start", json!({"target": self.restore_ssid}));
        let mut ops = RealOps::new(&self.device);
        let r = restore::restore_with(&mut ops, self.restore_ssid.as_deref(), restore::DEADLINE);
        let _ = write_json_atomic(&self.bundle.join("restore.json"), &r);
        self.timeline.event("restore_done", json!({"ok": r.ok, "total_sec": r.total_sec}));
        self.state = RestoreState::Done(r.ok);
        r.ok
    }
}

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        match self.state {
            RestoreState::Pending => {
                self.run();
            }
            // Panicked during restore: do not recurse; only try not to leave Wi-Fi off
            RestoreState::Running => {
                let _ = restore::set_power(&self.device, true);
            }
            RestoreState::Done(_) => {}
        }
    }
}

/// Results collected during the capture phase. Even if a panic aborts it, what was collected so far ends up in the summary.
#[derive(Default)]
struct CaptureState {
    join_error: Option<String>,
    ip_source: Option<&'static str>,
    ip_acquired_after_sec: Option<f64>,
    link_local_seen: bool,
    first_failure: Option<String>,
    aborted: Option<String>,
    our_mac: Option<String>,
}

impl CaptureState {
    /// If the abort flag is set, records the reason and returns `true`.
    fn check_abort(&mut self, phase: &str, tl: &Timeline) -> bool {
        if terminated() {
            if self.aborted.is_none() {
                self.aborted = Some(format!("aborted by signal (before {phase})"));
                tl.event("aborted", json!({"before": phase}));
            }
            return true;
        }
        false
    }
}

/// Saves command output to `commands/<name>.txt` (stdout, plus stderr if any).
fn dump_command(bundle: &Path, name: &str, program: &str, args: &[&str]) {
    let text = match exec::run(program, args, Duration::from_secs(10)) {
        Ok(o) if o.stderr.trim().is_empty() => o.stdout,
        Ok(o) => format!("{}\n--- stderr ---\n{}", o.stdout, o.stderr),
        Err(e) => format!("(failed to run: {e})\n"),
    };
    let _ = std::fs::write(bundle.join("commands").join(format!("{name}.txt")), text);
}

/// Determines the Wi-Fi IP configuration method from `networksetup -getinfo`.
fn detect_ip_method(device: &str) -> Option<IpMethod> {
    let order = collect::stdout_of("networksetup", &["-listnetworkserviceorder"])?;
    let service = collect::parse_service_for_device(&order, device)?;
    let info = collect::stdout_of("networksetup", &["-getinfo", &service])?;
    Some(collect::parse_ip_method(&info))
}

/// Saves the snapshot (same diagnosis as P1 `test`) and raw command output.
fn snapshot(bundle: &Path, meta: &Meta, st: &mut CaptureState, tl: &Timeline) {
    tl.event("snapshot_start", json!(null));
    let dev = meta.device.as_str();
    let _ = std::fs::create_dir_all(bundle.join("commands"));
    let c = collect::collect();
    let report = crate::diagnose::build_test_report(c);
    st.first_failure = report.first_failure.map(String::from);
    let _ = write_json_atomic(&bundle.join("snapshot.json"), &report);
    let service = report.network.service.clone();
    dump_command(bundle, "ipconfig-getsummary", "ipconfig", &["getsummary", dev]);
    dump_command(bundle, "ipconfig-getpacket", "ipconfig", &["getpacket", dev]);
    dump_command(bundle, "ifconfig", "ifconfig", &[dev]);
    dump_command(bundle, "route", "route", &["-n", "get", "-ifscope", dev, "default"]);
    dump_command(bundle, "scutil-dns", "scutil", &["--dns"]);
    dump_command(bundle, "hardwareports", "networksetup", &["-listallhardwareports"]);
    if let Some(s) = service {
        dump_command(bundle, "networksetup-getinfo", "networksetup", &["-getinfo", &s]);
    }
    tl.event("snapshot_done", json!({"first_failure": st.first_failure}));
}

/// Extracts the unified log for the attempt's time range into `unified.log` (continues on failure).
fn collect_unified_log(bundle: &Path, meta: &Meta, tl: &Timeline) {
    tl.event("log_start", json!(null));
    let predicate = "subsystem == \"com.apple.IPConfiguration\" OR process == \"airportd\" OR process == \"wifid\" OR process == \"configd\"";
    let args = ["show", "--start", &meta.started_log, "--style", "compact", "--predicate", predicate];
    match exec::run("log", &args, Duration::from_secs(60)) {
        Ok(o) if o.timed_out => {
            // Keep partial output instead of discarding it
            let _ = std::fs::write(bundle.join("unified.log"), &o.stdout);
            tl.event("log_timeout", json!({"bytes": o.stdout.len()}));
        }
        Ok(o) if o.success() => {
            let _ = std::fs::write(bundle.join("unified.log"), &o.stdout);
            tl.event("log_done", json!({"bytes": o.stdout.len()}));
        }
        Ok(o) => tl.event("log_failed", json!({"code": o.code, "stderr": o.stderr.trim()})),
        Err(e) => tl.event("log_failed", json!({"error": e.to_string()})),
    }
}

/// Polls every second until an IP is obtained (up to `dhcp_wait` seconds).
fn wait_for_ip(meta: &Meta, st: &mut CaptureState, tl: &Timeline) {
    let dev = meta.device.as_str();
    let method = detect_ip_method(dev);
    tl.event("ip_poll_start", json!({"max_sec": meta.dhcp_wait, "ip_method": method.map(|m| format!("{m:?}"))}));
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(meta.dhcp_wait) {
        if st.check_abort("ip_poll", tl) {
            return;
        }
        let ip = collect::stdout_of("ipconfig", &["getifaddr", dev]).unwrap_or_default();
        let ip = ip.trim();
        if collect::is_link_local(ip) && !st.link_local_seen {
            st.link_local_seen = true;
            tl.event("link_local_seen", json!({"ip": ip, "after_sec": t0.elapsed().as_secs_f64()}));
        }
        // Check for a lease only when a valid IP is present and the method is not manual (getpacket is somewhat expensive)
        let server = if is_usable_ip(ip) && !matches!(method, Some(IpMethod::Manual | IpMethod::ManualWithDhcpRouter)) {
            collect::stdout_of("ipconfig", &["getpacket", dev]).and_then(|t| collect::parse_getpacket(&t).server)
        } else {
            None
        };
        if let Some(src) = decide_acquired(method, ip, server.as_deref()) {
            let sec = t0.elapsed().as_secs_f64();
            st.ip_source = Some(src.as_str());
            if src == IpSource::Dhcp {
                st.ip_acquired_after_sec = Some(sec);
            }
            tl.event("ip_acquired", json!({"ip": ip, "source": src.as_str(), "after_sec": sec}));
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    tl.event("ip_timeout", json!({"waited_sec": meta.dhcp_wait}));
}

/// join -> wait for IP -> snapshot -> log. Even if this panics, the caller restores.
fn capture_phase(bundle: &Path, meta: &Meta, st: &mut CaptureState, tl: &Timeline) {
    if st.check_abort("join", tl) {
        st.join_error = Some("aborted before join".into());
        return;
    }
    let password = std::env::var("WFX_WIFI_PASSWORD").ok().filter(|p| !p.is_empty());
    tl.event("join_start", json!({"ssid": meta.ssid, "device": meta.device, "with_password": password.is_some()}));
    let t_join = Instant::now();
    let joined = restore::join_network(&meta.device, &meta.ssid, password.as_deref(), Duration::from_secs(30));
    tl.event("join_done", json!({"ok": joined.is_ok(), "error": joined.as_ref().err(), "sec": t_join.elapsed().as_secs_f64()}));
    if let Err(e) = joined {
        st.join_error = Some(e);
        return;
    }
    // MAC at join time (Private Wi-Fi Address differs per network). analyze uses it to attribute the pcap
    dump_command(bundle, "ifconfig_after_join", "ifconfig", &[&meta.device]);
    st.our_mac = collect::stdout_of("ifconfig", &[&meta.device]).and_then(|t| collect::parse_ether(&t));
    tl.event("our_mac", json!({"mac": st.our_mac}));

    wait_for_ip(meta, st, tl);
    if st.check_abort("snapshot", tl) {
        return;
    }
    snapshot(bundle, meta, st, tl);
    if st.check_abort("log", tl) {
        return;
    }
    collect_unified_log(bundle, meta, tl);
}

/// Tells the tcpdump supervisor to stop and briefly waits for the pcap to close. Returns the value for the summary's `pcap`.
///
/// The supervisor watches for the `tcpdump.stop` file and stops tcpdump with SIGINT (the user never kills a root process).
fn finish_pcap(bundle: &Path, meta: &Meta, tl: &Timeline) -> String {
    if meta.no_pcap {
        return "none".into();
    }
    let _ = std::fs::write(bundle.join("tcpdump.stop"), "");
    let pid: Option<i32> = std::fs::read_to_string(bundle.join("tcpdump.pid")).ok().and_then(|t| t.trim().parse().ok());
    let Some(pid) = pid else {
        tl.event("pcap_unknown", json!({"reason": "cannot read tcpdump.pid"}));
        return "unknown".into();
    };
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(8) {
        if !pid_alive(pid) {
            tl.event("pcap_closed", json!({"pid": pid}));
            return "complete".into();
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    tl.event("pcap_still_recording", json!({"pid": pid}));
    "still_recording".into()
}

/// Worker entry point. Returns the exit code.
pub fn run(bundle: &Path) -> i32 {
    install_signals();
    protect_lock_fd();
    let meta: Meta = match read_json(&bundle.join("meta.json")) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("worker: {e}");
            return 1;
        }
    };
    let tl = Timeline::new(bundle);
    tl.event("worker_start", json!({"pid": std::process::id(), "run_id": meta.run_id}));

    let mut guard = RestoreGuard {
        device: meta.device.clone(),
        restore_ssid: meta.restore_ssid.clone(),
        bundle: bundle.to_path_buf(),
        timeline: tl.clone(),
        state: RestoreState::Pending,
    };
    let mut st = CaptureState::default();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        capture_phase(bundle, &meta, &mut st, &tl);
    }));
    if let Err(p) = outcome {
        let msg = p
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".into());
        tl.event("panic", json!({"message": msg}));
        st.aborted = Some(format!("panic: {msg}"));
    }

    let restore_ok = guard.run();
    let pcap = finish_pcap(bundle, &meta, &tl);
    let summary = Summary {
        schema_version: SCHEMA_VERSION,
        ssid: meta.ssid.clone(),
        started_at: meta.started_at.clone(),
        finished_at: collect::now_iso8601(),
        join: if st.join_error.is_none() { "ok" } else { "failed" }.into(),
        join_error: st.join_error.clone(),
        ip_source: st.ip_source.map(String::from),
        ip_acquired_after_sec: st.ip_acquired_after_sec,
        link_local_seen: st.link_local_seen,
        first_failure: st.first_failure.clone(),
        restore: if restore_ok { "ok" } else { "failed" }.into(),
        restore_ssid: meta.restore_ssid.clone(),
        aborted: st.aborted.clone(),
        bundle: meta.bundle.clone(),
        run_id: meta.run_id.clone(),
        our_mac: st.our_mac.clone(),
        pcap: Some(pcap),
    };
    // The summary is written atomically last (completion marker)
    if let Err(e) = write_json_atomic(&bundle.join("summary.json"), &summary) {
        eprintln!("worker: cannot write summary.json: {e}");
        return 1;
    }
    tl.event("worker_done", json!(null));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usable_ip_excludes_empty_and_link_local() {
        assert!(is_usable_ip("172.20.10.4\n"));
        assert!(!is_usable_ip(""));
        assert!(!is_usable_ip("\n"));
        assert!(!is_usable_ip("169.254.161.32\n"));
        assert!(!is_usable_ip("garbage"));
    }

    #[test]
    fn dhcp_acquisition_requires_a_lease_server() {
        // An IP alone (possibly left over from before the switch) does not count as obtained
        assert_eq!(decide_acquired(Some(IpMethod::Dhcp), "10.0.0.5", None), None);
        assert_eq!(decide_acquired(Some(IpMethod::Dhcp), "10.0.0.5", Some("")), None);
        assert_eq!(decide_acquired(Some(IpMethod::Dhcp), "10.0.0.5", Some("10.0.0.1")), Some(IpSource::Dhcp));
        // A lease is required even when the method is unknown
        assert_eq!(decide_acquired(None, "10.0.0.5", None), None);
        assert_eq!(decide_acquired(None, "10.0.0.5", Some("10.0.0.1")), Some(IpSource::Dhcp));
    }

    #[test]
    fn manual_ip_is_reported_as_manual() {
        assert_eq!(decide_acquired(Some(IpMethod::Manual), "10.0.0.5", None), Some(IpSource::Manual));
        assert_eq!(decide_acquired(Some(IpMethod::ManualWithDhcpRouter), "10.0.0.5", None), Some(IpSource::Manual));
    }

    #[test]
    fn link_local_or_empty_is_never_acquired() {
        assert_eq!(decide_acquired(Some(IpMethod::Manual), "169.254.1.2", Some("x")), None);
        assert_eq!(decide_acquired(Some(IpMethod::Dhcp), "", Some("x")), None);
    }
}
