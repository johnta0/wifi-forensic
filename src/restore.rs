//! Wi-Fi restore (returning to the original network after a capture).
//!
//! The staged retry logic is written against `RestoreOps`, and the clock and sleep are swappable too, so
//! unit tests finish instantly without using real time.

use crate::collect;
use crate::exec;
use serde::Serialize;
use std::time::Duration;

/// Upper bound on the whole restore.
pub const DEADLINE: Duration = Duration::from_secs(120);
/// Maximum number of joins to the restore SSID.
const JOIN_ATTEMPTS: u32 = 3;
/// Interval between joins.
const JOIN_INTERVAL: Duration = Duration::from_secs(3);
/// Upper bound on a single join during restore.
const JOIN_TIMEOUT: Duration = Duration::from_secs(20);
/// Time held back so joins can't use up the budget and leave no room for a power cycle.
const POWER_CYCLE_RESERVE: Duration = Duration::from_secs(15);

/// External operations performed by restore. Replaced with a fake in tests.
pub trait RestoreOps {
    /// The currently connected SSID (via the helper; `None` if unavailable).
    fn current_ssid(&mut self) -> Option<String>;
    /// Joins the SSID and verifies it is actually connected to it. The failure reason is in `Err`.
    fn join(&mut self, ssid: &str, timeout: Duration) -> Result<(), String>;
    /// Turns Wi-Fi power on / off.
    fn power(&mut self, on: bool) -> Result<(), String>;
    /// Whether the internet is reachable (the captive check URL returns `Success`).
    fn is_online(&mut self) -> bool;
    fn sleep(&mut self, d: Duration);
    /// Time elapsed since the restore started.
    fn elapsed(&mut self) -> Duration;
}

/// Record of one restore attempt (an element of `restore.json`).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Attempt {
    /// `already_online` / `join` / `power_off` / `power_on` / `wait`
    pub action: String,
    pub ssid: Option<String>,
    pub ok: bool,
    pub error: Option<String>,
    pub at_sec: f64,
}

/// Result of a restore.
#[derive(Debug, Clone, Serialize)]
pub struct RestoreResult {
    pub ok: bool,
    pub total_sec: f64,
    pub attempts: Vec<Attempt>,
}

/// Restores with staged retries.
///
/// 0. If there is a restore SSID and **the current SSID matches it and we are online**, succeed without doing anything
///    (if the SSID is unknown or different, don't skip even when online, since it may be another network)
/// 1. a. Join the restore SSID (up to 3 times, 3 s apart; after a join, wait for DHCP while checking online)
/// 2. b. Power-cycle Wi-Fi (always run ON even if OFF fails, and retry ON within the deadline)
/// 3. c. Wait for auto-join for the remaining time
///
/// Each operation's timeout is derived from the remaining time (keeping the power-cycle reserve). Step a is skipped when there is no restore SSID.
pub fn restore_with(ops: &mut dyn RestoreOps, target: Option<&str>, deadline: Duration) -> RestoreResult {
    let mut attempts = Vec::new();
    let mut rec = |ops: &mut dyn RestoreOps, action: &str, ssid: Option<&str>, r: Result<(), String>| {
        let ok = r.is_ok();
        attempts.push(Attempt {
            action: action.into(),
            ssid: ssid.map(String::from),
            ok,
            error: r.err(),
            at_sec: ops.elapsed().as_secs_f64(),
        });
        ok
    };

    if let Some(t) = target {
        if ops.current_ssid().as_deref() == Some(t) && ops.is_online() {
            rec(ops, "already_online", Some(t), Ok(()));
            return finish(ops, true, attempts);
        }
    }

    if let Some(ssid) = target {
        for i in 0..JOIN_ATTEMPTS {
            let remaining = deadline.saturating_sub(ops.elapsed());
            if remaining <= POWER_CYCLE_RESERVE {
                break;
            }
            let timeout = JOIN_TIMEOUT.min(remaining - POWER_CYCLE_RESERVE);
            let joined = ops.join(ssid, timeout);
            let join_ok = joined.is_ok();
            rec(ops, "join", Some(ssid), joined);
            if join_ok {
                // DHCP takes a few seconds, so wait a bit while checking online
                for _ in 0..3 {
                    if ops.elapsed() >= deadline {
                        break;
                    }
                    ops.sleep(JOIN_INTERVAL);
                    if ops.is_online() {
                        rec(ops, "wait", Some(ssid), Ok(()));
                        return finish(ops, true, attempts);
                    }
                }
            } else if i + 1 < JOIN_ATTEMPTS {
                ops.sleep(JOIN_INTERVAL);
            }
        }
    }

    if ops.elapsed() < deadline {
        let off = ops.power(false);
        rec(ops, "power_off", None, off);
        ops.sleep(Duration::from_secs(2));
        // Never leave Wi-Fi OFF: retry ON within the deadline until it succeeds
        loop {
            let on = ops.power(true);
            let on_ok = rec(ops, "power_on", None, on);
            if on_ok || ops.elapsed() >= deadline {
                break;
            }
            ops.sleep(Duration::from_secs(2));
        }
    }

    // c. Wait for auto-join for the remaining time
    while ops.elapsed() < deadline {
        ops.sleep(JOIN_INTERVAL);
        if ops.is_online() {
            rec(ops, "wait", None, Ok(()));
            return finish(ops, true, attempts);
        }
    }
    rec(ops, "wait", None, Err("still offline after the deadline".into()));
    finish(ops, false, attempts)
}

fn finish(ops: &mut dyn RestoreOps, ok: bool, attempts: Vec<Attempt>) -> RestoreResult {
    RestoreResult { ok, total_sec: ops.elapsed().as_secs_f64(), attempts }
}

/// Determines join success from the output of `networksetup -setairportnetwork`.
///
/// This command exits **0** even on failure and prints the error to stdout
/// (e.g. `Failed to join network X.` / `Error: -3900 ...`), so the output is checked too.
pub fn parse_join_output(out: &str) -> Result<(), String> {
    let text = out.trim();
    let failed = text.contains("Failed to join")
        || text.contains("Could not find network")
        || text.contains("Error:")
        || text.contains("Error -")
        || text.contains("is not a Wi-Fi interface");
    if failed {
        Err(text.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" "))
    } else {
        Ok(())
    }
}

/// SSID state as checked via the helper after a join.
#[derive(Debug, PartialEq)]
pub enum SsidCheck {
    Matched,
    /// Connected to a different SSID
    Other(String),
    /// Could not be verified via the helper
    Unknown,
}

/// Determines join success from the `networksetup` result (exit / timeout / output) and the SSID check.
///
/// - timeout / killed by signal / non-zero exit / error in output → failure
/// - SSID matches target → success, different SSID → failure
/// - if the SSID can't be verified, succeed only when the output is empty (any output means failure)
pub fn judge_join(
    code: Option<i32>,
    timed_out: bool,
    stdout: &str,
    stderr: &str,
    check: &SsidCheck,
) -> Result<(), String> {
    if timed_out {
        return Err("networksetup timed out".into());
    }
    match code {
        None => return Err("networksetup was killed by a signal".into()),
        Some(0) => {}
        Some(c) => {
            return Err(format!("networksetup exited {c}: {} {}", stdout.trim(), stderr.trim()).trim().to_string())
        }
    }
    let text = format!("{}\n{}", stdout.trim(), stderr.trim());
    parse_join_output(&text)?;
    match check {
        SsidCheck::Matched => Ok(()),
        SsidCheck::Other(s) => Err(format!("SSID after join differs from target (current: {s})")),
        SsidCheck::Unknown if text.trim().is_empty() => Ok(()),
        SsidCheck::Unknown => Err(format!("could not verify SSID and got output: {}", text.trim())),
    }
}

/// Runs `networksetup -setairportnetwork` and verifies via the helper that the SSID became the target.
///
/// `timeout` covers networksetup plus the SSID check (the check gets at most `timeout/3`, capped at 10 s).
/// The password ends up in argv, but only briefly (it is received via env, not as an argument).
pub fn join_network(device: &str, ssid: &str, password: Option<&str>, timeout: Duration) -> Result<(), String> {
    let confirm_window = Duration::from_secs(10).min(timeout / 3);
    let mut args = vec!["-setairportnetwork", device, ssid];
    if let Some(p) = password {
        args.push(p);
    }
    let out = exec::run("networksetup", &args, timeout - confirm_window).map_err(|e| e.to_string())?;
    // If the command itself failed, skip the SSID check (the helper is slow)
    let text = format!("{}\n{}", out.stdout, out.stderr);
    let cmd_ok = !out.timed_out && out.code == Some(0) && parse_join_output(&text).is_ok();
    let check = if cmd_ok { confirm_ssid(ssid, confirm_window) } else { SsidCheck::Unknown };
    judge_join(out.code, out.timed_out, &out.stdout, &out.stderr, &check)
}

/// Waits up to `window` for the helper to report `ssid` as the SSID.
fn confirm_ssid(ssid: &str, window: Duration) -> SsidCheck {
    let start = std::time::Instant::now();
    let mut last = SsidCheck::Unknown;
    loop {
        match collect::current_ssid() {
            Some(s) if s == ssid => return SsidCheck::Matched,
            Some(s) => last = SsidCheck::Other(s),
            None => {}
        }
        if start.elapsed() >= window {
            return last;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Turns Wi-Fi power on / off.
pub fn set_power(device: &str, on: bool) -> Result<(), String> {
    let state = if on { "on" } else { "off" };
    let out = exec::run("networksetup", &["-setairportpower", device, state], Duration::from_secs(20))
        .map_err(|e| e.to_string())?;
    if out.success() {
        Ok(())
    } else {
        Err(format!("-setairportpower {state} failed: {} {}", out.stdout.trim(), out.stderr.trim()))
    }
}

/// `RestoreOps` for the real machine.
pub struct RealOps {
    pub device: String,
    start: std::time::Instant,
}

impl RealOps {
    pub fn new(device: &str) -> Self {
        RealOps { device: device.into(), start: std::time::Instant::now() }
    }
}

impl RestoreOps for RealOps {
    fn current_ssid(&mut self) -> Option<String> {
        collect::current_ssid()
    }

    fn join(&mut self, ssid: &str, timeout: Duration) -> Result<(), String> {
        join_network(&self.device, ssid, None, timeout)
    }

    fn power(&mut self, on: bool) -> Result<(), String> {
        set_power(&self.device, on)
    }

    fn is_online(&mut self) -> bool {
        let args = [
            "--interface",
            &self.device,
            "-s",
            "-m",
            "5",
            "-w",
            "\n%{http_code}",
            "http://captive.apple.com/hotspot-detect.html",
        ];
        match exec::run("curl", &args, Duration::from_secs(8)) {
            Ok(o) if o.success() => crate::diagnose::interpret_captive(&o.stdout).is_ok(),
            _ => false,
        }
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }

    fn elapsed(&mut self) -> Duration {
        self.start.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake with a clock. `sleep` advances the clock.
    struct Fake {
        now: Duration,
        /// Join results returned in order (success once exhausted)
        joins: Vec<Result<(), String>>,
        join_calls: u32,
        join_timeouts: Vec<Duration>,
        /// power(false) / power(true) results returned in order (success once exhausted)
        off_results: Vec<Result<(), String>>,
        on_results: Vec<Result<(), String>>,
        on_calls: u32,
        off_calls: u32,
        /// Goes online at or after this time (if the other conditions hold)
        online_after: Option<Duration>,
        /// If true, only goes online after a power on
        needs_power_cycle: bool,
        ssid: Option<String>,
    }

    impl Fake {
        fn new() -> Self {
            Fake {
                now: Duration::ZERO,
                joins: vec![],
                join_calls: 0,
                join_timeouts: vec![],
                off_results: vec![],
                on_results: vec![],
                on_calls: 0,
                off_calls: 0,
                online_after: None,
                needs_power_cycle: false,
                ssid: None,
            }
        }
    }

    impl RestoreOps for Fake {
        fn current_ssid(&mut self) -> Option<String> {
            self.ssid.clone()
        }
        fn join(&mut self, _ssid: &str, timeout: Duration) -> Result<(), String> {
            self.join_calls += 1;
            self.join_timeouts.push(timeout);
            self.now += Duration::from_secs(1);
            if self.joins.is_empty() {
                Ok(())
            } else {
                self.joins.remove(0)
            }
        }
        fn power(&mut self, on: bool) -> Result<(), String> {
            self.now += Duration::from_secs(1);
            let (calls, results) = if on {
                (&mut self.on_calls, &mut self.on_results)
            } else {
                (&mut self.off_calls, &mut self.off_results)
            };
            *calls += 1;
            if results.is_empty() {
                Ok(())
            } else {
                results.remove(0)
            }
        }
        fn is_online(&mut self) -> bool {
            self.online_after.is_some_and(|t| self.now >= t) && (!self.needs_power_cycle || self.on_calls > 0)
        }
        fn sleep(&mut self, d: Duration) {
            self.now += d;
        }
        fn elapsed(&mut self) -> Duration {
            self.now
        }
    }

    #[test]
    fn success_on_first_join() {
        let mut f = Fake::new();
        f.online_after = Some(Duration::from_secs(4));
        let r = restore_with(&mut f, Some("Home"), DEADLINE);
        assert!(r.ok);
        assert_eq!(f.join_calls, 1);
        assert_eq!(f.on_calls, 0);
    }

    #[test]
    fn skips_only_when_ssid_matches_and_online() {
        let mut f = Fake::new();
        f.online_after = Some(Duration::ZERO);
        f.ssid = Some("Home".into());
        let r = restore_with(&mut f, Some("Home"), DEADLINE);
        assert!(r.ok);
        assert_eq!(f.join_calls, 0);
        assert_eq!(r.attempts[0].action, "already_online");
    }

    #[test]
    fn online_on_other_ssid_still_restores() {
        let mut f = Fake::new();
        f.online_after = Some(Duration::ZERO);
        f.ssid = Some("TargetNet".into());
        let r = restore_with(&mut f, Some("Home"), DEADLINE);
        assert_eq!(f.join_calls, 1, "joins when the SSID differs, even if online");
        assert_eq!(r.attempts[0].action, "join");
    }

    #[test]
    fn online_with_unknown_ssid_still_restores() {
        let mut f = Fake::new();
        f.online_after = Some(Duration::ZERO);
        f.ssid = None;
        restore_with(&mut f, Some("Home"), DEADLINE);
        assert_eq!(f.join_calls, 1);
    }

    #[test]
    fn no_target_never_skips_even_if_online() {
        let mut f = Fake::new();
        f.online_after = Some(Duration::ZERO);
        f.ssid = Some("Whatever".into());
        restore_with(&mut f, None, DEADLINE);
        assert_eq!(f.on_calls, 1, "with no restore target, power-cycle and rely on auto-join");
    }

    #[test]
    fn join_fails_three_times_then_power_cycle_succeeds() {
        let mut f = Fake::new();
        f.joins = vec![Err("e1".into()), Err("e2".into()), Err("e3".into())];
        f.online_after = Some(Duration::ZERO);
        f.needs_power_cycle = true;
        let r = restore_with(&mut f, Some("Home"), DEADLINE);
        assert!(r.ok);
        assert_eq!(f.join_calls, 3);
        let actions: Vec<_> = r.attempts.iter().map(|a| a.action.as_str()).collect();
        assert_eq!(actions, ["join", "join", "join", "power_off", "power_on", "wait"]);
        assert_eq!(r.attempts[0].error.as_deref(), Some("e1"));
    }

    #[test]
    fn power_on_runs_even_if_off_failed_and_is_retried() {
        let mut f = Fake::new();
        f.off_results = vec![Err("off failed".into())];
        f.on_results = vec![Err("busy".into()), Err("busy".into())];
        f.online_after = Some(Duration::ZERO);
        f.needs_power_cycle = true;
        let r = restore_with(&mut f, None, DEADLINE);
        assert!(r.ok);
        assert_eq!(f.off_calls, 1);
        assert_eq!(f.on_calls, 3, "on is retried until it succeeds");
    }

    #[test]
    fn power_on_attempted_at_least_once_near_deadline() {
        let mut f = Fake::new();
        f.now = Duration::from_secs(119);
        f.on_results = vec![Err("x".into()); 50];
        let r = restore_with(&mut f, None, DEADLINE);
        assert!(!r.ok);
        assert!(f.on_calls >= 1);
        assert!(f.now < DEADLINE + Duration::from_secs(10), "retries stop at the deadline");
    }

    #[test]
    fn join_timeout_is_capped_by_remaining_budget() {
        let mut f = Fake::new();
        f.joins = vec![Err("e".into()); 3];
        restore_with(&mut f, Some("Home"), DEADLINE);
        assert_eq!(f.join_timeouts[0], JOIN_TIMEOUT);
        // With only 30 s left, subtract the power-cycle reserve
        let mut f = Fake::new();
        f.now = Duration::from_secs(90);
        f.joins = vec![Err("e".into()); 3];
        restore_with(&mut f, Some("Home"), DEADLINE);
        assert_eq!(f.join_timeouts[0], Duration::from_secs(15));
        // If the remainder is at most the reserve, skip join and go to power cycle
        let mut f = Fake::new();
        f.now = Duration::from_secs(110);
        restore_with(&mut f, Some("Home"), DEADLINE);
        assert_eq!(f.join_calls, 0);
        assert!(f.on_calls >= 1);
    }

    #[test]
    fn never_online_fails_after_deadline() {
        let mut f = Fake::new();
        let r = restore_with(&mut f, Some("Home"), DEADLINE);
        assert!(!r.ok);
        assert!(f.now >= DEADLINE);
        assert_eq!(f.on_calls, 1);
        assert_eq!(r.attempts.last().unwrap().action, "wait");
        assert!(!r.attempts.last().unwrap().ok);
    }

    #[test]
    fn join_output_failure_is_detected_despite_exit_0() {
        let out = "Failed to join network ExampleCafe.\nError: -3900  The operation couldn't be completed.\n";
        let e = parse_join_output(out).unwrap_err();
        assert!(e.contains("-3900"));
        assert!(parse_join_output("Could not find network Foo.\n").is_err());
        assert!(parse_join_output("").is_ok());
        assert!(parse_join_output("  \n").is_ok());
    }

    #[test]
    fn judge_join_rules() {
        let m = SsidCheck::Matched;
        assert!(judge_join(Some(0), false, "", "", &m).is_ok());
        // timeout / signal / non-zero are failures
        assert!(judge_join(Some(0), true, "", "", &m).is_err());
        assert!(judge_join(None, false, "", "", &m).is_err());
        assert!(judge_join(Some(1), false, "", "boom", &m).unwrap_err().contains("boom"));
        // exit 0 but an error in the output (including stderr)
        assert!(judge_join(Some(0), false, "Failed to join network X.", "", &m).is_err());
        assert!(judge_join(Some(0), false, "", "Error: -3900", &m).is_err());
        // Different SSID is a failure
        assert!(judge_join(Some(0), false, "", "", &SsidCheck::Other("Old".into())).unwrap_err().contains("Old"));
        // Unknown SSID: success if output is empty, failure otherwise
        assert!(judge_join(Some(0), false, "", "", &SsidCheck::Unknown).is_ok());
        assert!(judge_join(Some(0), false, "something odd", "", &SsidCheck::Unknown).is_err());
    }
}
