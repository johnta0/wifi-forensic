//! Diagnosis logic for `test`. Checks layers bottom-up and pinpoints the first failure.
//!
//! The verdict is a pure function (`evaluate`) that takes connectivity probe results as input.

use crate::exec;
use crate::model::*;
use std::time::Duration;

/// Connectivity probe results. `None` means not run (a prerequisite layer failed).
#[derive(Debug, Default, Clone)]
pub struct ProbeResults {
    pub gateway_ping: Option<Result<(), String>>,
    pub internet_ping: Option<Result<(), String>>,
    pub dns: Option<Result<String, String>>,
    pub http: Option<Result<(), String>>,
}

const INTERNET_HOST: &str = "1.1.1.1";
const DNS_NAME: &str = "apple.com";
const CAPTIVE_URL: &str = "http://captive.apple.com/hotspot-detect.html";

/// Whether L1-L4 are in place so connectivity probes can run.
pub fn ready_for_probes(wifi: &WifiInfo, net: &NetworkInfo) -> bool {
    // associated == None (unknown due to helper failure) just means undetermined, so still try the probes
    wifi.associated != Some(false) && net.ipv4.is_some() && !net.link_local && net.gateway.is_some()
}

/// Runs connectivity probes in parallel. ping / curl are bound to `iface` so successes via Ethernet or VPN don't leak in.
/// DNS uses the system resolver (getaddrinfo), so it cannot be bound to an interface.
pub fn run_probes(net: &NetworkInfo, iface: &str) -> ProbeResults {
    let gateway = net.gateway.clone().unwrap_or_default();
    std::thread::scope(|s| {
        let gw = s.spawn(|| ping(&gateway, iface));
        let inet = s.spawn(|| ping(INTERNET_HOST, iface));
        let dns = s.spawn(resolve_dns);
        let http = s.spawn(|| check_captive(iface));
        ProbeResults {
            gateway_ping: Some(gw.join().unwrap_or_else(|_| Err("probe crashed".into()))),
            internet_ping: Some(inet.join().unwrap_or_else(|_| Err("probe crashed".into()))),
            dns: Some(dns.join().unwrap_or_else(|_| Err("probe crashed".into()))),
            http: Some(http.join().unwrap_or_else(|_| Err("probe crashed".into()))),
        }
    })
}

/// Sends two ICMP echoes from `iface`; success if any reply comes back.
fn ping(host: &str, iface: &str) -> Result<(), String> {
    let args = ["-c", "2", "-t", "4", "-b", iface, host];
    match exec::run("ping", &args, Duration::from_secs(8)) {
        Ok(o) if o.success() => Ok(()),
        Ok(o) if o.timed_out => Err("timeout".into()),
        Ok(_) => Err("no response".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// Whether the system resolver (getaddrinfo) can resolve the name. Returns the first address on success.
///
/// `dig` is not used because it bypasses macOS's native resolution path (VPN supplemental resolvers etc.).
/// std resolution has no timeout, so it runs on a separate thread with a capped wait.
fn resolve_dns() -> Result<String, String> {
    use std::net::ToSocketAddrs;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send((DNS_NAME, 80).to_socket_addrs().map(|it| it.collect::<Vec<_>>()));
    });
    match rx.recv_timeout(Duration::from_secs(6)) {
        Ok(Ok(addrs)) => addrs
            .first()
            .map(|a| a.ip().to_string())
            .ok_or_else(|| "name resolution failed".into()),
        Ok(Err(e)) => Err(format!("name resolution failed ({e})")),
        Err(_) => Err("name resolution timed out".into()),
    }
}

/// Fetches Apple's captive-portal check URL over HTTP from `iface` and checks for `Success`.
fn check_captive(iface: &str) -> Result<(), String> {
    let args = ["-s", "-m", "6", "--interface", iface, "-w", "\n%{http_code}", CAPTIVE_URL];
    let o = exec::run("curl", &args, Duration::from_secs(8)).map_err(|e| e.to_string())?;
    if o.timed_out || !o.success() {
        return Err("HTTP connection failed (transfer failed)".into());
    }
    interpret_captive(&o.stdout)
}

/// Interprets curl output (body plus HTTP status on the last line).
pub fn interpret_captive(out: &str) -> Result<(), String> {
    let out = out.trim_end();
    let (body, code) = out.rsplit_once('\n').unwrap_or(("", out));
    match code.trim() {
        "" | "000" => Err("HTTP connection failed".into()),
        "200" if body.contains("Success") => Ok(()),
        c => Err(format!("possible captive portal (HTTP {c}, unexpected response)")),
    }
}

fn check(layer: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check { layer, status, detail: detail.into() }
}

fn from_probe(layer: &'static str, r: &Option<Result<(), String>>, ok: &str) -> Check {
    match r {
        Some(Ok(())) => check(layer, Status::Ok, ok),
        Some(Err(e)) => check(layer, Status::Fail, e.clone()),
        None => check(layer, Status::Skipped, "not run because an earlier layer failed"),
    }
}

/// Builds per-layer verdicts from the collected state and probe results.
pub fn evaluate(wifi: &WifiInfo, net: &NetworkInfo, probes: &ProbeResults) -> Vec<Check> {
    let mut checks = Vec::new();

    checks.push(match wifi.associated {
        Some(true) => {
            let rssi = wifi.rssi_dbm.map(|r| format!("RSSI {r} dBm")).unwrap_or_default();
            check("wifi_association", Status::Ok, rssi)
        }
        Some(false) => check("wifi_association", Status::Fail, "not associated with an AP"),
        // A helper failure is not a disconnect, so don't mark it Fail
        None => check(
            "wifi_association",
            Status::Unknown,
            format!("could not be determined ({})", wifi.helper_error.as_deref().unwrap_or("unknown reason")),
        ),
    });

    checks.push(match (net.ip_method, wifi.associated) {
        (_, Some(false)) => check("ip_config", Status::Skipped, "not run because an earlier layer failed"),
        (Some(IpMethod::Manual | IpMethod::ManualWithDhcpRouter), _) => check(
            "ip_config",
            Status::Ok,
            format!("⚠ manual ({}); DHCP will not assign an address", net.ipv4.as_deref().unwrap_or("no IP")),
        ),
        (Some(IpMethod::Unknown) | None, _) => {
            check("ip_config", Status::Unknown, "cannot determine how the IP is configured")
        }
        (Some(m), _) => check("ip_config", Status::Ok, format!("{m:?}").to_lowercase()),
    });

    // Unknown (undetermined) is not a failure, so later checks keep going
    let passes = |cs: &[Check]| cs.iter().all(|c| matches!(c.status, Status::Ok | Status::Unknown));
    let prior_ok = passes(&checks);
    checks.push(if !prior_ok {
        check("ip_address", Status::Skipped, "not run because an earlier layer failed")
    } else if net.link_local {
        check(
            "ip_address",
            Status::Fail,
            format!("{} is self-assigned (no DHCP response)", net.ipv4.as_deref().unwrap_or("")),
        )
    } else if let Some(ip) = &net.ipv4 {
        let lease = net.lease_seconds.map(|s| format!(", lease {s}s")).unwrap_or_default();
        check("ip_address", Status::Ok, format!("{ip}{lease}"))
    } else {
        check("ip_address", Status::Fail, "no IPv4 address")
    });

    let prior_ok = passes(&checks);
    checks.push(if !prior_ok {
        check("gateway", Status::Skipped, "not run because an earlier layer failed")
    } else if let Some(gw) = &net.gateway {
        check("gateway", Status::Ok, gw.clone())
    } else {
        check("gateway", Status::Fail, "no default route")
    });

    checks.push(from_probe("gateway_reachable", &probes.gateway_ping, "ping replied"));
    // On links that block ICMP, a working HTTP still proves reachability, so HTTP success counts as evidence
    checks.push(match (&probes.internet_ping, &probes.http) {
        (Some(Err(_)), Some(Ok(()))) => {
            check("internet", Status::Ok, "ICMP blocked, but reachable over HTTP")
        }
        (ping, _) => from_probe("internet", ping, &format!("reached {INTERNET_HOST}")),
    });
    checks.push(match &probes.dns {
        Some(Ok(ip)) => check("dns", Status::Ok, format!("{DNS_NAME} → {ip}")),
        Some(Err(e)) => check("dns", Status::Fail, e.clone()),
        None => check("dns", Status::Skipped, "not run because an earlier layer failed"),
    });
    checks.push(from_probe("http", &probes.http, "no captive portal"));
    checks
}

/// Returns the first failed layer and a hint on how to address it.
pub fn first_failure(checks: &[Check], net: &NetworkInfo) -> (Option<&'static str>, Option<String>) {
    // If a later layer (internet) passes, treat the gateway's lack of ICMP replies as AP behavior and ignore it
    let internet_ok = checks.iter().any(|c| c.layer == "internet" && c.status == Status::Ok);
    let Some(failed) = checks
        .iter()
        .find(|c| c.status == Status::Fail && !(internet_ok && c.layer == "gateway_reachable"))
    else {
        return (None, None);
    };
    let mut hint = match failed.layer {
        "wifi_association" => "Not associated with an AP. Check signal strength, the password, and DFS channels",
        "ip_address" => "No DHCP response. Renew with `sudo ipconfig set en0 DHCP` and check the AP's DHCP pool and MAC filter",
        "gateway" => "No default route. Check the IP settings",
        "gateway_reachable" => "Gateway unreachable (the AP may simply be dropping ICMP)",
        "internet" => "Cannot get past the gateway. Check for a captive portal or the upstream link",
        "dns" => "Name resolution is failing. Check the DNS server settings",
        "http" => "Possible captive portal. Open the login page in a browser",
        _ => "",
    }
    .to_string();
    if matches!(net.ip_method, Some(IpMethod::Manual | IpMethod::ManualWithDhcpRouter)) {
        let service = net.service.as_deref().unwrap_or("Wi-Fi");
        hint.push_str(&format!(
            ". Note: IPv4 is configured manually. If that is unintended, switch back to DHCP with `networksetup -setdhcp \"{service}\"`"
        ));
    }
    (Some(failed.layer), Some(hint))
}

/// Builds the diagnosis report shared by `wfx test` and `capture` snapshots.
///
/// Runs probes from the collected state (when connectivity allows) and assembles layer verdicts and the first failure.
pub fn build_test_report(c: crate::collect::Collected) -> TestReport {
    let probes = if ready_for_probes(&c.wifi, &c.network) {
        run_probes(&c.network, &c.wifi.interface)
    } else {
        ProbeResults::default()
    };
    let checks = evaluate(&c.wifi, &c.network, &probes);
    let (first_failure, hint) = first_failure(&checks, &c.network);
    TestReport {
        schema_version: SCHEMA_VERSION,
        timestamp: crate::collect::now_iso8601(),
        wifi: c.wifi,
        network: c.network,
        checks,
        first_failure,
        hint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wifi(associated: bool) -> WifiInfo {
        WifiInfo { associated: Some(associated), rssi_dbm: Some(-60), ..Default::default() }
    }
    fn net(ip: Option<&str>, method: IpMethod, gw: Option<&str>) -> NetworkInfo {
        NetworkInfo {
            ip_method: Some(method),
            ipv4: ip.map(String::from),
            link_local: ip.is_some_and(|i| i.starts_with("169.254.")),
            gateway: gw.map(String::from),
            ..Default::default()
        }
    }
    fn all_ok() -> ProbeResults {
        ProbeResults {
            gateway_ping: Some(Ok(())),
            internet_ping: Some(Ok(())),
            dns: Some(Ok("17.253.144.10".into())),
            http: Some(Ok(())),
        }
    }
    fn status_of<'a>(checks: &'a [Check], layer: &str) -> &'a Status {
        &checks.iter().find(|c| c.layer == layer).unwrap().status
    }

    #[test]
    fn healthy_connection_has_no_failure() {
        let n = net(Some("172.16.5.54"), IpMethod::Dhcp, Some("172.16.5.1"));
        let checks = evaluate(&wifi(true), &n, &all_ok());
        assert!(checks.iter().all(|c| c.status == Status::Ok));
        assert_eq!(first_failure(&checks, &n).0, None);
    }

    #[test]
    fn link_local_is_dhcp_failure_and_skips_the_rest() {
        let n = net(Some("169.254.161.32"), IpMethod::Dhcp, None);
        let checks = evaluate(&wifi(true), &n, &ProbeResults::default());
        assert_eq!(status_of(&checks, "ip_address"), &Status::Fail);
        assert_eq!(status_of(&checks, "gateway"), &Status::Skipped);
        assert_eq!(status_of(&checks, "internet"), &Status::Skipped);
        assert_eq!(first_failure(&checks, &n).0, Some("ip_address"));
    }

    #[test]
    fn not_associated_fails_at_layer_one() {
        let n = net(None, IpMethod::Dhcp, None);
        let checks = evaluate(&wifi(false), &n, &ProbeResults::default());
        assert_eq!(first_failure(&checks, &n).0, Some("wifi_association"));
        assert_eq!(status_of(&checks, "ip_config"), &Status::Skipped);
    }

    #[test]
    fn manual_ip_is_flagged_in_the_hint() {
        let n = net(Some("10.16.95.90"), IpMethod::Manual, Some("10.16.95.65"));
        let mut probes = all_ok();
        probes.internet_ping = Some(Err("timeout".into()));
        probes.http = Some(Err("HTTP connection failed".into()));
        let checks = evaluate(&wifi(true), &n, &probes);
        let (layer, hint) = first_failure(&checks, &n);
        assert_eq!(layer, Some("internet"));
        assert!(hint.unwrap().contains("setdhcp"));
    }

    #[test]
    fn icmp_blocked_but_http_ok_is_reachable() {
        let n = net(Some("172.16.5.54"), IpMethod::Dhcp, Some("172.16.5.1"));
        let mut probes = all_ok();
        probes.gateway_ping = Some(Err("no response".into()));
        probes.internet_ping = Some(Err("no response".into()));
        let checks = evaluate(&wifi(true), &n, &probes);
        assert_eq!(status_of(&checks, "internet"), &Status::Ok);
        assert_eq!(first_failure(&checks, &n).0, None);
    }

    #[test]
    fn helper_failure_is_unknown_not_disconnected() {
        let n = net(Some("172.16.5.54"), IpMethod::Dhcp, Some("172.16.5.1"));
        let w = WifiInfo { associated: None, helper_error: Some("helper missing".into()), ..Default::default() };
        let checks = evaluate(&w, &n, &all_ok());
        assert_eq!(status_of(&checks, "wifi_association"), &Status::Unknown);
        assert_eq!(first_failure(&checks, &n).0, None);
        assert!(ready_for_probes(&w, &n));
    }

    #[test]
    fn gateway_ping_failure_does_not_hide_later_layers() {
        let n = net(Some("172.16.5.54"), IpMethod::Dhcp, Some("172.16.5.1"));
        let mut probes = all_ok();
        probes.gateway_ping = Some(Err("no response".into()));
        let checks = evaluate(&wifi(true), &n, &probes);
        assert_eq!(status_of(&checks, "gateway_reachable"), &Status::Fail);
        assert_eq!(status_of(&checks, "internet"), &Status::Ok);
        // internet passes, so the gateway's lack of ICMP replies alone is not a failure
        assert_eq!(first_failure(&checks, &n).0, None);
    }

    #[test]
    fn gateway_ping_failure_counts_when_internet_is_also_down() {
        let n = net(Some("172.16.5.54"), IpMethod::Dhcp, Some("172.16.5.1"));
        let mut probes = all_ok();
        probes.gateway_ping = Some(Err("no response".into()));
        probes.internet_ping = Some(Err("timeout".into()));
        probes.http = Some(Err("HTTP connection failed".into()));
        let checks = evaluate(&wifi(true), &n, &probes);
        assert_eq!(first_failure(&checks, &n).0, Some("gateway_reachable"));
    }

    #[test]
    fn captive_portal_detection() {
        assert!(interpret_captive("<HTML><BODY>Success</BODY></HTML>\n200").is_ok());
        assert!(interpret_captive("<html>Please login</html>\n302").unwrap_err().contains("captive"));
        assert!(interpret_captive("\n000").is_err());
        // Even if the body contains Success, anything other than HTTP 200 is not success
        assert!(interpret_captive("<BODY>Success</BODY>\n500").is_err());
    }
}
