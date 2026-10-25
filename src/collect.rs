//! Collects the current network state from macOS commands and the Swift helper.
//!
//! Parsing of external command output lives in pure functions (`parse_*`) so it can be unit-tested.

use crate::exec;
use crate::model::*;
use std::path::PathBuf;
use std::time::Duration;

const CMD_TIMEOUT: Duration = Duration::from_secs(5);
/// Give the helper a longer allowance so it can wait on the location permission dialog.
const HELPER_TIMEOUT: Duration = Duration::from_secs(45);

/// Simple run that just grabs stdout. `None` on failure or non-zero exit.
pub fn stdout_of(program: &str, args: &[&str]) -> Option<String> {
    let out = exec::run(program, args, CMD_TIMEOUT).ok()?;
    out.success().then_some(out.stdout)
}

/// Current time in ISO 8601 (with time zone).
pub fn now_iso8601() -> String {
    stdout_of("date", &["+%Y-%m-%dT%H:%M:%S%z"])
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

// ---------------------------------------------------------------- parsing (pure functions)

/// Returns the device for the given port name (e.g. `Wi-Fi`) from `networksetup -listallhardwareports`.
pub fn parse_device_for_port(text: &str, port: &str) -> Option<String> {
    let mut in_port = false;
    for line in text.lines() {
        if let Some(name) = line.strip_prefix("Hardware Port:") {
            in_port = name.trim() == port;
        } else if in_port {
            if let Some(dev) = line.strip_prefix("Device:") {
                return Some(dev.trim().to_string());
            }
        }
    }
    None
}

/// Returns the service name for a device from `networksetup -listnetworkserviceorder`.
///
/// Hardware port names and service names differ (services can be renamed), so this output maps them.
/// Format: `(1) Wi-Fi` followed by a line `(Hardware Port: Wi-Fi, Device: en0)`.
pub fn parse_service_for_device(text: &str, device: &str) -> Option<String> {
    let mut service: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("(Hardware Port:") {
            let dev = line.rsplit_once("Device:").map(|(_, d)| d.trim_end_matches(')').trim());
            if dev == Some(device) {
                return service;
            }
        } else if let Some(rest) = line.strip_prefix('(') {
            // "(1) Wi-Fi" / "(*) Disabled Service"
            service = rest.split_once(") ").map(|(_, name)| name.to_string());
        }
    }
    None
}

/// Determines the IPv4 configuration method from the first line of `networksetup -getinfo <service>`.
pub fn parse_ip_method(text: &str) -> IpMethod {
    match text.lines().next().unwrap_or("").trim() {
        "DHCP Configuration" => IpMethod::Dhcp,
        "Manual Configuration" => IpMethod::Manual,
        "Manually Using DHCP Router Configuration" => IpMethod::ManualWithDhcpRouter,
        "BOOTP Configuration" => IpMethod::Bootp,
        _ => IpMethod::Unknown,
    }
}

/// Extracts (gateway, interface) from `route -n get default`.
pub fn parse_route(text: &str) -> (Option<String>, Option<String>) {
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(key))
            .map(|v| v.trim().to_string())
    };
    (field("gateway:"), field("interface:"))
}

/// Parsed result of `ipconfig getpacket`.
#[derive(Debug, Default, PartialEq)]
pub struct Lease {
    pub server: Option<String>,
    pub lease_seconds: Option<u64>,
    pub dns: Vec<String>,
}

/// Extracts the DHCP server, lease time, and DNS from `ipconfig getpacket <if>`.
pub fn parse_getpacket(text: &str) -> Lease {
    let mut lease = Lease::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let (key, value) = (key.trim(), value.trim());
        if key.starts_with("server_identifier") {
            lease.server = Some(value.to_string());
        } else if key.starts_with("lease_time") {
            lease.lease_seconds = value
                .strip_prefix("0x")
                .and_then(|h| u64::from_str_radix(h, 16).ok());
        } else if key.starts_with("domain_name_server") {
            lease.dns = value
                .trim_matches(|c| c == '{' || c == '}')
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    lease
}

/// Returns the current MAC from the `ether` line of `ifconfig <if>`.
pub fn parse_ether(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("ether "))
        .map(|m| m.trim().to_string())
}

/// Whether the address is in 169.254.0.0/16 (link-local = self-assigned when DHCP fails).
pub fn is_link_local(ip: &str) -> bool {
    ip.starts_with("169.254.")
}

// ---------------------------------------------------------------- calling the helper

/// Locates the Swift helper (`helper/wfx-helper`).
///
/// Search order: `WFX_HELPER` env var → ancestors of the executable's directory → current directory.
pub fn helper_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("WFX_HELPER") {
        return Some(PathBuf::from(p));
    }
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.to_path_buf()));
    let cwd = std::env::current_dir().ok();
    for start in [exe_dir, cwd].into_iter().flatten() {
        for dir in start.ancestors() {
            let cand = dir.join("helper").join("wfx-helper");
            if cand.exists() {
                return Some(cand);
            }
        }
    }
    None
}

/// Runs a helper subcommand (`current` / `scan`) and returns the raw JSON string.
///
/// Returns the JSON even on a non-zero exit code if any was printed (so authorization etc. can be used).
pub fn helper_raw(cmd: &str) -> Result<String, String> {
    let path = helper_path().ok_or("helper/wfx-helper not found (set WFX_HELPER to specify it)")?;
    let out = exec::run(
        path.to_str().unwrap_or_default(),
        &[cmd, "--timeout", "30"],
        HELPER_TIMEOUT,
    )
    .map_err(|e| e.to_string())?;
    if out.timed_out {
        return Err("helper is not responding (it may be waiting for location permission)".into());
    }
    Ok(out.stdout)
}

/// The currently connected SSID. `None` if the helper failed, is unauthorized, or not connected.
pub fn current_ssid() -> Option<String> {
    let report: HelperReport = serde_json::from_str(&helper_raw("current").ok()?).ok()?;
    report.interface?.ssid.filter(|s| !s.is_empty())
}

/// Runs the helper to get a `HelperReport`. The failure reason is returned as the `Err` string.
fn run_helper() -> Result<HelperReport, String> {
    let raw = helper_raw("current")?;
    serde_json::from_str(&raw).map_err(|e| format!("cannot parse helper output: {e}"))
}

// ---------------------------------------------------------------- collection

/// Collection result. `warnings` describes information that could not be obtained.
pub struct Collected {
    pub wifi: WifiInfo,
    pub network: NetworkInfo,
    pub warnings: Vec<String>,
}

/// Wi-Fi device name (e.g. `en0`). Falls back to `en0`.
pub fn wifi_device() -> String {
    let ports = stdout_of("networksetup", &["-listallhardwareports"]).unwrap_or_default();
    parse_device_for_port(&ports, "Wi-Fi").unwrap_or_else(|| "en0".into())
}

/// Returns the device's "Ethernet Address" (hardware MAC) from `-listallhardwareports`.
pub fn parse_hardware_mac(text: &str, device: &str) -> Option<String> {
    let mut lines = text.lines();
    while let Some(l) = lines.next() {
        if l.trim().strip_prefix("Device:").map(str::trim) == Some(device) {
            let mac = lines.next()?.trim().strip_prefix("Ethernet Address:")?.trim();
            return (mac != "(null)" && !mac.is_empty()).then(|| mac.to_string());
        }
    }
    None
}

/// Collects the current L1-L4 state (Wi-Fi, IP settings, gateway). Does not test connectivity.
pub fn collect() -> Collected {
    let mut warnings = Vec::new();
    let device = wifi_device();

    let mut wifi = WifiInfo { interface: device.clone(), ..Default::default() };
    match run_helper() {
        Ok(report) => {
            wifi.location_authorization = report.authorization.clone();
            if let Some(err) = report.error.as_deref().filter(|e| !e.is_empty()) {
                warnings.push(format!("helper: {err}"));
                wifi.helper_error = Some(err.to_string());
            }
            if let Some(i) = report.interface {
                wifi.ssid = i.ssid;
                wifi.bssid = i.bssid;
                wifi.rssi_dbm = i.rssi_dbm;
                wifi.noise_dbm = i.noise_dbm;
                wifi.phy_mode = i.phy_mode;
                wifi.security = i.security;
                wifi.transmit_rate_mbps = i.transmit_rate_mbps;
                // The SSID needs location permission, so association is judged by whether a channel is present
                wifi.associated = Some(i.channel.as_ref().and_then(|c| c.number).is_some());
                wifi.channel = i.channel.as_ref().and_then(|c| c.number);
                wifi.band = i.channel.and_then(|c| c.band);
            }
            if wifi.location_authorization.as_deref() != Some("authorized") {
                warnings.push("location permission not granted, so SSID / BSSID are unavailable".into());
            }
        }
        Err(e) => {
            // Only means it could not be read, not necessarily disconnected (associated stays None)
            warnings.push(e.clone());
            wifi.helper_error = Some(e);
        }
    }
    wifi.current_mac = stdout_of("ifconfig", &[&device]).and_then(|t| parse_ether(&t));

    let order = stdout_of("networksetup", &["-listnetworkserviceorder"]).unwrap_or_default();
    let mut net = NetworkInfo {
        service: parse_service_for_device(&order, &device),
        ..Default::default()
    };
    if let Some(service) = net.service.clone() {
        if let Some(info) = stdout_of("networksetup", &["-getinfo", &service]) {
            net.ip_method = Some(parse_ip_method(&info));
        }
    }
    net.ipv4 = stdout_of("ipconfig", &["getifaddr", &device])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    net.link_local = net.ipv4.as_deref().is_some_and(is_link_local);

    if let Some(route) = stdout_of("route", &["-n", "get", "-ifscope", &device, "default"]) {
        let (gw, iface) = parse_route(&route);
        net.gateway = gw;
        net.default_route_interface = iface;
    }
    if let Some(packet) = stdout_of("ipconfig", &["getpacket", &device]) {
        let lease = parse_getpacket(&packet);
        net.dhcp_server = lease.server;
        net.lease_seconds = lease.lease_seconds;
        net.dns = lease.dns;
    }
    // DNS servers set explicitly on the service take precedence over DHCP-provided ones
    if let Some(service) = &net.service {
        if let Some(text) = stdout_of("networksetup", &["-getdnsservers", service]) {
            let manual: Vec<String> = text
                .lines()
                .map(str::trim)
                .filter(|l| l.parse::<std::net::IpAddr>().is_ok())
                .map(String::from)
                .collect();
            if !manual.is_empty() {
                net.dns = manual;
            }
        }
    }
    Collected { wifi, network: net, warnings }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORDER: &str = "An asterisk (*) denotes that a network service is disabled.\n(1) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n\n(2) Home Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(*) Old Service\n(Hardware Port: iPhone USB, Device: en5)\n";
    const PORTS: &str = "\nHardware Port: Thunderbolt Bridge\nDevice: bridge0\nEthernet Address: (null)\n\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: 00:00:5e:00:53:01\n";

    #[test]
    fn device_and_service_lookup() {
        assert_eq!(parse_device_for_port(PORTS, "Wi-Fi").as_deref(), Some("en0"));
        // Services can be renamed, so look up via service order rather than port name
        assert_eq!(parse_service_for_device(ORDER, "en0").as_deref(), Some("Home Wi-Fi"));
        assert_eq!(parse_service_for_device(ORDER, "en5").as_deref(), Some("Old Service"));
        assert_eq!(parse_service_for_device(ORDER, "en9"), None);
        assert_eq!(parse_device_for_port(PORTS, "Nope"), None);
    }

    #[test]
    fn ip_method_from_first_line() {
        assert_eq!(parse_ip_method("DHCP Configuration\nIP address: 1.2.3.4"), IpMethod::Dhcp);
        assert_eq!(parse_ip_method("Manual Configuration\nIP address: 1.2.3.4"), IpMethod::Manual);
        assert_eq!(
            parse_ip_method("Manually Using DHCP Router Configuration\nIP address: 1.2.3.4"),
            IpMethod::ManualWithDhcpRouter
        );
        assert_eq!(parse_ip_method("garbage"), IpMethod::Unknown);
    }

    #[test]
    fn route_gateway_and_interface() {
        let text = "   route to: default\ndestination: default\n       mask: default\n    gateway: 172.16.5.1\n  interface: en0\n";
        assert_eq!(parse_route(text), (Some("172.16.5.1".into()), Some("en0".into())));
        assert_eq!(parse_route("route: writing to routing socket: not in table"), (None, None));
    }

    #[test]
    fn getpacket_lease() {
        let text = "op = BOOTREPLY\nyiaddr = 172.16.5.54\nserver_identifier (ip): 172.16.5.1\nlease_time (uint32): 0x5460\ndomain_name_server (ip_mult): {172.16.5.1, 203.0.113.53}\n";
        let lease = parse_getpacket(text);
        assert_eq!(lease.server.as_deref(), Some("172.16.5.1"));
        assert_eq!(lease.lease_seconds, Some(0x5460));
        assert_eq!(lease.dns, vec!["172.16.5.1", "203.0.113.53"]);
    }

    #[test]
    fn link_local_detection() {
        assert!(is_link_local("169.254.161.32"));
        assert!(!is_link_local("172.16.5.54"));
    }

    #[test]
    fn hardware_mac_lookup() {
        assert_eq!(parse_hardware_mac(PORTS, "en0").as_deref(), Some("00:00:5e:00:53:01"));
        assert_eq!(parse_hardware_mac(PORTS, "bridge0"), None);
        assert_eq!(parse_hardware_mac(PORTS, "en9"), None);
    }

    #[test]
    fn ether_line() {
        assert_eq!(parse_ether("en0: flags=8863\n\tether 02:00:5e:00:53:02\n").as_deref(), Some("02:00:5e:00:53:02"));
    }
}
