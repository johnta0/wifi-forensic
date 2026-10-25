//! Human-readable output (when `--json` is not given).

use crate::model::*;
use std::fmt::Write;

fn opt<T: ToString>(v: &Option<T>) -> String {
    v.as_ref().map(ToString::to_string).unwrap_or_else(|| "—".into())
}

fn wifi_section(out: &mut String, w: &WifiInfo) {
    let _ = writeln!(out, "Wi-Fi\n────────────────────────");
    let _ = writeln!(out, "Interface   {}", w.interface);
    let _ = writeln!(out, "SSID        {}", opt(&w.ssid));
    let _ = writeln!(out, "BSSID       {}", opt(&w.bssid));
    let _ = writeln!(out, "Security    {}", opt(&w.security));
    let _ = writeln!(out, "PHY         {}", opt(&w.phy_mode));
    let ch = match (&w.channel, &w.band) {
        (Some(n), Some(b)) => format!("{n} ({b})"),
        (Some(n), None) => n.to_string(),
        _ => "—".into(),
    };
    let _ = writeln!(out, "Channel     {ch}");
    let _ = writeln!(out, "RSSI/Noise  {} / {} dBm", opt(&w.rssi_dbm), opt(&w.noise_dbm));
    let _ = writeln!(out, "Tx rate     {} Mbps", opt(&w.transmit_rate_mbps));
    let _ = writeln!(out, "MAC         {}", opt(&w.current_mac));
}

fn network_section(out: &mut String, n: &NetworkInfo) {
    let _ = writeln!(out, "\nNetwork\n────────────────────────");
    let method = n.ip_method.map(|m| format!("{m:?}").to_lowercase());
    let _ = writeln!(out, "IP method   {}", opt(&method));
    let ip = match (&n.ipv4, n.link_local) {
        (Some(ip), true) => format!("{ip} (self-assigned)"),
        (Some(ip), false) => ip.clone(),
        _ => "—".into(),
    };
    let _ = writeln!(out, "IPv4        {ip}");
    let _ = writeln!(out, "Gateway     {}", opt(&n.gateway));
    let dns = if n.dns.is_empty() { "—".into() } else { n.dns.join(", ") };
    let _ = writeln!(out, "DNS         {dns}");
    let _ = writeln!(out, "DHCP server {}", opt(&n.dhcp_server));
    let _ = writeln!(out, "Lease       {}", n.lease_seconds.map(|s| format!("{s} s")).unwrap_or_else(|| "—".into()));
}

/// Rendering for `inspect`.
pub fn inspection(r: &Inspection) -> String {
    let mut out = String::new();
    wifi_section(&mut out, &r.wifi);
    network_section(&mut out, &r.network);
    out
}

/// Rendering for `test`.
pub fn test_report(r: &TestReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Diagnosis\n────────────────────────");
    for (i, c) in r.checks.iter().enumerate() {
        let mark = match c.status {
            Status::Ok => "✓",
            Status::Fail => "✗",
            Status::Skipped => "—",
            Status::Unknown => "?",
        };
        let _ = writeln!(out, "[{}/{}] {:<18} {}  {}", i + 1, r.checks.len(), c.layer, mark, c.detail);
    }
    if let Some(hint) = &r.hint {
        let _ = writeln!(out, "\n→ {hint}");
    }
    out.push('\n');
    wifi_section(&mut out, &r.wifi);
    network_section(&mut out, &r.network);
    out
}
