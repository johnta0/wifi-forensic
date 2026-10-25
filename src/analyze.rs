//! `wfx analyze <bundle>`: rule-based offline analysis of a bundle.
//!
//! The output of `tcpdump -nr dhcp.pcap -tt -v 'port 67 or port 68'` is split into packets, and
//! **only DHCP within the join-to-restore window and addressed to our own MAC (as of join)** is counted (matched by xid).
//! "An ACK exists" alone is not treated as success, so another client's ACK is never mistaken for ours.
//! The verdict lives in the pure function `judge`, which is unit-testable. With insufficient evidence it returns "inconclusive".

use crate::bundle::*;
use crate::collect;
use crate::exec;
use serde::Serialize;
use std::collections::HashSet;
use std::fmt::Write;
use std::path::Path;
use std::time::Duration;

/// DHCP Message Type (Option 53).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Discover,
    Offer,
    Request,
    Ack,
    Nak,
    Other,
}

impl Kind {
    /// Whether this is a reply from the server.
    fn is_reply(self) -> bool {
        matches!(self, Kind::Offer | Kind::Ack | Kind::Nak)
    }
}

/// A single DHCP packet in the pcap.
#[derive(Debug, Clone, PartialEq)]
pub struct DhcpPacket {
    /// Epoch seconds from `tcpdump -tt`
    pub epoch: f64,
    pub xid: Option<String>,
    /// Client-Ethernet-Address (chaddr)
    pub chaddr: Option<String>,
    pub kind: Kind,
}

/// Counts per DHCP Message Type (Option 53).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct DhcpCounts {
    pub discover: u32,
    pub offer: u32,
    pub request: u32,
    pub ack: u32,
    pub nak: u32,
    pub other: u32,
}

/// Reads the message type from a `DHCP-Message (53), length 1: Discover` line.
///
/// For both the new and old formats (`(53)` / `Option 53`), looks case-insensitively at the word after `:`
/// on a line containing `DHCP-Message`. Other options such as `DHCP-Message-Type` are excluded.
fn kind_of_line(line: &str) -> Option<Kind> {
    let pos = line.find("DHCP-Message")?;
    let rest = &line[pos + "DHCP-Message".len()..];
    if rest.starts_with('-') {
        return None;
    }
    let (_, ty) = rest.rsplit_once(':')?;
    Some(match ty.trim().to_ascii_lowercase().as_str() {
        "discover" => Kind::Discover,
        "offer" => Kind::Offer,
        "request" => Kind::Request,
        "ack" => Kind::Ack,
        "nak" | "nack" => Kind::Nak,
        _ => Kind::Other,
    })
}

/// A line starting with epoch seconds (`1727760000.123456 IP ...`) is the first line of a new packet.
fn epoch_of_header(line: &str) -> Option<f64> {
    if line.starts_with(char::is_whitespace) {
        return None;
    }
    let tok = line.split_whitespace().next()?;
    if !tok.contains('.') {
        return None;
    }
    tok.parse().ok()
}

/// Turns `tcpdump -nr <pcap> -tt -v` output into a list of DHCP packets. Packets without a DHCP-Message are dropped.
pub fn parse_dhcp_packets(text: &str) -> Vec<DhcpPacket> {
    let mut out = Vec::new();
    let mut cur: Option<DhcpPacket> = None;
    let mut cur_kind: Option<Kind> = None;
    let flush = |cur: &mut Option<DhcpPacket>, kind: &mut Option<Kind>, out: &mut Vec<DhcpPacket>| {
        if let (Some(mut p), Some(k)) = (cur.take(), kind.take()) {
            p.kind = k;
            out.push(p);
        }
        *kind = None;
    };
    for line in text.lines() {
        if let Some(epoch) = epoch_of_header(line) {
            flush(&mut cur, &mut cur_kind, &mut out);
            cur = Some(DhcpPacket { epoch, xid: None, chaddr: None, kind: Kind::Other });
            continue;
        }
        let Some(p) = cur.as_mut() else { continue };
        if let Some(i) = line.find("xid 0x") {
            let hex: String = line[i + 4..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
            p.xid.get_or_insert(hex);
        }
        if let Some(i) = line.find("Client-Ethernet-Address ") {
            let mac = line[i + "Client-Ethernet-Address ".len()..].split_whitespace().next().unwrap_or("");
            if !mac.is_empty() {
                p.chaddr.get_or_insert(mac.to_string());
            }
        }
        if let Some(k) = kind_of_line(line) {
            cur_kind.get_or_insert(k);
        }
    }
    flush(&mut cur, &mut cur_kind, &mut out);
    out
}

/// Compares MACs after normalizing them (ignores zero padding and case differences).
pub fn mac_eq(a: &str, b: &str) -> bool {
    fn norm(m: &str) -> Option<Vec<u8>> {
        m.trim().split(':').map(|o| u8::from_str_radix(o, 16).ok()).collect()
    }
    matches!((norm(a), norm(b)), (Some(x), Some(y)) if x.len() == 6 && x == y)
}

/// Counts only DHCP packets that belong to our MAC and the time window.
///
/// - Ignores anything outside the window `(start, end)` (epoch seconds)
/// - Only packets whose chaddr matches `mac` (server replies also carry the client's MAC in chaddr)
/// - If the xids of our own requests (Discover / Request) are known, only replies with those xids are counted
pub fn attribute(packets: &[DhcpPacket], mac: &str, window: Option<(f64, f64)>) -> DhcpCounts {
    let ours: Vec<&DhcpPacket> = packets
        .iter()
        .filter(|p| window.is_none_or(|(s, e)| p.epoch >= s && p.epoch <= e))
        .filter(|p| p.chaddr.as_deref().is_some_and(|c| mac_eq(c, mac)))
        .collect();
    let our_xids: HashSet<&str> =
        ours.iter().filter(|p| !p.kind.is_reply()).filter_map(|p| p.xid.as_deref()).collect();
    let mut c = DhcpCounts::default();
    for p in ours {
        if p.kind.is_reply() && !our_xids.is_empty() && !p.xid.as_deref().is_some_and(|x| our_xids.contains(x)) {
            continue;
        }
        match p.kind {
            Kind::Discover => c.discover += 1,
            Kind::Offer => c.offer += 1,
            Kind::Request => c.request += 1,
            Kind::Ack => c.ack += 1,
            Kind::Nak => c.nak += 1,
            Kind::Other => c.other += 1,
        }
    }
    c
}

/// Takes the epoch window from `join_start` to `restore_start` out of timeline.jsonl.
/// Without `restore_start` the end is unbounded (without `join_start` the result is `None`).
pub fn window_from_timeline(text: &str) -> Option<(f64, f64)> {
    let mut start = None;
    let mut end = None;
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let epoch = v["epoch"].as_f64();
        match v["event"].as_str() {
            Some("join_start") => start = start.or(epoch),
            Some("restore_start") => end = end.or(epoch),
            _ => {}
        }
    }
    Some((start?, end.unwrap_or(f64::MAX)))
}

/// Inputs to the verdict (facts gathered from the bundle).
#[derive(Debug, Default)]
pub struct Facts {
    /// summary.json is missing (capture did not complete)
    pub incomplete: bool,
    pub aborted: Option<String>,
    pub join_failed: bool,
    pub join_error: Option<String>,
    /// DHCP filtered by our MAC and the time window. `None` when the pcap is missing, unreadable, or cannot be attributed
    pub dhcp: Option<DhcpCounts>,
    /// `network.ip_method` from the snapshot (`dhcp` / `manual` ...)
    pub ip_method: Option<String>,
    pub first_failure: Option<String>,
    pub current_mac: Option<String>,
    pub hardware_mac: Option<String>,
    /// Reasons that lower confidence in the verdict, such as read failures
    pub unknown_reasons: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Finding {
    /// `problem` / `info`
    pub severity: &'static str,
    pub message: String,
}

/// Overall verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// A problem was found
    Problem,
    /// Evidence is complete, including a DHCP ACK to our MAC, and nothing is wrong
    Ok,
    /// Not enough evidence to decide
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct Analysis {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

fn problem(m: impl Into<String>) -> Finding {
    Finding { severity: "problem", message: m.into() }
}
fn info(m: impl Into<String>) -> Finding {
    Finding { severity: "info", message: m.into() }
}

/// Layers involved in obtaining an IP itself (a failure here is not called an "upper-layer problem").
fn is_ip_layer(layer: &str) -> bool {
    matches!(layer, "wifi_association" | "ip_config" | "ip_address")
}

/// Produces findings and an overall verdict according to the rule table.
///
/// `Ok` only when all of these hold: summary exists, join succeeded, not aborted, no snapshot failure, and an ACK to our MAC was seen.
pub fn judge(f: &Facts) -> Analysis {
    let mut out = Vec::new();
    let mut unknown: Vec<String> = f.unknown_reasons.clone();
    if f.incomplete {
        unknown.push("summary.json is missing (capture did not complete, or the worker exited abnormally)".into());
    }
    if let Some(a) = &f.aborted {
        unknown.push(format!("capture was aborted: {a}"));
    }
    if f.join_failed {
        let detail = f.join_error.as_deref().map(|e| format!(" ({e})")).unwrap_or_default();
        out.push(problem(format!("association failed: suspect signal, password, or DFS{detail}")));
    }
    // Snapshot failures are reported independently of the pcap
    if let Some(l) = &f.first_failure {
        if is_ip_layer(l) {
            out.push(problem(format!("first snapshot failure: `{l}` (connection / IP acquisition layer)")));
        } else {
            out.push(problem(format!("first snapshot failure: `{l}` (upper layer: captive portal / DNS / routing, etc.)")));
        }
    }

    let manual = f.ip_method.as_deref() == Some("manual");
    let mut ack_seen = false;
    match &f.dhcp {
        Some(d) => {
            if d.discover > 0 && d.offer == 0 {
                out.push(problem("no response from DHCP server (DISCOVER only): suspect pool exhaustion, MAC filtering, or signal"));
            }
            if d.nak > 0 {
                out.push(problem("received DHCP NAK: conflicts with a previous lease"));
            }
            if d.offer > 0 && d.ack == 0 {
                out.push(problem("got OFFER but no ACK: failed at or after REQUEST"));
            }
            if d.discover == 0 && manual {
                out.push(problem("not using DHCP (IP method is Manual). Revert with `networksetup -setdhcp`"));
            }
            if d.ack > 0 {
                ack_seen = true;
                out.push(info("DHCP ACK to our MAC confirmed (within the join-to-restore window)"));
            } else if !f.join_failed && !manual {
                unknown.push("no DHCP ACK to our MAC found in the pcap".into());
            }
        }
        None => {
            if manual {
                out.push(problem("IP method is Manual: DHCP may not be in use (no pcap)"));
            }
            if !f.join_failed {
                unknown.push("no DHCP evidence (pcap) (--no-pcap / read failure / unknown MAC)".into());
            }
        }
    }
    if let (Some(cur), Some(hw)) = (&f.current_mac, &f.hardware_mac) {
        if !mac_eq(cur, hw) {
            out.push(info(format!("Private Wi-Fi Address is enabled (current {cur} / hardware {hw})")));
        }
    }

    let has_problem = out.iter().any(|x| x.severity == "problem");
    let verdict = if has_problem {
        Verdict::Problem
    } else if unknown.is_empty() && ack_seen && !f.join_failed {
        out.push(info("no anomalies matching known rules"));
        Verdict::Ok
    } else {
        if unknown.is_empty() {
            unknown.push("not enough evidence for a verdict".into());
        }
        Verdict::Unknown
    };
    for u in unknown {
        out.push(info(format!("inconclusive because: {u}")));
    }
    Analysis { verdict, findings: out }
}

/// Gathers facts from the bundle and passes them to `judge`.
fn gather(bundle: &Path) -> (Facts, Option<Summary>, Option<DhcpCounts>) {
    let mut f = Facts::default();
    let summary_path = bundle.join("summary.json");
    let summary: Option<Summary> = match read_json(&summary_path) {
        Ok(s) => Some(s),
        Err(e) => {
            if summary_path.exists() {
                f.unknown_reasons.push(format!("{e}"));
            } else {
                f.incomplete = true;
            }
            None
        }
    };
    let snapshot: Option<serde_json::Value> = read_json(&bundle.join("snapshot.json")).ok();
    let meta: Option<Meta> = read_json(&bundle.join("meta.json")).ok();
    if let Some(s) = &summary {
        f.join_failed = s.join == "failed";
        f.join_error = s.join_error.clone();
        f.first_failure = s.first_failure.clone();
        f.aborted = s.aborted.clone();
        if !matches!(s.pcap.as_deref(), Some("complete") | Some("none")) {
            f.unknown_reasons.push(format!("pcap state is unknown ({})", s.pcap.as_deref().unwrap_or("not recorded")));
        }
        if !f.join_failed && snapshot.is_none() && s.aborted.is_none() {
            f.unknown_reasons.push("snapshot.json is missing or unreadable".into());
        }
    }
    if let Some(sn) = &snapshot {
        f.ip_method = sn["network"]["ip_method"].as_str().map(String::from);
        f.current_mac = sn["wifi"]["current_mac"].as_str().map(String::from);
        if f.first_failure.is_none() {
            f.first_failure = sn["first_failure"].as_str().map(String::from);
        }
    }
    let device = meta.as_ref().map(|m| m.device.clone()).unwrap_or_else(|| "en0".into());
    if let Ok(t) = std::fs::read_to_string(bundle.join("commands/hardwareports.txt")) {
        f.hardware_mac = collect::parse_hardware_mac(&t, &device);
    }

    let pcap = bundle.join("dhcp.pcap");
    let mut counts = None;
    if pcap.exists() {
        let window = std::fs::read_to_string(bundle.join("timeline.jsonl")).ok().and_then(|t| window_from_timeline(&t));
        if window.is_none() {
            f.unknown_reasons.push("cannot get the join-to-restore window from the timeline, so the pcap cannot be filtered".into());
        }
        let our_mac = summary.as_ref().and_then(|s| s.our_mac.clone());
        match our_mac {
            None => f.unknown_reasons.push("our MAC at join time is unknown, so the pcap cannot be attributed to us".into()),
            Some(mac) if window.is_some() => {
                let p = pcap.to_string_lossy().into_owned();
                match exec::run("tcpdump", &["-nr", &p, "-tt", "-v", "port 67 or port 68"], Duration::from_secs(30)) {
                    Ok(o) if o.success() => {
                        let c = attribute(&parse_dhcp_packets(&o.stdout), &mac, window);
                        counts = Some(c.clone());
                        f.dhcp = Some(c);
                    }
                    Ok(o) => f.unknown_reasons.push(format!("tcpdump cannot read the pcap: {}", o.stderr.trim())),
                    Err(e) => f.unknown_reasons.push(format!("cannot run tcpdump: {e}")),
                }
            }
            Some(_) => {}
        }
    }
    (f, summary, counts)
}

/// Entry point of `wfx analyze`.
pub fn run(bundle: &Path, json: bool) -> anyhow::Result<()> {
    if !bundle.is_dir() {
        anyhow::bail!("bundle directory not found: {}", bundle.display());
    }
    let (facts, summary, counts) = gather(bundle);
    let analysis = judge(&facts);
    if json {
        let v = serde_json::json!({
            "bundle": bundle.display().to_string(),
            "verdict": analysis.verdict,
            "summary": summary,
            "dhcp": counts,
            "findings": analysis.findings,
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    let mut out = String::new();
    let _ = writeln!(out, "Bundle  {}", bundle.display());
    match &summary {
        Some(s) => {
            let _ = writeln!(out, "SSID    {}  join={}  restore={}", s.ssid, s.join, s.restore);
        }
        None => {
            let _ = writeln!(out, "(no summary.json: capture may not have completed)");
        }
    }
    match &counts {
        Some(d) => {
            let _ = writeln!(
                out,
                "DHCP    discover={} offer={} request={} ack={} nak={} (our MAC, join-to-restore window only)",
                d.discover, d.offer, d.request, d.ack, d.nak
            );
        }
        None => {
            let _ = writeln!(out, "DHCP    (no pcap / cannot attribute)");
        }
    }
    let label = match analysis.verdict {
        Verdict::Problem => "problem",
        Verdict::Ok => "ok",
        Verdict::Unknown => "inconclusive",
    };
    let _ = writeln!(out, "Verdict {label}\n\nFindings\n────────────────────────");
    for f in &analysis.findings {
        let mark = if f.severity == "problem" { "✗" } else { "·" };
        let _ = writeln!(out, "{mark} {}", f.message);
    }
    print!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const US: &str = "02:00:5e:00:53:02";
    const OTHER: &str = "aa:bb:cc:dd:ee:ff";

    /// `tcpdump -tt -v`-style output for one packet.
    fn pkt(epoch: f64, from_client: bool, xid: &str, mac: &str, kind: &str) -> String {
        let dir = if from_client { "0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request" } else { "10.0.0.1.67 > 10.0.0.5.68: BOOTP/DHCP, Reply" };
        format!(
            "{epoch:.6} IP (tos 0x10, ttl 255, id 1, offset 0, flags [none], proto UDP (17), length 328)\n    {dir} from {mac}, length 300, xid 0x{xid}, Flags [none]\n\t  Client-Ethernet-Address {mac}\n\t  Vendor-rfc1048 Extensions\n\t    Magic Cookie 0x63825363\n\t    DHCP-Message (53), length 1: {kind}\n"
        )
    }

    #[test]
    fn parses_packets_with_xid_chaddr_and_kind() {
        let text = [
            pkt(100.5, true, "1a2b3c4d", US, "Discover"),
            pkt(100.6, false, "1a2b3c4d", US, "Offer"),
            pkt(100.7, true, "1a2b3c4d", US, "REQUEST"),
            pkt(100.8, false, "1a2b3c4d", US, "ACK"),
        ]
        .concat();
        let p = parse_dhcp_packets(&text);
        assert_eq!(p.len(), 4);
        assert_eq!(p[0].kind, Kind::Discover);
        assert_eq!(p[0].xid.as_deref(), Some("0x1a2b3c4d"));
        assert_eq!(p[0].chaddr.as_deref(), Some(US));
        assert_eq!(p[3].kind, Kind::Ack);
        assert!((p[3].epoch - 100.8).abs() < 1e-9);
    }

    #[test]
    fn old_style_option_line_and_nack_are_understood() {
        assert_eq!(kind_of_line("\t    DHCP-Message Option 53, length 1: Offer"), Some(Kind::Offer));
        assert_eq!(kind_of_line("\t    DHCP-Message (53), length 1: NACK"), Some(Kind::Nak));
        assert_eq!(kind_of_line("\t    DHCP-Message (53), length 1: Release"), Some(Kind::Other));
        assert_eq!(kind_of_line("\t    DHCP-Message-Type: x"), None);
        assert_eq!(kind_of_line("unrelated"), None);
    }

    #[test]
    fn packets_without_dhcp_message_are_dropped() {
        let text = "100.1 IP (tos 0x0)\n    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request, xid 0x1\n";
        assert!(parse_dhcp_packets(text).is_empty());
    }

    fn full_exchange(mac: &str, xid: &str, t: f64) -> Vec<DhcpPacket> {
        parse_dhcp_packets(
            &[
                pkt(t, true, xid, mac, "Discover"),
                pkt(t + 0.1, false, xid, mac, "Offer"),
                pkt(t + 0.2, true, xid, mac, "Request"),
                pkt(t + 0.3, false, xid, mac, "ACK"),
            ]
            .concat(),
        )
    }

    #[test]
    fn other_clients_acks_are_not_ours() {
        // Only another client's ACK was captured (we only sent DISCOVER)
        let mut p = full_exchange(OTHER, "deadbeef", 100.0);
        p.extend(parse_dhcp_packets(&pkt(101.0, true, "11111111", US, "Discover")));
        let c = attribute(&p, US, Some((90.0, 200.0)));
        assert_eq!((c.discover, c.offer, c.ack), (1, 0, 0));
    }

    #[test]
    fn packets_outside_the_window_are_ignored() {
        let p = full_exchange(US, "1", 50.0);
        assert_eq!(attribute(&p, US, Some((90.0, 200.0))), DhcpCounts::default());
        assert_eq!(attribute(&p, US, Some((40.0, 60.0))).ack, 1);
        assert_eq!(attribute(&p, US, None).ack, 1);
    }

    #[test]
    fn replies_must_match_our_request_xid() {
        let mut p = parse_dhcp_packets(&pkt(100.0, true, "aaaa0001", US, "Discover"));
        // An ACK with the same chaddr but a different xid (e.g. left over from an earlier exchange) is not counted
        p.extend(parse_dhcp_packets(&pkt(100.1, false, "bbbb0002", US, "ACK")));
        assert_eq!(attribute(&p, US, None).ack, 0);
        // Without a captured request, count by chaddr match
        let only_ack = parse_dhcp_packets(&pkt(100.1, false, "bbbb0002", US, "ACK"));
        assert_eq!(attribute(&only_ack, US, None).ack, 1);
    }

    #[test]
    fn mac_comparison_is_normalized() {
        assert!(mac_eq("02:00:5E:00:53:02", US));
        assert!(mac_eq("2:0:5e:0:53:2", "02:00:5e:00:53:02"));
        assert!(!mac_eq(US, OTHER));
        assert!(!mac_eq("junk", "junk"));
    }

    #[test]
    fn timeline_window() {
        let t = "{\"epoch\":10.0,\"event\":\"worker_start\"}\n{\"epoch\":11.5,\"event\":\"join_start\"}\nnot json\n{\"epoch\":40.0,\"event\":\"restore_start\"}\n";
        assert_eq!(window_from_timeline(t), Some((11.5, 40.0)));
        let aborted = "{\"epoch\":11.5,\"event\":\"join_start\"}\n";
        assert_eq!(window_from_timeline(aborted), Some((11.5, f64::MAX)));
        assert_eq!(window_from_timeline("{\"epoch\":1.0,\"event\":\"x\"}"), None);
    }

    fn counts(discover: u32, offer: u32, ack: u32, nak: u32) -> DhcpCounts {
        DhcpCounts { discover, offer, request: 0, ack, nak, other: 0 }
    }
    /// Baseline: summary present, join succeeded, no snapshot failure.
    fn base(d: Option<DhcpCounts>) -> Facts {
        Facts { dhcp: d, ip_method: Some("dhcp".into()), ..Default::default() }
    }
    fn has(a: &Analysis, needle: &str) -> bool {
        a.findings.iter().any(|f| f.message.contains(needle))
    }

    #[test]
    fn join_failure() {
        let f = Facts { join_failed: true, join_error: Some("-3900".into()), ..Default::default() };
        let r = judge(&f);
        assert_eq!(r.verdict, Verdict::Problem);
        assert!(has(&r, "association failed") && has(&r, "-3900"));
    }

    #[test]
    fn discover_without_offer() {
        let r = judge(&base(Some(counts(3, 0, 0, 0))));
        assert_eq!(r.verdict, Verdict::Problem);
        assert!(has(&r, "no response"));
    }

    #[test]
    fn nak_and_offer_without_ack() {
        assert!(has(&judge(&base(Some(counts(1, 1, 0, 1)))), "NAK"));
        assert!(has(&judge(&base(Some(counts(1, 1, 0, 0)))), "no ACK"));
    }

    #[test]
    fn manual_without_dhcp() {
        let f = Facts { dhcp: Some(counts(0, 0, 0, 0)), ip_method: Some("manual".into()), ..Default::default() };
        assert!(has(&judge(&f), "not using DHCP"));
        // Manual is reported even without a pcap
        let f = Facts { dhcp: None, ip_method: Some("manual".into()), ..Default::default() };
        assert_eq!(judge(&f).verdict, Verdict::Problem);
    }

    #[test]
    fn ack_alone_with_clean_snapshot_is_ok() {
        let r = judge(&base(Some(counts(1, 1, 1, 0))));
        assert_eq!(r.verdict, Verdict::Ok);
        assert!(has(&r, "no anomalies"));
    }

    #[test]
    fn ip_layer_failure_is_not_called_upper_layer() {
        let mut f = base(Some(counts(1, 1, 1, 0)));
        f.first_failure = Some("ip_address".into());
        let r = judge(&f);
        assert_eq!(r.verdict, Verdict::Problem);
        assert!(has(&r, "`ip_address` (connection / IP acquisition layer)"));
        assert!(!has(&r, "upper layer"));
        let mut f = base(Some(counts(1, 1, 1, 0)));
        f.first_failure = Some("dns".into());
        assert!(has(&judge(&f), "`dns` (upper layer"));
    }

    #[test]
    fn snapshot_failure_is_reported_without_pcap() {
        let mut f = base(None);
        f.first_failure = Some("gateway".into());
        let r = judge(&f);
        assert_eq!(r.verdict, Verdict::Problem);
        assert!(has(&r, "`gateway`"));
    }

    #[test]
    fn no_pcap_without_other_evidence_is_unknown_not_ok() {
        let r = judge(&base(None));
        assert_eq!(r.verdict, Verdict::Unknown);
        assert!(!has(&r, "no anomalies"));
        // A pcap without our ACK is also inconclusive
        assert_eq!(judge(&base(Some(counts(0, 0, 0, 0)))).verdict, Verdict::Unknown);
    }

    #[test]
    fn incomplete_aborted_and_read_errors_are_unknown() {
        let mut f = base(Some(counts(1, 1, 1, 0)));
        f.incomplete = true;
        assert_eq!(judge(&f).verdict, Verdict::Unknown);
        let mut f = base(Some(counts(1, 1, 1, 0)));
        f.aborted = Some("SIGTERM".into());
        assert_eq!(judge(&f).verdict, Verdict::Unknown);
        let mut f = base(Some(counts(1, 1, 1, 0)));
        f.unknown_reasons.push("tcpdump cannot read the pcap".into());
        let r = judge(&f);
        assert_eq!(r.verdict, Verdict::Unknown);
        assert!(has(&r, "inconclusive because"));
    }

    #[test]
    fn private_mac_is_info() {
        let mut f = base(Some(counts(1, 1, 1, 0)));
        f.current_mac = Some("02:00:5e:00:53:02".into());
        f.hardware_mac = Some("00:00:5e:00:53:01".into());
        let r = judge(&f);
        assert!(has(&r, "Private Wi-Fi Address"));
        assert_eq!(r.verdict, Verdict::Ok);
    }
}
