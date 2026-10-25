//! Data model emitted by `inspect` / `test` (the `--json` schema).

use serde::{Deserialize, Serialize};

/// Schema version of the `--json` output.
pub const SCHEMA_VERSION: u32 = 1;

/// The part of the Swift helper (`wfx-helper current`) output that Rust uses.
/// The schema matches `Report` in `helper/Sources/main.swift`.
#[derive(Debug, Default, Deserialize)]
pub struct HelperReport {
    pub authorization: Option<String>,
    pub error: Option<String>,
    pub interface: Option<HelperInterface>,
}

#[derive(Debug, Default, Deserialize)]
pub struct HelperInterface {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub rssi_dbm: Option<i32>,
    pub noise_dbm: Option<i32>,
    pub channel: Option<HelperChannel>,
    pub phy_mode: Option<String>,
    pub security: Option<String>,
    pub transmit_rate_mbps: Option<f64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct HelperChannel {
    pub number: Option<i32>,
    pub band: Option<String>,
}

/// Wi-Fi state (L1).
#[derive(Debug, Default, Serialize)]
pub struct WifiInfo {
    pub interface: String,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub rssi_dbm: Option<i32>,
    pub noise_dbm: Option<i32>,
    pub channel: Option<i32>,
    pub band: Option<String>,
    pub phy_mode: Option<String>,
    pub security: Option<String>,
    pub transmit_rate_mbps: Option<f64>,
    /// Actual MAC address (differs from the hardware one when Private Wi-Fi Address is enabled)
    pub current_mac: Option<String>,
    /// Whether associated with an AP. `None` when the helper failed and it cannot be determined (distinct from disconnected)
    pub associated: Option<bool>,
    /// Why the helper failed (`None` on success)
    pub helper_error: Option<String>,
    /// Helper's location authorization status (the SSID is unavailable unless `authorized`)
    pub location_authorization: Option<String>,
}

/// How IPv4 is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpMethod {
    Dhcp,
    Manual,
    /// Manual IP, router from DHCP (`Manually Using DHCP Router`)
    ManualWithDhcpRouter,
    Bootp,
    Unknown,
}

/// IP configuration state (L2-L4).
#[derive(Debug, Default, Serialize)]
pub struct NetworkInfo {
    /// Service name in `networksetup` (e.g. `Wi-Fi`)
    pub service: Option<String>,
    pub ip_method: Option<IpMethod>,
    pub ipv4: Option<String>,
    /// 169.254.0.0/16 (self-assigned when DHCP fails)
    pub link_local: bool,
    pub gateway: Option<String>,
    pub default_route_interface: Option<String>,
    pub dns: Vec<String>,
    pub dhcp_server: Option<String>,
    pub lease_seconds: Option<u64>,
}

/// Verdict for each layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Fail,
    /// Not run because an earlier layer failed
    Skipped,
    /// Could not be determined because information was unavailable (distinct from failure)
    Unknown,
}

/// Diagnosis result for one layer.
#[derive(Debug, Serialize)]
pub struct Check {
    pub layer: &'static str,
    pub status: Status,
    pub detail: String,
}

/// Output of `inspect`.
#[derive(Debug, Serialize)]
pub struct Inspection {
    pub schema_version: u32,
    pub timestamp: String,
    pub wifi: WifiInfo,
    pub network: NetworkInfo,
}

/// Output of `test`.
#[derive(Debug, Serialize)]
pub struct TestReport {
    pub schema_version: u32,
    pub timestamp: String,
    pub wifi: WifiInfo,
    pub network: NetworkInfo,
    pub checks: Vec<Check>,
    /// First failed layer. `None` if everything passed.
    pub first_failure: Option<&'static str>,
    pub hint: Option<String>,
}
