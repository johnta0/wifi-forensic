import AppKit
import CoreLocation
import CoreWLAN

let helperVersionString = "0.1.0"

// MARK: - JSON models (missing values are emitted as null, never omitted)

/// Channel information.
struct ChannelInfo: Encodable {
    let number: Int?
    let band: String
    let widthMhz: Int?
    enum CodingKeys: String, CodingKey { case number, band, widthMhz = "width_mhz" }
    func encode(to e: Encoder) throws {
        var c = e.container(keyedBy: CodingKeys.self)
        try c.encode(number, forKey: .number)
        try c.encode(band, forKey: .band)
        try c.encode(widthMhz, forKey: .widthMhz)
    }
}

/// Output of the `current` command: state of the associated interface.
struct InterfaceInfo: Encodable {
    var interfaceName: String?, hardwareAddress: String?, powerOn: Bool?
    var ssid: String?, bssid: String?, rssiDbm: Int?, noiseDbm: Int?
    var channel: ChannelInfo?, phyMode: String?, security: String?
    var transmitRateMbps: Double?, txPowerMw: Int?, countryCode: String?, interfaceMode: String?
    enum CodingKeys: String, CodingKey {
        case interfaceName = "interface_name", hardwareAddress = "hardware_address", powerOn = "power_on"
        case ssid, bssid, rssiDbm = "rssi_dbm", noiseDbm = "noise_dbm", channel
        case phyMode = "phy_mode", security, transmitRateMbps = "transmit_rate_mbps"
        case txPowerMw = "tx_power_mw", countryCode = "country_code", interfaceMode = "interface_mode"
    }
    func encode(to e: Encoder) throws {
        var c = e.container(keyedBy: CodingKeys.self)
        try c.encode(interfaceName, forKey: .interfaceName); try c.encode(hardwareAddress, forKey: .hardwareAddress)
        try c.encode(powerOn, forKey: .powerOn); try c.encode(ssid, forKey: .ssid); try c.encode(bssid, forKey: .bssid)
        try c.encode(rssiDbm, forKey: .rssiDbm); try c.encode(noiseDbm, forKey: .noiseDbm)
        try c.encode(channel, forKey: .channel); try c.encode(phyMode, forKey: .phyMode)
        try c.encode(security, forKey: .security); try c.encode(transmitRateMbps, forKey: .transmitRateMbps)
        try c.encode(txPowerMw, forKey: .txPowerMw); try c.encode(countryCode, forKey: .countryCode)
        try c.encode(interfaceMode, forKey: .interfaceMode)
    }
}

/// Element of the `scan` command output: one nearby AP.
struct NetworkInfo: Encodable {
    let ssid: String?
    let bssid: String?
    let rssiDbm: Int
    let noiseDbm: Int
    let channel: ChannelInfo?
    let beaconInterval: Int
    let countryCode: String?
    let ibss: Bool
    let security: [String]
    enum CodingKeys: String, CodingKey {
        case ssid, bssid, rssiDbm = "rssi_dbm", noiseDbm = "noise_dbm", channel
        case beaconInterval = "beacon_interval", countryCode = "country_code", ibss, security
    }
    func encode(to e: Encoder) throws {
        var c = e.container(keyedBy: CodingKeys.self)
        try c.encode(ssid, forKey: .ssid); try c.encode(bssid, forKey: .bssid)
        try c.encode(rssiDbm, forKey: .rssiDbm); try c.encode(noiseDbm, forKey: .noiseDbm)
        try c.encode(channel, forKey: .channel); try c.encode(beaconInterval, forKey: .beaconInterval)
        try c.encode(countryCode, forKey: .countryCode); try c.encode(ibss, forKey: .ibss)
        try c.encode(security, forKey: .security)
    }
}

/// Root of the output JSON.
struct Report: Encodable {
    var schemaVersion = 1
    var command: String
    var timestamp: String
    var helperVersion = helperVersionString
    var authorization: String
    var interface: InterfaceInfo?
    var networks: [NetworkInfo]?
    var error: String?
    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version", command, timestamp, helperVersion = "helper_version"
        case authorization, interface, networks, error
    }
    func encode(to e: Encoder) throws {
        var c = e.container(keyedBy: CodingKeys.self)
        try c.encode(schemaVersion, forKey: .schemaVersion); try c.encode(command, forKey: .command)
        try c.encode(timestamp, forKey: .timestamp); try c.encode(helperVersion, forKey: .helperVersion)
        try c.encode(authorization, forKey: .authorization); try c.encode(interface, forKey: .interface)
        try c.encode(networks, forKey: .networks); try c.encode(error, forKey: .error)
    }
}

// MARK: - Stringifying CoreWLAN values

/// Converts a CWChannel into a ChannelInfo for JSON output.
func channelInfo(_ ch: CWChannel?) -> ChannelInfo? {
    guard let ch else { return nil }
    let band: String
    switch ch.channelBand {
    case .band2GHz: band = "2.4GHz"
    case .band5GHz: band = "5GHz"
    case .band6GHz: band = "6GHz"
    default: band = "unknown"
    }
    let width: Int?
    switch ch.channelWidth {
    case .width20MHz: width = 20
    case .width40MHz: width = 40
    case .width80MHz: width = 80
    case .width160MHz: width = 160
    default: width = nil
    }
    return ChannelInfo(number: ch.channelNumber, band: band, widthMhz: width)
}

/// Display name of a CWSecurity.
func securityName(_ s: CWSecurity) -> String {
    switch s {
    case .none: return "none"
    case .WEP: return "WEP"
    case .dynamicWEP: return "dynamic_WEP"
    case .wpaPersonal: return "WPA_personal"
    case .wpaPersonalMixed: return "WPA_personal_mixed"
    case .wpa2Personal: return "WPA2_personal"
    case .personal: return "personal"
    case .wpaEnterprise: return "WPA_enterprise"
    case .wpaEnterpriseMixed: return "WPA_enterprise_mixed"
    case .wpa2Enterprise: return "WPA2_enterprise"
    case .enterprise: return "enterprise"
    case .wpa3Personal: return "WPA3_personal"
    case .wpa3Enterprise: return "WPA3_enterprise"
    case .wpa3Transition: return "WPA3_transition"
    case .OWE: return "OWE"
    case .oweTransition: return "OWE_transition"
    default: return "unknown"
    }
}

/// Lists the security modes supported by a scanned AP.
func supportedSecurities(_ n: CWNetwork) -> [String] {
    let all: [CWSecurity] = [.none, .WEP, .dynamicWEP, .wpaPersonal, .wpaPersonalMixed, .wpa2Personal,
        .personal, .wpaEnterprise, .wpaEnterpriseMixed, .wpa2Enterprise, .enterprise,
        .wpa3Personal, .wpa3Enterprise, .wpa3Transition, .OWE, .oweTransition]
    return all.filter { n.supportsSecurity($0) }.map(securityName)
}

/// Collects information about the associated interface.
func collectCurrent(_ i: CWInterface) -> InterfaceInfo {
    var r = InterfaceInfo()
    r.interfaceName = i.interfaceName
    r.hardwareAddress = i.hardwareAddress()
    r.powerOn = i.powerOn()
    r.ssid = i.ssid()
    r.bssid = i.bssid()
    // CoreWLAN returns 0 when not associated or on failure, so map 0 to null per value.
    // Fetch channel only once and reuse it so the values stay consistent if the link drops midway.
    let channel = i.wlanChannel()
    let associated = channel != nil
    let rssi = i.rssiValue(), noise = i.noiseMeasurement()
    r.rssiDbm = associated && rssi != 0 ? rssi : nil
    r.noiseDbm = associated && noise != 0 ? noise : nil
    r.channel = channelInfo(channel)
    switch i.activePHYMode() {
    case .mode11a: r.phyMode = "802.11a"
    case .mode11b: r.phyMode = "802.11b"
    case .mode11g: r.phyMode = "802.11g"
    case .mode11n: r.phyMode = "802.11n"
    case .mode11ac: r.phyMode = "802.11ac"
    case .mode11ax: r.phyMode = "802.11ax"
    case .modeNone: r.phyMode = nil
    default: r.phyMode = "unknown"
    }
    r.security = associated ? securityName(i.security()) : nil
    let rate = i.transmitRate(), power = i.transmitPower()
    r.transmitRateMbps = associated && rate != 0 ? rate : nil
    r.txPowerMw = power != 0 ? power : nil
    r.countryCode = i.countryCode()
    switch i.interfaceMode() {
    case .station: r.interfaceMode = "station"
    case .IBSS: r.interfaceMode = "ibss"
    case .hostAP: r.interfaceMode = "host_ap"
    default: r.interfaceMode = "none"
    }
    return r
}

// MARK: - Main logic

/// Obtains location authorization, reads Wi-Fi info via CoreWLAN, and writes the JSON.
/// CLLocationManager delegate callbacks arrive on the main run loop, so this is @MainActor.
@MainActor
final class Runner: NSObject, CLLocationManagerDelegate {
    let command: String
    let outPath: String
    let timeout: TimeInterval
    let manager = CLLocationManager()
    var finished = false

    init(command: String, outPath: String, timeout: TimeInterval) {
        self.command = command; self.outPath = outPath; self.timeout = timeout
        super.init()
        manager.delegate = self
    }

    /// Arms the timeout timer and starts evaluating the authorization status.
    func start() {
        Timer.scheduledTimer(withTimeInterval: timeout, repeats: false) { _ in
            MainActor.assumeIsolated { self.finish(auth: "timeout") }
        }
        evaluate()
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        MainActor.assumeIsolated { self.evaluate() }
    }

    /// Decides the next action based on the current authorization status.
    func evaluate() {
        switch manager.authorizationStatus {
        case .notDetermined:
            // requestWhenInUseAuthorization is available on macOS 10.15+ and
            // shows the prompt even for an LSUIElement app. Always is not used because
            // it is effectively the same as WhenInUse on macOS.
            // Fallback: if still undetermined after 2 seconds, call startUpdatingLocation
            // to actually start using location and trigger the prompt.
            manager.requestWhenInUseAuthorization()
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                MainActor.assumeIsolated {
                    if !self.finished && self.manager.authorizationStatus == .notDetermined {
                        self.manager.startUpdatingLocation()
                    }
                }
            }
        case .authorizedAlways, .authorized: finish(auth: "authorized")
        case .denied: finish(auth: "denied")
        case .restricted: finish(auth: "restricted")
        @unknown default: finish(auth: "not_determined")
        }
    }

    /// Collects Wi-Fi info, writes the JSON, and exits with the result code.
    func finish(auth: String) {
        if finished { return }
        finished = true
        manager.stopUpdatingLocation()
        var report = Report(command: command, timestamp: iso8601Now(), authorization: auth)
        var code: Int32 = 0
        if let iface = CWWiFiClient.shared().interface() {
            if command == "current" {
                report.interface = collectCurrent(iface)
            } else {
                do {
                    let nets = try iface.scanForNetworks(withName: nil)
                    report.networks = nets.map { n in
                        NetworkInfo(ssid: n.ssid, bssid: n.bssid, rssiDbm: n.rssiValue, noiseDbm: n.noiseMeasurement,
                                    channel: channelInfo(n.wlanChannel), beaconInterval: n.beaconInterval,
                                    countryCode: n.countryCode, ibss: n.ibss, security: supportedSecurities(n))
                    }.sorted { $0.rssiDbm > $1.rssiDbm }
                } catch {
                    report.error = "scan failed: \(error.localizedDescription)"
                    code = 3
                }
            }
        } else {
            report.error = "no Wi-Fi interface available"
            code = 3
        }
        // Missing authorization takes precedence over Wi-Fi errors: exit 2 (error is kept as extra context).
        if auth != "authorized" { code = 2 }
        writeReport(report, to: outPath)
        exit(code)
    }
}

/// Returns the current time as ISO 8601 with a time zone.
func iso8601Now() -> String {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds, .withTimeZone]
    f.timeZone = .current
    return f.string(from: Date())
}

/// Writes the Report to a file as pretty-printed JSON with sorted keys.
func writeReport(_ report: Report, to path: String) {
    let enc = JSONEncoder()
    enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    do {
        try enc.encode(report).write(to: URL(fileURLWithPath: path), options: .atomic)
    } catch {
        FileHandle.standardError.write(Data("failed to write \(path): \(error)\n".utf8))
        exit(1)
    }
}

// MARK: - Entry point

// Argument parsing. Invalid arguments are a usage error: exit 64.
let args = Array(CommandLine.arguments.dropFirst())
var cmd: String?, outPath: String?, timeout: TimeInterval = 60
var usageError: String?
var idx = 0
while idx < args.count {
    switch args[idx] {
    case "current", "scan": cmd = args[idx]
    case "--out": idx += 1; outPath = idx < args.count ? args[idx] : nil
    case "--timeout":
        idx += 1
        if idx < args.count, let t = TimeInterval(args[idx]), t.isFinite, t > 0 { timeout = t } else { usageError = "invalid --timeout" }
    default: usageError = "unknown argument: \(args[idx])"
    }
    idx += 1
}
if cmd == nil && usageError == nil { usageError = "command (current|scan) required" }
if outPath == nil && usageError == nil { usageError = "--out <path> required" }

if let usageError {
    FileHandle.standardError.write(Data("usage: WfxHelper current|scan --out <path> [--timeout <sec>]\n\(usageError)\n".utf8))
    if let outPath {
        var r = Report(command: cmd ?? "unknown", timestamp: iso8601Now(), authorization: "not_determined")
        r.error = "usage: \(usageError)"
        writeReport(r, to: outPath)
    }
    exit(64)
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
// Top-level code in main.swift runs on the main thread, so assumeIsolated satisfies MainActor isolation.
let runner = MainActor.assumeIsolated { Runner(command: cmd!, outPath: outPath!, timeout: timeout) }
MainActor.assumeIsolated { runner.start() }
app.run()
