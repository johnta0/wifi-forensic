# wifi-forensic

A Wi-Fi forensic CLI that works fully offline (Rust core + Swift macOS helper).

See [docs/design.md](docs/design.md) for the design and [docs/adr/](docs/adr/README.md) for the reasoning behind decisions.

## Setup (macOS)

```sh
helper/build.sh        # build the location helper (WfxHelper.app)
cargo build --release
```

The first time you run `wfx`, macOS asks whether to allow location access. Allow it (required to read the SSID / BSSID).

## Usage

| Command | Description |
|---|---|
| `wfx inspect [--json]` | Show the current Wi-Fi and IP configuration (no connectivity checks) |
| `wfx test [--json]` | Diagnose the current connection layer by layer. Exits 1 if any check fails |
| `wfx capture <SSID> [--restore <SSID>] [--dhcp-wait 45] [--no-pcap] [--no-wait] [--json]` | Join the target SSID, record evidence, and **always return to the original Wi-Fi**. Saves a bundle |
| `wfx analyze <bundle> [--json]` | Analyze a bundle with rules (DHCP Discover/Offer/ACK, etc.) |
| `wfx bundles` | List saved bundles, newest first |

```text
[1/8] wifi_association   ✓  RSSI -56 dBm
[2/8] ip_config          ✓  dhcp
[3/8] ip_address         ✓  10.68.134.10, lease 300s
[4/8] gateway            ✓  10.68.128.1
[5/8] gateway_reachable  ✗  no response
[6/8] internet           ✓  reached 1.1.1.1
[7/8] dns                ✓  apple.com → 17.253.144.10
[8/8] http               ✓  no captive portal
```

- If only the gateway ping fails while the internet is reachable, the AP is assumed to be dropping ICMP and it is not counted as a failure
- If IPv4 is configured manually, `ip_config` shows a warning and the failure hint suggests `networksetup -setdhcp Wi-Fi`
- The helper location can be overridden with the `WFX_HELPER` environment variable
- ping / HTTP are bound to the Wi-Fi interface (`ping -b`, `curl --interface`), so successes over Ethernet or VPN do not leak in
- If the helper fails, `wfx` does not conclude "disconnected"; it marks `wifi_association` as `?` (undetermined) and continues the diagnosis

## Using capture

**Run it manually from a terminal** (it prompts for the sudo password and switches Wi-Fi).

```sh
wfx capture ExampleCafe          # for an unknown network, prefix with WFX_WIFI_PASSWORD=...
wfx bundles                      # list
wfx analyze ~/.wifi-forensic/bundles/<bundle>
```

| Item | Details |
|---|---|
| Restore target | The SSID connected before the run (override with `--restore`). Aborts if it cannot be read because location access is not granted (continues when `--restore` is given) |
| sudo | Only tcpdump runs as root. Asks for the password with `sudo -v` at startup. If that fails, exits without touching Wi-Fi. Use `--no-pcap` if you don't need it |
| Execution | The worker runs detached (setsid). It runs to completion and restores even if the terminal is closed |
| Storage | `$WFX_HOME/bundles/` (default `~/.wifi-forensic/bundles/`) |
| Exit code | 0 done + restore ok / 1 preflight error, another capture running, or wait timed out (worker still running) / 2 restore failed (manual recovery steps shown) / 64 usage |
| Exclusion | flock per device. Two captures cannot run at the same time |
| analyze verdict | problem / ok / **inconclusive** (insufficient evidence). Only pcap packets within the join-to-restore window and addressed to our own MAC are counted |
| Password | Not accepted as an argument (`WFX_WIFI_PASSWORD` only). It briefly appears in the `networksetup` arguments during join |

### About sudo NOPASSWD

tcpdump is launched via a root `sh` (supervisor), so NOPASSWD for `tcpdump` alone does not let `sudo -n` succeed.
Skipping the password prompt would require NOPASSWD for `/bin/sh` for the supervisor, which grants far too much and is not recommended.
Normally, just enter the password at the `sudo -v` prompt on startup (or use `--no-pcap` if you don't need packets).

## Known limitations

| Item | Details |
|---|---|
| DNS check | Uses macOS name resolution (getaddrinfo), so the route cannot be bound to Wi-Fi. Times out after 6 seconds |
| Real-device testing of `capture` | Not covered by automated tests because it switches Wi-Fi and needs sudo (the restore logic is unit-tested with fakes) |
| Linux / Windows | Not supported (macOS only) |
