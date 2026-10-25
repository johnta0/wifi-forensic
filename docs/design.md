# wifi-forensic design

> **An offline-capable, agent-first Wi-Fi forensic CLI with a Rust core and Swift as a thin adapter for the macOS Wi-Fi APIs**

## Background (how it started)

On 2026-09-30, we used Claude Code to investigate a café Wi-Fi network (ExampleCafe) where "the iPhone connects but the Mac does not".

| What happened | Lesson |
|---|---|
| Joining the target Wi-Fi took the agent (Claude Code) offline, so it could not diagnose on the spot | → Need **capture that completes offline** |
| A batch script ran the diagnosis, but the restore SSID (phone hotspot) did not show up in the scan, so the Mac could not get back | → Need **guaranteed restore** (retries, fallback) |
| The root cause was not a DHCP failure but a **manual IP setting left on the Wi-Fi service** from trial and error | → Instead of guessing "169.254 = DHCP failure", **keep configuration state and packets as evidence** |
| SSID / BSSID show as `<redacted>` from the CLI | → Need a **Swift `.app` helper** with location permission |

## Layered diagnosis model

Isolate where the problem is, from the bottom up.

```text
L1 Wi-Fi association   CoreWLAN (SSID/BSSID/RSSI/channel), connection errors
L2 IP config method    Manual / DHCP / BOOTP, Private MAC
L3 DHCP                pcap: DISCOVER → OFFER → REQUEST → ACK / NAK
L4 IP / routing        ipconfig getpacket, default route
L5 Gateway             ping gateway, ARP (router MAC → vendor)
L6 Internet            ping 1.1.1.1, HTTPS
L7 DNS                 resolver response
L8 HTTP / captive      captive.apple.com
```

## Structure

```text
wifi-forensic
├── Rust CLI (core)
│   ├── commands   inspect / test / capture / history / compare
│   ├── probes     dhcp, gateway, dns, internet, http, captive
│   ├── platform   trait (macOS implementation only; Linux/Windows later)
│   └── storage    bundle dir + SQLite index
└── helper/ (Swift, macOS only)
    └── WfxHelper.app   current / scan → JSON file
```

- The boundary is **JSON files only** (no FFI) → [ADR-0001](adr/0001-rust-core-swift-helper.md)
- The helper `.app` is launched with `open -W` → [ADR-0002](adr/0002-location-helper-app-bundle.md)

## Commands

| Command | Purpose | Needs to be online? |
|---|---|---|
| `inspect [--json]` | Current Wi-Fi / network state | No |
| `test [--json]` | Check the current connection layer by layer | No (the result just says "offline") |
| **`capture <SSID> [--restore <SSID>]`** | Join → record → **always restore** → save bundle | No → [ADR-0003](adr/0003-offline-capture-with-restore.md) |
| `analyze <bundle>` | Apply rules to a bundle | No |
| `history` / `compare` | List and diff past bundles | No |

Pretty output for humans, `--json` for agents. The agent **reads and analyzes the bundle once back online**.

## Storage format → [ADR-0004](adr/0004-bundle-and-sqlite-storage.md)

```text
~/.wifi-forensic/
  bundles/<ts>_<ssid>/
    snapshot.json    # structured summary (the agent's entry point)
    helper.json      # Swift helper output
    dhcp.pcap        # port 67/68, arp, icmp
    unified.log      # IPConfiguration / airportd / wifid
    commands/        # raw output of ipconfig, route, ifconfig, etc.
  index.sqlite       # index for history / compare
```

## Roadmap

| Phase | Scope | Done when |
|---|---|---|
| ~~P0~~ ✅ | Swift helper (`current` / `scan`), build, signing | On macOS 26.6, the permission prompt appears and SSID/BSSID are unredacted (achieved 2026-09-30) |
| P1 | Rust: `inspect` / `test` (`--json`) | Layered checks on the current connection |
| P2 | Rust: `capture` (pcap, logs, guaranteed restore) | Can reproduce and record the ExampleCafe case |
| P3 | `history` / `compare` / OUI vendor lookup | Shows the diff between healthy and broken states |

### Out of scope (for now)

- Linux / Windows implementations (only define the trait)
- Resident daemon, deep packet inspection of DNS / ARP

## Development roles

| Who | Role |
|---|---|
| Claude Opus | Design decisions, specs, verification, commits |
| Claude Sonnet | Implementation of finalized specs |
| GPT (Codex) | Code review from an independent perspective |
