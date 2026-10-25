# P2: `wfx capture` specification

Implementation spec for [ADR-0003](adr/0003-offline-capture-with-restore.md).

## Decisions (confirmed with the user on 2026-10-01)

| Topic | Choice |
|---|---|
| Restore target | **The SSID connected before the run**. Can be overridden with `--restore <SSID>` |
| Packet capture | **Ask for sudo at run time** (only tcpdump runs as root) |
| Execution | **Detach the worker**. Even if the caller (agent / terminal) dies, it runs to completion and always restores |

## Commands

```text
wfx capture <SSID> [--restore <SSID>] [--dhcp-wait <sec=45>] [--no-pcap] [--no-wait] [--json]
wfx analyze <bundle-dir> [--json]
wfx bundles                       # list saved bundles (newest first)
```

- Passwords are assumed to come from known networks in the Keychain. For unknown networks, the `WFX_WIFI_PASSWORD` environment variable is accepted (not as an argument, because it would show up in ps)
- `--no-wait`: start the worker and return the bundle path immediately. By default, wait until completion and show the result

## Overall flow

```text
[foreground: wfx capture]
  0. lock        flock on $WFX_HOME/locks/<dev>.lock (if it cannot be taken, exit 1 with "another capture is running"). The fd is inherited by the worker
  1. preflight   helper current (record the restore SSID), helper scan (is the target SSID visible?)
  2. sudo -v     the only place the password is asked for (needs a tty)
  3. tcpdump     started with sudo -n /bin/sh -c <supervisor> (independent via setsid; see below)
  4. spawn       detach itself as `wfx __capture-worker <bundle>` via setsid
  5. wait        wait for bundle/summary.json and display it (return immediately with --no-wait)

[worker (detached, no network needed)]
  6. join        networksetup -setairportnetwork <dev> <SSID> [password] (success is judged as in "Judging join" below)
  7. ip poll     IP acquisition is judged as in "Judging IP acquisition" below. Every 1 second, up to --dhcp-wait seconds
  8. snapshot    collect + probes (same as P1's test), raw command output
  9. logs        slice the unified log to the attempt's time window
 10. restore     always runs (even on panic / errors midway). Staged retries below
 11. summary     write summary.json atomically at the very end (= completion marker)
```

**Why tcpdump is not started from the worker**: macOS sudo remembers authentication per tty. The detached worker has no tty, so `sudo -n` fails.

**tcpdump supervisor**: a root `sh` starts tcpdump in the background and stops it with SIGINT on any of the following. No root process is left behind if the foreground / worker dies (the user side does not kill it).

| Stop condition | Details |
|---|---|
| `tcpdump.stop` file | Created by the worker after restore (no sudo needed). This is the normal path |
| Maximum seconds N | N = the worker's budget = `dhcp_wait + 30(join) + 30(snapshot) + 60(log) + 120(restore) + 30(margin)`. The pcap covers everything up to restore |
| tcpdump exits on its own | Interface disappears, etc. |

- The pid is written to `tcpdump.pid`. Before the summary, the worker waits up to 8 seconds for the pid to disappear; if it remains, `pcap: "still_recording"` (non-blocking)
- If the worker fails to start, the foreground places `tcpdump.stop` to stop it

## Judging join

`networksetup -setairportnetwork` exits 0 even on failure and prints the error to stdout. Check all of the following.

| Condition | Verdict |
|---|---|
| timeout / killed by signal / non-zero exit | failure |
| stdout + stderr contain `Failed to join` / `Error:` etc. | failure |
| After running, helper `current` SSID matches the target (polled up to ~10 seconds) | success |
| A different SSID | failure |
| SSID cannot be confirmed (helper failed) | success if the output is empty, failure if there is output |

## Judging IP acquisition

After join (SSID confirmed), check `ipconfig getifaddr` every 1 second, plus `ipconfig getpacket` when needed.

| IP method | Condition for "acquired" | summary |
|---|---|---|
| DHCP | A valid IPv4 (not 169.254) **and** `server_identifier` in getpacket (an ACK was received on this link) | `ip_source: "dhcp"` + `ip_acquired_after_sec` |
| Manual / ManualWithDhcpRouter | A valid IPv4 | `ip_source: "manual"` (acquisition time not recorded) |

To avoid mistaking a leftover IP from before the switch for "acquired", the decision is based on whether a lease exists, not on comparing IP values or a grace period.

## Concurrency and bundle uniqueness

- Exclusive lock per device (`flock`). The foreground takes it before preflight; the worker inherits the fd and holds it until it exits. A second capture exits 1 immediately
- Bundle names are `<datetime>_<ssid>_<run_id>` (run_id = 6 random hex digits). Created with `create_dir`; fails on collision
- `run_id` is in `meta.json` / `summary.json`. The foreground verifies the summary's run_id
- Temp names for atomic writes are `.<name>.<pid>.tmp`

## Restore (most important)

```text
target_restore = --restore or the SSID at preflight (if none, rely on "automatic join to preferred networks")
deadline = 120 seconds

loop until online or deadline:
  a. setairportnetwork <target_restore>      (up to 3 times, 3 seconds apart)
  b. Wi-Fi power OFF → 2 seconds → ON        (once)
  c. wait for automatic join                 (remaining time)
online check: curl --interface <dev> captive.apple.com returns HTTP 200 + "Success"
```

- Each restore attempt is recorded in `restore.json` (what was tried, result, duration)
- If the deadline is exceeded, write `restore: "failed"` to `summary.json`, and the foreground **prompts for manual recovery in red**
- The worker always runs restore via a Rust `Drop` guard (even on early `?` returns or panics)
- SIGTERM / SIGINT / SIGHUP all set an "interrupted flag" (none are ignored). It is checked before join, before each phase, and inside wait loops; if set, proceed to restore. Restore itself ignores the flag and runs to completion
- `RestoreGuard` has Pending / Running / Done states. On `Drop`, if Pending it runs restore; if Running (= panic during restore) it does not recurse and only tries `-setairportpower on`
- A failure to write to the timeline is not a precondition for restore
- Each operation's timeout is derived from the time left until the deadline (join is `min(20s, remaining - 15s)`, leaving room for the power cycle)

**When restore may be skipped**: **only** when helper `current` SSID **matches** the restore target **and** the Mac is online. A join failure or timeout is not evidence that "the network did not change". If the SSID is unknown, do not skip. If the restore target is unknown (no `restore_ssid`), always power cycle and rely on automatic join.

**Power cycle**: always run ON even if OFF fails (with 2 seconds in between), and if ON fails, retry within the deadline. Never leave Wi-Fi OFF.

## bundle

```text
~/.wifi-forensic/bundles/<YYYYmmdd-HHMMSS>_<ssid with chars outside [A-Za-z0-9._-] replaced>/
  meta.json         wfx version, arguments, start time, restore SSID, host OS version
  preflight.json    helper current + scan (BSSID / RSSI / channel / security list for the target SSID)
  timeline.jsonl    one event per line {"t": ISO8601, "event": "...", "detail": ...}
  snapshot.json     same schema as P1's TestReport (state while connected)
  dhcp.pcap         port 67/68, arp, icmp (absent with --no-pcap)
  unified.log       IPConfiguration / airportd / wifid / configd
  commands/         raw output of ipconfig getsummary, getpacket, ifconfig, route, networksetup -getinfo, etc.
  restore.json      record of restore attempts
  worker.log        worker's stderr
  summary.json      written last; see below
```

```json
{
  "schema_version": 1,
  "ssid": "ExampleCafe",
  "started_at": "...", "finished_at": "...",
  "join": "ok | failed",
  "join_error": "Error: -3900 ...",
  "ip_acquired_after_sec": 3.2,
  "first_failure": "ip_address",
  "restore": "ok | failed | skipped",
  "restore_ssid": "ExampleHotspot",
  "bundle": "/Users/.../bundles/..."
}
```

## analyze (rule-based, offline)

The output of `tcpdump -nr dhcp.pcap -tt -v 'port 67 or port 68'` is split into packets and DHCP Message Types (Option 53) are counted. Only the following are counted.

- Within the window from `join_start` to `restore_start` (epoch) in the timeline
- chaddr (Client-Ethernet-Address) matches **our own MAC at join time** (`summary.our_mac`)
- If the xid of our own requests (Discover / Request) is known, only responses with that xid

To avoid mistaking another device's ACK for our own success, "an ACK exists" alone does not count as success.

| Condition | Verdict |
|---|---|
| join failed | Association failure (suspect signal, password, DFS) |
| DISCOVER present, no OFFER | No response from the DHCP server (pool exhausted, MAC filter, signal) |
| NAK present | Mismatch with a previous lease |
| OFFER present, no ACK | Failed at REQUEST or later |
| No DISCOVER, IP method is Manual | **DHCP is not being used** (the ExampleCafe case) |
| snapshot has first_failure (always reported, independent of pcap) | `wifi_association` / `ip_config` / `ip_address` are the "connection / IP acquisition layer"; anything else is an "upper layer" (captive portal / DNS, etc.) |
| current MAC ≠ hardware MAC | Private Wi-Fi Address is enabled (shown for reference) |

### Overall verdict

| verdict | Condition |
|---|---|
| `problem` | Any row in the table above applies |
| `ok` (no issues) | summary present, join succeeded, not interrupted, no snapshot failures, **ACK to our own MAC confirmed**, no read errors |
| `unknown` (shown as "inconclusive") | Anything else. No summary (incomplete) / interrupted / no pcap (`--no-pcap`) / unreadable by tcpdump / MAC unknown / window unavailable / pcap is `still_recording`, etc. Lists the reasons |

"No issues" is reported only when the evidence is complete.

## Testing approach

- Parsing of external command output (tcpdump DHCP lines, networksetup errors) and analyze verdicts are pure functions with unit tests
- The restore logic lets the "attempt function" and "online check function" be swapped via traits / closures, and unit tests cover "first attempt fails → power OFF/ON succeeds" and "deadline exceeded → failed"
- Real-device capture involves sudo and network switching, so it is **run manually by the user**
