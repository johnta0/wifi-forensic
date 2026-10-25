# ADR-0002: Ship the location helper as a `.app` and launch it with `open -W`

- Status: Accepted (verified on a real macOS 26.6 machine on 2026-09-30)
- Date: 2026-09-30

## Context

- Since macOS Sonoma, SSID/BSSID are returned only to a **"responsible app" that holds location permission**
- `wdutil` / `networksetup` / `system_profiler` / `ipconfig` are Apple CLIs that do not request permission → always `<redacted>`
- A bare CLI binary without an Info.plist cannot show the permission prompt
- Prior art: [noperator/wifi-unredactor](https://github.com/noperator/wifi-unredactor)

## Decision

| Item | Choice | Reason |
|---|---|---|
| Form | `WfxHelper.app` (`LSUIElement`, hidden from the Dock) | Can carry `NSLocationWhenInUseUsageDescription` in its Info.plist |
| Launch | **`open -W -n <app> --args ... --out <file>`** | Unless launched via LaunchServices, the terminal becomes the responsible app and the permission does not apply |
| Output | JSON file given by `--out` | `open` does not return stdout / exit code. The outcome is determined from `authorization` / `error` in the JSON |
| Signing | P0: ad-hoc (`codesign -s -`) / later: a fixed self-signed certificate (`WFX_SIGN_IDENTITY`) | TCC remembers permission by signing identity. Ad-hoc requires re-granting on every rebuild |
| Division of labor | SSID/BSSID/RSSI/scan via the helper, everything else via `wdutil` / `ipconfig` | Only the helper is granted permission; Apple CLI output does not change |

## Verification results (P0, macOS 26.6 / Swift 6.3.3)

| Item | Result |
|---|---|
| Permission prompt | Shown by `requestWhenInUseAuthorization()` even with ad-hoc signing and `LSUIElement` |
| `current` | SSID / BSSID unredacted (`authorized`) |
| `scan` | SSIDs obtained for all 19 networks, 0 `null` (the Sequoia 15.1 report did not reproduce) |
| After rebuild | Stayed `authorized` without re-granting (ad-hoc does not always require re-granting) |

## Risks

- There are reports on Sequoia 15.1 that "`scanForNetworks` SSIDs stay hidden even after permission is granted" ([Apple Forums](https://developer.apple.com/forums/thread/769950)) → not reproduced on 26.6. Re-verify on OS updates
- Distribution may require Developer ID signing + notarization
