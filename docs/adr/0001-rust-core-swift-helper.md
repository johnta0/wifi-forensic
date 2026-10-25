# ADR-0001: Rust core + Swift helper, JSON at the boundary

- Status: Accepted
- Date: 2026-09-30

## Context

On macOS, Wi-Fi details (SSID/BSSID/RSSI, etc.) can only be read correctly through CoreWLAN / CoreLocation. Meanwhile, we want the diagnosis logic (subprocess control, timeouts, parallel probes, history storage) to be OS-independent.

## Decision

| Item | Choice | Reason |
|---|---|---|
| Core | **Rust** | Single-binary distribution / strict handling of timeouts and exit codes / parallel probes / Linux and Windows in the future |
| macOS APIs | **Swift helper** (thin) | Calls CoreWLAN and CoreLocation naturally. Builds with a single `swiftc` invocation |
| Boundary | **JSON files** (with `schema_version`) | No FFI needed; the helper can be tested and debugged on its own |

## Alternatives

| Option | Why rejected |
|---|---|
| All Python (uv) | Packaging as a `.app` needs py2app, which is heavy. Hard to distribute |
| All Swift | Possible, but Rust is better for cross-platform expansion and parallel probes |
| Call CoreWLAN directly from Rust via objc2 | Location permission still requires a `.app` + Info.plist (ADR-0002), so little benefit |
| Swift ↔ Rust FFI | Complicates building and debugging. Calls are infrequent, so JSON is enough |

## Consequences

- When changing the helper's JSON schema, bump `schema_version` and handle compatibility on the Rust side
- No helper is needed outside macOS (swap the platform trait implementation)
