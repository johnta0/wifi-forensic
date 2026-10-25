# ADR-0004: Raw data in bundle directories, SQLite for the index only

- Status: Accepted (implemented in P2–P3)
- Date: 2026-09-30

## Decision

| Location | Contents | Reason |
|---|---|---|
| `~/.wifi-forensic/bundles/<ts>_<ssid>/` | `snapshot.json`, `helper.json`, `dhcp.pcap`, `unified.log`, `commands/*` | pcaps and logs are binary/large. The whole directory can be handed to an agent or Wireshark |
| `~/.wifi-forensic/index.sqlite` | SSID, BSSID, vendor, verdict, bundle path | Fast lookup for `history` / `compare`. Can be rebuilt from bundles if corrupted |

## Consequences

- Keep the `snapshot.json` schema stable as the agent's entry point (`schema_version`)
- Bundles contain SSIDs, BSSIDs, MACs, etc. → consider a masking option for sharing
