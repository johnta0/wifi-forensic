# ADR-0003: `capture` completes offline + guaranteed restore + evidence preservation

- Status: Accepted (implemented in P2)
- Date: 2026-09-30

## Context

- A Mac's Wi-Fi can only be connected to one AP at a time → joining the target SSID cuts off the agent (Claude Code, etc.)
- In the 2026-09-30 prototype script, the restore target (phone hotspot) did not show up in the scan, and the Mac **stayed offline**
- The root cause was "a leftover manual IP setting", and the guess "169.254 → DHCP failure" led to a misdiagnosis

## Decision

**`capture <SSID>` = join → record → restore → save bundle, all locally. Analysis happens later (offline or by the agent).**

| Item | Policy |
|---|---|
| Restore | Retry until online: specified SSID → Wi-Fi power OFF/ON → automatic join to preferred networks. Report failure explicitly once the time limit is exceeded |
| Reverting state | Any changed settings (IP configuration, etc.) are always reverted via `Drop` / signal handler |
| Evidence: configuration | `ConfigMethod` (Manual/DHCP), Private MAC (current MAC vs HW MAC) |
| Evidence: packets | `tcpdump -i en0 'port 67 or port 68 or arp or icmp'` (requires sudo) |
| Evidence: logs | unified log (IPConfiguration / airportd / wifid) sliced to the attempt's time window |
| Surviving session loss | Runs to completion even if the caller (agent) dies (make it detachable) |

## Alternatives

| Option | Why rejected |
|---|---|
| Stay online via a non-Wi-Fi uplink (USB tethering) | Effective but hardware-dependent. May be supported later as an **optional add-on** |
| Offline analysis with a local LLM | Accuracy and setup cost. Rule-based `analyze` + agent analysis after restore is enough |

## Consequences

- `capture` needs sudo (tcpdump). Provide sudoers setup instructions in the docs
- The interface for agent integration is "hand over the bundle directory"
