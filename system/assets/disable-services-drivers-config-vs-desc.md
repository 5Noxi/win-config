# Disable Services/Drivers: Config vs Desc Comparison

Date: 2026-03-01

Scope: compared `win-json/system/config.json` SUBOPTION contents against the `# Disable Services/Drivers` table in `win-config/system/desc.md`.

Rules used:
- `List Disabled Dependencies` helper entry excluded.
- Compared option naming and service/driver membership.
- `*_` values are treated as wildcard instance entries (per-user services).

## Summary

- Config suboptions reviewed: `77`
- Desc options reviewed: `77`
- Exact shared option names: `64`
- Option-name mismatches: `13` in config and `13` in desc
- Options with member mismatches: `9`

## Option-name mismatches

These are naming-only differences (same topic, different label text):

| Config SUBOPTION topic | Desc topic |
| --- | --- |
| `App Deployment` | `App Deployment Services` |
| `Demo / Shared Device` | `Demo / Shared Device Services` |
| `Enterprise Transaction & Storage` | `Enterprise Transaction & Storage Services` |
| `Epic Games` | `Epic Games Services` |
| `Everything` | `Everything Service` |
| `Graphics Compatibility` | `Graphics Compatibility Service` |
| `Logitech` | `Logitech Services` |
| `Management / Encryption Broker` | `Management / Encryption Broker Services` |
| `Mobile Broadband` | `Mobile Broadband Services` |
| `NVIDIA Container` | `NVIDIA Container Service` |
| `Network Authentication` | `Network Authentication Services` |
| `Network Profile & Connectivity UX` | `Network Profile & Connectivity UX Services` |
| `SteelSeries` | `SteelSeries Services` |

## Member mismatches

| Topic (Desc) | Config SUBOPTION | Missing in config (present in desc) | Extra in config (not listed in desc) |
| --- | --- | --- | --- |
| `Activity Moderation` | `Disable Activity Moderation Driver` | `dam` | - |
| `Broadcasts` | `Disable Broadcasts Service` | - | `BcastDVRUserService_*`, `CDPUserSvc_*`, `DevicePickerUserSvc_*`, `DevicesFlowUserSvc_*` |
| `Clipboard` | `Disable Clipboard Services` | - | `cbdhsvc_*` |
| `File/Printer Sharing` | `Disable File/Printer Sharing Services` | - | `P9RdrService_*` |
| `Miscellaneous` | `Disable Miscellaneous Services` | - | `PenService_*` |
| `Remote Desktop` | `Disable Remote Desktop Services` | `RemoteRegistry` | - |
| `Smart Card` | `Disable Smart Card Services` | `CertPropSvc` | - |
| `Time` | `Disable Time Zone Services` | `W32Time` | - |
| `User Data & Sync Platform` | `Disable User Data & Sync Platform Services` | - | `ConsentUxUserSvc_*`, `MessagingService_*`, `PimIndexMaintenanceSvc_*`, `UnistoreSvc_*`, `UserDataSvc_*` |

## Practical interpretation (no edits applied)

- `dam`, `RemoteRegistry`, `CertPropSvc`, and `W32Time` are documented in desc but not currently inside matching config suboptions.
- Wildcard instance entries (for example `cbdhsvc_*`, `ConsentUxUserSvc_*`, `BcastDVRUserService_*`) exist in config via `registry_pattern` commands but are not always explicitly listed in desc.
- The 13 topic-name mismatches are mainly suffix differences (`Service`/`Services`) and can be normalized later if you want exact naming parity.

No config or desc content was changed by this comparison task.
