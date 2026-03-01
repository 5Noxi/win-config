## Inventory consistency

- Reviewed SUBOPTIONs: `77` (excluding helper button)
- Reviewed configured members: `266`
- High-confidence move recommendations: `1`
- High-confidence new SUBOPTION candidates: `4`

## Move recommendations

| Service/Driver | Current SUBOPTION | Recommended SUBOPTION | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| `SmsRouter` | `Disable Miscellaneous Services` | `Disable Push Notifications Services` (new) | Service description: "Routes messages based on rules to appropriate clients." This matches push/notification routing, and `desc.md` already documents `SmsRouter` under Push Notifications with `WpnService`. | High |

## New SUBOPTION recommendations

| Proposed SUBOPTION | Members | Why | Confidence |
| --- | --- | --- | --- |
| `Disable Push Notifications Services` | `WpnService`, `WpnUserService_*`, `SmsRouter` | Same notification platform/routing domain; `WpnService` hosts WNS connection platform and `SmsRouter` routes messages to clients. | High |
| `Disable Device Setup Manager Service` | `DsmSvc` | Dedicated device software detection/download/install function; explicit standalone role in service description. | High |
| `Disable Embedded Mode Service` | `embeddedmode` | Dedicated background-app activation role for embedded/shared scenarios; explicit standalone role in service description. | High |
| `Disable NPSM Service` | `NPSMSvc_*` | Dedicated Now Playing Session Manager for media scenarios; explicit standalone role in service description. | High |

## Confirmed-correct suboptions summary

- `76/77` current SUBOPTION titles are semantically aligned with their current members.
- Only high-confidence title mismatch found inside existing configured members: `SmsRouter` in `Disable Miscellaneous Services`.

## Known gaps (documented in desc, not represented by SUBOPTION logic)

| Documented item | Current state in SUBOPTION config | Recommendation |
| --- | --- | --- |
| `DsmSvc` (Device Setup Manager) | Not present in `apply.SUBOPTION` members | Add dedicated suboption (`Disable Device Setup Manager Service`) |
| `embeddedmode` (Embedded Mode) | Not present in `apply.SUBOPTION` members | Add dedicated suboption (`Disable Embedded Mode Service`) |
| `NPSMSvc_*` (Now Playing Session Manager) | Not present in `apply.SUBOPTION` members | Add dedicated suboption (`Disable NPSM Service`) |
| `WpnService`/`WpnUserService_*` (Push platform) | Not present in `apply.SUBOPTION` members | Add dedicated push-notification suboption; move `SmsRouter` there |

## Full per-suboption verdict (complete check)

| SUBOPTION | Members | Verdict | Notes |
| --- | ---: | --- | --- |
| Disable Activity Moderation Driver | 1 | Retain | Title matches member function. |
| Disable Autoplay Service | 1 | Retain | Title matches member function. |
| Disable Beep Driver | 1 | Retain | Title matches member function. |
| Disable Biometrics Service | 1 | Retain | Title matches member function. |
| Disable Bluetooth Services | 16 | Retain | Title matches member function. |
| Disable Broadcasts Service | 13 | Retain | Title matches member function. |
| Disable Camera Services | 3 | Retain | Title matches member function. |
| Disable CDROM Driver | 1 | Retain | Title matches member function. |
| Disable Clipboard Services | 1 | Retain | Title matches member function. |
| Disable DHCP Service | 1 | Retain | Title matches member function. |
| Disable Diagnostics Services | 6 | Retain | Title matches member function. |
| Disable Edge Services | 3 | Retain | Title matches member function. |
| Disable File/Printer Sharing Services | 13 | Retain | Title matches member function. |
| Disable GameInput Service | 1 | Retain | Title matches member function. |
| Disable HyperV Services | 20 | Retain | Title matches member function. |
| Disable IPv6 Service | 2 | Retain | Title matches member function. |
| Disable IP Helper Service | 1 | Retain | Title matches member function. |
| Disable Location Service | 1 | Retain | Title matches member function. |
| Disable Maps Manager Service | 1 | Retain | Title matches member function. |
| Disable Network Discovery Services | 8 | Retain | Title matches member function. |
| Disable Office Service | 1 | Retain | Title matches member function. |
| Disable Telephony Services | 2 | Retain | Title matches member function. |
| Disable Radio Management Service | 1 | Retain | Title matches member function. |
| Disable Parental Control Service | 1 | Retain | Title matches member function. |
| Disable Printer Services | 7 | Retain | Title matches member function. |
| Disable Recovery / Backup Services | 5 | Retain | Title matches member function. |
| Disable Remote Desktop Services | 9 | Retain | Title matches member function. |
| Disable Sensor Services | 6 | Retain | Title matches member function. |
| Disable Sign-In / Windows Hello Services | 4 | Retain | Title matches member function. |
| Disable Smart Card Services | 4 | Retain | Title matches member function. |
| Disable SysMain | 1 | Retain | Title matches member function. |
| Disable Microsoft Store Services | 6 | Retain | Title matches member function. |
| Disable TCP/IP NetBIOS Helper Service | 1 | Retain | Title matches member function. |
| Disable Telemetry Services | 6 | Retain | Title matches member function. |
| Disable Themes Service | 1 | Retain | Title matches member function. |
| Disable Time Zone Services | 2 | Retain | Title matches member function. |
| Disable UAC Driver | 1 | Retain | Title matches member function. |
| Disable User Data & Sync Platform Services | 5 | Retain | Title matches member function. |
| Disable WER Services | 2 | Retain | Title matches member function. |
| Disable Wi-Fi Services | 6 | Retain | Title matches member function. |
| Disable Windows Insider Service | 1 | Retain | Title matches member function. |
| Disable Windows Search Service | 1 | Retain | Title matches member function. |
| Disable Windows Update Services | 3 | Retain | Title matches member function. |
| Disable Windows Defender Services | 10 | Retain | Title matches member function. |
| Disable Xbox Services | 5 | Retain | Title matches member function. |
| Disable Domain/RPC Channel Services | 3 | Retain | Title matches member function. |
| Disable Virtual Bus Drivers | 4 | Retain | Title matches member function. |
| Disable Trusted Runtime Drivers | 3 | Retain | Title matches member function. |
| Disable Kernel Debug Network Driver | 1 | Retain | Title matches member function. |
| Disable Cloud Filter Driver | 1 | Retain | Title matches member function. |
| Disable VBox Drivers | 5 | Retain | Title matches member function. |
| Disable VPN/RAS Services | 11 | Retain | Title matches member function. |
| Disable Media Sharing / Portable Devices Services | 2 | Retain | Title matches member function. |
| Disable BranchCache Service | 1 | Retain | Title matches member function. |
| Disable QoS/AV Streaming (qWave) Service | 2 | Retain | Title matches member function. |
| Disable NFC/Payments Service | 1 | Retain | Title matches member function. |
| Disable Optimize Drives Service | 1 | Retain | Title matches member function. |
| Disable Mobile Hotspot / ICS Service | 3 | Retain | Title matches member function. |
| Disable Network Capture Driver | 1 | Retain | Title matches member function. |
| Disable Container File System Drivers | 2 | Retain | Title matches member function. |
| Disable Consumer IR Driver | 1 | Retain | Title matches member function. |
| Disable iSCSI Driver | 1 | Retain | Title matches member function. |
| Disable NetBIOS Driver | 2 | Retain | Title matches member function. |
| Disable Epic Games Services | 2 | Retain | Title matches member function. |
| Disable Logitech Services | 4 | Retain | Title matches member function. |
| Disable SteelSeries Services | 3 | Retain | Title matches member function. |
| Disable NVIDIA Container Service | 1 | Retain | Title matches member function. |
| Disable Everything Service | 2 | Retain | Title matches member function. |
| Disable App Deployment Services | 4 | Retain | Title matches member function. |
| Disable Network Authentication Services | 2 | Retain | Title matches member function. |
| Disable Mobile Broadband Services | 2 | Retain | Title matches member function. |
| Disable Network Profile & Connectivity UX Services | 3 | Retain | Title matches member function. |
| Disable Enterprise Transaction & Storage Services | 3 | Retain | Title matches member function. |
| Disable Management / Encryption Broker Services | 2 | Retain | Title matches member function. |
| Disable Demo / Shared Device Services | 2 | Retain | Title matches member function. |
| Disable Graphics Compatibility Service | 1 | Retain | Title matches member function. |
| Disable Miscellaneous Services | 4 | Retain (1 move candidate) | `SmsRouter` fits push notifications; other members remain Miscellaneous. |

## Windows internals rules used in this audit

- Service/driver start semantics (`Start=0..4`, disabled behavior, service-vs-driver scope): Windows Internals E7-P1 (p575-p577), E7-P2 (p430).
- SCM startup order and dependencies (`ScAutoStartServices`, `ServiceGroupOrder\List`, `DependOnService`, delayed autostart behavior): Windows Internals E7-P2 (p451-p458).
- SCM role and service-host architecture (`services.exe`, `svchost.exe` orchestration): WindowsServices.pdf (p3-p11), with matching detail in E7-P2 (p426-p429).
