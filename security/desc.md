# Windows Defender

## [Current Defender Status](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-endpoint/microsoft-defender-antivirus-windows.md#use-powershell-to-check-the-status-of-microsoft-defender-antivirus)

1. Select the **Start** menu, and begin typing `PowerShell`. Then open Windows PowerShell in the results.
2. Type `Get-MpComputerStatus`.
3. In the list of results, look at the **AMRunningMode** row.
   - **Normal** means Microsoft Defender Antivirus is running in active mode.
   - **Passive mode** means Microsoft Defender Antivirus running, but isn't the primary antivirus/anti-malware product on your device. Passive mode is only available for devices that are onboarded to Microsoft Defender for Endpoint and that meet certain requirements. To learn more, see [Requirements for Microsoft Defender Antivirus to run in passive mode](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-endpoint/microsoft-defender-antivirus-compatibility.md#requirements-for-microsoft-defender-antivirus-to-run-in-passive-mode).
   - **EDR Block Mode** means Microsoft Defender Antivirus is running and [Endpoint detection and response (EDR) in block mode](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-endpoint/edr-in-block-mode.md), a capability in Microsoft Defender for Endpoint, is enabled. Check the **ForceDefenderPassiveMode** registry key. If its value is 0, it's running in normal mode; otherwise, it's running in passive mode.
   - **SxS Passive Mode** means Microsoft Defender Antivirus is running alongside another antivirus/anti-malware product, and [limited periodic scanning is used](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-endpoint/limited-periodic-scanning-microsoft-defender-antivirus.md).

## Privacy Preset (`Configured`)

This is my preset which keeps Defender enabled but turning off privacy sensitive (cloud/reporting...) parts:
- Defender core AV enabled
- Real-time / on-access / IOAV / behavior monitoring enabled
- PUA set to `Block`
- MAPS reporting disabled
- sample submission set to `Never send`
- Block at First Sight disabled
- extended cloud check disabled
- cloud block level left at default
- Network Protection disabled
- Controlled Folder Access disabled
- SmartScreen disabled
- Email scanning disabled
- Enhanced Phishing Protection disabled
- [Defender core telemetry](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-endpoint/microsoft-defender-core-service-overview.md) disabled (`DisableCoreServiceTelemetry` = true: "*The Microsoft Defender Core service doesn't collect telemetry from Microsoft Defender Antivirus and other Defender software. Disabling this setting can impact Microsoft's ability to quickly recognize and address problems, such as slow performance and false positives*")
- [Defender core ECS integration](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-endpoint/microsoft-defender-core-service-overview.md) disabled (ECS = Experimentation and Configuration Service)

If using [`native.winoffice.txt`](https://github.com/hagezi/dns-blocklists/blob/main/adblock/native.winoffice.txt) ECS won't function properly, since it [has to receive payload](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-endpoint/microsoft-defender-core-service-configurations-and-experimentation.md) from:

- Enterprise customers should allow the following URLs:
  - `*.events.data.microsoft.com`
  - `*.endpoint.security.microsoft.com`
  - `*.ecs.office.com`

- Enterprise U.S. Government customers should allow the following URLs:
  - `*.events.data.microsoft.com`
  - `*.endpoint.security.microsoft.us` (GCC-H & DoD)
  - `*.gccmod.ecs.office.com` (GCC-M)
  - `*.config.ecs.gov.teams.microsoft.us` (GCC-H)
  - `*.config.ecs.dod.teams.microsoft.us` (DoD)

## Windows Policies

Since the tool includes a seperate `Policies` section and most of the Defender settings are controlled via them (not all SmartScreen parts are, which is why it's a suboption), I won't add them as suboptions to keep the UI clean. If you want to fine tune specific parts of Defender after applying the `Configured` preset, you can do so by copying the value name and pasting it into the search bar, it'll show the policy (or go into the Policies section and open WindowsDefender / WindowsDefenderSecurityCenter / WebThreatDefense).

### Main AV Parts

| Value name | Description |
| --- | --- |
| `PUAProtection` | Controls whether potentially unwanted applications are allowed, audited, or blocked when they are downloaded or try to install. |
| `DisableBehaviorMonitoring` | Controls whether Defender behavior monitoring stays enabled or is disabled. |
| `DisableIOAVProtection` | Controls whether downloaded files and attachments are scanned. |
| `DisableEmailScanning` | Controls whether Defender scans supported mailbox and mail-file formats for message bodies and attachments; modern email clients are not supported by this feature. |
| `DisableOnAccessProtection` | Controls whether file and program activity is monitored. |
| `DisableRealtimeMonitoring` | Controls whether Defender real-time protection is turned off or left on. |
| `DisableScanOnRealtimeEnable` | Controls whether a process scan is started when real-time protection is turned on. |

### Cloud / MAPS

| Value name | Description |
| --- | --- |
| `SpynetReporting` | Controls whether the device joins Microsoft MAPS and whether it sends basic or additional threat information to Microsoft. |
| `LocalSettingOverrideSpynetReporting` | Controls whether a local MAPS reporting preference can override Group Policy. |
| `SubmitSamplesConsent` | Controls how Defender submits file samples for further analysis when MAPS is in use. |
| `DisableBlockAtFirstSeen` | Controls whether Defender checks suspicious content with MAPS before allowing it to run or be accessed. (*Defender marks it as `DisableBlockAtFirstSeen` and deletes the value*) |
| `MpBafsExtendedTimeout` | Controls the extra time Defender can hold a suspicious file for an extended cloud check. |
| `MpCloudBlockLevel` | Controls how aggressively Defender blocks and scans suspicious files using cloud protection. |
| `SignatureDisableNotification` | Controls whether the antimalware service can receive MAPS notifications that disable security intelligence causing false positives. |

### Exploit Guard

| Value name | Description |
| --- | --- |
| `EnableNetworkProtection` | Controls whether Network Protection blocks or audits access to dangerous domains used for phishing, exploits, or other malicious content. |
| `AllowNetworkProtectionOnWinServer` | Controls whether Network Protection is allowed to run in block or audit mode on Windows Server. |
| `EnableControlledFolderAccess` | Controls whether untrusted apps can modify protected folders or write to disk sectors, and whether those actions are blocked or audited. |

### WebThreatDefense / Enhanced Phishing

| Value name | Description |
| --- | --- |
| `ServiceEnabled` | Controls whether Enhanced Phishing Protection runs in audit mode or stays off, audit mode records unsafe password entry events and sends telemetry. |
| `NotifyMalicious` | Controls whether users are warned when they enter a work or school password into phishing or invalid Microsoft sign-in scenarios. |
| `NotifyPasswordReuse` | Controls whether users are warned when they reuse their work or school password. |
| `NotifyUnsafeApp` | Controls whether users are warned when they type their work or school password into unsafe apps such as text editors or Office apps. |
| `CaptureThreatWindow` | Controls whether Enhanced Phishing Protection may collect additional security data when a password is entered into a suspicious site or app. |

### Reporting / Notifications

| Value name | Description |
| --- | --- |
| `DisableGenericRePorts` | Controls whether Watson events are sent. |
| `DisableEnhancedNotifications` | Controls whether enhanced or non-critical Defender notifications are shown on clients. |
| `DisableNotifications` | Controls whether local users can see notifications from Windows Security. |

### SmartScreen Policy Values

| Value name | Description |
| --- | --- |
| `EnableSmartScreen` | Controls whether Windows Defender SmartScreen is turned on or off for app reputation warnings and related checks. |
| `ShellSmartScreenLevel` | Controls whether SmartScreen warns users or warns and prevents bypass when the Windows Defender SmartScreen policy is enabled. |
| `EnabledV9` | Controls whether legacy Microsoft Edge SmartScreen is enforced, including phishing and malware checks against sites that are not on the allow list. |
| `SmartScreenEnabled` | Controls whether current Microsoft Edge SmartScreen is turned on or off in the browser. |

> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender  
> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-webthreatdefense  
> https://learn.microsoft.com/en-us/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus  
> https://learn.microsoft.com/en-us/defender-endpoint/configure-protection-features-microsoft-defender-antivirus  
> https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus  
> https://learn.microsoft.com/en-us/defender-endpoint/specify-cloud-protection-level-microsoft-defender-antivirus  
> https://learn.microsoft.com/en-us/defender-endpoint/enable-controlled-folders  
> https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-problems-with-tamper-protection  
> [security/assets | Windows-Defender.txt](https://github.com/nohuto/win-config/blob/main/security/assets/Windows-Defender.txt)

## Remove Defender from Image

If you want to completely remove Windows Defender for a specific reason, use DISM.

Obviously, you need to change the `mount` path before running it.

```powershell
@echo off
setlocal

set "mount=%userprofile%\Desktop\DISMT\mount"

MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthSystray.exe"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthService.exe"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthAgent.dll"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthHost.exe"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthSSO.dll"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthSsoUdk.dll"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthCore.dll"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthProxyStub.dll"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\SecurityHealthUdk.dll"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\drivers\WdNisDrv.sys"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\Windows\System32\SecurityHealth"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\Program Files\Windows Defender Advanced Threat Protection"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\Program Files\Windows Defender"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\Program Files (x86)\Windows Defender"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\ProgramData\Microsoft\Windows Defender"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\ProgramData\Microsoft\Windows Defender Advanced Threat Protection"
MinSudo -NoL -P -TI cmd /c rd /s /q "%mount%\ProgramData\Microsoft\Windows Security Health"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\smartscreen.exe"
MinSudo -NoL -P -TI cmd /c del /f /q "%mount%\Windows\System32\smartscreenps.dll"

endlocal
```

### Task Leftovers

You can remove task leftovers after installation or in the `oobeSystem` phase with:
```batch
powershell -command "Get-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' | Unregister-ScheduledTask -Confirm:$false"
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Windows Defender" /f
rmdir /s /q "%windir%\System32\Tasks\Microsoft\Windows\Windows Defender"
```

## Windows Security Records

```c
// Real-time protection - 0 = On, 1 = Off
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring	Type: REG_DWORD

// Dev Drive protection - 0 = On, 1 = Off
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableAsyncScanOnOpen	Type: REG_DWORD

// Cloud-delivered protection - 0 = Off, 2 = On
HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SpyNetReporting	Type: REG_DWORD

// Automatic sample submission - 0 = Off, 1 = On
HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent	Type: REG_DWORD

// Tamper Protection
// Off
HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection	Type: REG_DWORD, Length: 4, Data: 4	RegSetValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtectionSource	Type: REG_DWORD, Length: 4, Data: 2	RegSetValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TPExclusions	Type: REG_DWORD, Length: 4, Data: 0	RegSetValue
// On
HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection	Type: REG_DWORD, Length: 4, Data: 5	RegSetValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtectionSource	Type: REG_DWORD, Length: 4, Data: 2	RegSetValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TPExclusions	Type: REG_DWORD, Length: 4, Data: 0	RegSetValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Device Control\WddState	Type: REG_DWORD, Length: 4, Data: 1	RegSetValue
HKLM\SOFTWARE\Microsoft\Windows Defender\DisableRoutinelyTakingAction		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\MpEngine\DisableScriptScanning		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableEarlyLaunchAntimalware		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableIntrusionPreventionSystem		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableOnAccessProtection		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableScanOnRealtimeEnable		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableScriptScanning		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Reporting\DisableEnhancedNotifications		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Scan\DisableArchiveScanning		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\1		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\2		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\4		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\5		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration\DisablePrivacyMode		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration\Notification_Suppress		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration\SuppressRebootNotification		RegDeleteValue
HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration\SuppressWdoNotification		RegDeleteValue

// Controlled folder access - 0 = Off, 1 = On
HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\EnableControlledFolderAccess	Type: REG_DWORD

// Dynamic lock - 0 = Off, 1 = On
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\EnableGoodbye	Type: REG_DWORD

// Check apps and files, "Off" = Off, "Warn" = On
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SmartScreenEnabled	Type: REG_SZ

// SmartScreen for Microsoft Edge - 0 = Off, 1 = On
HKCU\Software\Microsoft\Edge\SmartScreenEnabled\(Default)	Type: REG_DWORD

// Phishing Protection - 0 = Off, 1 = On
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components\ServiceEnabled	Type: REG_DWORD

// Warn me about malicious apps and sites - 0 = Off, 1 = On
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components\NotifyMalicious	Type: REG_DWORD

// Warn me about password reuse - 0 = Off, 1 = On
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components\NotifyPasswordReuse	Type: REG_DWORD


// Warn me about unsafe password storage - 0 = Off, 1 = On
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components\NotifyUnsafeApp	Type: REG_DWORD

// Automatically collect website or app content when additional analysis is needed to help identify security threats - 0 = Off, 1 = On
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components\CaptureThreatWindow	Type: REG_DWORD

// Potentially unwanted app blocking - 0 = Off, 1 = On
HKLM\SOFTWARE\Microsoft\Windows Defender\PUAProtection	Type: REG_DWORD
HKCU\Software\Microsoft\Edge\SmartScreenPuaEnabled\(Default)	Type: REG_DWORD
HKLM\SOFTWARE\Microsoft\Windows Defender\PUAProtection	Type: REG_DWORD
HKCU\Software\Microsoft\Edge\SmartScreenPuaEnabled\(Default)	Type: REG_DWORD

// SmartScreen for Microsoft Store apps - 0 = Off, 1 = On (PreventOverride = 0 for both)
HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation	Type: REG_DWORD
//HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost\PreventOverride	Type: REG_DWORD

// Local Security Authority protection - 0 = Off, 2 = On
HKLM\System\CurrentControlSet\Control\Lsa\RunAsPPL	Type: REG_DWORD

// Microsoft Vulnerable Driver Blocklist - 0 = Off, 1 = On
HKLM\System\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable	Type: REG_DWORD

//  --- Miscellaneous MpPreference Records ---

// Set-MpPreference -DisableCoreServiceTelemetry $true
HKLM\SOFTWARE\Microsoft\Windows Defender\Features\DisableCoreService1DSTelemetry	Type: REG_DWORD, Length: 4, Data: 1
HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\DisableCoreService1DSTelemetry	Type: REG_DWORD, Length: 4, Data: 1

// Set-MpPreference -DisableCoreServiceTelemetry $false
HKLM\SOFTWARE\Microsoft\Windows Defender\Features\DisableCoreService1DSTelemetry	Type: REG_DWORD, Length: 4, Data: 0
HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\DisableCoreService1DSTelemetry	Type: REG_DWORD, Length: 4, Data: 0
```

# Windows Update

| Option | Description |
| ---- | ---- |
| `Disable WU` | Stops normal Windows Update scanning, download, install, and orchestrated update activity. |
| `Enable WU` | Restores normal update behavior for the controls managed in this section. |
| `Security Only` | Keeps monthly Windows quality and security servicing for the current release while blocking feature upgrades, WU driver updates, optional content, CFR rollouts, preview content, Microsoft product updates, and MRT through Windows Update. |

| Suboption | Description |
| ---- | ---- |
| `Disable Feature Updates` | Keeps the device on its current Windows release while quality updates continue. New Windows releases are not offered until removed. |
| `Disable Quality Updates (35D)` | Temporarily pauses monthly cumulative updates, including security fixes. Security fixes stop until the pause is cleared or expires. |
| `Disable WU Driver Updates` | Blocks Windows Update from installing driver-class updates. Hardware fixes and newer vendor drivers are not delivered through Windows Update. |
| `Disable Microsoft Product Updates` | Stops updates for other Microsoft products through this channel. Office and other Microsoft apps stop receiving updates from Windows Update. |
| `Disable Optional Updates` | Hides optional update content from normal servicing. Optional fixes and non-essential improvements are not offered. |
| `Disable CFR Features` | Stops gradual rollout features delivered through servicing. New feature rollouts arrive later or only through full releases. |
| `Disable Preview Builds` | Prevents preview and Insider-style update content. Pre-release Windows builds and preview tracks are unavailable. |
| `Disable Store App Updates` | Stops automatic Microsoft Store app updates. Store apps stop receiving background fixes and feature updates. |
| `Disable Device Metadata Retrieval` | Stops automatic retrieval of device metadata from Microsoft. Device names, icons, and related suggestions may be less complete. |
| `Disable Automatic Root Certificate Updates` | Stops automatic refresh of trusted root certificates. Some secure sites, apps, or signed content can fail until trust is updated another way. |
| `Disable Defender Definition Updates` | Stops Defender definition updates from this update path. Malware detection ages quickly unless another definition source is provided. |
| `Block MRT via WU` | Stops the MRT (Malicious Software Removal Tool) from being offered through Windows Update. MRT scans and related reporting are unavailable from this channel. |

> https://learn.microsoft.com/en-us/windows/deployment/update/waas-configure-wufb  
> https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings  
> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update  
> https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services

# Windows Firewall

"*Windows Firewall is a security feature that helps to protect your device by filtering network traffic that enters and exits your device. This traffic can be filtered based on several criteria, including source and destination IP address, IP protocol, or source and destination port number. Windows Firewall can be configured to block or allow network traffic based on the services and applications that are installed on your device. This allows you to restrict network traffic to only those applications and services that are explicitly allowed to communicate on the network.*" ([*](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/))

## Inbound vs Outbound

- **Inbound**: traffic initiated elsewhere that comes into your PC, like file sharing, hosted game sessions, or Remote Desktop.
- **Outbound**: traffic initiated by your PC going to another device or the internet, like web browsing, app updates, or apps connecting to their servers.

## Firewall Presets

The option currently includes 4 different presets, note that `Allowlist Mode` will need rules that you've to add. It's recommended to allow outbound, look at the network section in system informer, afterwards adding rules for programs that require network outbound access.

On first use kind of everything get's blocked -> minimalfirewall asks you to block/allow it. This continues until every required rule is set.

- `Off`: firewall disabled
- `Default`: inbound block, outbound allow
- `Allowlist`: inbound block, outbound block unless allowed (recommended, but requires time to set up)

## Firewall Records

```c
// {profile} = always 'DomainProfile' + 'StandardProfile' + 'PublicProfile'

// Firewall state - 0 = Off, 1 = On
HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}\EnableFirewall	Type: REG_DWORD

// Inbound connections - 0 = Allow, 1 = Block
// 'Block all connections' - DefaultInboundAction = 1 & DoNotAllowExceptions = 1 (DoNotAllowExceptions gets deleted otherwise)
HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}\DefaultInboundAction
HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}\DoNotAllowExceptions	

// Outbound connections - 0 = Allow, 1 = Block
HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}\DefaultOutboundAction	Type: REG_DWORD

// --- Settings ---

// Display a notification - 0 = On, 1 = Off
HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}\DisableNotifications	Type: REG_DWORD

// Allow unicast response - 0 = On, 1 = Off
HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}\DisableUnicastResponsesToMulticastBroadcast	Type: REG_DWORD

// --- Logging ---

// Name
HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}\Logging\LogFilePath	Type: REG_SZ

// Size limit (KB) - Data: 4096 = 4,096KB
HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}\Logging\LogFileSize	Type: REG_DWORD

// Log dropped packets - 0 = Off, 1 = On
HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}\Logging\LogDroppedPackets	Type: REG_DWORD

// Log successful connections - 0 = Off, 1 = On 
HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}\Logging\LogSuccessfulConnections	Type: REG_DWORD
```

## Firewall Service

Disabling the firewall service (`Disable Services/Driver`) can break:
- Microsoft Store & UWP apps
- `winget` / app deployment
- Windows Sandbox
- Xbox networking
- Start menu
- Modern applications can fail to install or update
- Activation of Windows via phone
- Application or OS incompatibilities that depend on Windows Firewall

"The proper method to disable the Windows Firewall is to disable the Windows Firewall Profiles and leave the service running."

# UAC

Disabling UAC stops the prompts for administrative permissions, allowing programs and processes to run with elevated rights without user confirmation.

Windows Internals (E7-P1, UAC): "*User Account Control (UAC) is meant to enable users to run with standard user rights as opposed to administrative rights. Without administrative rights, users cannot accidentally (or deliberately) modify system settings, malware can’t normally alter system security settings or disable antivirus software, and users can’t compromise the sensitive information of other users on shared computers. Running with standard user rights can thus mitigate the impact of malware and protect sensitive data on shared computers.*

*UAC runs most apps with standard user rights and uses a filtered admin token for administrators, elevating only when needed. Disabling UAC removes this filtered-token model and disables UAC file/registry virtualization (Luafv.sys).*"

**Table 7-18** UAC options
| Slider Position | Attempts to change Windows settings | Attempts to install software or run a program requiring elevation | Remarks |
| --- | --- | --- | --- |
| Highest position (`Always Notify`) | A UAC elevation prompt appears on the Secure Desktop. | A UAC elevation prompt appears on the Secure Desktop. | This was the Windows Vista behavior. |
| Second position | UAC elevation occurs automatically with no prompt or notification. | A UAC elevation prompt appears on the Secure Desktop. | Windows default setting. |
| Third position | UAC elevation occurs automatically with no prompt or notification. | A UAC elevation prompt appears on the user’s normal desktop. | Not recommended. |
| Lowest position (`Never Notify`) | UAC is turned off for administrative users. | UAC is turned off for administrative users. | Not recommended. |

**Table 7-19** UAC registry values
| Slider Position | ConsentPromptBehaviorAdmin | ConsentPromptBehaviorUser | EnableLUA | PromptOnSecureDesktop |
| --- | --- | --- | --- | --- |
| Highest position (`Always Notify`) | `2` (display AAC UAC elevation prompt) | `3` (display OTS UAC elevation prompt) | `1` (enabled) | `1` (enabled) |
| Second position | `5` (display AAC UAC elevation prompt, except for changes to Windows settings) | `3` | `1` | `1` |
| Third position | `5` | `3` | `1` | `0` (disabled; UAC prompt appears on user’s normal desktop) |
| Lowest position (`Never Notify`) | `0` | `3` | `0` (disabled; logins to administrative accounts do not create a restricted admin access token) | `0` |

Read more about UAC/file virtualization/(auto-)elevation in [Windows Internals E7, P1 - P.722f. 'User Account Control and virtualization'](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf).

## Registry Values Details

Value: `FilterAdministratorToken`

| Value        | Meaning                                                                                                                                          |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `0x00000000` | Only the built-in administrator account (RID 500) should be placed into Full Token mode.                                                         |
| `0x00000001` | Only the built-in administrator account (RID 500) is placed into Admin Approval Mode. Approval is required when performing administrative tasks. |

Value: `ConsentPromptBehaviorAdmin`

| Value        | Meaning                                                                                                              |
| ------------ | -------------------------------------------------------------------------------------------------------------------- |
| `0x00000000` | Allows the admin to perform operations that require elevation without consent or credentials.                        |
| `0x00000001` | Prompts for username and password on the secure desktop when elevation is required.                                  |
| `0x00000002` | Prompts the admin to Permit or Deny an elevation request (secure desktop). Removes the need to re-enter credentials. |
| `0x00000003` | Prompts for credentials (admin username/password) when elevation is required.                                        |
| `0x00000004` | Prompts the admin to Permit or Deny elevation (non-secure desktop).                                                  |
| `0x00000005` | Default: Prompts admin to Permit or Deny elevation for non-Windows binaries on the secure desktop.                   |

Value: `ConsentPromptBehaviorUser`

| Value        | Meaning                                                                       |
| ------------ | ----------------------------------------------------------------------------- |
| `0x00000000` | Any operation requiring elevation fails for standard users.                   |
| `0x00000001` | Standard users are prompted for an admin's credentials to elevate privileges. |
| `0x00000003` | Display OTS UAC elevation prompt |

Value: `EnableInstallerDetection`

| Value        | Meaning                                                            |
| ------------ | ------------------------------------------------------------------ |
| `0x00000000` | Disables automatic detection of installers that require elevation. |
| `0x00000001` | Enables heuristic detection of installers needing elevation.       |

Value: `ValidateAdminCodeSignatures`

| Value        | Meaning                                                                        |
| ------------ | ------------------------------------------------------------------------------ |
| `0x00000000` | Does not enforce cryptographic signatures on elevated apps.                    |
| `0x00000001` | Enforces cryptographic signatures on any interactive app requesting elevation. |

Value: `EnableLUA`

| Value        | Meaning                                                                             |
| ------------ | ----------------------------------------------------------------------------------- |
| `0x00000000` | Disables the "Administrator in Admin Approval Mode" user type and all UAC policies ("*logins to administrative accounts do not create a restricted admin access token*"). |
| `0x00000001` | Enables the "Administrator in Admin Approval Mode" and activates all UAC policies.  |

Value: `PromptOnSecureDesktop`
| Option | Description |
| ---- | ---- |
| `UAC: Disable completely` | Turns UAC off, disables LUA and virtualization, and removes consent prompts entirely. Highest compatibility risk and lowest protection. |
| `UAC: Windows default (prompt, secure desktop)` | Restores the normal Windows UAC behavior with prompts on the secure desktop. |
| `UAC: Always notify` | Prompts on every administrative change with the most protective prompt behavior. |
| `UAC: Notify apps only (no desktop dimming)` | Keeps app elevation prompts but does not switch to the secure desktop. |
| `UAC: Elevate without prompting (admins)` | Keeps LUA on for administrators but removes the admin consent prompt. Lower friction, weaker protection. |

| Value        | Meaning                                                                        |
| ------------ | ------------------------------------------------------------------------------ |
| `0x00000000` | Disables secure desktop prompting - prompts appear on the interactive desktop. |
| `0x00000001` | Forces all UAC prompts to occur on the secure desktop.                         |

Value: `EnableVirtualization`

| Value        | Meaning                                                                                       |
| ------------ | --------------------------------------------------------------------------------------------- |
| `0x00000000` | Disables data redirection for interactive processes.                                          |
| `0x00000001` | Enables file and registry redirection for legacy apps to allow writes in user-writable paths. |

> https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/12867da0-2e4e-4a4f-9dc4-84a7f354c8d9  
> https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration?tabs=reg

# PS Unrestricted Policy

Used to make powershell (`.ps1`) scripts work on your PC without showing any warning.

| **Value Name** | **Description** |
| ---- | ---- |
| `EnableScriptBlockLogging` | Enables or disables logging of PowerShell script input to the event log. If enabled, it logs the processing of commands, script blocks, functions, and scripts. |
| `EnableScriptBlockInvocationLogging` | Enables or disables logging of invocation events for commands, script blocks, functions, or scripts. Enabling this generates high volume of event logs for start/stop events. |
| `EnableModuleLogging` | Enables or disables logging of pipeline execution events for specified PowerShell modules. If enabled, logs events in Event Viewer for the specified modules. |
| `EnableTranscripting` | Enables or disables transcription of PowerShell commands. If enabled, records the input and output of PowerShell commands into text-based transcripts stored by default in My Documents. |
| `EnableScripts` | Controls which types of scripts are allowed to run on the system. Options include allowing only signed scripts, allowing local scripts and remote signed scripts, or allowing all scripts to run. |

| **Scope** | **Description** |
|---- | ---- |
| `MachinePolicy` | Set by a Group Policy for all users of the computer |
| `UserPolicy` | Set by a Group Policy for the current user of the computer |
| `Process` | Sets the execution policy only for the current session - stored in an environment variable & removed when the session ends |
| `CurrentUser` | The execution policy affects only the current user - stored in the HLCU subkey |
| `LocalMachine` | The execution policy affects all users on the current computer - stored in the HKLM subkey |

> https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.5#execution-policy-scope

| **Execution Policy**  | **Description** |
| ---- | ---- |
| `AllSigned` | All scripts must be signed by a trusted publisher. Prompts for untrusted publishers. |
| `Bypass` | No prompts or restrictions. Used in apps or environments with their own security. |
| `Default` | Acts like `RemoteSigned` on Windows. |
| `RemoteSigned` | Scripts run freely unless downloaded from the internet. Internet scripts need a trusted signature or must be unblocked. Local scripts don't require signatures. |
| `Restricted` | No scripts allowed (only individual commands). Blocks all `.ps1`, `.psm1`, `.ps1xml`, and profile scripts. |
| `Undefined` | No policy in this scope. If all scopes are undefined, defaults to `Restricted` (clients) or `RemoteSigned` (servers). |
| `Unrestricted` | Unsigned scripts can run. Prompts for scripts from outside the intranet zone. |

See your current execution policies via:
```powershell
Get-ExecutionPolicy -l
```
`Set-ExecutionPolicy Unrestricted -Force`:
```
powershell.exe    HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy    Type: REG_SZ, Length: 26, Data: Unrestricted
```

> https://powershellisfun.com/2022/07/31/powershell-and-logging/  
> https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file?view=powershell-7.5  
> https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.5  
> https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_config?view=powershell-7.5  
> https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.5  
> https://learn.microsoft.com/en-us/previous-versions/troubleshoot/browsers/security-privacy/ie-security-zones-registry-entries#zones

# Disable System Mitigations

Security features that protect against memory based attacks like buffer overflows and code injection. Enabling this option will reduce system security.

It currently applies all valid values **system wide** using `Set-ProcessMitigation -System`:
```powershell
HKLM\System\CurrentControlSet\Control\Session Manager\kernel\MitigationOptions	Type: REG_BINARY, Length: 24, Data: 00 22 22 20 22 20 22 22 22 20 22 22 22 22 22 22
HKLM\System\CurrentControlSet\Control\Session Manager\kernel\MitigationAuditOptions	Type: REG_BINARY, Length: 24, Data: 02 22 22 02 02 02 20 22 22 22 22 22 22 22 22 22
```

Disable specific mitigation:
```powershell
Set-ProcessMitigation -Name process.exe -Disable Value
```

Editing process mitigations via LGPE (`Administrative Templates\System\Mitigation Options\Process Mitigation Options`):

![](https://github.com/nohuto/win-config/blob/main/security/images/processmiti.png?raw=true)

| Flag | Bit | Setting | Details |
| --- | --- | --- | --- |
| A | 0 | PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE (0x00000001) | Turns on Data Execution Prevention (DEP) for child processes. |
| B | 1 | PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE (0x00000002) | Turns on DEP-ATL thunk emulation for child processes. DEP-ATL thunk emulation lets the system intercept nonexecutable (NX) faults that originate from the Active Template Library (ATL) thunk layer, and then emulate and handle the instructions so the process can continue to run. |
| C | 2 | PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE (0x00000004) | Turns on Structured Exception Handler Overwrite Protection (SEHOP) for child processes. SEHOP helps to block exploits that use the Structured Exception Handler (SEH) overwrite technique. |
| D | 8 | PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON (0x00000100) | Uses the force ASLR setting to act as though an image base collision happened at load time, forcibly rebasing images that aren't dynamic base compatible. Images without the base relocation section aren't loaded if relocations are required. |
| E | 15 | PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON (0x00010000) | Turns on the bottom-up randomization policy, which includes stack randomization options and causes a random location to be used as the lowest user address. |
| F | 16 | PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_OFF (0x00020000) | Turns off the bottom-up randomization policy, which includes stack randomization options and causes a random location to be used as the lowest user address. |

> https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/override-mitigation-options-for-app-related-security-policies

---

**Table 7-20** Process mitigation options

| Mitigation Name | Use Case | Enabling Mechanism |
| --- | --- | --- |
| ASLR Bottom Up Randomization | Makes calls to `VirtualAlloc` subject to ASLR with 8-bit entropy, including stack-base randomization. | Set with the `PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON` process-creation attribute flag. |
| ASLR Force Relocate Images | Forces ASLR even on binaries that do not have the `/DYNAMICBASE` linker flag. | Set with `SetProcessMitigationPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON` process-creation flag. |
| High Entropy ASLR (HEASLR) | Significantly increases entropy of ASLR on 64-bit images, increasing bottom-up randomization to up to 1 TB of variance. | Must be set through `/HIGHENTROPYVA` at link time or the `PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON` process-creation attribute flag. |
| ASLR Disallow Stripped Images | Blocks the load of any library without relocations (linked with the `/FIXED` flag) when combined with ASLR Force Relocate Images. | Set with `SetProcessMitigationPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS` process-creation flag. |
| DEP: Permanent | Prevents the process from disabling DEP on itself. Only relevant on x86 and 32-bit applications, including WoW64. | Set with `SetProcessMitigationPolicy`, a process-creation attribute, or `SetProcessDEPPolicy`. |
| DEP: Disable ATL Thunk Emulation | Prevents legacy ATL library code from executing ATL thunks in the heap, even if a known compatibility issue exists. Only relevant on x86 and 32-bit applications, including WoW64. | Set with `SetProcessMitigationPolicy`, a process-creation attribute, or `SetProcessDEPPolicy`. |
| SEH Overwrite Protection (SEHOP) | Prevents structured exception handlers from being overwritten with incorrect ones, even if the image was not linked with `Safe SEH` (`/SAFESEH`). Only relevant on 32-bit applications, including WoW64. | Set with `SetProcessDEPPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE` process-creation flag. |
| Raise Exception on Invalid Handle | Helps catch handle reuse attacks by crashing the process instead of returning a failure that the process might ignore. | Set with `SetProcessMitigationPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON` process-creation attribute flag. |
| Raise Exception on Invalid Handle Close | Helps catch double-handle-close attacks, limiting exploit reliability and effectiveness. | Undocumented and can only be set through an undocumented API. |
| Disallow Win32k System Calls | Disables all access to the Win32 kernel-mode subsystem driver, including Window Manager, GDI, and DirectX system calls. | Set with `SetProcessMitigationPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON` process-creation attribute flag. |
| Filter Win32k System Calls | Filters access to the Win32k subsystem to certain APIs, allowing simple GUI and DirectX access while reducing attack surface. | Set through an internal process-creation attribute flag with one of three hard-coded Win32k filter sets; reserved for Microsoft internal usage. |
| Disable Extension Points | Prevents a process from loading IMEs, Windows hook DLLs, AppInit DLLs, or Winsock layered service providers. | Set with `SetProcessMitigationPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON` process-creation attribute flag. |
| Arbitrary Code Guard (CFG) | Prevents a process from allocating executable code or changing existing executable code to writable-executable memory. | Set with `SetProcessMitigationPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON` and `PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON_ALLOW_OPT_OUT` process-creation attribute flags. |
| Control Flow Guard (CFG) | Helps prevent memory corruption from hijacking control flow by validating indirect `CALL` and `JMP` targets against valid functions. | The image must be compiled and linked with `/guard:cf`; it can also be set with the `PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON` process-creation attribute flag for other images loading in the process. |
| CFG Export Suppression | Strengthens CFG by suppressing indirect calls to the exported API table of the image. | The image must be compiled with `/guard: exportsuppress`, and can also be configured through `SetProcessMitigationPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_EXPORT_SUPPRESSION` process-creation attribute flag. |
| CFG Strict Mode | Prevents loading any image library in the current process that was not linked with `/guard:cf`. | Set through `SetProcessMitigationPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD_ALWAYS_ON` process-creation attribute flag. |
| Disable Non System Fonts | Prevents loading any font files that were not registered by Winlogon at user logon time after installation in `C:\Windows\Fonts`. | Set through `SetProcessMitigationPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON` process-creation attribute flag. |
| Microsoft-Signed Binaries Only | Prevents loading any image library in the current process that was not signed by a Microsoft CA-issued certificate. | Set through the `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` process-attribute flag at startup time. |
| Store-Signed Binaries Only | Prevents loading any image library in the current process that was not signed by the Microsoft Store CA. | Set through the `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE` process attribute flag at startup time. |
| No Remote Images | Prevents loading any image library in the current process that is present on a non-local UNC or WebDAV path. | Set through `SetProcessMitigationPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON` process-creation attribute flag. |
| No Low IL Images | Prevents loading any image library in the current process that has a mandatory label below medium (`0x2000`). | Set through `SetProcessMitigationPolicy`, the `PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON` process-creation flag, or a resource claim ACE called `IMAGELOAD` on the process file. |
| Prefer System32 Images | Modifies the loader search path to always look in `%SystemRoot%\\System32` for relatively named image libraries before other locations. | Set through `SetProcessMitigationPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON` process-creation attribute flag. |
| Return Flow Guard (RFG) | Helps prevent additional control-flow attacks by validating `RET` instructions against expected call and stack behavior. | Not yet available; included in the table for completeness. |
| Restrict Set Thread Context | Restricts modification of the current thread’s context. | Currently disabled pending the availability of RFG and may appear in a future version of Windows; included for completeness. |
| Loader Continuity | Prohibits dynamic loading of DLLs that do not have the same integrity level as the process when signature-policy mitigations could not be enabled at startup. | Set through `SetProcessMitigationPolicy` or the `PROCESS_CREATION_MITIGATION_POLICY2_LOADER_INTEGRITY_CONTINUITY_ALWAYS_ON` process-creation attribute flag. |
| Heap Terminate On Corruption | Disables the Fault Tolerant Heap and turns heap corruption into immediate process termination instead of a continuable exception. | Set through `HeapSetInformation` or the `PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON` process-creation attribute flag. |
| Disable Child Process Creation | Prohibits creation of child processes by marking the token with a special restriction. | Set through the `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` process-creation attribute flag; can be overridden for packaged desktop apps with `PROCESS_CREATION_DESKTOP_APPX_OVERRIDE`. |
| All Application Packages Policy | Makes an AppContainer application unable to access resources that only have an `ALL APPLICATION PACKAGES` SID, requiring `ALL RESTRICTED APPLICATION PACKAGES` instead. | Set through the `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` process-creation attribute. |

Read more about process-mitigation policies in [Windows Internals E7, P1 - P.735f. 'Process-mitigation policies'](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf).

---

`(gcm set-processmitigation).Parameters.Disable.Attributes.ValidValues`:
```powershell
DEP
EmulateAtlThunks
ForceRelocateImages
RequireInfo
BottomUp
HighEntropy
StrictHandle
DisableWin32kSystemCalls
AuditSystemCall
DisableExtensionPoints
DisableFsctlSystemCalls
AuditFsctlSystemCall
BlockDynamicCode
AllowThreadsToOptOut
AuditDynamicCode
CFG
SuppressExports
StrictCFG
MicrosoftSignedOnly
AllowStoreSignedBinaries
AuditMicrosoftSigned
AuditStoreSigned
EnforceModuleDependencySigning
DisableNonSystemFonts
AuditFont
BlockRemoteImageLoads
BlockLowLabelImageLoads
PreferSystem32
AuditRemoteImageLoads
AuditLowLabelImageLoads
AuditPreferSystem32
EnableExportAddressFilter
AuditEnableExportAddressFilter
EnableExportAddressFilterPlus
AuditEnableExportAddressFilterPlus
EnableImportAddressFilter
AuditEnableImportAddressFilter
EnableRopStackPivot
AuditEnableRopStackPivot
EnableRopCallerCheck
AuditEnableRopCallerCheck
EnableRopSimExec
AuditEnableRopSimExec
SEHOP
AuditSEHOP
SEHOPTelemetry
TerminateOnError
DisallowChildProcessCreation
AuditChildProcess
UserShadowStack
UserShadowStackStrictMode
AuditUserShadowStack
```

# Opt-Out DMA Remapping

"To ensure compatibility with Kernel DMA Protection and DMAGuard Policy, PCIe device drivers can opt into Direct Memory Access (DMA) remapping. DMA remapping for device drivers protects against memory corruption and malicious DMA attacks, and provides a higher level of compatibility for devices. Also, devices with DMA remapping-compatible drivers can start and perform DMA regardless of lock screen status. On Kernel DMA Protection enabled systems, DMAGuard Policy might block devices, with DMA remapping-incompatible drivers, connected to external/exposed PCIe ports (for example, M.2, Thunderbolt), depending on the policy value set by the system administrator. DMA remapping isn't supported for graphics device drivers. `DmaRemappingCompatible` key is ignored if `RemappingSupported` is set."

"Only use this per-driver method for Windows versions up to Windows 11 23H2. Use the [per-device method](https://github.com/nohuto/windows-driver-docs/blob/staging/windows-driver-docs-pr/pci/enabling-dma-remapping-for-device-drivers.md#per-device-opt-in-mechanism)."

`per-device` - recommended and preferred mechanism (`DmaRemappingCompatible`)
`per-driver` - legacy mechanism (`RemappingSupported`)

`DmaRemappingCompatible`:

| Value | Meaning |
|--|--|
| 0 | Opt-out, indicates that your driver is incompatible with DMA remapping. |
| 1 | Opt-in, indicates that your driver is fully compatible with DMA remapping. |
| 2 | Opt-in, but only when one or more of the following conditions are met: A. The device is an external device (for example, Thunderbolt); B. DMA verification is enabled in Driver Verifier |
| 3 | Opt-in |
| No registry key | Let the system determine the policy. |

`RemappingFlags`:

| Value | Meaning |
|--|--|
| 0 | If **RemappingSupported** is 1, opt in, unconditionally. |
| 1 | If **RemappingSupported** is 1, opt in, but only when one or more of the following conditions are met: A. The device is an external device (for example, Thunderbolt); B. DMA verification is enabled in Driver Verifier |
| No registry key | Same as 0 value. |

`RemappingSupported`:

| Value | Meaning |
|--|--|
| 0 | Opt-out, indicates the device and driver are incompatible with DMA remapping. |
| 1 | Opt-in, indicates the device and driver are fully compatible with DMA remapping. |
| No registry key | Let the system determine the policy. |

> https://github.com/nohuto/windows-driver-docs/blob/staging/windows-driver-docs-pr/pci/enabling-dma-remapping-for-device-drivers.md

Example paths:
```powershell
\Registry\Machine\SYSTEM\ControlSet001\Services\msisadrv\Parameters : DmaRemappingCompatible
\Registry\Machine\SYSTEM\ControlSet001\Enum\pci\VEN_1022&DEV_1483&SUBSYS_88081043&REV_00\3&11583659&0&09\Device Parameters\DMA Management : RemappingFlags
\Registry\Machine\SYSTEM\ControlSet001\Enum\pci\VEN_1022&DEV_1483&SUBSYS_88081043&REV_00\3&11583659&0&09\Device Parameters\DMA Management : RemappingSupported
```

---

Since `EnableNVMeInterface` is included in the function, I'll add it here. Default value of `0`, range `0`-`1`? Located in:
```
\Registry\Machine\SYSTEM\ControlSet001\Enum\pci\<dev>\<id>\Device Parameters\StorPort : EnableNVMeInterface
```
`DisableNativeNVMeStack`, range `0`-`1`?
```c
\Registry\Machine\SYSTEM\ControlSet001\Control\StorPort : DisableNativeNVMeStack

DisableNativeNVMeStack db 0 // default
```
> https://github.com/nohuto/win-registry/blob/main/records/StorPort.txt

# Disable System Restore

```powershell
Disable-ComputerRestore -Drive "C:\"
```
Does:
```powershell
"wmiprvse.exe", "RegSetValue","HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\RPSessionInterval","Type: REG_DWORD, Length: 4, Data: 0"
```

> https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/disable-computerrestore?view=powershell-5.1  
> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-delete-shadows  
> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-list-shadows  
> https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service

# Disable Downloads Blocking

Windows adds a hidden tag called `Zone.Identifier` to files downloaded from the internet. This tag (also known as MotW) stores info about the file's origin and helps apply security warnings, see files including the tag with:
```powershell
gi * -Stream "Zone.Identifier" -ErrorAction SilentlyContinue
```

> https://www.cyberengage.org/post/unveiling-file-origins-the-role-of-alternate-data-streams-ads-zone-identifier-in-forensic-inve  
> https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8?redirectedfrom=MSDN  
> https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms537183(v=vs.85)?redirectedfrom=MSDN

```powershell
gc -Path "C:\Path\Script.ps1" -Stream Zone.Identifier
```

**ZoneID** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones`) - number indicating the security zone the file came from:
`0` – Local machine
`1` – Local intranet (internal network)
`2` – Trusted sites
`3` – Internet (mostly web downloads)
`4` – Untrusted / Restricted sites (flagged as dangerous by smartscreen)

Files downloaded from the internet still getting blocked? Unblock it/them with (one of them):
```powershell
Unblock-File -Path "C:\Path\Script.ps1" -> File

dir C:\Path\*Files* | Unblock-File -> Multiple files 
```

```powershell
{
	"File":  "AttachmentManager.admx",
	"NameSpace":  "Microsoft.Policies.AttachmentManager",
	"Class":  "User",
	"CategoryName":  "AM_AM",
	"DisplayName":  "Do not preserve zone information in file attachments",
	"ExplainText":  "This policy setting allows you to manage whether Windows marks file attachments with information about their zone of origin (such as restricted, Internet, intranet, local). This requires NTFS in order to function correctly, and will fail without notice on FAT32. By not preserving the zone information, Windows cannot make proper risk assessments.If you enable this policy setting, Windows does not mark file attachments with their zone information.If you disable this policy setting, Windows marks file attachments with their zone information.If you do not configure this policy setting, Windows marks file attachments with their zone information.",
	"Supported":  "WindowsXPSP2",
	"KeyPath":  "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments",
	"KeyName":  "SaveZoneInformation",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "2",
							"Type":  "DisabledValue"
						}
					]
},
```

![](https://github.com/nohuto/win-config/blob/main/security/images/downblocking.png?raw=true)

# Disable WPBT

WPBT allows hardware manufacturers to run programs during Windows startup that may introduce unwanted software.
```
\Registry\Machine\SYSTEM\ControlSet001\Control\Session Manager : DisableWpbtExecution
```

> https://persistence-info.github.io/Data/wpbbin.html  
> https://github.com/Jamesits/dropWPBT

# Disable Bitlocker & EFS

Disable Bitlocker on all volumes:
```powershell
$nvbvol = Get-BitLockerVolume
Disable-BitLocker -MountPoint $nvbvol
```
> https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/  
> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior  
> https://learn.microsoft.com/en-us/powershell/module/bitlocker/disable-bitlocker?view=windowsserver2025-ps

`fsutil behavior set disableencryption 1` sets:
```powershell
fsutil.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\FileSystem\NtfsDisableEncryption	Type: REG_DWORD, Length: 4, Data: 1
```
```
\Registry\Machine\SYSTEM\ControlSet001\Policies : NtfsDisableEncryption
\Registry\Machine\SYSTEM\ControlSet001\Control\FileSystem : NtfsDisableEncryption
```
```json
{
  "File": "FileSys.admx",
  "CategoryName": "NTFS",
  "PolicyName": "DisableEncryption",
  "NameSpace": "Microsoft.Policies.FileSys",
  "Supported": "Windows7",
  "DisplayName": "Do not allow encryption on all NTFS volumes",
  "ExplainText": "Encryption can add to the processing overhead of filesystem operations. Enabling this setting will prevent access to and creation of encrypted files. A reboot is required for this setting to take effect",
  "KeyPath": [
    "HKLM\\System\\CurrentControlSet\\Policies"
  ],
  "ValueName": "NtfsDisableEncryption",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```
Enabling `NtfsDisableEncryption` (`1`) may cause Xbox games to fail to install (error code `0x8007177E` - "Allow encryption on selected disk volume to install this game"):
```py
ERROR_VOLUME_NOT_SUPPORT_EFS = 0x8007177E;
```
> [Windows API - Error Defines](https://github.com/arizvisa/BugId-mWindowsAPI/blob/904a1c0bd22c019ef6ca8313945fe38f4ca26f30/mDefines/mErrorDefines.py#L1793)

# Disable VBS (HVCI)

VBS won't work if Hyper-V is disabled. HVCI = hypervisor-protected code integrity.

Hypervisor-Based Code Integrity (HVCI) and Kernel-Mode Code Integrity (KMCI) power `Device Guard`, LSA (Lsass.exe) and isolated LSA (LsaIso.exe) power `Credential Guard`.

"Virtualization-based security, or VBS, uses hardware virtualization and the Windows hypervisor to create an isolated virtual environment that becomes the root of trust of the OS that assumes the kernel can be compromised. Windows uses this isolated environment to host a number of security solutions, providing them with greatly increased protection from vulnerabilities in the operating system, and preventing the use of malicious exploits which attempt to defeat protections. VBS enforces restrictions to protect vital system and operating system resources, or to protect security assets such as authenticated user credentials.

One such example security solution is memory integrity, which protects and hardens Windows by running kernel mode code integrity within the isolated virtual environment of VBS. Kernel mode code integrity is the Windows process that checks all kernel mode drivers and binaries before they're started, and prevents unsigned or untrusted drivers or system files from being loaded into system memory. Memory integrity also restricts kernel memory allocations that could be used to compromise the system, ensuring that kernel memory pages are only made executable after passing code integrity checks inside the secure runtime environment, and executable pages themselves are never writable. That way, even if there are vulnerabilities like a buffer overflow that allow malware to attempt to modify memory, executable code pages cannot be modified, and modified memory cannot be made executable."

## VBS Requirements

| Hardware requirement | Details |
| --- | --- |
| 64-bit CPU | Virtualization-based security (VBS) requires the Windows hypervisor, which is only supported on 64-bit IA processors with virtualization extensions, including Intel VT-X and AMD-v. |
| Second Level Address Translation (SLAT) | VBS also requires that the processor's virtualization support includes Second Level Address Translation (SLAT), either Intel VT-X2 with Extended Page Tables (EPT), or AMD-v with Rapid Virtualization Indexing (RVI). |
| IOMMUs or SMMUs (Intel VT-D, AMD-Vi, Arm64 SMMUs) | All I/O devices capable of DMA must be behind an IOMMU or SMMU. An IOMMU can be used to enhance system resiliency against memory attacks. |
| Trusted Platform Module (TPM) 2.0 | For more information, see Trusted Platform Module (TPM) 2.0. |
| Firmware support for SMM protection | System firmware must adhere to the recommendations for hardening SMM code described in the Windows SMM Security Mitigations Table (WSMT) specification. The WSMT specification contains details of an ACPI table that was created for use with Windows operating systems that support VBS features. Firmware must implement the protections described in the WSMT specification, and set the corresponding protection flags as described in the specification to report compliance with these requirements to the operating system. |
| Unified Extensible Firmware Interface (UEFI)<br>Memory Reporting | UEFI firmware must adhere to the following memory map reporting format and memory allocation guidelines in order for firmware to ensure compatibility with VBS.<br><br UEFI v2.6 Memory Attributes Table (MAT) - To ensure compatibility with VBS, firmware must cleanly separate EFI runtime memory ranges for code and data, and report this to the operating system. Proper segregation and reporting of EFI runtime memory ranges allows VBS to apply the necessary page protections to EFI runtime services code pages within the VBS secure region.<br><br>Conveying this information to the OS is accomplished using the EFI_MEMORY_ATTRIBUTES_TABLE. To implement the UEFI MAT, follow these guidelines:<br><br>1. The entire EFI runtime must be described by this table.<br>2. All appropriate attributes for EfiRuntimeServicesData and EfiRuntimeServicesCode pages must be marked.<br>3. These ranges must be aligned on page boundaries (4KB), and can not overlap.<br><br> EFI Page Protections - All entries must include attributes EFI_MEMORY_RO, EFI_MEMORY_XP, or both. All UEFI memory that is marked executable must be read only. Memory marked writable must not be executable. Entries may not be left with neither of the attributes set, indicating memory that is both executable and writable. |
| Secure Memory Overwrite Request (MOR)<br>revision 2 | Secure MOR v2 is enhanced to protect the MOR lock setting using a UEFI secure variable. This helps guard against advanced memory attacks. For details, see Secure MOR implementation. |
| Memory integrity-compatible drivers | Ensure all system drivers have been tested and verified to be compatible with memory integrity. The Windows Driver Kit and Driver Verifier contain tests for driver compatibility with memory integrity. There are three steps to verify driver compatibility:<br><br>1. Use Driver Verifier with the Code Integrity compatibility checks enabled.<br>2. Run the Hypervisor Code Integrity Readiness Test in the Windows HLK.<br>3. Test the driver on a system with VBS and memory integrity enabled. This step is imperative to validate the driver's behavior with memory integrity, as static code analysis tools simply aren't capable of detecting all memory integrity violations possible at runtime. |
| Secure Boot | Secure Boot must be enabled on devices leveraging VBS. For more information, see Secure Boot |

> https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs  
> https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
> https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity?tabs=security

You can disable VBS for a VM with:
```powershell
Set-VMSecurity -VMName <VMName> -VirtualizationBasedSecurityOptOut $true
```

Details on device/credential guard:

![](https://github.com/nohuto/win-config/blob/main/security/images/vbs-guards1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/security/images/vbs-guards2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/security/images/vbs-guards3.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/security/images/vbs-guards4.png?raw=true)

```json
{
  "File": "DeviceCredential.admx",
  "CategoryName": "MSSecondaryAuthFactorCategory",
  "PolicyName": "MSSecondaryAuthFactor_AllowSecondaryAuthenticationDevice",
  "NameSpace": "Microsoft.Policies.SecondaryAuthenticationFactor",
  "Supported": "Windows_10_0",
  "DisplayName": "Allow companion device for secondary authentication",
  "ExplainText": "This policy allows users to use a companion device, such as a phone, fitness band, or IoT device, to sign on to a desktop computer running Windows 10. The companion device provides a second factor of authentication with Windows Hello. If you enable or do not configure this policy setting, users can authenticate to Windows Hello using a companion device. If you disable this policy, users cannot use a companion device to authenticate with Windows Hello.",
  "KeyPath": [
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\SecondaryAuthenticationFactor"
  ],
  "ValueName": "AllowSecondaryAuthenticationDevice",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "DeviceGuard.admx",
  "CategoryName": "DeviceGuardCategory",
  "PolicyName": "VirtualizationBasedSecurity",
  "NameSpace": "Microsoft.Windows.DeviceGuard",
  "Supported": "Windows_10_0",
  "DisplayName": "Turn On Virtualization Based Security",
  "ExplainText": "Specifies whether Virtualization Based Security is enabled. Virtualization Based Security uses the Windows Hypervisor to provide support for security services. Virtualization Based Security requires Secure Boot, and can optionally be enabled with the use of DMA Protections. DMA protections require hardware support and will only be enabled on correctly configured devices. Virtualization Based Protection of Code Integrity This setting enables virtualization based protection of Kernel Mode Code Integrity. When this is enabled, kernel mode memory protections are enforced and the Code Integrity validation path is protected by the Virtualization Based Security feature. The \"Disabled\" option turns off Virtualization Based Protection of Code Integrity remotely if it was previously turned on with the \"Enabled without lock\" option. The \"Enabled with UEFI lock\" option ensures that Virtualization Based Protection of Code Integrity cannot be disabled remotely. In order to disable the feature, you must set the Group Policy to \"Disabled\" as well as remove the security functionality from each computer, with a physically present user, in order to clear configuration persisted in UEFI. The \"Enabled without lock\" option allows Virtualization Based Protection of Code Integrity to be disabled remotely by using Group Policy. The \"Not Configured\" option leaves the policy setting undefined. Group Policy does not write the policy setting to the registry, and so it has no impact on computers or users. If there is a current setting in the registry it will not be modified. The \"Require UEFI Memory Attributes Table\" option will only enable Virtualization Based Protection of Code Integrity on devices with UEFI firmware support for the Memory Attributes Table. Devices without the UEFI Memory Attributes Table may have firmware that is incompatible with Virtualization Based Protection of Code Integrity which in some cases can lead to crashes or data loss or incompatibility with certain plug-in cards. If not setting this option the targeted devices should be tested to ensure compatibility. Warning: All drivers on the system must be compatible with this feature or the system may crash. Ensure that this policy setting is only deployed to computers which are known to be compatible. Credential Guard This setting lets users turn on Credential Guard with virtualization-based security to help protect credentials. For Windows 11 21H2 and earlier, the \"Disabled\" option turns off Credential Guard remotely if it was previously turned on with the \"Enabled without lock\" option. For later versions, the \"Disabled\" option turns off Credential Guard remotely if it was previously turned on with the \"Enabled without lock\" option or was \"Not Configured\". The \"Enabled with UEFI lock\" option ensures that Credential Guard cannot be disabled remotely. In order to disable the feature, you must set the Group Policy to \"Disabled\" as well as remove the security functionality from each computer, with a physically present user, in order to clear configuration persisted in UEFI. The \"Enabled without lock\" option allows Credential Guard to be disabled remotely by using Group Policy. The devices that use this setting must be running at least Windows 10 (Version 1511). For Windows 11 21H2 and earlier, the \"Not Configured\" option leaves the policy setting undefined. Group Policy does not write the policy setting to the registry, and so it has no impact on computers or users. If there is a current setting in the registry it will not be modified. For later versions, if there is no current setting in the registry, the \"Not Configured\" option will enable Credential Guard without UEFI lock. Machine Identity Isolation This setting controls Credential Guard protection of Active Directory machine accounts. Enabling this policy has certain prerequisites. The prerequisites and more information about this policy can be found at https://go.microsoft.com/fwlink/?linkid=2251066. The \"Not Configured\" option leaves the policy setting undefined. Group Policy does not write the policy setting to the registry, and so it has no impact on computers or users. If there is a current setting in the registry it will not be modified. The \"Disabled\" option turns off Machine Identity Isolation. If this policy was previously set to \"Enabled in audit mode\", no further action is needed. If this policy was previously set to \u201cEnabled in enforcement mode\u201d, the device must be unjoined and rejoined to the domain. More details can be found at the link above. The \"Enabled in audit mode\" option copies the machine identity into Credential Guard. Both LSA and Credential Guard will have access to the machine identity. This allows users to validate that \"Enabled in enforcement mode\" will work in their Active Directory Domain. The \"Enabled in enforcement mode\" option moves the machine identity into Credential Guard. This makes the machine identity only accessible to Credential Guard. Secure Launch This setting sets the configuration of Secure Launch to secure the boot chain. The \"Not Configured\" setting is the default, and allows configuration of the feature by Administrative users. The \"Enabled\" option turns on Secure Launch on supported hardware. The \"Disabled\" option turns off Secure Launch, regardless of hardware support. Kernel-mode Hardware-enforced Stack Protection This setting enables Hardware-enforced Stack Protection for kernel-mode code. When this security feature is enabled, kernel-mode data stacks are hardened with hardware-based shadow stacks, which store intended return address targets to ensure that program control flow is not tampered. This security feature has the following prerequisites: 1) The CPU hardware supports hardware-based shadow stacks. 2) Virtualization Based Protection of Code Integrity is enabled. If either prerequisite is not met, this feature will not be enabled, even if an \"Enabled\" option is selected for this feature. Note that selecting an \"Enabled\" option for this feature will not automatically enable Virtualization Based Protection of Code Integrity, that needs to be done separately. Devices that enable this security feature must be running at least Windows 11 (Version 22H2). The \"Disabled\" option turns off kernel-mode Hardware-enforced Stack Protection. The \"Enabled in audit mode\" option enables kernel-mode Hardware-enforced Stack Protection in audit mode, where shadow stack violations are not fatal and will be logged to the system event log. The \"Enabled in enforcement mode\" option enables kernel-mode Hardware-enforced Stack Protection in enforcement mode, where shadow stack violations are fatal. The \"Not Configured\" option leaves the policy setting undefined. Group Policy does not write the policy setting to the registry, and so it has no impact on computers or users. If there is a current setting in the registry it will not be modified. Warning: All drivers on the system must be compatible with this security feature or the system may crash in enforcement mode. Audit mode can be used to discover incompatible drivers. For more information, refer to https://go.microsoft.com/fwlink/?LinkId=2162953.",
  "KeyPath": [
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard"
  ],
  "ValueName": "EnableVirtualizationBasedSecurity",
  "Elements": [
    { "Type": "Enum", "ValueName": "RequirePlatformSecurityFeatures", "Items": [
        { "DisplayName": "Secure Boot", "Data": "1" },
        { "DisplayName": "Secure Boot and DMA Protection", "Data": "3" }
      ]
    },
    { "Type": "Enum", "ValueName": "HypervisorEnforcedCodeIntegrity", "Items": [
        { "DisplayName": "Disabled", "Data": "0" },
        { "DisplayName": "Enabled with UEFI lock", "Data": "1" },
        { "DisplayName": "Enabled without lock", "Data": "2" },
        { "DisplayName": "Not Configured", "Data": "3" }
      ]
    },
    { "Type": "Boolean", "ValueName": "HVCIMATRequired", "TrueValue": "1", "FalseValue": "0" },
    { "Type": "Enum", "ValueName": "LsaCfgFlags", "Items": [
        { "DisplayName": "Disabled", "Data": "0" },
        { "DisplayName": "Enabled with UEFI lock", "Data": "1" },
        { "DisplayName": "Enabled without lock", "Data": "2" },
        { "DisplayName": "Not Configured", "Data": "3" }
      ]
    },
    { "Type": "Enum", "ValueName": "MachineIdentityIsolation", "Items": [
        { "DisplayName": "Disabled", "Data": "0" },
        { "DisplayName": "Enabled in audit mode", "Data": "1" },
        { "DisplayName": "Enabled in enforcement mode", "Data": "2" },
        { "DisplayName": "Not Configured", "Data": "3" }
      ]
    },
    { "Type": "Enum", "ValueName": "ConfigureSystemGuardLaunch", "Items": [
        { "DisplayName": "Not Configured", "Data": "0" },
        { "DisplayName": "Enabled", "Data": "1" },
        { "DisplayName": "Disabled", "Data": "2" }
      ]
    },
    { "Type": "Enum", "ValueName": "ConfigureKernelShadowStacksLaunch", "Items": [
        { "DisplayName": "Not Configured", "Data": "0" },
        { "DisplayName": "Enabled in enforcement mode", "Data": "1" },
        { "DisplayName": "Enabled in audit mode", "Data": "2" },
        { "DisplayName": "Disabled", "Data": "3" }
      ]
    },
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```

# Disable Password Reveal

"This policy setting allows you to configure the display of the password reveal button in password entry user experiences. If you enable this policy setting, the password reveal button won't be displayed after a user types a password in the password entry text box. If you disable or don't configure this policy setting, the password reveal button will be displayed after a user types a password in the password entry text box. By default, the password reveal button is displayed after a user types a password in the password entry text box."

`Disable Picture Password Sign-In`:  
"This policy setting allows you to control whether a domain user can sign in using a picture password. If you enable this policy setting, a domain user can't set up or sign in with a picture password. If you disable or don't configure this policy setting, a domain user can set up and use a picture password. Note that the user's domain password will be cached in the system vault when using this feature."

```json
{
  "File": "CredUI.admx",
  "CategoryName": "CredUI",
  "PolicyName": "DisablePasswordReveal",
  "NameSpace": "Microsoft.Policies.CredentialsUI",
  "Supported": "Windows8_Or_IE10",
  "DisplayName": "Do not display the password reveal button",
  "ExplainText": "This policy setting allows you to configure the display of the password reveal button in password entry user experiences. If you enable this policy setting, the password reveal button will not be displayed after a user types a password in the password entry text box. If you disable or do not configure this policy setting, the password reveal button will be displayed after a user types a password in the password entry text box. By default, the password reveal button is displayed after a user types a password in the password entry text box. To display the password, click the password reveal button. The policy applies to all Windows components and applications that use the Windows system controls, including Internet Explorer.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\CredUI",
    "HKCU\\Software\\Policies\\Microsoft\\Windows\\CredUI"
  ],
  "ValueName": "DisablePasswordReveal",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "CredentialProviders.admx",
  "CategoryName": "Logon",
  "PolicyName": "BlockDomainPicturePassword",
  "NameSpace": "Microsoft.Policies.CredentialProviders",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Turn off picture password sign-in",
  "ExplainText": "This policy setting allows you to control whether a domain user can sign in using a picture password. If you enable this policy setting, a domain user can't set up or sign in with a picture password. If you disable or don't configure this policy setting, a domain user can set up and use a picture password. Note that the user's domain password will be cached in the system vault when using this feature.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\System"
  ],
  "ValueName": "BlockDomainPicturePassword",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```

# Disable P2P Updates

Default is configured to LAN. The Group Download mode combined with Group ID, enables administrators to create custom device groups that share content between devices in the group. Download mode dictates which download sources clients are allowed to use when downloading Windows updates in addition to Windows Update servers.

The option applies `0` = disables peer-to-peer (P2P) caching but still allows Delivery Optimization to download content over HTTP from the download's original source or a Microsoft Connected Cache server.

| Download mode option | Data  | Functionality when configured |
| ---- | :----: | ---- |
| HTTP Only | `0` | This setting disables peer-to-peer caching but still allows Delivery Optimization to download content over HTTP from the download's original source or a Microsoft Connected Cache server. This mode uses additional metadata provided by the Delivery Optimization cloud services for a peerless, reliable and efficient download experience. |
| LAN (Default) | `1` | This default operating mode for Delivery Optimization enables peer sharing on the same network. The Delivery Optimization cloud service finds other clients that connect to the Internet using the same public IP as the target client. These clients then try to connect to other peers on the same network by using their private subnet IP. |
| Group | `2` | When group mode is set, the group is automatically selected based on the device's Active Directory Domain Services (AD DS) site (Windows 10, version 1607) or the domain the device is authenticated to (Windows 10, version 1511). In group mode, peering occurs across internal subnets, between devices that belong to the same group, including devices in remote offices. You can use GroupID option to create your own custom group independently of domains and AD DS sites. Starting with Windows 10, version 1803, you can use the GroupIDSource parameter to take advantage of other method to create groups dynamically. Group download mode is the recommended option for most organizations looking to achieve the best bandwidth optimization with Delivery Optimization. |
| Internet | `3` | Enable Internet peer sources for Delivery Optimization. |
| Simple | `99` | Simple mode disables the use of Delivery Optimization cloud services completely (for offline environments). Delivery Optimization switches to this mode automatically when the Delivery Optimization cloud services are unavailable, unreachable, or when the content file size is less than 50 MB, as the default. In this mode, Delivery Optimization provides a reliable download experience over HTTP from the download's original source or a Microsoft Connected Cache server, with no peer-to-peer caching. |
| Bypass | `100` | Starting in Windows 11, this option is deprecated. Don't configure Download mode to '100' (Bypass), which can cause some content to fail to download. If you want to disable peer-to-peer functionality, configure DownloadMode to (0). If your device doesn't have internet access, configure Download Mode to (99). When you configure Bypass (100), the download bypasses Delivery Optimization and uses BITS instead. You don't need to configure this option if you're using Configuration Manager. |

> https://learn.microsoft.com/en-us/windows/deployment/do/waas-delivery-optimization-reference#download-mode

---

Microsoft has a cmdlet for it, but seems like they didn't work much on it yet.

> https://learn.microsoft.com/en-us/powershell/module/deliveryoptimization/set-dodownloadmode?view=windowsserver2025-ps


HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DeliveryOptimization\DODownloadMode

**WUDODownloadMode**  Retrieves whether DO is turned on and how to acquire/distribute updates Delivery Optimization (DO) allows users to deploy previously downloaded WU updates to other devices on the same network.

# Increased DH & RSA Key

By default it uses a minimum size of `1024` bits (both) - hardens Windows TLS engine by forcing minimum key sizes during secure communications (SSL/TLS handshake process).

"NSA recommends RSA key transport and ephemeral DH (DHE) or ECDH (ECDHE) mechanisms, with RSA or DHE key exchange using at least 3072-bit keys and ECDHE key exchanges using the secp384r1 elliptic curve. For RSA keytransport and DH/DHE key exchange, keys less than 2048 bits should not be used, and ECDH/ECDHE using custom curves should not be used."

> https://media.defense.gov/2021/Jan/05/2002560140/-1/-1/0/ELIMINATING_OBSOLETE_TLS_UOO197443-20.PDF  
> https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings?tabs=diffie-hellman

# Disable Legacy TLS/Crypto

Disables legacy/insecure protocols, ciphers, renegotiation, hashes, and forces .NET apps to use strong cryptography (Disables RC2 (40/56/128), RC4 (40/56/64/128), DES, 3DES, NULL, MD5/SHA-1, SSL 2.0/3.0, TLS 1.0/1.1, DTLS 1.0, insecure TLS renegotiation - Enables TLS SCSV, .NET StrongCrypto & SystemDefaultTlsVersions, NTLMv2 only). Windows may use insecure connections for e.g. older software (compatibility reasons), so disabling them can cause issues with old software.

| Setting | Description | Registry security level |
| ---- | ---- | ---- |
| Send LM & NTLM responses | Client devices use LM and NTLM authentication, and they never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication. | 0 |
| Send LM & NTLM use NTLMv2 session security if negotiated | Client devices use LM and NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication. | 1 |
| Send NTLM response only | Client devices use NTLMv1 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication. | 2 |
| Send NTLMv2 response only | Client devices use NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication. | 3 |
| Send NTLMv2 response only. Refuse LM | Client devices use NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers refuse to accept LM authentication, and they'll accept only NTLM and NTLMv2 authentication. | 4 |
| Send NTLMv2 response only. Refuse LM & NTLM | Client devices use NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers refuse to accept LM and NTLM authentication, and they'll accept only NTLMv2 authentication. | 5 |

Level `5` gets applied.

> https://browserleaks.com/tls  
> https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls#schusestrongcrypto  
> https://dirteam.com/sander/2019/07/30/howto-disable-weak-protocols-cipher-suites-and-hashing-algorithms-on-web-application-proxies-ad-fs-servers-and-windows-servers-running-azure-ad-connect/  
> https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level

![](https://github.com/nohuto/win-config/blob/main/security/images/insecureconn.png?raw=true)

DTLS 1.2 & TLS 1.3:
```json
{
  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\DTLS 1.2\\Server": {
    "Enabled": { "Type": "REG_DWORD", "Data": 1 },
    "DisabledByDefault": { "Type": "REG_DWORD", "Data": 0 }
  },
  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\DTLS 1.2\\Client": {
    "Enabled": { "Type": "REG_DWORD", "Data": 1 },
    "DisabledByDefault": { "Type": "REG_DWORD", "Data": 0 }
  },
  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.3\\Server": {
    "Enabled": { "Type": "REG_DWORD", "Data": 1 },
    "DisabledByDefault": { "Type": "REG_DWORD", "Data": 0 }
  },
  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.3\\Client": {
    "Enabled": { "Type": "REG_DWORD", "Data": 1 },
    "DisabledByDefault": { "Type": "REG_DWORD", "Data": 0 }
  },
  "HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v2.0.50727": {
    "SystemDefaultTlsVersions": { "Type": "REG_DWORD", "Data": 1 }
  },
  "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v2.0.50727": {
    "SystemDefaultTlsVersions": { "Type": "REG_DWORD", "Data": 1 }
  },
  "HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319": {
    "SystemDefaultTlsVersions": { "Type": "REG_DWORD", "Data": 1 }
  },
  "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319": {
    "SystemDefaultTlsVersions": { "Type": "REG_DWORD", "Data": 1 }
  },
  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client": {
    "AllowBasic": { "Type": "REG_DWORD", "Data": 0 }
  },
  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa": {
    "restrictanonymoussam": { "Type": "REG_DWORD", "Data": 1 }
  },
  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters": {
    "restrictnullsessaccess": { "Type": "REG_DWORD", "Data": 1 },
    "AutoShareWks": { "Type": "REG_DWORD", "Data": 0 }
  },
  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA": {
    "restrictanonymous": { "Type": "REG_DWORD", "Data": 1 }
  }
}
```

# Enhanced Domain NTLM Logs

Controls the Netlogon policy that enables or disables enhanced domain wide NTLM logs on domain controllers (includes NTLMv1 usage). Applies to domain controllers only (Windows 11 24H2+). If not configured, domain controllers default to logging these on supported builds.

> https://aka.ms/ntlmlogandblock

```json
{
  "File": "Netlogon.admx",
  "CategoryName": "Netlogon",
  "PolicyName": "Netlogon_EnhancedDomainNtlmLogs",
  "NameSpace": "Microsoft.Policies.NetLogon",
  "Supported": "Windows_11_0_24H2 - At least Windows 11 Version 24H2",
  "DisplayName": "Log Enhanced Domain-wide NTLM Logs",
  "ExplainText": "This policy setting configures whether the domain controllers to which this setting is applied will log the new, enhanced domain-wide NTLM logs. These logs contain more information about NTLM authentication on a domain-wide level, including NTLMv1 usage. If enabled, domain controllers will log the new domain-wide NTLM logs. If disabled, domain controllers will not log the new domain-wide NTLM logs. If not configured, domain controllers will default to logging the new domain-wide NTLM logs. More information is available at aka.ms/ntlmlogandblock.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Netlogon\\Parameters"
  ],
  "ValueName": "EnableEnhancedDomainNtlmLogs",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```

# Enable USB Write Protection
Restricts write access to USB devices (read only). You can also change it with `diskpart`, by selecting the disk with `select disk` and chaning it to read only with `attributes disk set readonly` (revert it with `attributes disk clear readonly`).

Rather leave USB connection error notifications enabled, unless there's a specific reason for it.

# Increase TDR

"TDR stands for Timeout Detection and Recovery. This is a feature of the Windows operating system which detects response problems from a graphics card, and recovers to a functional desktop by resetting the card. If the operating system does not receive a response from a graphics card within a certain amount of time (default is 2 seconds), the operating system resets the graphics card."

> Disabling TDR removes a valuable layer of protection, so it is generally recommended that you keep it enabled.

| Registry key       | Value name           | Default value                | Description                                                                                               |
| ------------------ | -------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------- |
| TdrLevel           | `TdrLevel`           | `3` (TdrLevelRecover)        | Controls the GPU timeout behavior. `0` = disabled, `1` = bugcheck, `2` = recover to VGA (not implemented) `3` = reset/recover (Windows default). |
| TdrDelay           | `TdrDelay`           | `2` seconds                  | Timeout threshold before Windows starts TDR handling. Longer value = GPU gets more time. |
| TdrDdiDelay        | `TdrDdiDelay`        | `5` seconds                  | Extra time for driver/user-mode threads to exit after a timeout before VIDEO_TDR_FAILURE (0x116). |
| TdrDebugMode       | `TdrDebugMode`       | `2`                          | TDR debug control: `0` break, `1` ignore, `2` recover (default), `3` always recover.                      |
| TdrLimitTime       | `TdrLimitTime`       | `60` seconds (doc) / `5` driver?                 | Time window to count repeated TDRs before forcing a crash. Works with `TdrLimitCount`.                    |
| TdrLimitCount      | `TdrLimitCount`      | `5`                          | Max number of TDRs allowed within `TdrLimitTime` before Windows stops recovering and bugchecks.           |
| TdrTestMode        | `TdrTestMode`        | -                            | Reserved/test entry, not for normal use.                                                                  |
| TdrDodPresentDelay | `TdrDodPresentDelay` | `2` seconds (min 1, max 900) | Extra time for display-only drivers to report an async present before a TDR is triggered.                 |
| TdrDodVSyncDelay   | `TdrDodVSyncDelay`   | `2` seconds (min 1, max 900) | Time the VSync watchdog waits for VSync from a display-only driver before triggering TDR.                 |

> https://github.com/nohuto/windows-driver-docs/blob/staging/windows-driver-docs-pr/display/tdr-registry-keys.md  
> https://docs.nvidia.com/gameworks/content/developertools/desktop/timeout_detection_recovery.htm

Driver code snippets:
```c
if ( v0 < 0 )
{
  v13 = 3; // TdrLevel
  v8 = 2; // TdrDelay
  v9 = 2; // TdrDodPresentDelay
  v10 = 2; // TdrDodVSyncDelay
  v11 = 5; // TdrDdiDelay
  v12 = 2; // TdrDebugMode
  WdLogSingleEntry1(3LL, v0);
  WdLogGlobalForLineNumber = 2211;
}

v67 = L"TdrLimitTime";
v66 = 288;
v68 = &v15;
v6 = v15;
v7 = 3600LL;
if (v15 <= 0xE10) { // 3600
  if (v15 < 5)
    v6 = 5; // set to 5 minimum
  else
    v6 = v15;
  dword_1C015B874 = v6;
} else {
  dword_1C015B874 = 3600; // clamp max
}

if (dword_1C015B874 != v15) {
    WdLogSingleEntry2(3LL, v15, (unsigned int)dword_1C015B874);
    WdLogGlobalForLineNumber = 2387;
}
```
> https://github.com/nohuto/win-registry/blob/main/records/Graphics-Drivers.txt  
> [security/assets | TdrInit.c](https://github.com/nohuto/win-config/blob/main/security/assets/TdrInit.c)

Notes to the values located in:
```
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\Parameters : TdrDdiDelay
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\Parameters : TdrDelay
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\Parameters : TdrLevel
```

`TdrDdiDelay` used alongside TdrDelay to determine the WDDM timeout. RM reads `TdrDdiDelay`, subtracts 1, and caps `TdrDelay` to that override. If `TdrDdiDelay` is absent, `tdrDdiOverride = 4`. `TdrDelay` shows the WDDM timeout duration (seconds). RM clamps to >= 2 and <= (TdrDdiDelay - 1), then converts to microseconds. Default when missing is `1.8` seconds. `TdrLevel` = WDDM TDR behavior (documented in CUDA WDDM code).

Note that this information is based on a 4 year old documentation and may not be accurate anymore.

# Password Age

`/MAXPWAGE:{days | UNLIMITED}`:  
"Sets the maximum number of days that a password is valid. No limit is specified by using UNLIMITED. /MAXPWAGE can't be less than /MINPWAGE. The range is 1-999; the default is 90 days."

```powershell
NET ACCOUNTS  
[/FORCELOGOFF:{minutes | NO}]  
[/MINPWLEN:length]  
[/MAXPWAGE:{days | UNLIMITED}]  
[/MINPWAGE:days]  
[/UNIQUEPW:number] [/DOMAIN]
```

Congigure the policy yourself via `Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy`:

![](https://github.com/nohuto/win-config/blob/main/security/images/passwordage.png?raw=true)

# Trusted Path Credential Prompting

This policy setting requires the user to enter Microsoft Windows credentials using a trusted path, to prevent a Trojan horse or other types of malicious code from stealing the user's Windows credentials.

```json
{
  "File": "CredUI.admx",
  "CategoryName": "CredUI",
  "PolicyName": "EnableSecureCredentialPrompting",
  "NameSpace": "Microsoft.Policies.CredentialsUI",
  "Supported": "WindowsVista",
  "DisplayName": "Require trusted path for credential entry",
  "ExplainText": "This policy setting requires the user to enter Microsoft Windows credentials using a trusted path, to prevent a Trojan horse or other types of malicious code from stealing the user\u2019s Windows credentials. Note: This policy affects nonlogon authentication tasks only. As a security best practice, this policy should be enabled. If you enable this policy setting, users will be required to enter Windows credentials on the Secure Desktop by means of the trusted path mechanism. If you disable or do not configure this policy setting, users will enter Windows credentials within the user\u2019s desktop session, potentially allowing malicious code access to the user\u2019s Windows credentials.",
  "KeyPath": [
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI"
  ],
  "ValueName": "EnableSecureCredentialPrompting",
  "Elements": []
},
```

# Enable Dynamic Lock

Automatically locks your device when you're away. It requires Bluetooth to be active. This option is disabled by default.

Toggling it via `Accounts > Sign-in options`:
```c
// Enabled
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\EnableGoodbye	Type: REG_DWORD, Length: 4, Data: 1

// Disabled (default)
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\EnableGoodbye	Type: REG_DWORD, Length: 4, Data: 0
```

---

Miscellaneous notes:

```json
{
  "File": "Passport.admx",
  "CategoryName": "MSPassportForWorkCategory",
  "PolicyName": "MSPassport_UseDynamicLock",
  "NameSpace": "Microsoft.Policies.MicrosoftPassportForWork",
  "Supported": "Windows_10_0_NOSERVER - At least Windows 10",
  "DisplayName": "Configure dynamic lock factors",
  "ExplainText": "Configure a comma separated list of signal rules in the form of xml for each signal type. If you enable this policy setting, these signal rules will be evaluated to detect user absence and automatically lock the device. If you disable or do not configure this policy setting, users can continue to lock with existing locking options. For more information see: https://go.microsoft.com/fwlink/?linkid=849684",
  "KeyPath": [
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\PassportForWork\\DynamicLock"
  ],
  "ValueName": "DynamicLock",
  "Elements": [
    { "Type": "Text", "ValueName": "Plugins" },
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```

# Sudo

[Sudo](https://github.com/microsoft/sudo) is a new way for users to run elevated commands (as an administrator) directly from an unelevated console session on Windows.

Note that sudo uses administrator previledges and doesn't include `TrustedInstaller`/`SYSTEM` previledges.

| Mode | Description |
| ---- | ---- |
| `forceNewWindow` | Runs the command elevated in a new console window. |
| `disableInput` | Runs elevated in the same window but blocks keyboard input while it runs. |
| `normal` | Runs elevated in the same window with normal input and output behavior. |

```json
{
  "File": "Sudo.admx",
  "CategoryName": "System",
  "PolicyName": "EnableSudo",
  "NameSpace": "Microsoft.Policies.DeveloperTools",
  "Supported": "Windows_11_0_NOSERVER - At least Windows 11",
  "DisplayName": "Configure the behavior of the sudo command",
  "ExplainText": "This policy setting controls use of the sudo.exe command line tool. If you enable this policy setting, then you may set a maximum allowed mode to run sudo in. This restricts the ways in which users may interact with command-line applications run with sudo. You may pick one of the following modes to allow sudo to run in: \"Disabled\": sudo is entirely disabled on this machine. When the user tries to run sudo, sudo will print an error message and exit. \"Force new window\": When sudo launches a command line application, it will launch that app in a new console window. \"Disable input\": When sudo launches a command line application, it will launch the app in the current console window, but the user will not be able to type input to the command line app. The user may also choose to run sudo in \"Force new window\" mode. \"Normal\": When sudo launches a command line application, it will launch the app in the current console window. The user may also choose to run sudo in \"Force new window\" or \"Disable input\" mode. If you disable this policy or do not configure it, the user will be able to run sudo.exe normally (after enabling the setting in the Settings app).",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\Sudo"
  ],
  "Elements": [
    { "Type": "Enum", "ValueName": "Enabled", "Items": [
        { "DisplayName": "Disabled", "Data": "0" },
        { "DisplayName": "Force new window", "Data": "1" },
        { "DisplayName": "Disable input", "Data": "2" },
        { "DisplayName": "Normal", "Data": "3" }
      ]
    }
  ]
}
```

> https://learn.microsoft.com/en-us/windows/advanced-settings/sudo/  
> https://devblogs.microsoft.com/commandline/introducing-sudo-for-windows/

# Enable Camera OSD Indicator

"`NoPhysicalCameraLED` indicates that there is no physical LED for the device's camera. An example of a physical LED for a camera is the small blue light that turns on whenever the camera is streaming video. This setting is used to indicate to the shell component that it will need to provide a small indicator in the user interface (UI) to show when video frames are streaming or not streaming to replace the notification by physical LED."

![](https://github.com/nohuto/win-config/blob/main/system/images/cameraosd.png?raw=true)

| Data | Description |
| :---: | --- |
| 0 | Does not draw an indicator in the UI to show when the camera is on or off. Instead, a physical LED exists to show when video frames are streaming or not streaming. This is the default value. |
| 1 | Draws an indicator in the UI to show when video frames are streaming or not streaming. |

> https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-coremmres-nophysicalcameraled

```
\Registry\Machine\SOFTWARE\Microsoft\OEM\Device\Capture : NoPhysicalCameraLED
```

# Administrator Account

This security setting determines whether the local Administrator account is enabled or disabled. The following conditions prevent disabling the Administrator account, even if this security setting is disabled.

- he Administrator account is currently in use
- The Administrators group has no other members
- All other members of the Administrators group are:
  - Disabled
  - Listed in the [Deny log on locally](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/deny-log-on-locally) User Rights Assignment
  
If the Administrator account is disabled, you can't enable it if the password doesn't meet requirements. In this case, another member of the Administrators group must reset the password.

## Best practices

Disabling the administrator account can become a maintenance issue under certain circumstances. For example, in a domain environment, if the secure channel that constitutes your connection fails for any reason, and there's no other local administrator account, you must restart the computer in safe mode to fix the problem that broke your connection status.

## Vulnerability

The built-in administrator account can't be locked out no matter how many failed logons it accrues, which makes it a prime target for brute-force attacks that attempt to guess passwords. Also, this account has a well-known security identifier (SID), and there are non-Microsoft tools that allow authentication by using the SID rather than the account name. Therefore, even if you rename the Administrator account, an attacker could launch a brute-force attack by using the SID to sign in. All other accounts that are members of the Administrator's group have the safeguard of locking out the account if the number of failed logons exceeds its configured maximum.

> https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-administrator-account-status

# Guest Account

Guest account status policy setting determines whether the Guest account is enabled or disabled. This account allows unauthenticated network users to gain access to the system by signing in as a Guest with no password. Unauthorized users can access any resources that are accessible to the Guest account over the network. This privilege means that any network shared folders with permissions that allow access to the Guest account, the Guests group, or the Everyone group will be accessible over the network. This accessibility can lead to the exposure or corruption of data.

## Best practices

Set Guest account status to Disabled so that the built-in Guest account is no longer usable. All network users will have to authenticate before they can access shared resources on the system. If the Guest account is disabled and Network access: Sharing and security model for local accounts is set to Guest only, network logons, such as those logons performed by the SMB Service will fail.

## Vulnerability

The default Guest account allows unauthenticated network users to sign in as a Guest with no password. These unauthorized users could access any resources that are accessible to the Guest account over the network. This capability means that any shared folders with permissions that allow access to the Guest account, the Guests group, or the Everyone group are accessible over the network, which could lead to the exposure or corruption of data.

> https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-guest-account-status

# defaultuser0 Account

defaultuser0 is a temporary Windows setup account.

---

### Miscellaneous Notes

If extracting the whole System32 folder recursively using [strings2](https://github.com/nohuto/strings2-tui) you'll see that the string `defaultuser0` only exists in `DeviceEnroller.exe` (at least for me). The notes below are based on several decompiled functions from `DeviceEnroller.exe` (`MakeActiveUserLocalAdmin`).

`defaultuser0` is only used as a "do not elevate" sentinel in the admin promotion path.

```c
// WinMainCommon
if (!HasActiveLocalAdminAccount()) {
    MakeActiveUserLocalAdmin();
}
```
```c
// MakeActiveUserLocalAdmin
DmGetActiveUserSid(&StringSid);
LookupAccountSidW(..., &name, &domain, ...);
if (_wcsicmp(name, L"defaultuser0")) {
    MakeAUserLocalAdmin(name, domain);
    DmDeleteTask(L"\\Microsoft\\Windows\\EnterpriseMgmt", 0,
                L"Login Schedule created by enrollment client");
} else {
    // defaultuser0: skip elevation
}
```

DeviceEnroller.exe = MDM/Enterprise enrollment client that runs enrollment and renewal sessions (e.g., `EnrollEngineInitialize`, `InitiateSessionAsync`, `WaitForEnrollment`) here.

