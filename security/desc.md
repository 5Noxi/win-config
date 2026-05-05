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

## [Windows Policies](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)

```json
{
  "File": "MicrosoftEdge.admx",
  "CategoryName": "MicrosoftEdge",
  "PolicyName": "AllowSmartScreen",
  "NameSpace": "Microsoft.Policies.MicrosoftEdge",
  "Supported": "INTERNET_BROWSER_WIN10 - Microsoft Edge on Windows 10 or later",
  "DisplayName": "Configure Windows Defender SmartScreen",
  "ExplainText": "This policy setting lets you configure whether to turn on Windows Defender SmartScreen. Windows Defender SmartScreen provides warning messages to help protect your employees from potential phishing scams and malicious software. By default, Windows Defender SmartScreen is turned on. If you enable this setting, Windows Defender SmartScreen is turned on and employees can't turn it off. If you disable this setting, Windows Defender SmartScreen is turned off and employees can't turn it on. If you don't configure this setting, employees can choose whether to use Windows Defender SmartScreen.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter",
    "HKCU\\Software\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter"
  ],
  "ValueName": "EnabledV9",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "SmartScreen.admx",
  "CategoryName": "Shell",
  "PolicyName": "ShellConfigureSmartScreen",
  "NameSpace": "Microsoft.Policies.SmartScreen",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Configure Windows Defender SmartScreen",
  "ExplainText": "This policy allows you to turn Windows Defender SmartScreen on or off. SmartScreen helps protect PCs by warning users before running potentially malicious programs downloaded from the Internet. This warning is presented as an interstitial dialog shown before running an app that has been downloaded from the Internet and is unrecognized or known to be malicious. No dialog is shown for apps that do not appear to be suspicious. Some information is sent to Microsoft about files and programs run on PCs with this feature enabled. If you enable this policy, SmartScreen will be turned on for all users. Its behavior can be controlled by the following options: \u2022 Warn and prevent bypass \u2022 Warn If you enable this policy with the \"Warn and prevent bypass\" option, SmartScreen's dialogs will not present the user with the option to disregard the warning and run the app. SmartScreen will continue to show the warning on subsequent attempts to run the app. If you enable this policy with the \"Warn\" option, SmartScreen's dialogs will warn the user that the app appears suspicious, but will permit the user to disregard the warning and run the app anyway. SmartScreen will not warn the user again for that app if the user tells SmartScreen to run the app. If you disable this policy, SmartScreen will be turned off for all users. Users will not be warned if they try to run suspicious apps from the Internet. If you do not configure this policy, SmartScreen will be enabled by default, but users may change their settings.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\System"
  ],
  "ValueName": "EnableSmartScreen",
  "Elements": [
    { "Type": "Enum", "ValueName": "ShellSmartScreenLevel", "Items": [
        { "DisplayName": "Warn and prevent bypass", "Data": "Block" },
        { "DisplayName": "Warn", "Data": "Warn" }
      ]
    },
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "SmartScreen.admx",
  "CategoryName": "Edge",
  "PolicyName": "EdgeConfigureSmartScreen",
  "NameSpace": "Microsoft.Policies.SmartScreen",
  "Supported": "INTERNET_BROWSER_WIN10 - Microsoft Edge on Windows 10 or later",
  "DisplayName": "Configure Windows Defender SmartScreen",
  "ExplainText": "This policy setting lets you configure whether to turn on Windows Defender SmartScreen. Windows Defender SmartScreen provides warning messages to help protect your employees from potential phishing scams and malicious software. By default, Windows Defender SmartScreen is turned on. If you enable this setting, Windows Defender SmartScreen is turned on and employees can't turn it off. If you disable this setting, Windows Defender SmartScreen is turned off and employees can't turn it on. If you don't configure this setting, employees can choose whether to use Windows Defender SmartScreen.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Edge",
    "HKCU\\Software\\Policies\\Microsoft\\Edge"
  ],
  "ValueName": "SmartScreenEnabled",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WebThreatDefense.admx",
  "CategoryName": "WebThreatDefense",
  "PolicyName": "ServiceEnabled",
  "NameSpace": "Microsoft.Policies.WebThreatDefense",
  "Supported": "Windows_11_0_22H2 - At least Windows 11 Version 22H2",
  "DisplayName": "Service Enabled",
  "ExplainText": "This policy setting determines whether Enhanced Phishing Protection in Microsoft Defender SmartScreen is in audit mode or off. Users do not see notifications for any protection scenarios when Enhanced Phishing Protection in Microsoft Defender is in audit mode. Audit mode captures unsafe password entry events and sends telemetry through Microsoft Defender. If you enable this policy setting, Enhanced Phishing Protection in Microsoft Defender SmartScreen is enabled in audit mode and your users are unable to turn it off. If you disable this policy setting, Enhanced Phishing Protection in Microsoft Defender SmartScreen is off and it will not capture events, send telemetry, or notify users. Additionally, your users are unable to turn it on. If you don\u2019t configure this setting, users can decide whether or not they will enable Enhanced Phishing Protection in Microsoft Defender SmartScreen.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WTDS\\Components"
  ],
  "ValueName": "ServiceEnabled",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WebThreatDefense.admx",
  "CategoryName": "WebThreatDefense",
  "PolicyName": "NotifyMalicious",
  "NameSpace": "Microsoft.Policies.WebThreatDefense",
  "Supported": "Windows_11_0_22H2 - At least Windows 11 Version 22H2",
  "DisplayName": "Notify Malicious",
  "ExplainText": "This policy setting determines whether Enhanced Phishing Protection in Microsoft Defender SmartScreen warns your users if they type their work or school password into one of the following malicious scenarios: into a reported phishing site, into a Microsoft login URL with an invalid certificate, or into an application connecting to either a reported phishing site or a Microsoft login URL with an invalid certificate. If you enable this policy setting, Enhanced Phishing Protection in Microsoft Defender SmartScreen warns your users if they type their work or school password into one of the malicious scenarios described above and encourages them to change their password. If you disable or don\u2019t configure this policy setting, Enhanced Phishing Protection in Microsoft Defender SmartScreen will not warn your users if they type their work or school password into one of the malicious scenarios described above.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WTDS\\Components"
  ],
  "ValueName": "NotifyMalicious",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WebThreatDefense.admx",
  "CategoryName": "WebThreatDefense",
  "PolicyName": "NotifyPasswordReuse",
  "NameSpace": "Microsoft.Policies.WebThreatDefense",
  "Supported": "Windows_11_0_22H2 - At least Windows 11 Version 22H2",
  "DisplayName": "Notify Password Reuse",
  "ExplainText": "This policy setting determines whether Enhanced Phishing Protection in Microsoft Defender SmartScreen warns your users if they reuse their work or school password. If you enable this policy setting, Enhanced Phishing Protection in Microsoft Defender SmartScreen warns users if they reuse their work or school password and encourages them to change it. If you disable or don\u2019t configure this policy setting, Enhanced Phishing Protection in Microsoft Defender SmartScreen will not warn users if they reuse their work or school password.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WTDS\\Components"
  ],
  "ValueName": "NotifyPasswordReuse",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WebThreatDefense.admx",
  "CategoryName": "WebThreatDefense",
  "PolicyName": "NotifyUnsafeApp",
  "NameSpace": "Microsoft.Policies.WebThreatDefense",
  "Supported": "Windows_11_0_22H2 - At least Windows 11 Version 22H2",
  "DisplayName": "Notify Unsafe App",
  "ExplainText": "This policy setting determines whether Enhanced Phishing Protection in Microsoft Defender SmartScreen warns your users if they type their work or school passwords in Notepad, Winword, or M365 Office apps like OneNote, Word, Excel, etc. If you enable this policy setting, Enhanced Phishing Protection in Microsoft Defender SmartScreen warns your users if they store their password in text editor apps. If you disable or don\u2019t configure this policy setting, Enhanced Phishing Protection in Microsoft Defender SmartScreen will not warn users if they store their password in text editor apps.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WTDS\\Components"
  ],
  "ValueName": "NotifyUnsafeApp",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WebThreatDefense.admx",
  "CategoryName": "WebThreatDefense",
  "PolicyName": "AutomaticDataCollection",
  "NameSpace": "Microsoft.Policies.WebThreatDefense",
  "Supported": "Windows_11_0_22H2 - At least Windows 11 Version 22H2",
  "DisplayName": "Automatic Data Collection",
  "ExplainText": "This policy setting determines whether Enhanced Phishing Protection can collect additional information-such as content displayed, sounds played, and application memory-when your users enter their work or school password into a suspicious website or app. This information is used only for security purposes and helps SmartScreen determine whether the website or app is malicious. If you enable this policy setting, Enhanced Phishing Protection may automatically collect additional content for security analysis from a suspicious website or app when your users enter their work or school password into that website or app. If you disable this policy setting, Enhanced Phishing Protection will not collect additional content for security analysis when your users enter their work or school password into a suspicious site or app. If this policy is not set, Enhanced Phishing Protection automatic data collection will honor the end user\u2019s settings.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WTDS\\Components"
  ],
  "ValueName": "CaptureThreatWindow",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "AntiSpywareDefender",
  "PolicyName": "Root_PUAProtection",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows_10_0_RS1 - At least Windows Server 2016, Windows 10 Version 1607",
  "DisplayName": "Configure detection for potentially unwanted applications",
  "ExplainText": "Enable or disable detection for potentially unwanted applications. You can choose to block, audit, or allow when potentially unwanted software is being downloaded or attempts to install itself on your computer. Enabled: Specify the mode in the Options section: -Block: Potentially unwanted software will be blocked. -Audit Mode: Potentially unwanted software will not be blocked, however if this feature would have blocked access if it were set to Block, then a record of the event will be in the event logs. Disabled: Potentially unwanted software will not be blocked. Not configured: Same as Disabled.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender"
  ],
  "Elements": [
    { "Type": "Enum", "ValueName": "PUAProtection", "Items": [
        { "DisplayName": "Disable (Default)", "Data": "0" },
        { "DisplayName": "Block", "Data": "1" },
        { "DisplayName": "Audit Mode", "Data": "2" }
      ]
    }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "RealtimeProtection",
  "PolicyName": "RealtimeProtection_DisableBehaviorMonitoring",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Turn on behavior monitoring",
  "ExplainText": "This policy setting allows you to configure behavior monitoring. If you enable or do not configure this setting, behavior monitoring will be enabled. If you disable this setting, behavior monitoring will be disabled.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
  ],
  "ValueName": "DisableBehaviorMonitoring",
  "Elements": [
    { "Type": "EnabledValue", "Data": "0" },
    { "Type": "DisabledValue", "Data": "1" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "RealtimeProtection",
  "PolicyName": "RealtimeProtection_DisableIOAVProtection",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Scan all downloaded files and attachments",
  "ExplainText": "This policy setting allows you to configure scanning for all downloaded files and attachments. If you enable or do not configure this setting, scanning for all downloaded files and attachments will be enabled. If you disable this setting, scanning for all downloaded files and attachments will be disabled.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
  ],
  "ValueName": "DisableIOAVProtection",
  "Elements": [
    { "Type": "EnabledValue", "Data": "0" },
    { "Type": "DisabledValue", "Data": "1" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "RealtimeProtection",
  "PolicyName": "RealtimeProtection_DisableOnAccessProtection",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Monitor file and program activity on your computer",
  "ExplainText": "This policy setting allows you to configure monitoring for file and program activity. If you enable or do not configure this setting, monitoring for file and program activity will be enabled. If you disable this setting, monitoring for file and program activity will be disabled.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
  ],
  "ValueName": "DisableOnAccessProtection",
  "Elements": [
    { "Type": "EnabledValue", "Data": "0" },
    { "Type": "DisabledValue", "Data": "1" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "RealtimeProtection",
  "PolicyName": "DisableRealtimeMonitoring",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "WindowsVista - At least Windows Vista",
  "DisplayName": "Turn off real-time protection",
  "ExplainText": "This policy turns off real-time protection in Microsoft Defender Antivirus. Real-time protection consists of always-on scanning with file and process behavior monitoring and heuristics. When real-time protection is on, Microsoft Defender Antivirus detects malware and potentially unwanted software that attempts to install itself or run on your device, and prompts you to take action on malware detections. If you enable this policy setting, real-time protection is turned off. If you either disable or do not configure this policy setting, real-time protection is turned on.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
  ],
  "ValueName": "DisableRealtimeMonitoring",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "RealtimeProtection",
  "PolicyName": "RealtimeProtection_DisableScanOnRealtimeEnable",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Turn on process scanning whenever real-time protection is enabled",
  "ExplainText": "This policy setting allows you to configure process scanning when real-time protection is turned on. This helps to catch malware which could start when real-time protection is turned off. If you enable or do not configure this setting, a process scan will be initiated when real-time protection is turned on. If you disable this setting, a process scan will not be initiated when real-time protection is turned on.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
  ],
  "ValueName": "DisableScanOnRealtimeEnable",
  "Elements": [
    { "Type": "EnabledValue", "Data": "0" },
    { "Type": "DisabledValue", "Data": "1" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "Reporting",
  "PolicyName": "Reporting_DisablegenericrePorts",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Configure Watson events",
  "ExplainText": "This policy setting allows you to configure whether or not Watson events are sent. If you enable or do not configure this setting, Watson events will be sent. If you disable this setting, Watson events will not be sent.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Reporting"
  ],
  "ValueName": "DisableGenericRePorts",
  "Elements": [
    { "Type": "EnabledValue", "Data": "0" },
    { "Type": "DisabledValue", "Data": "1" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "Reporting",
  "PolicyName": "Reporting_DisableEnhancedNotifications",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows_10_0 - At least Windows Server 2016, Windows 10",
  "DisplayName": "Turn off enhanced notifications",
  "ExplainText": "Use this policy setting to specify if you want Microsoft Defender Antivirus enhanced notifications to display on clients. If you disable or do not configure this setting, Microsoft Defender Antivirus enhanced notifications will display on clients. If you enable this setting, Microsoft Defender Antivirus enhanced notifications will not display on clients.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Reporting"
  ],
  "ValueName": "DisableEnhancedNotifications",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "Scan",
  "PolicyName": "Scan_DisableEmailScanning",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Turn on e-mail scanning",
  "ExplainText": "This policy setting allows you to configure e-mail scanning. When e-mail scanning is enabled, the engine will parse the mailbox and mail files, according to their specific format, in order to analyze the mail bodies and attachments. Several e-mail formats are currently supported, for example: pst (Outlook), dbx, mbx, mime (Outlook Express), binhex (Mac). Email scanning is not supported on modern email clients. If you enable this setting, e-mail scanning will be enabled. If you disable or do not configure this setting, e-mail scanning will be disabled.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan"
  ],
  "ValueName": "DisableEmailScanning",
  "Elements": [
    { "Type": "EnabledValue", "Data": "0" },
    { "Type": "DisabledValue", "Data": "1" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "ExploitGuard_NetworkProtection",
  "PolicyName": "AllowNetworkProtectionOnWinServer",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows_10_0_RS3 - At least Windows Server 2016, Windows 10 Version 1709",
  "DisplayName": "This settings controls whether Network Protection is allowed to be configured into block or audit mode on Windows Server.",
  "ExplainText": "Disabled (Default): If Not Configured or Disabled, network protection is not allowed to be configured into block or audit mode on Windows Server. Enabled: If Enabled, administrators can control whether Network Protection is allowed to be configured into block or audit mode on Windows Server. Note, that this configuration is dependent on the EnableNetworkProtection configuration. If this configuration is false, EnableNetworkProtection will be ignored, otherwise network protection will start on Windows Server depending on the value of EnableNetworkProtection.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection"
  ],
  "ValueName": "AllowNetworkProtectionOnWinServer",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "SignatureUpdate",
  "PolicyName": "SignatureUpdate_SignatureDisableNotification",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Allow notifications to disable security intelligence based reports to Microsoft MAPS",
  "ExplainText": "This policy setting allows you to configure the antimalware service to receive notifications to disable individual security intelligence in response to reports it sends to Microsoft MAPS. Microsoft MAPS uses these notifications to disable security intelligence that are causing false positive reports. You must have configured your computer to join Microsoft MAPS for this functionality to work. If you enable this setting or do not configure, the antimalware service will receive notifications to disable security intelligence. If you disable this setting, the antimalware service will not receive notifications to disable security intelligence.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Signature Updates"
  ],
  "ValueName": "SignatureDisableNotification",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "Spynet",
  "PolicyName": "DisableBlockAtFirstSeen",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows_10_0 - At least Windows Server 2016, Windows 10",
  "DisplayName": "Configure the 'Block at First Sight' feature",
  "ExplainText": "This feature ensures the device checks in real time with the Microsoft Active Protection Service (MAPS) before allowing certain content to be run or accessed. If this feature is disabled, the check will not occur, which will lower the protection state of the device. Enabled \u2013 The Block at First Sight setting is turned on. Disabled \u2013 The Block at First Sight setting is turned off. This feature requires these Group Policy settings to be set as follows: MAPS -> The \u201cJoin Microsoft MAPS\u201d must be enabled or the \u201cBlock at First Sight\u201d feature will not function. MAPS -> The \u201cSend file samples when further analysis is required\u201d should be set to 1 (Send safe samples) or 3 (Send all samples). Setting to 0 (Always Prompt) will lower the protection state of the device. Setting to 2 (Never send) means the \u201cBlock at First Sight\u201d feature will not function. Real-time Protection -> The \u201cScan all downloaded files and attachments\u201d policy must be enabled or the \u201cBlock at First Sight\u201d feature will not function. Real-time Protection -> Do not enable the \u201cTurn off real-time protection\u201d policy or the \u201cBlock at First Sight\u201d feature will not function.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet"
  ],
  "ValueName": "DisableBlockAtFirstSeen",
  "Elements": [
    { "Type": "EnabledValue", "Data": "0" },
    { "Type": "DisabledValue", "Data": "1" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "Spynet",
  "PolicyName": "Spynet_LocalSettingOverrideSpynetReporting",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Configure local setting override for reporting to Microsoft MAPS",
  "ExplainText": "This policy setting configures a local override for the configuration to join Microsoft MAPS. This setting can only be set by Group Policy. If you enable this setting, the local preference setting will take priority over Group Policy. If you disable or do not configure this setting, Group Policy will take priority over the local preference setting.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet"
  ],
  "ValueName": "LocalSettingOverrideSpynetReporting",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "Spynet",
  "PolicyName": "SpynetReporting",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "WindowsVista - At least Windows Vista",
  "DisplayName": "Join Microsoft MAPS",
  "ExplainText": "This policy setting allows you to join Microsoft MAPS. Microsoft MAPS is the online community that helps you choose how to respond to potential threats. The community also helps stop the spread of new malicious software infections. You can choose to send basic or additional information about detected software. Additional information helps Microsoft create new security intelligence and help it to protect your computer. This information can include things like location of detected items on your computer if harmful software was removed. The information will be automatically collected and sent. In some instances, personal information might unintentionally be sent to Microsoft. However, Microsoft will not use this information to identify you or contact you. Possible options are: (0x0) Disabled (default) (0x1) Basic membership (0x2) Advanced membership Basic membership will send basic information to Microsoft about software that has been detected, including where the software came from, the actions that you apply or that are applied automatically, and whether the actions were successful. Advanced membership, in addition to basic information, will send more information to Microsoft about malicious software, spyware, and potentially unwanted software, including the location of the software, file names, how the software operates, and how it has impacted your computer. If you enable this setting, you will join Microsoft MAPS with the membership specified. If you disable or do not configure this setting, you will not join Microsoft MAPS. In Windows 10, Basic membership is no longer available, so setting the value to 1 or 2 enrolls the device into Advanced membership.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet"
  ],
  "Elements": [
    { "Type": "Enum", "ValueName": "SpynetReporting", "Items": [
        { "DisplayName": "Disabled", "Data": "0" },
        { "DisplayName": "Basic MAPS", "Data": "1" },
        { "DisplayName": "Advanced MAPS", "Data": "2" }
      ]
    }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "Spynet",
  "PolicyName": "SubmitSamplesConsent",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "WindowsVista - At least Windows Vista",
  "DisplayName": "Send file samples when further analysis is required",
  "ExplainText": "This policy setting configures behaviour of samples submission when opt-in for MAPS telemetry is set. Possible options are: (0x0) Always prompt (0x1) Send safe samples automatically (0x2) Never send (0x3) Send all samples automatically",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet"
  ],
  "Elements": [
    { "Type": "Enum", "ValueName": "SubmitSamplesConsent", "Items": [
        { "DisplayName": "Always prompt", "Data": "0" },
        { "DisplayName": "Send safe samples", "Data": "1" },
        { "DisplayName": "Never send", "Data": "2" },
        { "DisplayName": "Send all samples", "Data": "3" }
      ]
    }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "MpEngine",
  "PolicyName": "MpEngine_MpCloudBlockLevel",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows_10_0 - At least Windows Server 2016, Windows 10",
  "DisplayName": "Select cloud protection level",
  "ExplainText": "This policy setting determines how aggressive Microsoft Defender Antivirus will be in blocking and scanning suspicious files. If this setting is on, Microsoft Defender Antivirus will be more aggressive when identifying suspicious files to block and scan; otherwise, it will be less aggressive and therefore block and scan with less frequency. For more information about specific values that are supported, see the Microsoft Defender Antivirus documentation site. Note: This feature requires the \"Join Microsoft MAPS\" setting enabled in order to function. Possible options are: (0x0) Default Microsoft Defender Antivirus blocking level (0x1) Moderate Microsoft Defender Antivirus blocking level, delivers verdict only for high confidence detections (0x2) High blocking level - aggressively block unknowns while optimizing client performance (greater chance of false positives) (0x4) High+ blocking level \u2013 aggressively block unknowns and apply additional protection measures (may impact client performance) (0x6) Zero tolerance blocking level \u2013 block all unknown executables",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\MpEngine"
  ],
  "Elements": [
    { "Type": "Enum", "ValueName": "MpCloudBlockLevel", "Items": [
        { "DisplayName": "Default blocking level", "Data": "0" },
        { "DisplayName": "Moderate blocking level", "Data": "1" },
        { "DisplayName": "High blocking level", "Data": "2" },
        { "DisplayName": "High+ blocking level", "Data": "4" },
        { "DisplayName": "Zero tolerance blocking level", "Data": "6" }
      ]
    }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "MpEngine",
  "PolicyName": "MpEngine_MpBafsExtendedTimeout",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows_10_0 - At least Windows Server 2016, Windows 10",
  "DisplayName": "Configure extended cloud check",
  "ExplainText": "This feature allows Microsoft Defender Antivirus to block a suspicious file for up to 60 seconds, and scan it in the cloud to make sure it's safe. The typical cloud check timeout is 10 seconds. To enable the extended cloud check feature, specify the extended time in seconds, up to an additional 50 seconds. For example, if the desired timeout is 60 seconds, specify 50 seconds in this setting, which will enable the extended cloud check feature, and will raise the total time to 60 seconds. Note: This feature depends on three other MAPS settings - \"Configure the 'Block at First Sight' feature; \"Join Microsoft MAPS\"; \"Send file samples when further analysis is required\" all need to be enabled.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\MpEngine"
  ],
  "Elements": [
    { "Type": "Decimal", "ValueName": "MpBafsExtendedTimeout", "MinValue": "0", "MaxValue": "50" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "ExploitGuard_NetworkProtection",
  "PolicyName": "ExploitGuard_EnableNetworkProtection",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows_10_0_RS3 - At least Windows Server 2016, Windows 10 Version 1709",
  "DisplayName": "Prevent users and apps from accessing dangerous websites",
  "ExplainText": "Enable or disable Microsoft Defender Exploit Guard network protection to prevent employees from using any application to access dangerous domains that may host phishing scams, exploit-hosting sites, and other malicious content on the Internet. Enabled: Specify the mode in the Options section: -Block: Users and applications will not be able to access dangerous domains -Audit Mode: Users and applications can connect to dangerous domains, however if this feature would have blocked access if it were set to Block, then a record of the event will be in the event logs. Disabled: Users and applications will not be blocked from connecting to dangerous domains. Not configured: Same as Disabled.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection"
  ],
  "Elements": [
    { "Type": "Enum", "ValueName": "EnableNetworkProtection", "Items": [
        { "DisplayName": "Disable (Default)", "Data": "0" },
        { "DisplayName": "Block", "Data": "1" },
        { "DisplayName": "Audit Mode", "Data": "2" }
      ]
    }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "ExploitGuard_ControlledFolderAccess",
  "PolicyName": "ExploitGuard_ControlledFolderAccess_EnableControlledFolderAccess",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows_10_0_RS3 - At least Windows Server 2016, Windows 10 Version 1709",
  "DisplayName": "Configure Controlled folder access",
  "ExplainText": "Enable or disable controlled folder access for untrusted applications. You can choose to block, audit, or allow attempts by untrusted apps to: - Modify or delete files in protected folders, such as the Documents folder - Write to disk sectors You can also choose to only block or audit writes to disk sectors while still allowing the modification or deletion of files in protected folders. Microsoft Defender Antivirus automatically determines which applications can be trusted. You can add additional trusted applications in the Configure allowed applications GP setting. Default system folders are automatically protected, but you can add folders in the Configure protected folders GP setting. Block: The following will be blocked: - Attempts by untrusted apps to modify or delete files in protected folders - Attempts by untrusted apps to write to disk sectors The Windows event log will record these blocks under Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational > ID 1123. Disabled: The following will not be blocked and will be allowed to run: - Attempts by untrusted apps to modify or delete files in protected folders - Attempts by untrusted apps to write to disk sectors These attempts will not be recorded in the Windows event log. Audit Mode: The following will not be blocked and will be allowed to run: - Attempts by untrusted apps to modify or delete files in protected folders - Attempts by untrusted apps to write to disk sectors The Windows event log will record these attempts under Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational > ID 1124. Block disk modification only: The following will be blocked: - Attempts by untrusted apps to write to disk sectors The Windows event log will record these attempts under Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational > ID 1123. The following will not be blocked and will be allowed to run: - Attempts by untrusted apps to modify or delete files in protected folders These attempts will not be recorded in the Windows event log. Audit disk modification only: The following will not be blocked and will be allowed to run: - Attempts by untrusted apps to write to disk sectors - Attempts by untrusted apps to modify or delete files in protected folders Only attempts to write to protected disk sectors will be recorded in the Windows event log (under Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational > ID 1124). Attempts to modify or delete files in protected folders will not be recorded. Not configured: Same as Disabled.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access"
  ],
  "Elements": [
    { "Type": "Enum", "ValueName": "EnableControlledFolderAccess", "Items": [
        { "DisplayName": "Disable (Default)", "Data": "0" },
        { "DisplayName": "Block", "Data": "1" },
        { "DisplayName": "Audit Mode", "Data": "2" },
        { "DisplayName": "Block disk modification only", "Data": "3" },
        { "DisplayName": "Audit disk modification only", "Data": "4" }
      ]
    }
  ]
},
{
  "File": "WindowsDefenderSecurityCenter.admx",
  "CategoryName": "Notifications",
  "PolicyName": "Notifications_DisableNotifications",
  "NameSpace": "Microsoft.Policies.WindowsDefenderSecurityCenter",
  "Supported": "Windows_10_0_RS3 - At least Windows Server 2016, Windows 10 Version 1709",
  "DisplayName": "Hide all notifications",
  "ExplainText": "Hide notifications from Windows Security. Enabled: Local users will not see notifications from Windows Security. Disabled: Local users can see notifications from Windows Security. Not configured: Same as Disabled.",
  "KeyPath": [
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications"
  ],
  "ValueName": "DisableNotifications",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsDefenderSecurityCenter.admx",
  "CategoryName": "Notifications",
  "PolicyName": "Notifications_DisableEnhancedNotifications",
  "NameSpace": "Microsoft.Policies.WindowsDefenderSecurityCenter",
  "Supported": "Windows_10_0_RS3 - At least Windows Server 2016, Windows 10 Version 1709",
  "DisplayName": "Hide non-critical notifications",
  "ExplainText": "Only show critical notifications from Windows Security. If the Suppress all notifications GP setting has been enabled, this setting will have no effect. Enabled: Local users will only see critical notifications from Windows Security. They will not see other types of notifications, such as regular PC or device health information. Disabled: Local users will see all types of notifications from Windows Security. Not configured: Same as Disabled.",
  "KeyPath": [
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications"
  ],
  "ValueName": "DisableEnhancedNotifications",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsExplorer.admx",
  "CategoryName": "WindowsExplorer",
  "PolicyName": "EnableSmartScreen",
  "NameSpace": "Microsoft.Policies.WindowsExplorer",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Configure Windows Defender SmartScreen",
  "ExplainText": "This policy allows you to turn Windows Defender SmartScreen on or off. SmartScreen helps protect PCs by warning users before running potentially malicious programs downloaded from the Internet. This warning is presented as an interstitial dialog shown before running an app that has been downloaded from the Internet and is unrecognized or known to be malicious. No dialog is shown for apps that do not appear to be suspicious. Some information is sent to Microsoft about files and programs run on PCs with this feature enabled. If you enable this policy, SmartScreen will be turned on for all users. Its behavior can be controlled by the following options: \u2022 Warn and prevent bypass \u2022 Warn If you enable this policy with the \"Warn and prevent bypass\" option, SmartScreen's dialogs will not present the user with the option to disregard the warning and run the app. SmartScreen will continue to show the warning on subsequent attempts to run the app. If you enable this policy with the \"Warn\" option, SmartScreen's dialogs will warn the user that the app appears suspicious, but will permit the user to disregard the warning and run the app anyway. SmartScreen will not warn the user again for that app if the user tells SmartScreen to run the app. If you disable this policy, SmartScreen will be turned off for all users. Users will not be warned if they try to run suspicious apps from the Internet. If you do not configure this policy, SmartScreen will be enabled by default, but users may change their settings.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\System"
  ],
  "ValueName": "EnableSmartScreen",
  "Elements": [
    { "Type": "Enum", "ValueName": "ShellSmartScreenLevel", "Items": [
        { "DisplayName": "Warn and prevent bypass", "Data": "Block" },
        { "DisplayName": "Warn", "Data": "Warn" }
      ]
    },
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
}
```

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

## Windows Security Captures

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

## Suboptions

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

## [Windows Policies](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)

```json
{
  "File": "DeviceSetup.admx",
  "CategoryName": "DeviceInstall_Category",
  "PolicyName": "DriverSearchPlaces_SearchOrderConfiguration",
  "NameSpace": "Microsoft.Policies.DeviceSoftwareSetup",
  "Supported": "Windows7 - At least Windows Server 2008 R2 or Windows 7",
  "DisplayName": "Specify search order for device driver source locations",
  "ExplainText": "This policy setting allows you to specify the order in which Windows searches source locations for device drivers. If you enable this policy setting, you can select whether Windows searches for drivers on Windows Update unconditionally, only if necessary, or not at all. Note that searching always implies that Windows will attempt to search Windows Update exactly one time. With this setting, Windows will not continually search for updates. This setting is used to ensure that the best software will be found for the device, even if the network is temporarily available. If the setting for searching only if needed is specified, then Windows will search for a driver only if a driver is not locally available on the system. If you disable or do not configure this policy setting, members of the Administrators group can determine the priority order in which Windows searches source locations for device drivers.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\DriverSearching"
  ],
  "Elements": [
    { "Type": "Enum", "ValueName": "SearchOrderConfig", "Items": [
        { "DisplayName": "Always search Windows Update", "Data": "1" },
        { "DisplayName": "Search Windows Update only if needed", "Data": "2" },
        { "DisplayName": "Do not search Windows Update", "Data": "0" }
      ]
    }
  ]
},
{
  "File": "DeviceSetup.admx",
  "CategoryName": "DeviceInstall_Category",
  "PolicyName": "DeviceMetadata_PreventDeviceMetadataFromNetwork",
  "NameSpace": "Microsoft.Policies.DeviceSoftwareSetup",
  "Supported": "Windows7 - At least Windows Server 2008 R2 or Windows 7",
  "DisplayName": "Prevent automatic download of applications associated with device metadata",
  "ExplainText": "This policy setting allows you to prevent Windows from downloading applications associated with device metadata. If you enable this policy setting, Windows does not download applications associated with device metadata for installed devices. This policy setting overrides the setting in the Device Installation Settings dialog box (Control Panel > System and Security > System > Advanced System Settings > Hardware tab). If you disable or do not configure this policy setting, the setting in the Device Installation Settings dialog box controls whether Windows downloads applications associated with device metadata.",
  "KeyPath": [
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata"
  ],
  "ValueName": "PreventDeviceMetadataFromNetwork",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "ICM.admx",
  "CategoryName": "InternetManagement_Settings",
  "PolicyName": "CertMgr_DisableAutoRootUpdates",
  "NameSpace": "Microsoft.Policies.InternetCommunicationManagement",
  "Supported": "WindowsXPSP2_Or_WindowsNETSP1 - At least Windows Server 2003 operating systems with SP1 or Windows XP Professional with SP2",
  "DisplayName": "Turn off Automatic Root Certificates Update",
  "ExplainText": "This policy setting specifies whether to automatically update root certificates using the Windows Update website. Typically, a certificate is used when you use a secure website or when you send and receive secure email. Anyone can issue certificates, but to have transactions that are as secure as possible, certificates must be issued by a trusted certificate authority (CA). Microsoft has included a list in Windows XP and other products of companies and organizations that it considers trusted authorities. If you enable this policy setting, when you are presented with a certificate issued by an untrusted root authority, your computer will not contact the Windows Update website to see if Microsoft has added the CA to its list of trusted authorities. If you disable or do not configure this policy setting, your computer will contact the Windows Update website.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\SystemCertificates\\AuthRoot"
  ],
  "ValueName": "DisableRootAutoUpdate",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "ICM.admx",
  "CategoryName": "InternetManagement_Settings",
  "PolicyName": "DriverSearchPlaces_DontSearchWindowsUpdate",
  "NameSpace": "Microsoft.Policies.InternetCommunicationManagement",
  "Supported": "WindowsVistaToXPSP2 - Windows Server 2008, Windows Server 2003, Windows Vista, and Windows XP SP2",
  "DisplayName": "Turn off Windows Update device driver searching",
  "ExplainText": "This policy setting specifies whether Windows searches Windows Update for device drivers when no local drivers for a device are present. If you enable this policy setting, Windows Update is not searched when a new device is installed. If you disable this policy setting, Windows Update is always searched for drivers when no local drivers are present. If you do not configure this policy setting, searching Windows Update is optional when installing a device. Also see \"Turn off Windows Update device driver search prompt\" in \"Administrative Templates/System,\" which governs whether an administrator is prompted before searching Windows Update for device drivers if a driver is not found locally. Note: This policy setting is replaced by \"Specify Driver Source Search Order\" in \"Administrative Templates/System/Device Installation\" on newer versions of Windows.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\DriverSearching"
  ],
  "ValueName": "DontSearchWindowsUpdate",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "ICM.admx",
  "CategoryName": "InternetManagement_Settings",
  "PolicyName": "RemoveWindowsUpdate_ICM",
  "NameSpace": "Microsoft.Policies.InternetCommunicationManagement",
  "Supported": "WindowsUpdate - At least Windows Server 2003 operating systems, Windows XP Professional Service Pack 1, or Windows 2000 Service Pack 3",
  "DisplayName": "Turn off access to all Windows Update features",
  "ExplainText": "This policy setting allows you to remove access to Windows Update. If you enable this policy setting, all Windows Update features are removed. This includes blocking access to the Windows Update website at http://windowsupdate.microsoft.com, from the Windows Update hyperlink on the Start menu, and also on the Tools menu in Internet Explorer. Windows automatic updating is also disabled; you will neither be notified about nor will you receive critical updates from Windows Update. This policy setting also prevents Device Manager from automatically installing driver updates from the Windows Update website. If you disable or do not configure this policy setting, users can access the Windows Update website and enable automatic updating to receive notifications and critical updates from Windows Update. Note: This policy applies only when this PC is configured to connect to an intranet update service using the \"Specify intranet Microsoft update service location\" policy.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  ],
  "ValueName": "DisableWindowsUpdateAccess",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "SignatureUpdate",
  "PolicyName": "SignatureUpdate_DefinitionUpdateFileSharesSources",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Define file shares for downloading security intelligence updates",
  "ExplainText": "This policy setting allows you to configure UNC file share sources for downloading security intelligence updates. Sources will be contacted in the order specified. The value of this setting should be entered as a pipe-separated string enumerating the security intelligence update sources. For example: \"{\\\\unc1 | \\\\unc2 }\". The list is empty by default. If you enable this setting, the specified sources will be contacted for security intelligence updates. Once security intelligence updates have been successfully downloaded from one specified source, the remaining sources in the list will not be contacted. If you disable or do not configure this setting, the list will remain empty by default and no sources will be contacted.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Signature Updates"
  ],
  "Elements": [
    { "Type": "Text", "ValueName": "DefinitionUpdateFileSharesSources" }
  ]
},
{
  "File": "WindowsDefender.admx",
  "CategoryName": "SignatureUpdate",
  "PolicyName": "SignatureUpdate_FallbackOrder",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Define the order of sources for downloading security intelligence updates",
  "ExplainText": "This policy setting allows you to define the order in which different security intelligence update sources should be contacted. The value of this setting should be entered as a pipe-separated string enumerating the security intelligence update sources in order. Possible values are: \u201cInternalDefinitionUpdateServer\u201d, \u201cMicrosoftUpdateServer\u201d, \u201cMMPC\u201d, and \u201cFileShares\u201d For example: { InternalDefinitionUpdateServer | MicrosoftUpdateServer | MMPC } If you enable this setting, security intelligence update sources will be contacted in the order specified. Once security intelligence updates have been successfully downloaded from one specified source, the remaining sources in the list will not be contacted. If you disable or do not configure this setting, security intelligence update sources will be contacted in a default order.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Signature Updates"
  ],
  "Elements": [
    { "Type": "Text", "ValueName": "FallbackOrder" }
  ]
},
{
  "File": "WindowsStore.admx",
  "CategoryName": "WindowsStore",
  "PolicyName": "DisableAutoInstall",
  "NameSpace": "Microsoft.Policies.WindowsStore",
  "Supported": "Windows_6_3 - At least Windows Server 2012 R2, Windows 8.1 or Windows RT 8.1",
  "DisplayName": "Turn off Automatic Download and Install of updates",
  "ExplainText": "Enables or disables the automatic download and installation of app updates. If you enable this setting, the automatic download and installation of app updates is turned off. If you disable this setting, the automatic download and installation of app updates is turned on. If you don't configure this setting, the automatic download and installation of app updates is determined by a registry setting that the user can change using Settings in the Microsoft Store.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\WindowsStore"
  ],
  "ValueName": "AutoDownload",
  "Elements": [
    { "Type": "EnabledValue", "Data": "2" },
    { "Type": "DisabledValue", "Data": "4" }
  ]
},
{
  "File": "WindowsStore.admx",
  "CategoryName": "WindowsStore",
  "PolicyName": "DisableAutoDownloadWin8",
  "NameSpace": "Microsoft.Policies.WindowsStore",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Turn off Automatic Download of updates on Win8 machines",
  "ExplainText": "Enables or disables the automatic download of app updates on PCs running Windows 8. If you enable this setting, the automatic download of app updates is turned off. If you disable this setting, the automatic download of app updates is turned on. If you don't configure this setting, the automatic download of app updates is determined by a registry setting that the user can change using Settings in the Microsoft Store.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\WindowsStore"
  ],
  "ValueName": "AutoDownload",
  "Elements": [
    { "Type": "EnabledValue", "Data": "2" },
    { "Type": "DisabledValue", "Data": "3" }
  ]
},
{
  "File": "WindowsUpdate.admx",
  "CategoryName": "WindowsUpdateExperience",
  "PolicyName": "AutoUpdateCfg",
  "NameSpace": "Microsoft.Policies.WindowsUpdate",
  "Supported": "WU_SUPPORTED_XPSP1_or_Win2kSP3_AUOption7_SUPPORTED_Server2016 - Windows XP Professional Service Pack 1 or At least Windows 2000 Service Pack 3 Option 7 only supported on servers of at least Windows Server 2016 edition\u200b",
  "DisplayName": "Configure Automatic Updates",
  "ExplainText": "Specifies whether this computer will receive security updates and other important downloads through the Windows automatic updating service. Note: This policy does not apply to Windows RT. This setting lets you specify whether automatic updates are enabled on this computer. If the service is enabled, you must select one of the four options in the Group Policy Setting: 2 = Notify before downloading and installing any updates. When Windows finds updates that apply to this computer, users will be notified that updates are ready to be downloaded. After going to Windows Update, users can download and install any available updates. 3 = (Default setting) Download the updates automatically and notify when they are ready to be installed Windows finds updates that apply to the computer and downloads them in the background (the user is not notified or interrupted during this process). When the downloads are complete, users will be notified that they are ready to install. After going to Windows Update, users can install them. 4 = Automatically download updates and install them on the schedule specified below. When \"Automatic\" is selected as the scheduled install time, Windows will automatically check, download, and install updates. The device will reboot as per Windows default settings unless configured by group policy. (Applies to Windows 10, version 1809 and higher) Specify the schedule using the options in the Group Policy Setting. For version 1709 and above, there is an additional choice of limiting updating to a weekly, bi-weekly, or monthly occurrence. If no schedule is specified, the default schedule for all installations will be every day at 3:00 AM. If any updates require a restart to complete the installation, Windows will restart the computer automatically. (If a user is signed in to the computer when Windows is ready to restart, the user will be notified and given the option to delay the restart.) On Windows 8 and later, you can set updates to install during automatic maintenance instead of a specific schedule. Automatic maintenance will install updates when the computer is not in use and avoid doing so when the computer is running on battery power. If automatic maintenance is unable to install updates for 2 days, Windows Update will install updates right away. Users will then be notified about an upcoming restart, and that restart will only take place if there is no potential for accidental data loss. 5 = Allow local administrators to select the configuration mode that Automatic Updates should notify and install updates. (This option has not been carried over to any Win 10 Versions) With this option, local administrators will be allowed to use the Windows Update control panel to select a configuration option of their choice. Local administrators will not be allowed to disable the configuration for Automatic Updates. 7 = Notify for install and notify for restart. (Windows Server only) With this option from Windows Server 2016, applicable only to Server SKU devices, local administrators will be allowed to use Windows Update to proceed with installations or reboots manually. If the status for this policy is set to Disabled, any updates that are available on Windows Update must be downloaded and installed manually. To do this, search for Windows Update using Start. If the status is set to Not Configured, use of Automatic Updates is not specified at the Group Policy level. However, an administrator can still configure Automatic Updates through Control Panel.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
  ],
  "ValueName": "NoAutoUpdate",
  "Elements": [
    { "Type": "Enum", "ValueName": "AUOptions", "Items": [
        { "DisplayName": "2 - Notify for download and auto install", "Data": "2" },
        { "DisplayName": "3 - Auto download and notify for install", "Data": "3" },
        { "DisplayName": "4 - Auto download and schedule the install", "Data": "4" },
        { "DisplayName": "5 - Allow local admin to choose setting", "Data": "5" },
        { "DisplayName": "7 - Auto Download, Notify to install, Notify to Restart", "Data": "7" }
      ]
    },
    { "Type": "Boolean", "ValueName": "AutomaticMaintenanceEnabled", "TrueValue": "1", "FalseValue": "0" },
    { "Type": "Enum", "ValueName": "ScheduledInstallDay", "Items": [
        { "DisplayName": "0 - Every day", "Data": "0" },
        { "DisplayName": "1 - Every Sunday", "Data": "1" },
        { "DisplayName": "2 - Every Monday", "Data": "2" },
        { "DisplayName": "3 - Every Tuesday", "Data": "3" },
        { "DisplayName": "4 - Every Wednesday", "Data": "4" },
        { "DisplayName": "5 - Every Thursday", "Data": "5" },
        { "DisplayName": "6 - Every Friday", "Data": "6" },
        { "DisplayName": "7 - Every Saturday", "Data": "7" }
      ]
    },
    { "Type": "Enum", "ValueName": "ScheduledInstallTime", "Items": [
        { "DisplayName": "Automatic", "Data": "24" },
        { "DisplayName": "00:00", "Data": "0" },
        { "DisplayName": "01:00", "Data": "1" },
        { "DisplayName": "02:00", "Data": "2" },
        { "DisplayName": "03:00", "Data": "3" },
        { "DisplayName": "04:00", "Data": "4" },
        { "DisplayName": "05:00", "Data": "5" },
        { "DisplayName": "06:00", "Data": "6" },
        { "DisplayName": "07:00", "Data": "7" },
        { "DisplayName": "08:00", "Data": "8" },
        { "DisplayName": "09:00", "Data": "9" },
        { "DisplayName": "10:00", "Data": "10" },
        { "DisplayName": "11:00", "Data": "11" },
        { "DisplayName": "12:00", "Data": "12" },
        { "DisplayName": "13:00", "Data": "13" },
        { "DisplayName": "14:00", "Data": "14" },
        { "DisplayName": "15:00", "Data": "15" },
        { "DisplayName": "16:00", "Data": "16" },
        { "DisplayName": "17:00", "Data": "17" },
        { "DisplayName": "18:00", "Data": "18" },
        { "DisplayName": "19:00", "Data": "19" },
        { "DisplayName": "20:00", "Data": "20" },
        { "DisplayName": "21:00", "Data": "21" },
        { "DisplayName": "22:00", "Data": "22" },
        { "DisplayName": "23:00", "Data": "23" }
      ]
    },
    { "Type": "Boolean", "ValueName": "AllowMUUpdateService", "TrueValue": "1", "FalseValue": "0" },
    { "Type": "Boolean", "ValueName": "ScheduledInstallEveryWeek", "TrueValue": "1", "FalseValue": "0" },
    { "Type": "Boolean", "ValueName": "ScheduledInstallFirstWeek", "TrueValue": "1", "FalseValue": "0" },
    { "Type": "Boolean", "ValueName": "ScheduledInstallSecondWeek", "TrueValue": "1", "FalseValue": "0" },
    { "Type": "Boolean", "ValueName": "ScheduledInstallThirdWeek", "TrueValue": "1", "FalseValue": "0" },
    { "Type": "Boolean", "ValueName": "ScheduledInstallFourthWeek", "TrueValue": "1", "FalseValue": "0" },
    { "Type": "EnabledValue", "Data": "0" },
    { "Type": "DisabledValue", "Data": "1" }
  ]
},
{
  "File": "WindowsUpdate.admx",
  "CategoryName": "WSUSOffering",
  "PolicyName": "CorpWuURL",
  "NameSpace": "Microsoft.Policies.WindowsUpdate",
  "Supported": "WU_SUPPORTED_Win2kSP3_Or_XPSP1_NoWinRT - At least Windows XP Professional Service Pack 1 or Windows 2000 Service Pack 3, excluding Windows RT",
  "DisplayName": "Specify intranet Microsoft update service location",
  "ExplainText": "Specifies an intranet server to host updates from Microsoft Update. You can then use this update service to automatically update computers on your network. This setting lets you specify a server on your network to function as an internal update service. The Automatic Updates client will search this service for updates that apply to the computers on your network. To use this setting, you must set two server name values: the server from which the Automatic Updates client detects and downloads updates, and the server to which updated workstations upload statistics. You can set both values to be the same server. An optional server name value can be specified to configure Windows Update Agent to download updates from an alternate download server instead of the intranet update service. If the status is set to Enabled, the Automatic Updates client connects to the specified intranet Microsoft update service (or alternate download server), instead of Windows Update, to search for and download updates. Enabling this setting means that end users in your organization don't have to go through a firewall to get updates, and it gives you the opportunity to test updates before deploying them. If the status is set to Disabled or Not Configured, and if Automatic Updates is not disabled by policy or user preference, the Automatic Updates client connects directly to the Windows Update site on the Internet. The alternate download server configures the Windows Update Agent to download files from an alternative download server instead of the intranet update service. The option to download files with missing Urls allows content to be downloaded from the Alternate Download Server when there are no download Urls for files in the update metadata. This option should only be used when the intranet update service does not provide download Urls in the update metadata for files which are present on the alternate download server. Note: If the \"Configure Automatic Updates\" policy is disabled, then this policy has no effect. Note: If the \"Alternate Download Server\" is not set, it will use the intranet update service by default to download updates. Note: The option to \"Download files with no Url...\" is only used if the \"Alternate Download Server\" is set. Note: This policy is not supported on Windows RT. Setting this policy will not have any effect on Windows RT PCs. To ensure the highest level of security, Microsoft recommends securing WSUS with TLS/SSL protocol, thereby using HTTPS based intranet servers to keep systems secure. If a proxy is required, we recommend configuring system proxy. To ensure highest levels of security, additionally leverage WSUS TLS certificate pinning on all devices. In order to keep clients inherently secure, we are no longer allowing intranet servers to leverage user proxy by default for detecting updates. If you need to leverage user proxy for detecting updates while using an intranet server despite the vulnerabilities it presents, you must configure the proxy behavior to \"Allow user proxy to be used as a fallback if detection using system proxy fails\". Detection for updates against intranet servers will fail when user proxy is needed as a fallback and the alternate proxy behavior is not configured.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  ],
  "Elements": [
    { "Type": "Text", "ValueName": "WUServer" },
    { "Type": "Text", "ValueName": "WUStatusServer" },
    { "Type": "Text", "ValueName": "UpdateServiceUrlAlternate" },
    { "Type": "Boolean", "ValueName": "FillEmptyContentUrls", "TrueValue": "1", "FalseValue": "0" },
    { "Type": "Boolean", "ValueName": "DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection", "TrueValue": "1", "FalseValue": "0" },
    { "Type": "Enum", "ValueName": "SetProxyBehaviorForUpdateDetection", "Items": [
        { "DisplayName": "Only use system proxy for detecting updates (default)", "Data": "0" },
        { "DisplayName": "Allow user proxy to be used as a fallback if detection using system proxy fails", "Data": "1" }
      ]
    }
  ]
},
{
  "File": "WindowsUpdate.admx",
  "CategoryName": "WSUSOffering",
  "PolicyName": "DoNotConnectToWindowsUpdateInternetLocations",
  "NameSpace": "Microsoft.Policies.WindowsUpdate",
  "Supported": "Windows_6_3 - At least Windows Server 2012 R2, Windows 8.1 or Windows RT 8.1",
  "DisplayName": "Do not connect to any Windows Update Internet locations",
  "ExplainText": "Even when Windows Update is configured to receive updates from an intranet update service, it will periodically retrieve information from the public Windows Update service to enable future connections to Windows Update, and other services like Microsoft Update or the Windows Store. Enabling this policy will disable that functionality, and may cause connection to public services such as the Windows Store to stop working. Note: This policy applies only when this PC is configured to connect to an intranet update service using the \"Specify intranet Microsoft update service location\" policy.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  ],
  "ValueName": "DoNotConnectToWindowsUpdateInternetLocations",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsUpdate.admx",
  "CategoryName": "WindowsUpdateOffering",
  "PolicyName": "TargetReleaseVersion",
  "NameSpace": "Microsoft.Policies.WindowsUpdate",
  "Supported": "Windows_10_0_NOARM - At least Windows Server 2016 or Windows 10",
  "DisplayName": "Select the target Feature Update version",
  "ExplainText": "Enter the product and version as listed on the Windows Update target version page: aka.ms/WindowsTargetVersioninfo The device will request that Windows Update product and version in subsequent scans. Entering a target product and clicking OK or Apply means I accept the Microsoft Software License Terms for it found at aka.ms/WindowsTargetVersioninfo. If an organization is licensing the software, I am authorized to bind the organization. If you enter an invalid value, you will remain on your current version until you correct the values to a supported product and version.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  ],
  "ValueName": "TargetReleaseVersion",
  "Elements": [
    { "Type": "Text", "ValueName": "ProductVersion" },
    { "Type": "Text", "ValueName": "TargetReleaseVersionInfo" },
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsUpdate.admx",
  "CategoryName": "WindowsUpdateOffering",
  "PolicyName": "ManagePreviewBuilds",
  "NameSpace": "Microsoft.Policies.WindowsUpdate",
  "Supported": "Windows_10_0_RS3 - At least Windows Server 2016, Windows 10 Version 1709",
  "DisplayName": "Manage preview builds",
  "ExplainText": "Enable this policy to manage which updates you receive prior to the update being released to the world. Dev Channel Ideal for highly technical users. Insiders in the Dev Channel will receive builds from our active development branch that is earliest in a development cycle. These builds are not matched to a specific Windows 10 release. Beta Channel Ideal for feature explorers who want to see upcoming Windows 10 features. Your feedback will be especially important here as it will help our engineers ensure key issues are fixed before a major release. Release Preview Channel (default) Insiders in the Release Preview Channel will have access to the upcoming release of Windows 10 prior to it being released to the world. These builds are supported by Microsoft. The Release Preview Channel is where we recommend companies preview and validate upcoming Windows 10 releases before broad deployment within their organization. Release Preview Channel, Quality Updates Only Ideal for those who want to validate the features and fixes coming soon to their current version. Note, released feature updates will continue to be offered in accordance with configured policies when this option is selected. Note: Preview Build enrollment requires a telemetry level setting of 2 or higher and your domain registered on insider.windows.com. For additional information on Preview Builds, see: https://aka.ms/wipforbiz If you disable or do not configure this policy, Windows Update will not offer you any pre-release updates and you will receive such content once released to the world. Disabling this policy will cause any devices currently on a pre-release build to opt out and stay on the latest Feature Update once released.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  ],
  "ValueName": "ManagePreviewBuildsPolicyValue",
  "Elements": [
    { "Type": "Enum", "ValueName": "BranchReadinessLevel", "Items": [
        { "DisplayName": "Dev Channel", "Data": "2" },
        { "DisplayName": "Beta Channel", "Data": "4" },
        { "DisplayName": "Release Preview Channel", "Data": "8" },
        { "DisplayName": "Release Preview of Quality Updates Only", "Data": "64" }
      ]
    },
    { "Type": "EnabledValue", "Data": "2" },
    { "Type": "DisabledValue", "Data": "1" }
  ]
},
{
  "File": "WindowsUpdate.admx",
  "CategoryName": "WindowsUpdateOffering",
  "PolicyName": "DeferQualityUpdates",
  "NameSpace": "Microsoft.Policies.WindowsUpdate",
  "Supported": "Windows_10_0_NOARM - At least Windows Server 2016 or Windows 10",
  "DisplayName": "Select when Quality Updates are received",
  "ExplainText": "Enable this policy to specify when to receive quality updates. You can defer receiving quality updates for up to 30 days. To prevent quality updates from being received on their scheduled time, you can temporarily pause quality updates. The pause will remain in effect for 35 days or until you clear the start date field. To resume receiving Quality Updates which are paused, clear the start date field. If you disable or do not configure this policy, Windows Update will not alter its behavior.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  ],
  "ValueName": "DeferQualityUpdates",
  "Elements": [
    { "Type": "Decimal", "ValueName": "DeferQualityUpdatesPeriodInDays", "MinValue": "0", "MaxValue": "30" },
    { "Type": "Text", "ValueName": "PauseQualityUpdatesStartTime" },
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsUpdate.admx",
  "CategoryName": "WindowsUpdateOffering",
  "PolicyName": "ExcludeWUDriversInQualityUpdate",
  "NameSpace": "Microsoft.Policies.WindowsUpdate",
  "Supported": "Windows_10_0_NOARM - At least Windows Server 2016 or Windows 10",
  "DisplayName": "Do not include drivers with Windows Updates",
  "ExplainText": "Enable this policy to not include drivers with Windows quality updates. If you disable or do not configure this policy, Windows Update will include updates that have a Driver classification.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  ],
  "ValueName": "ExcludeWUDriversInQualityUpdate",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsUpdate.admx",
  "CategoryName": "WindowsUpdateExperience",
  "PolicyName": "DisableUXWUAccess",
  "NameSpace": "Microsoft.Policies.WindowsUpdate",
  "Supported": "Windows_10_0_NOARM - At least Windows Server 2016 or Windows 10",
  "DisplayName": "Remove access to use all Windows Update features",
  "ExplainText": "This setting allows you to remove access to scan Windows Update. If you enable this setting user access to Windows Update scan, download and install is removed.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  ],
  "ValueName": "SetDisableUXWUAccess",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsUpdate.admx",
  "CategoryName": "WindowsUpdateExperience",
  "PolicyName": "DisablePauseUXAccess",
  "NameSpace": "Microsoft.Policies.WindowsUpdate",
  "Supported": "Windows_10_0_RS5 - At least Windows Server 2016, Windows 10 Version 1809",
  "DisplayName": "Remove access to \"Pause updates\" feature",
  "ExplainText": "This setting allows to remove access to \"Pause updates\" feature. Once enabled user access to pause updates is removed.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  ],
  "ValueName": "SetDisablePauseUXAccess",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsUpdate.admx",
  "CategoryName": "WindowsUpdateExperience",
  "PolicyName": "AllowTemporaryEnterpriseFeatureControl",
  "NameSpace": "Microsoft.Policies.WindowsUpdate",
  "Supported": "Windows_11_0_22H2 - At least Windows 11 Version 22H2",
  "DisplayName": "Enable features introduced via servicing that are off by default",
  "ExplainText": "Features introduced via servicing (outside of the annual feature update) are off by default for devices that have their Windows updates managed*. If this policy is configured to \u201cEnabled\u201d, then all features available in the latest monthly quality update installed will be on. If this policy is set to \u201cNot Configured\u201d or \u201cDisabled\u201d then features that are shipped via a monthly quality update (servicing) will remain off until the feature update that includes these features is installed. *Windows update managed devices are those that have their Windows updates managed via policy; whether via the cloud using Windows Update for Business or on-premises with Windows Server Update Services (WSUS).",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  ],
  "ValueName": "AllowTemporaryEnterpriseFeatureControl",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsUpdate.admx",
  "CategoryName": "WindowsUpdateOffering",
  "PolicyName": "AllowOptionalContent",
  "NameSpace": "Microsoft.Policies.WindowsUpdate",
  "Supported": "WU_SUPPORTED_WinServer2025_Win1021H2_Win1122H2 - At least Windows Server 2025, Windows 10 Version 21H2, or Windows 11 Version 22H2",
  "DisplayName": "Enable optional updates",
  "ExplainText": "This policy enables devices to get optional updates (including gradual feature rollouts (CFRs) - learn more by visiting aka.ms/AllowOptionalContent) When the policy is configured \u2022 If \"Automatically receive optional updates (including CFRs)\" is selected, the device will get the latest optional updates automatically in line with the configured quality update deferrals. This includes optional cumulative updates and gradual feature rollouts (CFRs). \u2022 If \"Automatically receive optional updates\" is selected, the device will only get optional cumulative updates automatically, in line with the quality update deferrals. \u2022 If \"Users can select which optional updates to receive\" is selected, users can select which optional updates to get by visiting Settings > Windows Update > Advanced options > Optional updates. Users can also enable the toggle \"Get the latest updates as soon as they're available\" to automatically receive optional updates and gradual feature rollouts.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  ],
  "ValueName": "SetAllowOptionalContent",
  "Elements": [
    { "Type": "Enum", "ValueName": "AllowOptionalContent", "Items": [
        { "DisplayName": "Automatically receive optional updates (including CFRs)", "Data": "1" },
        { "DisplayName": "Automatically receive optional updates", "Data": "2" },
        { "DisplayName": "Users can select which optional updates to receive", "Data": "3" }
      ]
    },
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
}
```

# Windows Firewall

> "*Windows Firewall is a security feature that helps to protect your device by filtering network traffic that enters and exits your device. This traffic can be filtered based on several criteria, including source and destination IP address, IP protocol, or source and destination port number. Windows Firewall can be configured to block or allow network traffic based on the services and applications that are installed on your device. This allows you to restrict network traffic to only those applications and services that are explicitly allowed to communicate on the network.*"
>
> — Microsoft, [Windows Firewall](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/)

## Inbound vs Outbound

- **Inbound**: traffic initiated elsewhere that comes into your PC, like file sharing, hosted game sessions, or Remote Desktop.
- **Outbound**: traffic initiated by your PC going to another device or the internet, like web browsing, app updates, or apps connecting to their servers.

## Firewall Presets

The option currently includes 4 different presets, note that `Allowlist Mode` will need rules that you've to add. 

It's recommended to allow outbound, **look at the network section in system informer**, afterwards adding rules for programs that require network outbound access.

Make sure that you're looking at your local IP address (`192.168.x.x`), not at loopback addresses (`127.0.0.1`), these don't access the network and are local traffic.

On first use kind of everything get's blocked -> minimalfirewall asks you to block/allow it. This continues until every required rule is set.

- `Off`: firewall disabled
- `Default`: inbound block, outbound allow
- `Allowlist`: inbound block, outbound block unless allowed (recommended, but requires time to set up)

## Firewall Captures

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

> *User Account Control (UAC) is meant to enable users to run with standard user rights as opposed to administrative rights. Without administrative rights, users cannot accidentally (or deliberately) modify system settings, malware can’t normally alter system security settings or disable antivirus software, and users can’t compromise the sensitive information of other users on shared computers. Running with standard user rights can thus mitigate the impact of malware and protect sensitive data on shared computers.*
> *UAC runs most apps with standard user rights and uses a filtered admin token for administrators, elevating only when needed. Disabling UAC removes this filtered-token model and disables UAC file/registry virtualization (Luafv.sys).*"
>
> — Windows Internals, [E7, P1: 'UAC'](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

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

## [Registry Values Details](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration?tabs=reg)

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

# PS Execution Policy

> "*PowerShell execution policy is a safety feature that controls when PowerShell loads configuration files and runs scripts, helping prevent accidental execution of malicious scripts.*
>
> *On Windows, you can set it for the local computer, current user, a single session, or through Group Policy. Local computer and current user policies are stored in PowerShell configuration files, while session policy exists only in memory until the session closes.*
>
> *It is not a real security boundary, since users can bypass it, but it helps enforce basic rules and avoid accidental misuse.*
>
> *On non-Windows systems, the reported default is `Unrestricted` and cannot be changed, though the actual behavior is closer to `Bypass` because Windows security zones do not exist there.*"
>
> — Microsoft, [about_Execution_Policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.5)

### [Execution Policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.5)

| **Execution Policy**  | **Description** |
| ---- | ---- |
| `AllSigned` | All scripts must be signed by a trusted publisher. Prompts for untrusted publishers. |
| `Bypass` | No prompts or restrictions. Used in apps or environments with their own security. |
| `Default` | Acts like `RemoteSigned` on Windows. |
| `RemoteSigned` | Scripts run freely unless downloaded from the internet. Internet scripts need a trusted signature or must be unblocked. Local scripts don't require signatures. |
| `Restricted` | No scripts allowed (only individual commands). Blocks all `.ps1`, `.psm1`, `.ps1xml`, and profile scripts. |
| `Undefined` | No policy in this scope. If all scopes are undefined, defaults to `Restricted` (clients) or `RemoteSigned` (servers). |
| `Unrestricted` | Unsigned scripts can run. Prompts for scripts from outside the intranet zone. |

### Scope

| **Scope** | **Description** |
|---- | ---- |
| `MachinePolicy` | Set by a Group Policy for all users of the computer |
| `UserPolicy` | Set by a Group Policy for the current user of the computer |
| `Process` | Sets the execution policy only for the current session - stored in an environment variable & removed when the session ends |
| `CurrentUser` | The execution policy affects only the current user - stored in the HKCU subkey |
| `LocalMachine` | The execution policy affects all users on the current computer - stored in the HKLM subkey |

### [Registry Values](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_config?view=powershell-7.5)

| **Value Name** | **Description** |
| ---- | ---- |
| `EnableScriptBlockLogging` | Enables or disables logging of PowerShell script input to the event log. If enabled, it logs the processing of commands, script blocks, functions, and scripts. |
| `EnableScriptBlockInvocationLogging` | Enables or disables logging of invocation events for commands, script blocks, functions, or scripts. Enabling this generates high volume of event logs for start/stop events. |
| `EnableModuleLogging` | Enables or disables logging of pipeline execution events for specified PowerShell modules. If enabled, logs events in Event Viewer for the specified modules. |
| `EnableTranscripting` | Enables or disables transcription of PowerShell commands. If enabled, records the input and output of PowerShell commands into text-based transcripts stored by default in My Documents. |
| `EnableScripts` | Controls which types of scripts are allowed to run on the system. Options include allowing only signed scripts, allowing local scripts and remote signed scripts, or allowing all scripts to run. |

See your current execution policies via:
```powershell
Get-ExecutionPolicy -List
```

## [Windows Policies](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)

```json
{
  "File": "PowerShellExecutionPolicy.admx",
  "CategoryName": "PowerShell",
  "PolicyName": "EnableScripts",
  "NameSpace": "Microsoft.Policies.PowerShell",
  "Supported": "WIN7 - At least Microsoft Windows 7 or Windows Server 2008 family",
  "DisplayName": "Turn on Script Execution",
  "ExplainText": "This policy setting lets you configure the script execution policy, controlling which scripts are allowed to run. If you enable this policy setting, the scripts selected in the drop-down list are allowed to run. The \"Allow only signed scripts\" policy setting allows scripts to execute only if they are signed by a trusted publisher. The \"Allow local scripts and remote signed scripts\" policy setting allows any local scrips to run; scripts that originate from the Internet must be signed by a trusted publisher. The \"Allow all scripts\" policy setting allows all scripts to run. If you disable this policy setting, no scripts are allowed to run. Note: This policy setting exists under both \"Computer Configuration\" and \"User Configuration\" in the Local Group Policy Editor. The \"Computer Configuration\" has precedence over \"User Configuration.\" If you disable or do not configure this policy setting, it reverts to a per-machine preference setting; the default if that is not configured is \"No scripts allowed.\"",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell",
    "HKCU\\Software\\Policies\\Microsoft\\Windows\\PowerShell"
  ],
  "ValueName": "EnableScripts",
  "Elements": [
    { "Type": "Enum", "ValueName": "ExecutionPolicy", "Items": [
        { "DisplayName": "Allow only signed scripts", "Data": "AllSigned" },
        { "DisplayName": "Allow local scripts and remote signed scripts", "Data": "RemoteSigned" },
        { "DisplayName": "Allow all scripts", "Data": "Unrestricted" }
      ]
    },
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "PowerShellExecutionPolicy.admx",
  "CategoryName": "PowerShell",
  "PolicyName": "EnableModuleLogging",
  "NameSpace": "Microsoft.Policies.PowerShell",
  "Supported": "WIN7 - At least Microsoft Windows 7 or Windows Server 2008 family",
  "DisplayName": "Turn on Module Logging",
  "ExplainText": "This policy setting allows you to turn on logging for Windows PowerShell modules. If you enable this policy setting, pipeline execution events for members of the specified modules are recorded in the Windows PowerShell log in Event Viewer. Enabling this policy setting for a module is equivalent to setting the LogPipelineExecutionDetails property of the module to True. If you disable this policy setting, logging of execution events is disabled for all Windows PowerShell modules. Disabling this policy setting for a module is equivalent to setting the LogPipelineExecutionDetails property of the module to False. If this policy setting is not configured, the LogPipelineExecutionDetails property of a module or snap-in determines whether the execution events of a module or snap-in are logged. By default, the LogPipelineExecutionDetails property of all modules and snap-ins is set to False. To add modules and snap-ins to the policy setting list, click Show, and then type the module names in the list. The modules and snap-ins in the list must be installed on the computer. Note: This policy setting exists under both Computer Configuration and User Configuration in the Group Policy Editor. The Computer Configuration policy setting takes precedence over the User Configuration policy setting.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",
    "HKCU\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging"
  ],
  "ValueName": "EnableModuleLogging",
  "Elements": [
    { "Type": "List", "ValueName": null },
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "PowerShellExecutionPolicy.admx",
  "CategoryName": "PowerShell",
  "PolicyName": "EnableTranscripting",
  "NameSpace": "Microsoft.Policies.PowerShell",
  "Supported": "WIN7 - At least Microsoft Windows 7 or Windows Server 2008 family",
  "DisplayName": "Turn on PowerShell Transcription",
  "ExplainText": "This policy setting lets you capture the input and output of Windows PowerShell commands into text-based transcripts. If you enable this policy setting, Windows PowerShell will enable transcripting for Windows PowerShell, the Windows PowerShell ISE, and any other applications that leverage the Windows PowerShell engine. By default, Windows PowerShell will record transcript output to each users' My Documents directory, with a file name that includes 'PowerShell_transcript', along with the computer name and time started. Enabling this policy is equivalent to calling the Start-Transcript cmdlet on each Windows PowerShell session. If you disable this policy setting, transcripting of PowerShell-based applications is disabled by default, although transcripting can still be enabled through the Start-Transcript cmdlet. If you use the OutputDirectory setting to enable transcript logging to a shared location, be sure to limit access to that directory to prevent users from viewing the transcripts of other users or computers. Note: This policy setting exists under both Computer Configuration and User Configuration in the Group Policy Editor. The Computer Configuration policy setting takes precedence over the User Configuration policy setting.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
    "HKCU\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"
  ],
  "ValueName": "EnableTranscripting",
  "Elements": [
    { "Type": "Text", "ValueName": "OutputDirectory" },
    { "Type": "Boolean", "ValueName": "EnableInvocationHeader", "TrueValue": "1", "FalseValue": "0" },
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "PowerShellExecutionPolicy.admx",
  "CategoryName": "PowerShell",
  "PolicyName": "EnableScriptBlockLogging",
  "NameSpace": "Microsoft.Policies.PowerShell",
  "Supported": "WIN7 - At least Microsoft Windows 7 or Windows Server 2008 family",
  "DisplayName": "Turn on PowerShell Script Block Logging",
  "ExplainText": "This policy setting enables logging of all PowerShell script input to the Microsoft-Windows-PowerShell/Operational event log. If you enable this policy setting, Windows PowerShell will log the processing of commands, script blocks, functions, and scripts - whether invoked interactively, or through automation. If you disable this policy setting, logging of PowerShell script input is disabled. If you enable the Script Block Invocation Logging, PowerShell additionally logs events when invocation of a command, script block, function, or script starts or stops. Enabling Invocation Logging generates a high volume of event logs. Note: This policy setting exists under both Computer Configuration and User Configuration in the Group Policy Editor. The Computer Configuration policy setting takes precedence over the User Configuration policy setting.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
    "HKCU\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
  ],
  "ValueName": "EnableScriptBlockLogging",
  "Elements": [
    { "Type": "Boolean", "ValueName": "EnableScriptBlockInvocationLogging", "TrueValue": "1", "FalseValue": "0" },
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
}
```

# Process Mitigations

Process mitigations are system or per process exploit protections for common memory corruption & control flow attack classes. These can improve exploit resistance, but some mitigations can break older software, drivers, game anti-cheat components, launchers, or injected overlays. The mitigation tables in the sections are copied from [Windows Internals E7 P1](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf), 'Exploit mitigations'.

The option currently includes the [system-level mitigations](https://learn.microsoft.com/en-us/defender-endpoint/customize-exploit-protection#exploit-protection-mitigations).

These options are stored system wide in:
```ini
HKLM\System\CurrentControlSet\Control\Session Manager\kernel\MitigationOptions ; REG_BINARY, 24 bytes
HKLM\System\CurrentControlSet\Control\Session Manager\kernel\MitigationAuditOptions ; REG_BINARY, 24 bytes
```

The relevant 4 bit field uses `0` = default/not configured, `1` = force on, and `2` = force off.

| Option | [PS reference](https://learn.microsoft.com/en-us/defender-endpoint/customize-exploit-protection#powershell-reference-table) | `MitigationOptions` field | Enable bytes | Disable bytes |
| --- | --- | --- | --- | --- |
| DEP | `DEP`, `EmulateAtlThunks` | byte `0`, low 4 bits | `01 00 00 XX` | `02 00 00 XX` |
| SEHOP | `SEHOP`, `SEHOPTelemetry` | byte `0`, high 4 bits | `10 00 00 XX` | `20 00 00 XX` |
| Validate heap integrity | `TerminateOnError` | byte `1`, high 4 bits | `00 10 00 XX` | `00 20 00 XX` |
| Mandatory ASLR | `ForceRelocateImages` | byte `1`, low 4 bits | `00 01 00 XX` | `00 02 00 XX` |
| Bottom-up ASLR | `BottomUp`, `HighEntropy` | byte `2`, low 4 bits | `00 00 01 XX` | `00 00 02 XX` |
| High-entropy ASLR | `HighEntropy` suboption of Bottom-up ASLR | byte `2`, high 4 bits | `00 00 10 XX` | `00 00 20 XX` |
| CFG | `CFG`, `StrictCFG`, `SuppressExports` | byte `5` low 4 bits, byte `9` low 4 bits | `XX XX XX XX XX 01 XX XX XX 01` | `XX XX XX XX XX 02 XX XX XX 02` |

## CFG

> "*validating the target of any indirect `CALL` or `JMP` instruction against a list of valid expected target functions*"
>
> — Windows Internals, [E7, P1: 'Exploit mitigations'](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

| Mitigation | Use case | Enabling mechanism |
| --- | --- | --- |
| Control Flow Guard (CFG) | Validates indirect `CALL` and `JMP` targets against expected valid functions, which helps stop control-flow hijacking after memory corruption. | Requires binaries compiled and linked with `/guard:cf`, or can be requested with the CFG process-creation mitigation flag for loaded images. |
| CFG Strict Mode | Blocks libraries that were not linked with `/guard:cf` from loading into the process. | Set through `SetProcessMitigationPolicy` or the strict CFG process-creation mitigation flag. |

## DEP

> "*Marking memory regions as non-executable means that code cannot be run from that region of memory*"
>
> — Microsoft, [Data Execution Prevention](https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention)

| Mitigation | Use case | Enabling mechanism |
| --- | --- | --- |
| DEP: Permanent | Prevents a process from disabling DEP for itself. It mainly applies to x86 and WoW64 processes. | Set through `SetProcessMitigationPolicy`, a process-creation attribute, or `SetProcessDEPPolicy`. |
| DEP: Disable ATL Thunk Emulation | Prevents legacy ATL thunk code from executing in heap memory, even where compatibility handling would otherwise allow it. | Set through `SetProcessMitigationPolicy`, a process-creation attribute, or `SetProcessDEPPolicy`. |

## Mandatory ASLR

> "*forces a rebase of all DLLs within the process*"
>
> "*this rebasing has no entropy, and can therefore be placed at a predictable location in memory*"
>
> — Microsoft, [Exploit protection reference](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference)

| Mitigation | Use case | Enabling mechanism |
| --- | --- | --- |
| ASLR Force Relocate Images | Forces rebasing for images that were not linked with `/DYNAMICBASE`. | Set through `SetProcessMitigationPolicy` or the force-relocate process-creation mitigation flag. |
| ASLR Disallow Stripped Images | Blocks libraries without relocation data when forced relocation is required. | Set through `SetProcessMitigationPolicy` or the force-relocate and require-relocations mitigation flag. |

## Bottom-up ASLR

> "*adds entropy to relocations, so their location is randomized and therefore less predictable*"
>
> — Microsoft, [Exploit protection reference](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference)

| Mitigation | Use case | Enabling mechanism |
| --- | --- | --- |
| ASLR Bottom Up Randomization | Randomizes bottom-up allocations such as `VirtualAlloc` and stack bases. | Set with the bottom-up ASLR process-creation mitigation flag. |

## High-entropy ASLR

> "*adds 24 bits of entropy (1 TB of variance) into the bottom-up allocation for 64-bit applications*"
>
> — Microsoft, [Exploit protection reference](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference)

| Mitigation | Use case | Enabling mechanism |
| --- | --- | --- |
| High Entropy ASLR (HEASLR) | Adds much more address-space entropy for supported 64-bit images. | Requires `/HIGHENTROPYVA` at link time or the high-entropy ASLR process-creation mitigation flag. |

## SEHOP

> "*validates the SEH chain when an exception is invoked*"
>
> "*No exception handler pointers are pointing to the stack... The exception chain ends at a known final exception handler*"
>
> — Microsoft, [Exploit protection reference](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference)

| Mitigation | Use case | Enabling mechanism |
| --- | --- | --- |
| SEH Overwrite Protection (SEHOP) | Validates structured exception handler chains so overwritten handlers cannot redirect exception dispatch. It mainly applies to 32-bit and WoW64 processes. | Set through `SetProcessDEPPolicy` or the SEHOP process-creation mitigation flag. |

## Validate Heap Integrity

> "*causing the application to terminate if a heap corruption is detected*"
>
> — Microsoft, [Exploit protection reference](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference)

| Mitigation | Use case | Enabling mechanism |
| --- | --- | --- |
| Heap Terminate On Corruption | Terminates the process on heap corruption instead of allowing a continuable heap exception path. This reduces exploit reliability for heap corruption bugs. | Set through `HeapSetInformation` or the heap terminate process-creation mitigation flag. |

### FTH

Used for preventing legacy or unstable applications from crashing, read through the picture below for more detailed information ([`Windows Internals 7th Edition, Part 1, Page 347`](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)).

In [Exploit Protection](https://learn.microsoft.com/en-us/defender-endpoint/customize-exploit-protection#powershell-reference-table) you can see the `Heap` mitigation with `TerminateOnError`, Windows Internals names the same heap termination behavior `Heap Terminate On Corruption`, so the FTH note below refers to that.

> "*causing the application to terminate if a heap corruption is detected*"
>
> — Microsoft, [Exploit protection reference](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference)

> "*disables the Fault Tolerant Heap (FTH)... by terminating the process instead*"
>
> — Windows Internals, [E7, P1: 'Exploit mitigations'](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

#### [Windows Internals](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

![](https://github.com/nohuto/win-config/blob/main/system/images/fth.png?raw=true)

[YouTube Video](https://www.youtube.com/watch?v=4SvNNXAwoqE).

## ProcessMitigation ValidValues

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

# DMA Remapping

[DMA remapping](https://learn.microsoft.com/en-us/windows-hardware/drivers/pci/enabling-dma-remapping-for-device-drivers) lets PCIe device drivers declare whether they are compatible with IOMMU backed DMA isolation. Windows uses this with [Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt) and DMAGuard policy to reduce memory corruption and malicious DMA attack exposure. Devices with DMA remapping compatible drivers can start and perform DMA, incompatible external or exposed PCIe devices can be blocked by DMAGuard policy on systems where Kernel DMA Protection is enabled.

`Opt-In` marks matching existing entries as compatible with DMA remapping. `Opt-Out` marks them as incompatible, which can reduce DMA remapping coverage and can cause external devices to be blocked until sign in or unlock.

`per-device` - recommended and preferred mechanism for Windows 24H2 and later (`RemappingSupported`)
`per-driver` - legacy mechanism for Windows versions up to Windows 11 23H2 (`DmaRemappingCompatible`)

If both are present, the per-device setting takes precedence and `DmaRemappingCompatible` is ignored. The PCI driver documentation still warns that DMA remapping is not supported through this path for graphics drivers. Display drivers use the separate [WDDM IOMMU DMA remapping](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/iommu-dma-remapping) path.

### `RemappingSupported`

| Value | Meaning |
|--|--|
| 0 | Opt-out, indicates the device and driver are incompatible with DMA remapping. |
| 1 | Opt-in, indicates the device and driver are fully compatible with DMA remapping. |
| No registry key | Let the system determine the policy. |

### `RemappingFlags`

| Value | Meaning |
|--|--|
| 0 | If **RemappingSupported** is 1, opt in, unconditionally. |
| 1 | If **RemappingSupported** is 1, opt in, but only when one or more of the following conditions are met: A. The device is an external device (for example, Thunderbolt). B. DMA verification is enabled in Driver Verifier |
| No registry key | Same as 0 value. |

### `DmaRemappingCompatible`

| Value | Meaning |
|--|--|
| 0 | Opt-out, indicates that your driver is incompatible with DMA remapping. |
| 1 | Opt-in, indicates that your driver is fully compatible with DMA remapping. |
| 2 | Opt-in, but only when one or more of the following conditions are met: A. The device is an external device (for example, Thunderbolt). B. DMA verification is enabled in Driver Verifier |
| 3 | Opt-in. Support was added in Windows 11 and degrades gracefully on Windows 10. |
| No registry key | Let the system determine the policy. |

Example paths:
```powershell
\Registry\Machine\SYSTEM\ControlSet001\Services\msisadrv\Parameters : DmaRemappingCompatible
\Registry\Machine\SYSTEM\ControlSet001\Enum\pci\VEN_1022&DEV_1483&SUBSYS_88081043&REV_00\3&11583659&0&09\Device Parameters\DMA Management : RemappingFlags
\Registry\Machine\SYSTEM\ControlSet001\Enum\pci\VEN_1022&DEV_1483&SUBSYS_88081043&REV_00\3&11583659&0&09\Device Parameters\DMA Management : RemappingSupported
```

## EnableNVMeInterface Notes

Since `EnableNVMeInterface` is included in the function, I'll add it here. Default value of `0`, range `0`-`1`? Located in:
```
\Registry\Machine\SYSTEM\ControlSet001\Enum\pci\<dev>\<id>\Device Parameters\StorPort : EnableNVMeInterface
```
[`DisableNativeNVMeStack`](https://github.com/nohuto/regkit/blob/main/records/StorPort.txt), range `0`-`1`?
```c
\Registry\Machine\SYSTEM\ControlSet001\Control\StorPort : DisableNativeNVMeStack

DisableNativeNVMeStack db 0 // default
```

# Disable System Restore

```powershell
Disable-ComputerRestore -Drive "C:\"
```
Does:
```powershell
"wmiprvse.exe", "RegSetValue","HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\RPSessionInterval","Type: REG_DWORD, Length: 4, Data: 0"
```

## [Windows Policies](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)

```json
{
  "File": "SystemRestore.admx",
  "CategoryName": "SR",
  "PolicyName": "SR_DisableConfig",
  "NameSpace": "Microsoft.Policies.SystemRestore",
  "Supported": "Windows7 - At least Windows Server 2008 R2 or Windows 7",
  "DisplayName": "Turn off Configuration",
  "ExplainText": "Allows you to disable System Restore configuration through System Protection. This policy setting allows you to turn off System Restore configuration through System Protection. System Restore enables users, in the event of a problem, to restore their computers to a previous state without losing personal data files. The behavior of this policy setting depends on the \"Turn off System Restore\" policy setting. If you enable this policy setting, the option to configure System Restore through System Protection is disabled. If you disable or do not configure this policy setting, users can change the System Restore settings through System Protection. Also, see the \"Turn off System Restore\" policy setting. If the \"Turn off System Restore\" policy setting is enabled, the \"Turn off System Restore configuration\" policy setting is overwritten.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows NT\\SystemRestore"
  ],
  "ValueName": "DisableConfig",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "SystemRestore.admx",
  "CategoryName": "SR",
  "PolicyName": "SR_DisableSR",
  "NameSpace": "Microsoft.Policies.SystemRestore",
  "Supported": "Windows7 - At least Windows Server 2008 R2 or Windows 7",
  "DisplayName": "Turn off System Restore",
  "ExplainText": "Allows you to disable System Restore. This policy setting allows you to turn off System Restore. System Restore enables users, in the event of a problem, to restore their computers to a previous state without losing personal data files. By default, System Restore is turned on for the boot volume. If you enable this policy setting, System Restore is turned off, and the System Restore Wizard cannot be accessed. The option to configure System Restore or create a restore point through System Protection is also disabled. If you disable or do not configure this policy setting, users can perform System Restore and configure System Restore settings through System Protection. Also, see the \"Turn off System Restore configuration\" policy setting. If the \"Turn off System Restore\" policy setting is disabled or not configured, the \"Turn off System Restore configuration\" policy setting is used to determine whether the option to configure System Restore is available.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows NT\\SystemRestore"
  ],
  "ValueName": "DisableSR",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
}
```

# Disable Downloads Blocking

Windows adds a hidden tag called [`Zone.Identifier`](https://www.cyberengage.org/post/unveiling-file-origins-the-role-of-alternate-data-streams-ads-zone-identifier-in-forensic-inve) to files downloaded from the internet. This tag (also known as MotW) stores info about the file's origin and helps apply security warnings, see files including the tag with:
```powershell
gi * -Stream "Zone.Identifier" -ErrorAction SilentlyContinue
```

![](https://github.com/nohuto/win-config/blob/main/security/images/downblocking.png?raw=true)

## ZoneID Data

**ZoneID** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones`) - number indicating the security zone the file came from:
`0` – Local machine
`1` – Local intranet (internal network)
`2` – Trusted sites
`3` – Internet (mostly web downloads)
`4` – Untrusted / Restricted sites (flagged as dangerous by smartscreen)

## Unblock-File

Files downloaded from the internet still getting blocked? Unblock it/them with (one of them):
```powershell
Unblock-File -Path "C:\Path\Script.ps1" -> File

dir C:\Path\*Files* | Unblock-File -> Multiple files 
```

## [Windows Policies](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)

```json
{
  "File": "AttachmentManager.admx",
  "CategoryName": "AM_AM",
  "PolicyName": "AM_MarkZoneOnSavedAtttachments",
  "NameSpace": "Microsoft.Policies.AttachmentManager",
  "Supported": "WindowsXPSP2 - At least Windows XP Professional with SP2",
  "DisplayName": "Do not preserve zone information in file attachments",
  "ExplainText": "This policy setting allows you to manage whether Windows marks file attachments with information about their zone of origin (such as restricted, Internet, intranet, local). This requires NTFS in order to function correctly, and will fail without notice on FAT32. By not preserving the zone information, Windows cannot make proper risk assessments. If you enable this policy setting, Windows does not mark file attachments with their zone information. If you disable this policy setting, Windows marks file attachments with their zone information. If you do not configure this policy setting, Windows marks file attachments with their zone information.",
  "KeyPath": [
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments"
  ],
  "ValueName": "SaveZoneInformation",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "2" }
  ]
}
```

# Disable WPBT

WPBT allows hardware manufacturers to run programs during Windows startup that may introduce unwanted software.
```
\Registry\Machine\SYSTEM\ControlSet001\Control\Session Manager : DisableWpbtExecution
```

# Disable Bitlocker & EFS

Disable [Bitlocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/) on all volumes:
```powershell
$nvbvol = Get-BitLockerVolume
Disable-BitLocker -MountPoint $nvbvol
```

## NtfsDisableEncryption Notes

`fsutil behavior set disableencryption 1` sets:
```powershell
fsutil.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\FileSystem\NtfsDisableEncryption	Type: REG_DWORD, Length: 4, Data: 1
```
```
\Registry\Machine\SYSTEM\ControlSet001\Policies : NtfsDisableEncryption
\Registry\Machine\SYSTEM\ControlSet001\Control\FileSystem : NtfsDisableEncryption
```

### 0x8007177E Error

Enabling `NtfsDisableEncryption` (`1`) may cause Xbox games to fail to install (error code `0x8007177E` - "Allow encryption on selected disk volume to install this game"):

```powershell
ERROR_VOLUME_NOT_SUPPORT_EFS = 0x8007177E;
```

- [Windows API - Error Defines](https://github.com/arizvisa/BugId-mWindowsAPI/blob/904a1c0bd22c019ef6ca8313945fe38f4ca26f30/mDefines/mErrorDefines.py#L1793)

## [Windows Policies](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)

```json
{
  "File": "FileSys.admx",
  "CategoryName": "NTFS",
  "PolicyName": "DisableEncryption",
  "NameSpace": "Microsoft.Policies.FileSys",
  "Supported": "Windows7 - At least Windows Server 2008 R2 or Windows 7",
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
}
```

# Disable VBS (HVCI)

[VBS](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) won't work if Hyper-V is disabled. HVCI = hypervisor-protected code integrity.

Hypervisor-Based Code Integrity (HVCI) and Kernel-Mode Code Integrity (KMCI) power `Device Guard`, LSA (Lsass.exe) and isolated LSA (LsaIso.exe) power [`Credential Guard`](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/).

"Virtualization-based security, or VBS, uses hardware virtualization and the Windows hypervisor to create an isolated virtual environment that becomes the root of trust of the OS that assumes the kernel can be compromised. Windows uses this isolated environment to host a number of security solutions, providing them with greatly increased protection from vulnerabilities in the operating system, and preventing the use of malicious exploits which attempt to defeat protections. VBS enforces restrictions to protect vital system and operating system resources, or to protect security assets such as authenticated user credentials.

One such example security solution is [memory integrity](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity?tabs=security), which protects and hardens Windows by running kernel mode code integrity within the isolated virtual environment of VBS. Kernel mode code integrity is the Windows process that checks all kernel mode drivers and binaries before they're started, and prevents unsigned or untrusted drivers or system files from being loaded into system memory. Memory integrity also restricts kernel memory allocations that could be used to compromise the system, ensuring that kernel memory pages are only made executable after passing code integrity checks inside the secure runtime environment, and executable pages themselves are never writable. That way, even if there are vulnerabilities like a buffer overflow that allow malware to attempt to modify memory, executable code pages cannot be modified, and modified memory cannot be made executable."

## [VBS Requirements](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs)

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

You can disable VBS for a VM with:
```powershell
Set-VMSecurity -VMName <VMName> -VirtualizationBasedSecurityOptOut $true
```

## [Windows Internals](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

![](https://github.com/nohuto/win-config/blob/main/security/images/vbs-guards1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/security/images/vbs-guards2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/security/images/vbs-guards3.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/security/images/vbs-guards4.png?raw=true)

## [Windows Policies](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)

```json
{
  "File": "DeviceGuard.admx",
  "CategoryName": "DeviceGuardCategory",
  "PolicyName": "VirtualizationBasedSecurity",
  "NameSpace": "Microsoft.Windows.DeviceGuard",
  "Supported": "Windows_10_0 - At least Windows Server 2016, Windows 10",
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
}
```

# Disable Password Reveal

"This policy setting allows you to configure the display of the password reveal button in password entry user experiences. If you enable this policy setting, the password reveal button won't be displayed after a user types a password in the password entry text box. If you disable or don't configure this policy setting, the password reveal button will be displayed after a user types a password in the password entry text box. By default, the password reveal button is displayed after a user types a password in the password entry text box."

## Suboption

`Disable Picture Password Sign-In`: "This policy setting allows you to control whether a domain user can sign in using a picture password. If you enable this policy setting, a domain user can't set up or sign in with a picture password. If you disable or don't configure this policy setting, a domain user can set up and use a picture password. Note that the user's domain password will be cached in the system vault when using this feature."

## [Windows Policies](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)

```json
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
{
  "File": "CredUI.admx",
  "CategoryName": "CredUI",
  "PolicyName": "DisablePasswordReveal",
  "NameSpace": "Microsoft.Policies.CredentialsUI",
  "Supported": "Windows8_Or_IE10 - At least Windows Server 2012, Windows 8 or Windows RT or at least Internet Explorer 10",
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
}
```

# Disable P2P Updates

Default is configured to LAN. The Group Download mode combined with Group ID, enables administrators to create custom device groups that share content between devices in the group. Download mode dictates which download sources clients are allowed to use when downloading Windows updates in addition to Windows Update servers.

The option applies `0` = disables peer-to-peer (P2P) caching but still allows Delivery Optimization to download content over HTTP from the download's original source or a Microsoft Connected Cache server.

### [DODownloadMode Data](https://learn.microsoft.com/en-us/windows/deployment/do/waas-delivery-optimization-reference#download-mode)

| Download mode option | Data  | Functionality when configured |
| ---- | :----: | ---- |
| HTTP Only | `0` | This setting disables peer-to-peer caching but still allows Delivery Optimization to download content over HTTP from the download's original source or a Microsoft Connected Cache server. This mode uses additional metadata provided by the Delivery Optimization cloud services for a peerless, reliable and efficient download experience. |
| LAN (Default) | `1` | This default operating mode for Delivery Optimization enables peer sharing on the same network. The Delivery Optimization cloud service finds other clients that connect to the Internet using the same public IP as the target client. These clients then try to connect to other peers on the same network by using their private subnet IP. |
| Group | `2` | When group mode is set, the group is automatically selected based on the device's Active Directory Domain Services (AD DS) site (Windows 10, version 1607) or the domain the device is authenticated to (Windows 10, version 1511). In group mode, peering occurs across internal subnets, between devices that belong to the same group, including devices in remote offices. You can use GroupID option to create your own custom group independently of domains and AD DS sites. Starting with Windows 10, version 1803, you can use the GroupIDSource parameter to take advantage of other method to create groups dynamically. Group download mode is the recommended option for most organizations looking to achieve the best bandwidth optimization with Delivery Optimization. |
| Internet | `3` | Enable Internet peer sources for Delivery Optimization. |
| Simple | `99` | Simple mode disables the use of Delivery Optimization cloud services completely (for offline environments). Delivery Optimization switches to this mode automatically when the Delivery Optimization cloud services are unavailable, unreachable, or when the content file size is less than 50 MB, as the default. In this mode, Delivery Optimization provides a reliable download experience over HTTP from the download's original source or a Microsoft Connected Cache server, with no peer-to-peer caching. |
| Bypass | `100` | Starting in Windows 11, this option is deprecated. Don't configure Download mode to '100' (Bypass), which can cause some content to fail to download. If you want to disable peer-to-peer functionality, configure DownloadMode to (0). If your device doesn't have internet access, configure Download Mode to (99). When you configure Bypass (100), the download bypasses Delivery Optimization and uses BITS instead. You don't need to configure this option if you're using Configuration Manager. |

### [Set-DODownloadMode](https://learn.microsoft.com/en-us/powershell/module/deliveryoptimization/set-dodownloadmode?view=windowsserver2025-ps)

Microsoft has a cmdlet for it, but seems like they didn't work much on it yet.

# Increased DH & RSA Key

By default it uses a minimum size of `1024` bits (both) - hardens Windows [TLS](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings?tabs=diffie-hellman) engine by forcing minimum key sizes during secure communications (SSL/TLS handshake process).

> "*NSA recommends RSA key transport and ephemeral DH (DHE) or ECDH (ECDHE) mechanisms, with RSA or DHE key exchange using at least 3072-bit keys and ECDHE key exchanges using the secp384r1 elliptic curve. For RSA keytransport and DH/DHE key exchange, keys less than 2048 bits should not be used, and ECDH/ECDHE using custom curves should not be used.*"
>
> — National Security Agency, [Eliminating obsolete TLS protocol configurations](https://media.defense.gov/2021/Jan/05/2002560140/-1/-1/0/ELIMINATING_OBSOLETE_TLS_UOO197443-20.PDF)

# Disable Legacy TLS/Crypto

Disables legacy/insecure protocols, ciphers, renegotiation, hashes, and forces .NET apps to use strong cryptography (Disables RC2 (40/56/128), RC4 (40/56/64/128), DES, 3DES, NULL, MD5/SHA-1, SSL 2.0/3.0, TLS 1.0/1.1, DTLS 1.0, insecure TLS renegotiation - Enables TLS SCSV, .NET StrongCrypto & SystemDefaultTlsVersions, NTLMv2 only). Windows may use insecure connections for e.g. older software (compatibility reasons), so disabling them can cause issues with old software.

## [LmCompatibilityLevel Data](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level#possible-values)

| Setting | Description | Registry security level |
| ---- | ---- | ---- |
| Send LM & NTLM responses | Client devices use LM and NTLM authentication, and they never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication. | 0 |
| Send LM & NTLM use NTLMv2 session security if negotiated | Client devices use LM and NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication. | 1 |
| Send NTLM response only | Client devices use NTLMv1 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication. | 2 |
| Send NTLMv2 response only | Client devices use NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication. | 3 |
| Send NTLMv2 response only. Refuse LM | Client devices use NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers refuse to accept LM authentication, and they'll accept only NTLM and NTLMv2 authentication. | 4 |
| Send NTLMv2 response only. Refuse LM & NTLM | Client devices use NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers refuse to accept LM and NTLM authentication, and they'll accept only NTLMv2 authentication. | 5 |

Level `5` gets applied.

![](https://github.com/nohuto/win-config/blob/main/security/images/insecureconn.png?raw=true)

## DTLS 1.2 & TLS 1.3 Notes

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

Controls the Netlogon policy that enables or disables [enhanced domain wide NTLM logs](https://aka.ms/ntlmlogandblock) on domain controllers (includes NTLMv1 usage). Applies to domain controllers only (Windows 11 24H2+). If not configured, domain controllers default to logging these on supported builds.

## [Windows Policies](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)

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
}
```

# Enable USB Write Protection
Restricts write access to USB devices (read only). You can also change it with `diskpart`, by selecting the disk with `select disk` and chaning it to read only with `attributes disk set readonly` (revert it with `attributes disk clear readonly`).

Rather leave USB connection error notifications enabled, unless there's a specific reason for it.

# Increase TDR

> "*TDR stands for Timeout Detection and Recovery. This is a feature of the Windows operating system which detects response problems from a graphics card, and recovers to a functional desktop by resetting the card. If the operating system does not receive a response from a graphics card within a certain amount of time (default is 2 seconds), the operating system resets the graphics card.*"
>
> — NVIDIA Docs, [Timeout Detection & Recovery](https://docs.nvidia.com/gameworks/content/developertools/desktop/timeout_detection_recovery.htm)

Disabling TDR removes a valuable layer of protection, so it is generally recommended that you keep it enabled.

### [Registry Values](https://github.com/nohuto/windows-driver-docs/blob/staging/windows-driver-docs-pr/display/tdr-registry-keys.md)

| Registry value     | Value name           | Default data                 | Description                                                                                               |
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

## Pseudocode Snippets

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

- [security/assets | TdrInit.c](https://github.com/nohuto/win-config/blob/main/security/assets/TdrInit.c)

## NVLDDMKM TDR

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

## [Windows Policies](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)

```json
{
  "File": "CredUI.admx",
  "CategoryName": "CredUI",
  "PolicyName": "EnableSecureCredentialPrompting",
  "NameSpace": "Microsoft.Policies.CredentialsUI",
  "Supported": "WindowsVista - At least Windows Vista",
  "DisplayName": "Require trusted path for credential entry",
  "ExplainText": "This policy setting requires the user to enter Microsoft Windows credentials using a trusted path, to prevent a Trojan horse or other types of malicious code from stealing the user\u2019s Windows credentials. Note: This policy affects nonlogon authentication tasks only. As a security best practice, this policy should be enabled. If you enable this policy setting, users will be required to enter Windows credentials on the Secure Desktop by means of the trusted path mechanism. If you disable or do not configure this policy setting, users will enter Windows credentials within the user\u2019s desktop session, potentially allowing malicious code access to the user\u2019s Windows credentials.",
  "KeyPath": [
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI"
  ],
  "ValueName": "EnableSecureCredentialPrompting",
  "Elements": []
}
```

# Enable Dynamic Lock

Automatically locks your device when you're away. It requires Bluetooth to be active. This option is disabled by default.

### Accounts Captures

Toggling it via `Accounts > Sign-in options`:
```c
// Enabled
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\EnableGoodbye	Type: REG_DWORD, Length: 4, Data: 1

// Disabled (default)
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\EnableGoodbye	Type: REG_DWORD, Length: 4, Data: 0
```

## [Windows Policies](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)

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
}
```

# Sudo

[Sudo](https://github.com/microsoft/sudo) ([introduction](https://devblogs.microsoft.com/commandline/introducing-sudo-for-windows/)) is a new way for users to run elevated commands (as an administrator) directly from an unelevated console session on Windows.

Note that sudo uses administrator previledges and doesn't include `TrustedInstaller`/`SYSTEM` previledges.

### Modes

| Mode | Description |
| ---- | ---- |
| `forceNewWindow` | Runs the command elevated in a new console window. |
| `disableInput` | Runs elevated in the same window but blocks keyboard input while it runs. |
| `normal` | Runs elevated in the same window with normal input and output behavior. |

## [Windows Policies](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)

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

# Enable Camera OSD Indicator

> "*`NoPhysicalCameraLED` indicates that there is no physical LED for the device's camera. An example of a physical LED for a camera is the small blue light that turns on whenever the camera is streaming video. This setting is used to indicate to the shell component that it will need to provide a small indicator in the user interface (UI) to show when video frames are streaming or not streaming to replace the notification by physical LED.*"
>
> — Microsoft, [NoPhysicalCameraLED](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-coremmres-nophysicalcameraled)

![](https://github.com/nohuto/win-config/blob/main/system/images/cameraosd.png?raw=true)

| Data | Description |
| :---: | --- |
| 0 | Does not draw an indicator in the UI to show when the camera is on or off. Instead, a physical LED exists to show when video frames are streaming or not streaming. This is the default value. |
| 1 | Draws an indicator in the UI to show when video frames are streaming or not streaming. |

```
\Registry\Machine\SOFTWARE\Microsoft\OEM\Device\Capture : NoPhysicalCameraLED
```

# Administrator Account

This security setting determines whether the [local Administrator account](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-administrator-account-status) is enabled or disabled. The following conditions prevent disabling the Administrator account, even if this security setting is disabled.

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

# Guest Account

[Guest account](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-guest-account-status) status policy setting determines whether the Guest account is enabled or disabled. This account allows unauthenticated network users to gain access to the system by signing in as a Guest with no password. Unauthorized users can access any resources that are accessible to the Guest account over the network. This privilege means that any network shared folders with permissions that allow access to the Guest account, the Guests group, or the Everyone group will be accessible over the network. This accessibility can lead to the exposure or corruption of data.

## Best practices

Set Guest account status to Disabled so that the built-in Guest account is no longer usable. All network users will have to authenticate before they can access shared resources on the system. If the Guest account is disabled and Network access: Sharing and security model for local accounts is set to Guest only, network logons, such as those logons performed by the SMB Service will fail.

## Vulnerability

The default Guest account allows unauthenticated network users to sign in as a Guest with no password. These unauthorized users could access any resources that are accessible to the Guest account over the network. This capability means that any shared folders with permissions that allow access to the Guest account, the Guests group, or the Everyone group are accessible over the network, which could lead to the exposure or corruption of data.

# defaultuser0 Account

defaultuser0 is a temporary Windows setup account.

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
