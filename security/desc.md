# Disable Windows Update

It works via pausing updates and disabling related services:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings
```
```
PauseFeatureUpdatesEndTime
PauseQualityUpdatesEndTime
PauseUpdatesExpiryTime
```
`String Value`, e.g.: `2030-01-01T00:00:00Z`

Example (pause till `2050`):
```bat
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v PauseFeatureUpdatesEndTime /t REG_SZ /d "2050-01-01T00:00:00Z" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v PauseQualityUpdatesEndTime /t REG_SZ /d "2050-01-01T00:00:00Z" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v PauseUpdatesExpiryTime /t REG_SZ /d "2050-01-01T00:00:00Z" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v PauseFeatureUpdatesStartTime /t REG_SZ /d "2000-01-01T00:00:00Z" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v PauseQualityUpdatesStartTime /t REG_SZ /d "2000-01-01T00:00:00Z" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v PauseUpdatesStartTime /t REG_SZ /d "2000-01-01T00:00:00Z" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v PauseFeatureUpdatesEndTime /t REG_SZ /d "2050-01-01T00:00:00Z" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v PauseQualityUpdatesEndTime /t REG_SZ /d "2000-01-01T00:00:00Z" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v PauseFeatureUpdatesStartTime /t REG_SZ /d "2050-01-01T00:00:00Z" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v PauseQualityUpdatesStartTime /t REG_SZ /d "2000-01-01T00:00:00Z" /f
```

---

Miscellaneous notes:
```ps
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer /t REG_SZ /d " " /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUStatusServer /t REG_SZ /d " " /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v UpdateServiceUrlAlternate /t REG_SZ /d " " /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DisableOSUpgrade /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v SetDisableUXWUAccess /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v UseWUServer /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v SetupWizardLaunchTime /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AcceleratedInstallRequired /f
```

# Disable WU Driver Updates

"Do not include drivers with Windows Updates", "Prevent device metadata retrieval from the Internet":

```ps
{
	"File":  "WindowsUpdate.admx",
	"NameSpace":  "Microsoft.Policies.WindowsUpdate",
	"Class":  "Machine",
	"CategoryName":  "WindowsUpdateOffering",
	"DisplayName":  "Do not include drivers with Windows Updates",
	"ExplainText":  "Enable this policy to not include drivers with Windows quality updates.If you disable or do not configure this policy, Windows Update will include updates that have a Driver classification.",
	"Supported":  "Windows_10_0_NOARM",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate",
	"KeyName":  "ExcludeWUDriversInQualityUpdate",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "DeviceSetup.admx",
	"NameSpace":  "Microsoft.Policies.DeviceSoftwareSetup",
	"Class":  "Machine",
	"CategoryName":  "DeviceInstall_Category",
	"DisplayName":  "Do not search Windows Update",
	"ExplainText":  "This policy setting allows you to specify the order in which Windows searches source locations for device drivers. If you enable this policy setting, you can select whether Windows searches for drivers on Windows Update unconditionally, only if necessary, or not at all.Note that searching always implies that Windows will attempt to search Windows Update exactly one time. With this setting, Windows will not continually search for updates. This setting is used to ensure that the best software will be found for the device, even if the network is temporarily available.If the setting for searching only if needed is specified, then Windows will search for a driver only if a driver is not locally available on the system.If you disable or do not configure this policy setting, members of the Administrators group can determine the priority order in which Windows searches source locations for device drivers.",
	"Supported":  "Windows7",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows",
	"KeyName":  "DriverSearching",
	"Elements":  [
						{
							"Type":  "Enum",
							"ValueName":  "SearchOrderConfig",
							"Items":  [
										{
											"DisplayName":  "Always search Windows Update",
											"Value":  "1"
										},
										{
											"DisplayName":  "Search Windows Update only if needed",
											"Value":  "2"
										},
										{
											"DisplayName":  "Do not search Windows Update",
											"Value":  "0"
										}
									]
						}
					]
},
{
	"File":  "ICM.admx",
	"NameSpace":  "Microsoft.Policies.InternetCommunicationManagement",
	"Class":  "Machine",
	"CategoryName":  "InternetManagement_Settings",
	"DisplayName":  "Turn off Windows Update device driver searching",
	"ExplainText":  "This policy setting specifies whether Windows searches Windows Update for device drivers when no local drivers for a device are present.If you enable this policy setting, Windows Update is not searched when a new device is installed.If you disable this policy setting, Windows Update is always searched for drivers when no local drivers are present.If you do not configure this policy setting, searching Windows Update is optional when installing a device.Also see \"Turn off Windows Update device driver search prompt\" in \"Administrative Templates/System,\" which governs whether an administrator is prompted before searching Windows Update for device drivers if a driver is not found locally.Note: This policy setting is replaced by \"Specify Driver Source Search Order\" in \"Administrative Templates/System/Device Installation\" on newer versions of Windows.",
	"Supported":  "WindowsVistaToXPSP2",
	"KeyPath":  "Software\\Policies\\Microsoft\\Windows\\DriverSearching",
	"KeyName":  "DontSearchWindowsUpdate",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
{
	"File":  "DeviceSetup.admx",
	"NameSpace":  "Microsoft.Policies.DeviceSoftwareSetup",
	"Class":  "Machine",
	"CategoryName":  "DeviceInstall_Category",
	"DisplayName":  "Prevent device metadata retrieval from the Internet",
	"ExplainText":  "This policy setting allows you to prevent Windows from retrieving device metadata from the Internet. If you enable this policy setting, Windows does not retrieve device metadata for installed devices from the Internet. This policy setting overrides the setting in the Device Installation Settings dialog box (Control Panel \u003e System and Security \u003e System \u003e Advanced System Settings \u003e Hardware tab).If you disable or do not configure this policy setting, the setting in the Device Installation Settings dialog box controls whether Windows retrieves device metadata from the Internet.",
	"Supported":  "Windows7",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata",
	"KeyName":  "PreventDeviceMetadataFromNetwork",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
```

# Disable Windows Defender

You may have to boot into `safeboot` to apply the changes:
```bat
bcdedit /set safeboot minimal
::bcdedit /deletevalue safeboot
```
Disable windows firewall with (breaks microsoft store, netsh advfirewall, winget, sandbox, docker, WSL ([*](https://privacylearn.com/windows/privacy-over-security/disable-defender/disable-defender-firewall/disable-defender-firewall-services-and-drivers))):
```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mpsdrv" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /v Start /t REG_DWORD /d 4 /f
netsh advfirewall set allprofiles state off
```
You'll need [powerrun](https://www.sordum.org/downloads/?power-run) to apply the edits.

If the `netsh` command doesn't work:
```ps
$paths = @('HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall','HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy')
'StandardProfile','PublicProfile','PrivateProfile','DomainProfile' | % {foreach ($p in $paths) {sp -Path "$p\$_" -Name EnableFirewall -Type DWord -Value 0 -Force}}
```
Remove defender from a mounted image with the code below. Obviously, you need to change the `mount` path before running it. You can remove task leftovers after installation or in the `oobeSystem` phase with:
```bat
powershell -command "Get-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' | Unregister-ScheduledTask -Confirm:$false"
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Windows Defender" /f
rmdir /s /q "%windir%\System32\Tasks\Microsoft\Windows\Windows Defender"
```
`smartscreen.exe` may still continue to run. Renaming it will block execution:
```bat
MinSudo -NoL -P -TI cmd /c ren "%windir%\System32\smartscreen.exe" "smartscreen.exee"
```

```ps
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

> [privacy/assets | Windows-Defender.txt](https://github.com/5Noxi/win-config/blob/main/privacy/assets/Windows-Defender.txt)

# Opt-out DMA Remapping

"To ensure compatibility with Kernel DMA Protection and DMAGuard Policy, PCIe device drivers can opt into Direct Memory Access (DMA) remapping. DMA remapping for device drivers protects against memory corruption and malicious DMA attacks, and provides a higher level of compatibility for devices. Also, devices with DMA remapping-compatible drivers can start and perform DMA regardless of lock screen status. On Kernel DMA Protection enabled systems, DMAGuard Policy might block devices, with DMA remapping-incompatible drivers, connected to external/exposed PCIe ports (for example, M.2, Thunderbolt), depending on the policy value set by the system administrator. DMA remapping isn't supported for graphics device drivers. `DmaRemappingCompatible` key is ignored if `RemappingSupported` is set."

"Only use this per-driver method for Windows versions up to Windows 11 23H2. Use the [per-device method](https://github.com/5Noxi/windows-driver-docs/blob/staging/windows-driver-docs-pr/pci/enabling-dma-remapping-for-device-drivers.md#per-device-opt-in-mechanism)."

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

> https://github.com/5Noxi/windows-driver-docs/blob/staging/windows-driver-docs-pr/pci/enabling-dma-remapping-for-device-drivers.md

Example paths:
```ps
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
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/StorPort.txt

# Disable System Restore
Removes all copies (volume backups), see your current shadows with:
```cmd
vssadmin list shadows /for=<ForVolumeSpec> /shadow=<ShadowID>
```
`<ForVolumeSpec>` -> Volume
`<ShadowID>` -> Shadow copy specified by ShadowID

Remove it with:
```cmd
vssadmin delete shadows /all
```
Random fact: Creating a `.bat` file for it & sending it into a discord channel will detect it as a virus.

```ps
Disable-ComputerRestore -Drive "C:\"
```
Does:
```ps
"wmiprvse.exe", "RegSetValue","HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\RPSessionInterval","Type: REG_DWORD, Length: 4, Data: 0"
```

> https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/disable-computerrestore?view=powershell-5.1  
> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-delete-shadows  
> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-list-shadows  
> https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service

# Disable Downloads Blocking

```ps
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

![](https://github.com/5Noxi/win-config/blob/main/privacy/images/downblocking.png?raw=true)

# ​Disable WPBT
WPBT allows hardware manufacturers to run programs during Windows startup that may introduce unwanted software.
```
\Registry\Machine\SYSTEM\ControlSet001\Control\Session Manager : DisableWpbtExecution
```

> https://persistence-info.github.io/Data/wpbbin.html
> https://github.com/Jamesits/dropWPBT

Disable WPBT within a image (`sources\install.wim`):
```ps
dism /get-imageinfo /imagefile:"<wimpath>"
dism /mount-image /imagefile:"<wimpath>" /index:<index> /mountdir:"<tempmountdir>" /optimize /checkintegrity
reg load "HKLM\image" "<tempmountdir>\windows\system32\config\system"
reg add "HKLM\image\ControlSet001\Control\Session Manager" /v DisableWpbtExecution /t REG_DWORD /d 1 /f
reg unload "HKLM\image"
dism /unmount-image /mountdir:"<tempmountdir>" /commit /checkintegrity
```

# Block MRT via WU
MRT takes a lot of time - there are better tools. It blocks 
```ps
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
```
Blocks infection reporting, if using MRT.

![](https://github.com/5Noxi/win-config/blob/main/privacy/images/mrt.png?raw=true)