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

# Opt-Out DMA Remapping

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

# Disable WPBT

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

# Disable Bitlocker & EFS

Disable bitlocker on all volumes:
```ps
$nvbvol = Get-BitLockerVolume
Disable-BitLocker -MountPoint $nvbvol
```
> https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/
> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior
> https://learn.microsoft.com/en-us/powershell/module/bitlocker/disable-bitlocker?view=windowsserver2025-ps

`fsutil behavior set disableencryption 1` sets:
```ps
fsutil.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\FileSystem\NtfsDisableEncryption	Type: REG_DWORD, Length: 4, Data: 1
```
```
\Registry\Machine\SYSTEM\ControlSet001\Policies : NtfsDisableEncryption
\Registry\Machine\SYSTEM\ControlSet001\Control\FileSystem : NtfsDisableEncryption
```
```json
{
	"File":  "FileSys.admx",
	"NameSpace":  "Microsoft.Policies.FileSys",
	"Class":  "Machine",
	"CategoryName":  "NTFS",
	"DisplayName":  "Do not allow encryption on all NTFS volumes",
	"ExplainText":  "Encryption can add to the processing overhead of filesystem operations. Enabling this setting will prevent access to and creation of encrypted files.A reboot is required for this setting to take effect",
	"Supported":  "Windows7",
	"KeyPath":  "System\\CurrentControlSet\\Policies",
	"KeyName":  "NtfsDisableEncryption",
	"Elements":  [
					 {"Value":  "1","Type":  "EnabledValue"},
					 {"Value":  "0","Type":  "DisabledValue"}
				 ]
},
```
Enabling `NtfsDisableEncryption` (`1`) may cause Xbox games to fail to install (error code `0x8007177E` - "Allow encryption on selected disk volume to install this game"):
```py
ERROR_VOLUME_NOT_SUPPORT_EFS = 0x8007177E;
```
> [Windows API - Error Defines](https://github.com/arizvisa/BugId-mWindowsAPI/blob/904a1c0bd22c019ef6ca8313945fe38f4ca26f30/mDefines/mErrorDefines.py#L1793)

# Disable VBS (HVCI) & Hyper-V

VBS won't work if Hyper-V is disabled.

"Memory integrity is a Virtualization-based security (VBS) feature available in Windows. Memory integrity and VBS improve the threat model of Windows and provide stronger protections against malware trying to exploit the Windows kernel. VBS uses the Windows hypervisor to create an isolated virtual environment that becomes the root of trust of the OS that assumes the kernel can be compromised. Memory integrity is a critical component that protects and hardens Windows by running kernel mode code integrity within the isolated virtual environment of VBS. Memory integrity also restricts kernel memory allocations that could be used to compromise the system."

> https://www.nirsoft.net/utils/serviwin.html  
> https://www.nirsoft.net/utils/device_manager_view.html  
> https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-deviceguard-unattend  
> https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure?tabs=reg  
> https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity?tabs=security

```json
{
	"File":  "DeviceGuard.admx",
	"NameSpace":  "Microsoft.Windows.DeviceGuard",
	"Class":  "Machine",
	"CategoryName":  "DeviceGuardCategory",
	"DisplayName":  "Disabled",
	"ExplainText":  " Specifies whether Virtualization Based Security is enabled. Virtualization Based Security uses the Windows Hypervisor to provide support for security services. Virtualization Based Security requires Secure Boot, and can optionally be enabled with the use of DMA Protections. DMA protections require hardware support and will only be enabled on correctly configured devices. Virtualization Based Protection of Code Integrity This setting enables virtualization based protection of Kernel Mode Code Integrity. When this is enabled, kernel mode memory protections are enforced and the Code Integrity validation path is protected by the Virtualization Based Security feature. The \"Disabled\" option turns off Virtualization Based Protection of Code Integrity remotely if it was previously turned on with the \"Enabled without lock\" option. The \"Enabled with UEFI lock\" option ensures that Virtualization Based Protection of Code Integrity cannot be disabled remotely. In order to disable the feature, you must set the Group Policy to \"Disabled\" as well as remove the security functionality from each computer, with a physically present user, in order to clear configuration persisted in UEFI. The \"Enabled without lock\" option allows Virtualization Based Protection of Code Integrity to be disabled remotely by using Group Policy. The \"Not Configured\" option leaves the policy setting undefined. Group Policy does not write the policy setting to the registry, and so it has no impact on computers or users. If there is a current setting in the registry it will not be modified. The \"Require UEFI Memory Attributes Table\" option will only enable Virtualization Based Protection of Code Integrity on devices with UEFI firmware support for the Memory Attributes Table. Devices without the UEFI Memory Attributes Table may have firmware that is incompatible with Virtualization Based Protection of Code Integrity which in some cases can lead to crashes or data loss or incompatibility with certain plug-in cards. If not setting this option the targeted devices should be tested to ensure compatibility. Warning: All drivers on the system must be compatible with this feature or the system may crash. Ensure that this policy setting is only deployed to computers which are known to be compatible. Credential Guard This setting lets users turn on Credential Guard with virtualization-based security to help protect credentials. For Windows 11 21H2 and earlier, the \"Disabled\" option turns off Credential Guard remotely if it was previously turned on with the \"Enabled without lock\" option. For later versions, the \"Disabled\" option turns off Credential Guard remotely if it was previously turned on with the \"Enabled without lock\" option or was \"Not Configured\". The \"Enabled with UEFI lock\" option ensures that Credential Guard cannot be disabled remotely. In order to disable the feature, you must set the Group Policy to \"Disabled\" as well as remove the security functionality from each computer, with a physically present user, in order to clear configuration persisted in UEFI. The \"Enabled without lock\" option allows Credential Guard to be disabled remotely by using Group Policy. The devices that use this setting must be running at least Windows 10 (Version 1511). For Windows 11 21H2 and earlier, the \"Not Configured\" option leaves the policy setting undefined. Group Policy does not write the policy setting to the registry, and so it has no impact on computers or users. If there is a current setting in the registry it will not be modified. For later versions, if there is no current setting in the registry, the \"Not Configured\" option will enable Credential Guard without UEFI lock. Machine Identity Isolation This setting controls Credential Guard protection of Active Directory machine accounts. Enabling this policy has certain prerequisites. The prerequisites and more information about this policy can be found at https://go.microsoft.com/fwlink/?linkid=2251066. The \"Not Configured\" option leaves the policy setting undefined. Group Policy does not write the policy setting to the registry, and so it has no impact on computers or users. If there is a current setting in the registry it will not be modified. The \"Disabled\" option turns off Machine Identity Isolation. If this policy was previously set to \"Enabled in audit mode\", no further action is needed. If this policy was previously set to â€œEnabled in enforcement modeâ€, the device must be unjoined and rejoined to the domain. More details can be found at the link above. The \"Enabled in audit mode\" option copies the machine identity into Credential Guard. Both LSA and Credential Guard will have access to the machine identity. This allows users to validate that \"Enabled in enforcement mode\" will work in their Active Directory Domain. The \"Enabled in enforcement mode\" option moves the machine identity into Credential Guard. This makes the machine identity only accessible to Credential Guard. Secure Launch This setting sets the configuration of Secure Launch to secure the boot chain. The \"Not Configured\" setting is the default, and allows configuration of the feature by Administrative users. The \"Enabled\" option turns on Secure Launch on supported hardware. The \"Disabled\" option turns off Secure Launch, regardless of hardware support. Kernel-mode Hardware-enforced Stack Protection This setting enables Hardware-enforced Stack Protection for kernel-mode code. When this security feature is enabled, kernel-mode data stacks are hardened with hardware-based shadow stacks, which store intended return address targets to ensure that program control flow is not tampered. This security feature has the following prerequisites: 1) The CPU hardware supports hardware-based shadow stacks. 2) Virtualization Based Protection of Code Integrity is enabled. If either prerequisite is not met, this feature will not be enabled, even if an \"Enabled\" option is selected for this feature. Note that selecting an \"Enabled\" option for this feature will not automatically enable Virtualization Based Protection of Code Integrity, that needs to be done separately. Devices that enable this security feature must be running at least Windows 11 (Version 22H2). The \"Disabled\" option turns off kernel-mode Hardware-enforced Stack Protection. The \"Enabled in audit mode\" option enables kernel-mode Hardware-enforced Stack Protection in audit mode, where shadow stack violations are not fatal and will be logged to the system event log. The \"Enabled in enforcement mode\" option enables kernel-mode Hardware-enforced Stack Protection in enforcement mode, where shadow stack violations are fatal. The \"Not Configured\" option leaves the policy setting undefined. Group Policy does not write the policy setting to the registry, and so it has no impact on computers or users. If there is a current setting in the registry it will not be modified. Warning: All drivers on the system must be compatible with this security feature or the system may crash in enforcement mode. Audit mode can be used to discover incompatible drivers. For more information, refer to https://go.microsoft.com/fwlink/?LinkId=2162953.",
	"Supported":  "Windows_10_0",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
	"KeyName":  "EnableVirtualizationBasedSecurity",
	"Elements":  [
						{
							"Type":  "Enum",
							"ValueName":  "RequirePlatformSecurityFeatures",
							"Items":  [
										{
											"DisplayName":  "Secure Boot",
											"Value":  "1"
										},
										{
											"DisplayName":  "Secure Boot and DMA Protection",
											"Value":  "3"
										}
									]
						},
						{
							"Type":  "Enum",
							"ValueName":  "HypervisorEnforcedCodeIntegrity",
							"Items":  [
										{
											"DisplayName":  "Disabled",
											"Value":  "0"
										},
										{
											"DisplayName":  "Enabled with UEFI lock",
											"Value":  "1"
										},
										{
											"DisplayName":  "Enabled without lock",
											"Value":  "2"
										},
										{
											"DisplayName":  "Not Configured",
											"Value":  "3"
										}
									]
						},
						{
							"ValueName":  "HVCIMATRequired",
							"FalseValue":  "0",
							"TrueValue":  "1",
							"Type":  "Boolean"
						},
						{
							"Type":  "Enum",
							"ValueName":  "LsaCfgFlags",
							"Items":  [
										{
											"DisplayName":  "Disabled",
											"Value":  "0"
										},
										{
											"DisplayName":  "Enabled with UEFI lock",
											"Value":  "1"
										},
										{
											"DisplayName":  "Enabled without lock",
											"Value":  "2"
										},
										{
											"DisplayName":  "Not Configured",
											"Value":  "3"
										}
									]
						},
						{
							"Type":  "Enum",
							"ValueName":  "MachineIdentityIsolation",
							"Items":  [
										{
											"DisplayName":  "Disabled",
											"Value":  "0"
										},
										{
											"DisplayName":  "Enabled in audit mode",
											"Value":  "1"
										},
										{
											"DisplayName":  "Enabled in enforcement mode",
											"Value":  "2"
										},
										{
											"DisplayName":  "Not Configured",
											"Value":  "3"
										}
									]
						},
						{
							"Type":  "Enum",
							"ValueName":  "ConfigureSystemGuardLaunch",
							"Items":  [
										{
											"DisplayName":  "Not Configured",
											"Value":  "0"
										},
										{
											"DisplayName":  "Enabled",
											"Value":  "1"
										},
										{
											"DisplayName":  "Disabled",
											"Value":  "2"
										}
									]
						},
						{
							"Type":  "Enum",
							"ValueName":  "ConfigureKernelShadowStacksLaunch",
							"Items":  [
										{
											"DisplayName":  "Not Configured",
											"Value":  "0"
										},
										{
											"DisplayName":  "Enabled in enforcement mode",
											"Value":  "1"
										},
										{
											"DisplayName":  "Enabled in audit mode",
											"Value":  "2"
										},
										{
											"DisplayName":  "Disabled",
											"Value":  "3"
										}
									]
						},
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

# Disable Password Reveal

"This policy setting allows you to configure the display of the password reveal button in password entry user experiences. If you enable this policy setting, the password reveal button won't be displayed after a user types a password in the password entry text box. If you disable or don't configure this policy setting, the password reveal button will be displayed after a user types a password in the password entry text box. By default, the password reveal button is displayed after a user types a password in the password entry text box."

> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-credentialsui

Turn off picture password sign-in with (`CredentialProviders.admx`):
```bat
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v BlockDomainPicturePassword /t REG_DWORD /d 1 /f
```
"This policy setting allows you to control whether a domain user can sign in using a picture password. If you enable this policy setting, a domain user can't set up or sign in with a picture password. If you disable or don't configure this policy setting, a domain user can set up and use a picture password. Note that the user's domain password will be cached in the system vault when using this feature."
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/Policies-System.txt

# Disable P2P Updates

Prevents updates that would be downloaded from PCs in your network (only downloads updates from micorosoft servers).

# Increased DH & RSA Key

By default it uses a minimum size of `1024` bits (both) - hardens Windows TLS engine by forcing minimum key sizes during secure communications (SSL/TLS handshake process).

"NSA recommends RSA key transport and ephemeral DH (DHE) or ECDH (ECDHE) mechanisms, with RSA or DHE key exchange using at least 3072-bit keys and ECDHE key exchanges using the secp384r1 elliptic curve. For RSA keytransport and DH/DHE key exchange, keys less than 2048 bits should not be used, and ECDH/ECDHE using custom curves should not be used."

> https://media.defense.gov/2021/Jan/05/2002560140/-1/-1/0/ELIMINATING_OBSOLETE_TLS_UOO197443-20.PDF
> https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings?tabs=diffie-hellman

# Disable Insecure Connections

Disables insecure protocols, ciphers, renegotiation, hashes, and forces .NET apps to use strong cryptography. Windows may use insecure connections for e.g. older software (compatibility reasons), so disabling them can cause issues with old software.

| Setting                                                    | Description                                                                                                                                                                                                              | Registry security level |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------- |
| Send LM & NTLM responses                                   | Client devices use LM and NTLM authentication, and they never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication.                                                                | 0                       |
| Send LM & NTLM – use NTLMv2 session security if negotiated | Client devices use LM and NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.                                            | 1                       |
| Send NTLM response only                                    | Client devices use NTLMv1 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.                                                 | 2                       |
| Send NTLMv2 response only                                  | Client devices use NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.                                                 | 3                       |
| Send NTLMv2 response only. Refuse LM                       | Client devices use NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers refuse to accept LM authentication, and they'll accept only NTLM and NTLMv2 authentication. | 4                       |
| Send NTLMv2 response only. Refuse LM & NTLM                | Client devices use NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers refuse to accept LM and NTLM authentication, and they'll accept only NTLMv2 authentication. | 5                       |

Level `5` gets applied.

> https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls#schusestrongcrypto  
> https://dirteam.com/sander/2019/07/30/howto-disable-weak-protocols-cipher-suites-and-hashing-algorithms-on-web-application-proxies-ad-fs-servers-and-windows-servers-running-azure-ad-connect/  
> https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level

![](https://github.com/5Noxi/win-config/blob/main/privacy/images/insecureconn.png?raw=true)

Enable DTLS 1.2 & TLS 1.3 with:
```ps
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowBasic /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v restrictnullsessaccess /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
```

# Enable USB Write Protection
Restricts write access to USB devices (read only). You can also change it with `diskpart`, by selecting the disk with `select disk` and chaning it to read only with `attributes disk set readonly` (revert it with `attributes disk clear readonly`). Revert the batch changes by removing the value or chaning it to `0`.

Disable USB connection errors (for whatever reason):
```bat
reg add "HKCU\Software\Microsoft\Shell\USB" /v NotifyOnUsbErrors /t REG_DWORD /d 0 /f
```