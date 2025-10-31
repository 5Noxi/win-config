# Disable Device Powersavings

Disables USB selective suspend, idle power management, and related LP features.

`Device-Powersavings.ps1` includes some comments, which can be tested - if not, leave them.

I added some comments to `QueryUsbflagsValuesForDevice.c`, since they renamed the values.

> https://discord.com/channels/836870260715028511/1326527941051678801/1375576361762295809
> https://discord.com/channels/836870260715028511/1326527941051678801/1375576424668336248
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/pci.txt
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/Enum-USB.txt

`pci.inf`:
```c
// D3 cold supported.
[PciD3ColdSupported]
Needs=PciD3ColdSupported.HW

[PciD3ColdSupported.HW]
AddReg=PciD3ColdSupported.RegHW

[PciD3ColdSupported.RegHW]
HKR,e5b3b5ac-9725-4f78-963f-03dfb1d828c7,D3ColdSupported,0x10001,1
```

> [power/assets | devicepower-HidpFdoConfigureIdleSettings.c](https://github.com/5Noxi/win-config/blob/main/power/assets/devicepower-HidpFdoConfigureIdleSettings.c)  
> [power/assets | devicepower-UsbhGetD3Policy.c](https://github.com/5Noxi/win-config/blob/main/power/assets/devicepower-UsbhGetD3Policy.c)  
> [power/assets | devicepower-QueryUsbflagsValuesForDevice.c](https://github.com/5Noxi/win-config/blob/main/power/assets/devicepower-QueryUsbflagsValuesForDevice.c)

---

Miscellaneous comments:
```ps
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\usbhub\hubg' -Name 'DisableSelectiveSuspendUI' -Value 1
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\usbhub\hubg' -Name 'DisableUxdSupport' -Value 1
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\usbhub\hubg' -Name 'WakeOnConnectUI' -Value 0
HcDisableAllSelectiveSuspend
WinUsbPowerPolicyOwnershipDisabled

$dev = @(
    'DefaultIdleState'
    'EnableSelectiveSuspend'
    'FullPowerDownOnTransientDx'
    'SelSuspCancelBehavior'
    'SuppressInputInCS'
    'SystemInputSuppressionEnabled'
    'SystemWakeEnabled'
    'WaitWakeEnabled'
    'WakeScreenOnInputSupport'
    'WriteReportExSupported'
)
$devsub = @(
    'DeviceD0DelayTime'
    'DevicePowerResetDelayTime'
)
```
```c
// Opt-out of ASPM.
[PciASPMOptOut]
Needs=PciASPMOptOut.HW

[PciASPMOptOut.HW]
AddReg=PciASPMOptOut.RegHW

[PciASPMOptOut.RegHW]
HKR,e5b3b5ac-9725-4f78-963f-03dfb1d828c7,ASPMOptOut,0x10001,1

// Opt-in to ASPM.
[PciASPMOptIn]
Needs=PciASPMOptIn.HW

[PciASPMOptIn.HW]
AddReg=PciASPMOptIn.RegHW

[PciASPMOptIn.RegHW]
HKR,e5b3b5ac-9725-4f78-963f-03dfb1d828c7,ASPMOptIn,0x10001,1
```

> [power/assets | devicepower-OptInOptOutPolicy.c](https://github.com/5Noxi/win-config/blob/main/power/assets/devicepower-OptInOptOutPolicy.c)

# Disable Hibernation

```c
dq offset aPower_2      ; "Power" // HKLM\SYSTEM\CurrentControlSet\Control\Power
dq offset aHibernateenabl_0 ; "HibernateEnabledDefault"
dq offset PopHiberEnabledDefaultReg
lkd> dq PopHiberEnabledDefaultReg l1
fffff806`c53c327c  ffffffff`ffffffff // 4294967295

dq offset aAllowhibernate ; "AllowHibernate"
dq offset PopAllowHibernateReg
lkd> dq PopAllowHibernateReg l1
fffff806`c53c30f4  ffffffff`ffffffff
```
`powercfg.exe /hibernate off`

`HibernateEnabledDefault`, `AllowHibernate` take a default value of `4294967295` dec. `hiber.c` includes some snippets (notes).
> https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/disable-and-re-enable-hibernation  
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/Power.txt

# Remove Power Options

Removes the `Hibernate`, `Lock`, `Sleep` power options.

# Disable Hiberboot

```json
{
    "File":  "WinInit.admx",
    "NameSpace":  "Microsoft.Policies.WindowsInitialization",
    "Class":  "Machine",
    "CategoryName":  "ShutdownOptions",
    "DisplayName":  "Require use of fast startup",
    "ExplainText":  "This policy setting controls the use of fast startup. If you enable this policy setting, the system requires hibernate to be enabled.If you disable or do not configure this policy setting, the local setting is used.",
    "Supported":  "Windows8",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\System",
    "KeyName":  "HiberbootEnabled",
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

# Disable Power Throttling

```
Power throttling, introduced in W10 and present in W11, limits CPU usage for background or minimized applications. It reduces the processing power available to these apps while allowing active applications to run normally.
```
You can see processes, which use power throttling by enabling the column (`Details` > `Select Column`) or add it to the active columns in system informer via the `Choose columns...` window (picture).
> https://systeminformer.io/

```c
dq offset aPowerPowerthro ; "Power\\PowerThrottling"
dq offset aPowerthrottlin ; "PowerThrottlingOff"
dq offset PpmPerfQosGroupPolicyDisable

PpmPerfQosGroupPolicyDisable dd 0 // Throttling enabled
```

![](https://github.com/5Noxi/win-config/blob/main/power/images/powerth.png?raw=true)

# Disable Energy Estimation

Not needed, if you disable energy estimation:
```
\Registry\Machine\SYSTEM\ControlSet001\Control\Power\EnergyEstimation\TaggedEnergy : DisableTaggedEnergyLogging
\Registry\Machine\SYSTEM\ControlSet001\Control\Power\EnergyEstimation\TaggedEnergy : TelemetryMaxApplication
\Registry\Machine\SYSTEM\ControlSet001\Control\Power\EnergyEstimation\TaggedEnergy : TelemetryMaxTagPerApplication
```
```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v DisableTaggedEnergyLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v TelemetryMaxApplication /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v TelemetryMaxTagPerApplication /t REG_DWORD /d 0 /f
```

> [power/assets | energyesti-PtInitializeTelemetry.c](https://github.com/5Noxi/win-config/blob/main/power/assets/energyesti-PtInitializeTelemetry.c)

![](https://github.com/5Noxi/win-config/blob/main/power/images/energyesti.png?raw=true)

# Powerplan

Use the commands below, to import power plans by double-clicking them. Modify the powerplan via `PowerSettingsExplorer.exe`.
> http://www.mediafire.com/file/wt37sbsejk7iepm/PowerSettingsExplorer.zip

```ps
reg add "HKCR\.pow" /ve /t REG_SZ /d "Power Plan" /f
reg add "HKCR\.pow" /v FriendlyTypeName /t REG_SZ /d "Power Plan" /f
reg add "HKCR\.pow\DefaultIcon" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\powercfg.cpl,-202" /f
reg add "HKCR\.pow\shell\Import" /f
reg add "HKCR\.pow\shell\Import\command" /ve /t REG_SZ /d "powercfg /import \"%%1\"" /f
```
Remove default powerplans with:
```bat
powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a
powercfg -delete e9a42b02-d5df-448d-aa00-03f14749eb61
```
> https://bitsum.com/known-windows-power-guids/

```bat
powercfg /availablesleepstates (or /a)
```
Shows the current available sleep states on your system.

> https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#option_availablesleepstates

# Disable HDD Parking

Disables HIPM, DIPM, and HDD Parking, preventing storage devices from entering low-power states.

---

Miscellaneous information:
```
HIPM = Host Initiated Link Power Management
DIPM = Device Initiated Link Power Management
```
`EnableDIPM` is set to `0` by default.
```c
Dst[37] = L"EnableHIPM";
LODWORD(Dst[11]) = 4;
Dst[38] = &dword_4C134;
Dst[40] = &dword_4C134;
Dst[44] = L"EnableDIPM";
LODWORD(Dst[13]) = 4;
Dst[45] = &dword_5D0C8;
Dst[47] = &dword_5D0C8;
Dst[58] = L"EnableHDDParking";
LODWORD(Dst[18]) = 4;
Dst[59] = &dword_4C13C;
Dst[61] = &dword_4C13C;

dword_5D0CC = 0;
dword_5D0C8 = 0;
dword_4C434 = 0;
dword_4C12C = -1;
dword_4C138 = -1;
dword_4C134 = -1;
dword_4C424 = 16;
dword_4C420 = 3000;
dword_5D510 = 1;
dword_4C13C = 1;
dword_4C130 = 1;
dword_4C140 = -1;
```

> [power/assets | hddpark-amdsbs.c](https://github.com/5Noxi/win-config/blob/main/power/assets/hddpark-amdsbs.c)

More values, which may work:
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Storage" /v StorageD3InModernStandby /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v IdlePowerMode /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorv" /v EnableAPM /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorv\Parameters" /v EnableAPM /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v EnableAPM /t REG_DWORD /d 0 /f
```
> https://github.com/5Noxi/wpr-reg-records#wpr--procmon-registry-activity-records

Needs more research (`ClassGetServiceParameter.c` - default `0`?):
```
\Registry\Machine\SYSTEM\ControlSet001\Services\disk : IdleClassSupported
```
Additional notes: `EnableALPEDisableHotplug` (`0`), `AhciDisablePxHotplug` - `amdsbs.c`

> https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/disk-settings-link-power-management-mode---hipm-dipm

> [power/assets | hddpark-ClassGetServiceParameter.c](https://github.com/5Noxi/win-config/blob/main/power/assets/hddpark-ClassGetServiceParameter.c)
> [power/assets | hddpark-DllInitialize.c](https://github.com/5Noxi/win-config/blob/main/power/assets/hddpark-DllInitialize.c)

# Disable Storport Idle

"Storport provides support for idle power management to allow storage devices to enter a low power state when not in use. Storport's idle power management (IPM) support includes handling idle power management for storage devices under its management, in coordination with the Power Manager in Windows.

Storport IPM allows the classpnp and disk class drivers to send the SCSI Stop Unit command to the storage device when it's idle for some period of time. The idle period is configurable by the system administrator. The Storport miniport driver is responsible for how the command is used by the Storport miniport driver to conserve power.

Storport Idle Power Management (IPM) isn't enabled by default. It can be enabled in the registry by setting the "EnableIdlePowerManagement" value in the "StorPort" subkey of the device's hardware key to any nonzero value. To do so, use the device INF file or manually edit the registry using the registry editor."

> https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/registry-entries-for-storport-miniport-drivers  
> https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/storage/storport-idle-power-management.md  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/ipm-configuration-and-usage  
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/pci.txt
> [power/assets | storport.c](https://github.com/5Noxi/win-config/blob/main/power/assets/storport.c)

# NoLazyMode

`NoLazyMode` = `0` (default)
`LazyModeTimeout` = `1000000` (default)


It sets `NoLazyMode` to `0`, don't set it to `1`. This is currently more likely a placeholder for future documentation. Instead of using `NoLazyMode`, change `LazyModeTimeout`.
```
\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MultiMedia\systemprofile : NoLazyMode
```
`AlwaysOn` value exists in W7 and W8, but doesn't exist in W10 and W11 anymore.

"The screenshot below demonstrates some of the initial differences between each mode enabled (0x1) vs off (x0, Non-Present), during these tests MMCSS tasks were engaged and the same pattern reoccurred each time e.g. the Idle related conditions were no longer present leaving only System Responsiveness, Deep Sleep and Realtime MMCSS scheduler task results."

> https://github.com/djdallmann/GamingPCSetup/blob/master/CONTENT/RESEARCH/WINSERVICES/README.md#q-what-the-heck-is-nolazymode-is-it-real-what-does-it-do
> https://github.com/djdallmann/GamingPCSetup/blob/master/CONTENT/RESEARCH/WINSERVICES/README.md#q-does-the-mmcss-alwayson-registry-setting-exist

![](https://github.com/5Noxi/win-config/blob/main/power/images/nolazymode.png?raw=true)

# Disable Timer Coalescing

"CoalesecingTimerinterval is a computer system energy-saving technique that reduces CPU power consumption by reducing the precision of software timers to allow the synchronization of process wake-ups, minimizing the number of times the CPU is forced to perform the relatively power-costly operation of entering and exiting idle states"

```c
PopCoalescingTimerInterval dd 5DCh // 1500
PopDeepIoCoalescingEnabled dd 0
```
```c
void InitTimerPowerSaving(void)
{
  UserSessionState = W32GetUserSessionState();
  FastGetProfileDword(0LL, 2LL, L"RITdemonTimerPowerSaveElapse", 43200000LL, UserSessionState + 62692); // 12H?
  v1 = W32GetUserSessionState();
  FastGetProfileDword(0LL, 2LL, L"RITdemonTimerPowerSaveCoalescing", 43200000LL, v1 + 62696); // 12H?
}
```
```c
lkd> dd PopCoalescingTimerInterval l1
fffff806`d300b1b8  000005dc

lkd> dd PopDeepIoCoalescingEnabled l1
fffff806`d31c3278  00000000
```

The `CoalescingTimerInterval` value exist (takes a default of `1500` dec, `DeepIo...` one is set to `0` by default - both are located in `ntoskrnl.exe`), but doesn't get read on 24H2, the `RIT...` & `TimerCoalescing` ones get read.

`TimerCoalescing` is a binary value (`v18 == 3`) with a size of 80 bytes (`v19 == 80`). `InitTimerCoalescing.c` shows all info about it, the batch should add it correctly, still needs some further reading. `InitTimerCoalescing.c` includes detail about it and some comments I added.
> https://discord.com/channels/836870260715028511/1371224441568231516/1372988981817380935
```c
v20[0..3] = 0
v20[4..7] ≤ 0x7FFFFFF5 // 0 = default timer coalescing?
v20[8..11] = 0
v20[12..15] ≤ 0x7FFFFFF5 // ^
v20[16..19] = 0
```
`Coalescing-Timer-Interval.bat` would currently use the upper bound (`ToleranceDelay`?)
```ps
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v TimerCoalescing /t REG_BINARY /d 00000000000000000000000000000000F5FFFF7FF5FFFF7FF5FFFF7FF5FFFF7F00000000000000000000000000000000F5FFFF7FF5FFFF7FF5FFFF7FF5FFFF7F00000000000000000000000000000000 /f
```
I removed it, since it causes a BSOD on my testing VMs.

> [power/assets | coalesc-InitTimerCoalescing.c](https://github.com/5Noxi/win-config/blob/main/power/assets/coalesc-InitTimerCoalescing.c)  
> https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setcoalescabletimer ?

![](https://github.com/5Noxi/win-config/blob/main/power/images/coalesc1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/power/images/coalesc2.png?raw=true)

# Disable USB Battery Saver 

Used to stop USB devices when your screen is off - Obviously only for laptop users.

```
Stop USB devices when my screen is off to help battery.
```
`Bluetooth & devices` > `USB` > `USB battery saver`

> [power/assets | usbbattery-OpenQueryAttemptRecoveryFromUsbPowerDrainValue](https://github.com/5Noxi/win-config/blob/main/power/assets/usbbattery-OpenQueryAttemptRecoveryFromUsbPowerDrainValue)  

---

Miscellaneous notes:
```ps
for /f "delims=" %%k in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\USB" /s /f "AttemptRecoveryFromUsbPowerDrain" ^| findstr "HKEY"') do reg add "%%k" /v AttemptRecoveryFromUsbPowerDrain /t REG_DWORD /d 0 /f
```

# USB Flags

In `USBXHCI.SYS`. Disables S0 idle on the host controller - remains in the working state (S0)?
```
\Registry\Machine\SYSTEM\ControlSet001\Control\usbflags : Allow64KLowOrFullSpeedControlTransfers
\Registry\Machine\SYSTEM\ControlSet001\Control\usbflags : DisableHCS0Idle
```
I didn't do proper research for them, either test them or leave it:
```ps
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\usbflags' -ErrorAction SilentlyContinue | ForEach-Object {
    Set-ItemProperty -Path $_.PSPath -Name 'DisableOnSoftRemove' -Value 1
    Set-ItemProperty -Path $_.PSPath -Name 'DisableRecoveryFromPowerDrain' -Value 0
    Set-ItemProperty -Path $_.PSPath -Name 'DisableLPM' -Value 1
}
```
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/USB-Flags.txt

# Disable Audio Idle

| Parameter              | Desc                                                                          | Default  | notes                                                                 |
| ---------------------- | ----------------------------------------------------------------------------- | -------- | --------------------------------------------------------------------- |
| `ConservationIdleTime` | Idle timeout (in seconds) used when the system is in power-conservation mode. | `0`      | `0` disables the inactivity timer for this mode, value is in seconds. |
| `PerformanceIdleTime`  | Idle timeout (in seconds) used when the system is in performance mode.        | `0`      | `0` disables the inactivity timer for this mode, value is in seconds. |
| `IdlePowerState`       | Device power state to enter when the inactivity timeout expires (D0–D3).      | `3` (D3) | Valid values `0–3` map to `D0–D3`.                                    |

I currently disable it, by setting the timeouts to `ff ff ff ff` (`~4.29e9 s ≈ 136 years`) & `IdlePowerState` to `0` (`D0`).

| Parameter              | Type           | Revert Hex data     | Parsed value                      | Meaning                       |
| ---------------------- | -------------- | ------------------- | --------------------------------- | ----------------------------- |
| `ConservationIdleTime` | REG_BINARY (3) | `1e,00,00,0`        | malformed; if `1e,00,00,00` -> 30s | `10s` on battery              |
| `PerformanceIdleTime`  | REG_BINARY (3) | `00,00,00,00`       | 0 seconds                         | No idle mgmt on AC            |
| `IdlePowerState`       | REG_BINARY (3) | `03,00,00,00`       | 3                                 | Go to `D3` when idle          |

| Category   | Class | Class GUID                           | Description                                                                                       |
| ---------- | ----- | ------------------------------------ | ------------------------------------------------------------------------------------------------- |
| Multimedia | Media | 4d36e96c-e325-11ce-bfc1-08002be10318 | Includes Audio and DVD multimedia devices, joystick ports, and full-motion video capture devices. |

> https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/audio-device-class-inactivity-timer-implementation  
> https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/audio-subsystem-power-management-for-modern-standby-platforms  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors

# Disable NVMe Perf Throttling

It get intialized, unsure what exactly it does. Might be related to thermal throttling (controller cuts IOPS and bandwidth to lower heat and protect the drive)?

The default data is `0` if the value is missing, but for new installations it's present with the value `1`. Il'll still leave it in here for documentation reasons.

```c
ResultLength = 0;
DestinationString = 0LL;
RtlInitUnicodeString(&DestinationString, L"NVMeDisablePerfThrottling");
if (ZwQueryValueKey(
        KeyHandle,
        &DestinationString,
        KeyValuePartialInformation,
        KeyValueInformation,
        0x110u,
        &ResultLength) < 0)           // query failed
{
    ClassNVMeDisablePerfThrottling = 0; // default if missing
}
else if (v6 == 4 && ResultLength >= 4)  // REG_DWORD
{
    ClassNVMeDisablePerfThrottling = (v7 != 0); // non zero = disable throttling
}
```

> https://github.com/5Noxi/wpr-reg-records/blob/main/records/Classpnp.txt  
> [power/assets | nvmeperf-ClassUpdateDynamicRegistrySettings.c](https://github.com/5Noxi/win-config/blob/main/power/assets/nvmeperf-ClassUpdateDynamicRegistrySettings.c)

# Disable Storage Idle States

Disables idle states for NVMe, SSD, SD, HDD. This is currently more of a possible idea. 

If `IdleStatesNumber` is set, the other values are ignored? Let me know if you have a better interpretation.

> The values are located in the `EnergyEstimation` (guesses how much power is used over time), so it's probably related to something else. I'll leave it for documentation reasons (and future extended declaration).

> https://github.com/5Noxi/wpr-reg-records/blob/main/records/Power.txt  
> [power/assets | storageidle-PmPowerContextInitialization.c](https://github.com/5Noxi/win-config/blob/main/power/assets/nvmeperf-ClassUpdateDynamicRegistrySettings.c)

# Disable PM in Standby Mode

This policy setting specifies that power management is disabled when the machine enters connected standby mode.
- If this policy setting is enabled, Windows Connection Manager doesn't manage adapter radios to reduce power consumption when the machine enters connected standby mode.
- If this policy setting isn't configured or is disabled, power management is enabled when the machine enters connected standby mode.

```json
{
    "File":  "WCM.admx",
    "NameSpace":  "Microsoft.Policies.WindowsConnectionManager",
    "Class":  "Machine",
    "CategoryName":  "WCM_Category",
    "DisplayName":  "Disable power management in connected standby mode",
    "ExplainText":  "This policy setting specifies that power management is disabled when the machine enters connected standby mode.If this policy setting is enabled, Windows Connection Manager does not manage adapter radios to reduce power consumption when the machine enters connected standby mode.If this policy setting is not configured or is disabled, power management is enabled when the machine enters connected standby mode.",
    "Supported":  "Windows8",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy",
    "KeyName":  "fDisablePowerManagement",
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
```ps
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\GroupPolicy : fAllowFailoverToCellular
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\GroupPolicy : fBlockNonDomain
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\GroupPolicy : fBlockRoaming
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\GroupPolicy : fDisablePowerManagement
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\GroupPolicy : fMinimizeConnections
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\GroupPolicy : fSoftDisconnectConnections
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\Local : fAllowFailoverToCellular
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\Local : fBlockNonDomain
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\Local : fBlockRoaming
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\Local : fDisablePowerManagement
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\Local : fMinimizeConnections
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\Local : fSoftDisconnectConnections
```