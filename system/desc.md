# Disable Service Splitting

Prevents services running under `svchost.exe` from being split into separate processes, keeping all grouped services within the same instance. This simplifies process management but increases the risk of system instability and reduces service isolation.

`Windows Internals 7th Edition, Part 2` handpicked snippets (shortened):
If system physical memory, obtained via `GlobalMemoryStatusEx`, exceeds the SvcHostSplitThresholdInKB registry value (default is `3.5 GB` on client systems and `3.7 GB` on server systems), Svchost service splitting is enabled.

Service splitting is allowed only if:  
- Splitting is globally enabled
- The service is not marked as critical (i.e., it doesn't reboot the machine on failure)
- The service is hosted in `svchost.exe`
- `SvcHostSplitDisable` is not set to `1` in the service registry key

Setting `SvcHostSplitDisable` to `0` for a critical service forces it to be split, but this can lead to issues.

Get the current amount of `svchost` process instances with:
```cmd
(get-process -Name "svchost" | measure).Count
```
```
\Registry\Machine\SYSTEM\ControlSet001\Control : SvcHostDebug
\Registry\Machine\SYSTEM\ControlSet001\Control : SvcHostSplitThresholdInKB
```
`SvcHostDebug` is set to `0` by default:
```c
v1 = 0;
if ( !RegistryValueWithFallbackW && Type == 4 )
    LOBYTE(v1) = Data != 0;
return v1;
```

> [system/assets | servicesplitting-ScReadSCMConfiguration.c](https://github.com/nohuto/win-config/blob/main/system/assets/servicesplitting-ScReadSCMConfiguration.c)  
> https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf (page `467`f)  
> https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring  
> https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex

![](https://github.com/nohuto/win-config/blob/main/system/images/servicesplitting1.png?raw=true)

## Windows Internals

![](https://github.com/nohuto/win-config/blob/main/system/images/servicesplitting2.png?raw=true)

# Kernel Values

Since many people don't yet know which values exist and what default value they have, here's a list. I used IDA, WinDbg, WinObjEx, Windows Internals E7 P1 to create it. Many applied values are defaults, some not. See documentation below for details. The applied data is sometimes pure speculation.

See win-registry repo for a list of `CCS\\Control\\Session Manager\\...` values/defaults/notes:
> https://github.com/nohuto/win-registry#session-manager-values

## Windows Internals

![](https://github.com/nohuto/win-config/blob/main/system/images/kernel0.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/kernel1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/kernel2.png?raw=true)

## Notes on SerializeTimerExpiration

`0` = depends on `HalpAcpiAoacCapable`, can end up with `0`/`1`. `HalpSetPlatformFlags` checks if bit 21
```c
if ( (*(_DWORD *)(a1 + 112) & 0x200000) != 0 )
  HalpPlatformFlags |= 8u;
```
is set or not, if set it's `1`, if not `0`.
```
LOW_POWER_S0_IDLE_CAPABLE Bit offset 21. Indicates that the platform supports low-power idle states within the ACPI S0 system power state that are more energy efficient than any Sx sleep state. If this flag is set, Windows won't try to sleep and resume, but will instead use platform idle states and connected standby.
```
Means for desktops/servers it's usually `0`, since "S0 Low‑Power Idle/Modern Standby" is more of a laptop/tablet thing.

You can check if the bit is true or false using [iasl & acpidump](https://github.com/acpica/acpica).

`1` = forced on (uses CPU 0 `KiProcessorBlock[0]`)
`>=2` = forced `0`

This isn't completey, it's currently only for the data ranges.

![](https://github.com/nohuto/win-config/blob/main/system/images/kernel-ste.png?raw=true)

Read more about 'Timer expiration' in [Windows Interals E7, P1, P.66f](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf).

# DXG Kernel Values

`dxgkrnl.sys` is Windows DirectX/WDDM graphics kernel driver that mediates between apps and the GPU to schedule work, manage graphics memory, present frames, and handle TDR hang recovery.

> https://github.com/nohuto/win-registry/blob/main/records/Graphics-Drivers.txt

Many applied values are defaults, some not. See documentation below for details. The applied data is sometimes pure speculation.

See win-registry repo for a list of `CCS\\Control\\GraphicsDrivers\\...` values/defaults/notes:
> https://github.com/nohuto/win-registry#dxg-kernel-values

# DWM Values

This option currently includes some speculations and default values. I haven't had time yet to test the behavior of the changed data.

See win-registry repo for a list of `SOFTWARE\\Microsoft\\Windows\\Dwm\\...` values/defaults/notes:
> https://github.com/nohuto/win-registry#dwm-values

# Quantum/Priority Separation

A quantum is the amount of time a thread is permitted to run before Windows checks to see whether another thread at the same priority is waiting to run. If a thread completes its quantum and there are no other threads at its priority, Windows permits the thread to run for another quantum.

You can calculate the clock cycles per quantum by dumping the value of `KiCyclesPerClockQuantum` (`dd nt!KiCyclesPerClockQuantum L1`), or follow the 'EXPERIMENT: Determining the clock cycles per quantum' in Windows Internals E7, P1.

Gets applied with:
```c
PsChangeQuantumTable(0, PsRawPrioritySeparation);
```

Only the first 6 bits are used (`PsChangeQuantumTable` = `a2 & 3` (bit 0/1), `a2 & 0xC` (bit 2/3), `a2 & 0x30` (bit 4/5)).

Client defaults are short + variable. Server defaults are long + fixed.

## Bits 0/1

"*For each extra priority level (up to 2), another quantum is given to the thread. For example, if the thread receives a boost of one priority level, it receives an extra quantum as well. By default, Windows sets the maximum possible priority boost to foreground threads, meaning that the priority separation will be 2, which means quantum index 2 is selected in the variable quantum table. This leads to the thread receiving two extra quantums, for a total of three quantums.*"

Clamped to `2`:
```c
v3 = a2 & 3;
if ( v3 >= 2 )
  v3 = 2;
PsPrioritySeparation = v3;
```

`00` = `0`: no foreground quantum advantage, foreground priority adds `+0` in boost part ("*The threads of foreground processes get the same amount of processor time as the threads of background processes and as the threads of processes with a priority class of Idle.*")  
`01` = `1`: foreground priority adds `+1` ("*2:1. The threads of foreground processes get twice the processor time as the threads of background processes each time they are scheduled for the processor.*")  
`10` = `2`: foreground priority adds `+2` ("*3:1. The threads of foreground processes get three times the processor time as the threads of background processes each time they are scheduled for the processor.*")  
`11` = `2`: same behavior as `10` because of the clamp.

## Bits 2/3

"*Determine whether the length of processor time varies or is fixed. It also determines whether the threads of foreground processes have longer processor intervals than those of background processes. If the processor interval is fixed, that interval applies equally to the threads of foreground and background processes. If the processor interval varies, the length of time each thread runs varies, but the ratio of processor time of foreground threads to background threads is fixed.*

*If a variable interval is specified, the ratio of foreground thread processor time to background thread processor time is determined by the value of the lowest set of bits.*"

```c
v5 = a2 & 0xC;
if ( (a2 & 0xC) != 0 )
{
  if ( v5 == 4 ) // 01
  {
    v8 = (char *)&PspVariableQuantums;
    goto LABEL_7;
  }
  if ( v5 == 8 ) // 10
  {
    v8 = PspFixedQuantums;
    goto LABEL_7;
  }
}
IsThisAnNtAsSystem = MmIsThisAnNtAsSystem();
v7 = (__int64 *)PspFixedQuantums;
if ( !IsThisAnNtAsSystem )
  v7 = &PspVariableQuantums;
v8 = (char *)v7;
```

`00` (`0x0`): server selects fixed table, client selects variable table.  
`01` (`0x4`): forces PspVariableQuantums.  
`10` (`0x8`): forces PspFixedQuantums.  
`11` (`0xC`): same as `00`.

## Bits 4/5

"*Determine how long the threads of processes are permitted to run each time they are scheduled. This interval is specified as a range because threads can be preempted and processor time is not precisely determined.*"

```c
LABEL_7:
  v9 = a2 & 0x30;
  if ( !v9 )
  {
LABEL_8:
    if ( !MmIsThisAnNtAsSystem() )
      goto LABEL_9;
    goto LABEL_22;
  }
  if ( v9 != 16 )
  {
    if ( v9 == 32 )
      goto LABEL_9;
    goto LABEL_8;
  }
LABEL_22:
  v8 += 3;
LABEL_9:
  PspForegroundQuantum = *(_WORD *)v8;
  result = v8[2];
```

`00` (`0x0`): server `goto LABEL_22` (longer intervals), client `goto LABEL_9` (shorter intervals).  
`01` (`0x10`): longer intervals.  
`10` (`0x20`): goes directly to `LABEL_9` = shorter intervals.  
`11` (`0x30`): falls to `LABEL_8`, so same behavior as `00`.

Note that everything above is based on 23H2 and is not complete yet.

I won't add much more details here since [Windows Internals E7, P1](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf) contains details, see 'Quantum / Priority Boosts' (Chapter 3).

> https://github.com/nohuto/decompiled-pseudocode/tree/main/ntoskrnl/PsChangeQuantumTable.c  
> https://github.com/nohuto/decompiled-pseudocode/tree/main/ntoskrnl/PspComputeQuantum.c  
> https://github.com/nohuto/decompiled-pseudocode/tree/main/ntoskrnl/PspInitPhase0.c  
> https://github.com/nohuto/decompiled-pseudocode/tree/main/ntoskrnl/MmIsThisAnNtAsSystem.c  
> https://github.com/nohuto/decompiled-pseudocode/tree/main/ntoskrnl/KeSetQuantumProcess.c  
> https://github.com/nohuto/decompiled-pseudocode/tree/main/ntoskrnl/KeStartThread.c  
> https://github.com/nohuto/decompiled-pseudocode/tree/main/ntoskrnl/KiSetQuantumTargetThread.c  
> https://github.com/nohuto/decompiled-pseudocode/tree/main/ntoskrnl/KiInitializeForegroundBoostThread.c  
> https://github.com/nohuto/decompiled-pseudocode/tree/main/ntoskrnl/KiComputeEffectivePriority.c  
> https://github.com/nohuto/decompiled-pseudocode/tree/main/ntoskrnl/NtSetSystemInformation.c  
> https://github.com/nohuto/decompiled-pseudocode/tree/main/ntoskrnl/CmInitSystem0.c  
> https://github.com/nohuto/decompiled-pseudocode/tree/main/ntoskrnl/CmpGetSystemControlValues.c

---

Miscellaneous notes:
```c
// from procmon boot trace
"HKLM\\System\\CurrentControlSet\\Control\\PriorityControl";
    "ConvertibilityEnabled" = ?;
    "ConvertibleSlateMode" = 0; // REG_DWORD
    "SystemDockMode" = ?;
    "Win32PrioritySeparation" = 2;
```

# MMCSS Values

See win-registry repo for a list of `SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\multimedia\\systemprofile\\...` values/defaults/notes:
> https://github.com/nohuto/win-registry#mmcss-values

## SystemResponsiveness Details

By default, multimedia threads get 80 percent of the CPU time available, while other threads receive 20 percent.

Note that when `SystemResponsiveness == 100` it would end up with skipping the part after `if ( CiSystemResponsiveness == 100 )`, the task init (`CiConfigInitializeFromRegistry`), thread priorities (didn't look futher into it yet, see [CiThreadUpdatePriorities](https://github.com/nohuto/decompiled-pseudocode/blob/main/mmcss/CiThreadUpdatePriorities.c)/[CiSchedulerSetPriority](https://github.com/nohuto/decompiled-pseudocode/blob/main/mmcss/CiSchedulerSetPriority.c)), but seems like that it would use a specific priority for the MMCSS thread instead of switching levels? It would also block CiNdisThrottleWorkItem (see below) and cause the [`CiSchedulerWait`](https://github.com/nohuto/decompiled-pseudocode/blob/main/mmcss/CiSchedulerWait.c) starvation threshold down to 0, so any busy-time increase can mark CPUs as starved (see [CiSchedulerWait](https://github.com/nohuto/decompiled-pseudocode/blob/main/mmcss/CiSchedulerWait.c) at line 118 and the bracket block of it).

Basically means MMCSS initialization fails if `SystemResponsiveness == 100`.

"Determines the percentage of CPU resources that should be guaranteed to low-priority tasks. For example, if this value is 20, then 20% of CPU resources are reserved for low-priority tasks. Note that values that are not evenly divisible by 10 are rounded down to the nearest multiple of 10. Values below 10 and above 100 are clamped to 20. A value of 100 disables MMCSS (driver returns `STATUS_SERVER_DISABLED`)." (`mmcss.sys`)

> https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/ProcThread/multimedia-class-scheduler-service.md#registry-settings

```c
// CiConfigInitialize
{
  DWORD = CiConfigReadDWORD(KeyHandle, 0x1C0011090LL, 100LL); // SystemResponsiveness, missing = 100
  if ( DWORD - 10 > 0x5A ) // data - 10 > 90 = 20
    v2 = 20LL;
  else
    v2 = 10 * (DWORD / 0xA); // 10 step
  CiSystemResponsiveness = v2;
  if ( (HIDWORD(WPP_GLOBAL_Control->Timer) & 1) != 0 && BYTE1(WPP_GLOBAL_Control->Timer) >= 4u )
    WPP_SF_d(WPP_GLOBAL_Control->AttachedDevice, 18LL, &WPP_350503daac883abe7be9cf63f89038d9_Traceguids, v2);
  if ( CiSystemResponsiveness == 100 )
  {
    if ( (HIDWORD(WPP_GLOBAL_Control->Timer) & 1) != 0 && BYTE1(WPP_GLOBAL_Control->Timer) >= 2u )
      WPP_SF_(WPP_GLOBAL_Control->AttachedDevice, 19LL, &WPP_350503daac883abe7be9cf63f89038d9_Traceguids);
    v0 = -1073741696; // STATUS_SERVER_DISABLED
  }
  else // only if CiSystemResponsiveness =! 100
  {
  // all other values
  }
  ZwClose(KeyHandle);
}

// CsIntialize (blocking CiNdisThrottleWorkItem if 100)
if ( LODWORD(WPP_MAIN_CB.Dpc.DpcData) != -1 && CiSystemResponsiveness != 100 )
{
  CiNdisThrottleWorkItem = IoAllocateWorkItem(CiDeviceObject);
  if ( CiNdisThrottleWorkItem )
    CiNdisOpenDevice();
}
```
```c
// -1073741696 = 0xC0000080
0xC0000080 // STATUS_SERVER_DISABLED

The GUID allocation server is disabled at the moment.
```
> https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

Calculation:
```c
CiSystemResponsiveness = 10 * (value / 10);

// Examples
< 10   -> 20   (fallback)
10-19  -> 10
20-29  -> 20
30-39  -> 30
40-49  -> 40
50-59  -> 50
60-69  -> 60
70-79  -> 70
80-89  -> 80
90-99  -> 90
== 100 -> 100  (STATUS_SERVER_DISABLED)
> 100  -> 20   (fallback)
```

## Tasks Details

Existing tasks (OEMs can add additional tasks):
- Audio
- Capture
- Distribution
- Games (unused)
- Playback
- Pro Audio
- Window Manager

| Value | Format | Possible values |
| --- | --- | --- |
| **Affinity** | **REG\_DWORD** | A bitmask that indicates the processor affinity. Both 0x00 and 0xFFFFFFFF indicate that processor affinity is not used. |
| **Background Only** | **REG\_SZ**    | Indicates whether this is a background task (no user interface). The threads of a background task do not change because of a change in window focus. This value can be set to True or False. |
| **BackgroundPriority** | **REG\_DWORD** | The background priority. The range of values is 1-8. |
| **Clock Rate** | **REG\_DWORD** | A hint used by MMCSS to determine the granularity of processor resource scheduling.**Windows Server 2008 and Windows Vista:** The maximum guaranteed clock rate the system uses if a thread joins this task, in 100-nanosecond intervals. Starting with Windows 7 and Windows Server 2008 R2, this guarantee was removed to reduce system power consumption.<br/> |
| **GPU Priority** | **REG\_DWORD** | The GPU priority. The range of values is 0-31. This priority is not yet used. |
| **Priority** | **REG\_DWORD** | The task priority. The range of values is 1 (low) to 8 (high).For tasks with a **Scheduling Category** of High, this value is always treated as 2.<br/> |
| **Scheduling Category** | **REG\_SZ**    | The scheduling category. This value can be set to High, Medium, or Low. |
| **SFIO Priority** | **REG\_SZ** | The scheduled I/O priority. This value can be set to Idle, Low, Normal, or High. This value is not used. |

> https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/ProcThread/multimedia-class-scheduler-service.md#registry-settings

![](https://github.com/nohuto/win-config/blob/main/system/images/mmcss1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/mmcss2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/mmcss3.png?raw=true)

## NoLazyMode Details

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

![](https://github.com/nohuto/win-config/blob/main/system/images/nolazymode.png?raw=true)

# Disable Scheduled Tasks

This list was created using my small [`ScheduledTasksLists.ps1`](https://github.com/nohuto/win-config/blob/main/system/assets/ScheduledTasksList.ps1) parser which displays name, path, description, principals, settings, triggers, actions if given. See example output of a stock 25H2 installation: [scheduled-tasks.json](https://github.com/nohuto/win-config/blob/main/system/assets/scheduled-tasks.json).

## Scheduled Tasks Table

| Option Name | Task | Description | Action Command |
| --- | --- | --- | --- |
| CEIP | `\Microsoft\Windows\Autochk\Proxy` | This task collects and uploads autochk SQM data if opted-in to the Microsoft Customer Experience Improvement Program. | `%windir%\system32\rundll32.exe /d acproxy.dll,PerformAutochkOperations` |
|  | `\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip` | The USB CEIP (Customer Experience Improvement Program) task collects Universal Serial Bus related statistics and information about your machine and sends it to the Windows Device Connectivity engineering group at Microsoft.  The information received is used to help improve the reliability, stability, and overall functionality of USB in Windows.  If the user has not consented to participate in Windows CEIP, this task does not do anything. | `ClassId:{C27F6B1D-FE0B-45E4-9257-38799FA69BC8}` |
|  | `\Microsoft\Windows\Customer Experience Improvement Program\Consolidator` | If the user has consented to participate in the Windows Customer Experience Improvement Program, this job collects and sends usage data to Microsoft. | `%WINDIR%\System32\wsqmcons.exe` |
|  | `\Microsoft\Windows\Customer Experience Improvement Program\Uploader` | - | - |
|  | `\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant` | - | - |
|  | `\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerRoleUsageCollector` | - | - |
| Error Reporting | `\Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate` | - | - |
|  | `\Microsoft\Windows\Windows Error Reporting\QueueReporting` | Windows Error Reporting task to process queued reports. | `%windir%\system32\wermgr.exe -upload` |
| Offline Files | `\Microsoft\Windows\Offline Files\Background Synchronization` | This task controls periodic background synchronization of Offline Files when the user is working in an offline mode. | `ClassId:{FA3F3DD9-4C1A-456B-A8FA-C76EF3ED83B8}` |
|  | `\Microsoft\Windows\Offline Files\Logon Synchronization` | This task initiates synchronization of Offline Files when a user logs onto the system. | `ClassId:{FA3F3DD9-4C1A-456B-A8FA-C76EF3ED83B8}` |
| Printing | `\Microsoft\Windows\Printing\PrintJobCleanupTask` | - | `ClassId:{8ABCE260-32B6-476C-AE13-B34D0C91292D}` |
|  | `\Microsoft\Windows\Printing\PrinterCleanupTask` | - | `ClassId:{C56F065E-DE49-4E42-BE7C-305C45609D25}` |
|  | `\Microsoft\Windows\Printing\EduPrintProv` | - | `%windir%\system32\eduprintprov.exe` |
| Wi-Fi Service | `\Microsoft\Windows\WCM\WiFiTask` | Background task for performing per user and web interactions | `%WINDIR%\System32\WiFiTask.exe` |
|  | `\Microsoft\Windows\WlanSvc\CDSSync` | - | `ClassId:{B0D2B535-12E1-439F-86B3-BADA289510F0}` |
|  | `\Microsoft\Windows\WwanSvc\NotificationTask` | Background task for performing per user and web interactions | `%WINDIR%\System32\WiFiTask.exe wwan` |
|  | `\Microsoft\Windows\WwanSvc\OobeDiscovery` | - | `ClassId:{C93CF9D5-031B-4AAA-AB0B-EF802347B381}` |
|  | `\Microsoft\Windows\WlanSvc\MoProfileManagement` | - | `ClassId:{085EDA12-CF4A-4944-8222-8ADCADE137CB}` |
| Office Telemetry | `\Microsoft\Office\OfficeTelemetryAgentFallBack` | - | - |
|  | `\Microsoft\Office\OfficeTelemetryAgentFallBack2016` | - | - |
|  | `\Microsoft\Office\OfficeTelemetryAgentLogOn` | - | - |
|  | `\Microsoft\Office\OfficeTelemetryAgentLogOn2016` | - | - |
| NVIDIA Telemetry | `NvTmRep_*` | Sends data at 12:25PM daily | - |
|  | `NvTmRepOnLogon*` | Sends data on logon | - |
|  | `NvTmMon_*` | Sends data on logon, then in a 1H interval | - |
| Feedback | `\Microsoft\Windows\Feedback\Siuf\DmClient` | Update SIUF strings | `%windir%\system32\dmclient.exe` |
|  | `\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload` | Update SIUF strings | `%windir%\system32\dmclient.exe utcwnf` |
| Application Experience | `\Microsoft\Windows\Application Experience\MareBackup` | Gathers Win32 application data for App Backup scenario | `%windir%\system32\compattelrunner.exe -m:aeinv.dll -f:UpdateSoftwareInventoryW invsvc ; %windir%\system32\compattelrunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun ; %windir%\system32\compattelrunner.exe -m:aemarebackup.dll -f:BackupMareData` |
|  | `\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser` | Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program. | `%windir%\system32\sc.exe start InventorySvc` |
|  | `\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp` | Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program. | `%windir%\system32\compattelrunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun express` |
|  | `\Microsoft\Windows\Application Experience\PcaPatchDbTask` | Updates compatibility database | `%windir%\system32\rundll32.exe %windir%\system32\PcaSvc.dll,PcaPatchSdbTask` |
|  | `\Microsoft\Windows\Application Experience\SdbinstMergeDbTask` | Merges shim databases that are pending merge. | `%windir%\system32\sdbinst.exe -mm` |
|  | `\Microsoft\Windows\Application Experience\StartupAppTask` | Scans startup entries and raises notification to the user if there are too many startup entries. | `%windir%\system32\rundll32.exe Startupscan.dll,SusRunTask` |
| Maintenance | `\Microsoft\Windows\ApplicationData\DsSvcCleanup` | Performs maintenance for the Data Sharing Service. | `%windir%\system32\dstokenclean.exe` |
|  | `\Microsoft\Windows\CloudExperienceHost\CreateObjectTask` | - | `ClassId:{E4544ABA-62BF-4C54-AAB2-EC246342626C}` |
|  | `\Microsoft\Windows\Defrag\ScheduledDefrag` | This task optimizes local storage drives. | `%windir%\system32\defrag.exe -c -h -o -$` |
|  | `\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner` | Check for recommended troubleshooting from Microsoft | `ClassId:{AD08DCC2-4E35-4486-9D49-547CBD30942D}` |
|  | `\Microsoft\Windows\Diagnosis\Scheduled` | The Windows Scheduled Maintenance Task performs periodic maintenance of the computer system by fixing problems automatically or reporting them through Security and Maintenance. | `ClassId:{C1F85EF8-BCC2-4606-BB39-70C523715EB3}` |
|  | `\Microsoft\Windows\Diagnosis\UnexpectedCodePath` | - | - |
|  | `\Microsoft\Windows\DiskCleanup\SilentCleanup` | Maintenance task used by the system to launch a silent auto disk cleanup when running low on free disk space. | `%windir%\system32\cleanmgr.exe /autocleanstoragesense /d %systemdrive%` |
|  | `\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector` | The Windows Disk Diagnostic reports general disk and system information to Microsoft for users participating in the Customer Experience Program. | `%windir%\system32\rundll32.exe dfdts.dll,DfdGetDefaultPolicyAndSMART` |
|  | `\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver` | The Microsoft-Windows-DiskDiagnosticResolver warns users about faults reported by hard disks that support the Self Monitoring and Reporting Technology (S.M.A.R.T.) standard. This task is triggered automatically by the Diagnostic Policy Service when a S.M.A.R.T. fault is detected. | `%windir%\system32\DFDWiz.exe` |
|  | `\Microsoft\Windows\DiskFootprint\Diagnostics` | - | `%windir%\system32\disksnapshot.exe -z` |
|  | `\Microsoft\Windows\DiskFootprint\StorageSense` | - | `ClassId:{AB2A519B-03B0-43CE-940A-A73DF850B49A}` |
|  | `\Microsoft\Windows\Speech\SpeechModelDownloadTask` | - | `%windir%\system32\speech_onecore\common\SpeechModelDownload.exe` |
|  | `\Microsoft\Windows\Sysmain\ResPriStaticDbSync` | Reserved Priority static db sync maintenance task | `ClassId:{297EE78C-BA95-4E94-81D3-D6E7F089C7B5}` |
|  | `\Microsoft\Windows\Sysmain\WsSwapAssessmentTask` | Working set swap assessment maintenance task | `%windir%\system32\rundll32.exe sysmain.dll,PfSvWsSwapAssessmentTask` |
|  | `\Microsoft\Windows\UNP\RunUpdateNotificationMgr` | - | - |
|  | `\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask` | Maintains registrations for background tasks for Universal Windows Platform applications. | `ClassId:{E984D939-0E00-4DD9-AC3A-7ACA04745521}` |
|  | `\Microsoft\Windows\capabilityaccessmanager\maintenancetasks` | Capability Access Manager Maintenance Tasks | `%windir%\system32\rundll32.exe %windir%\system32\CapabilityAccessManager.dll,CapabilityAccessManagerDoStoreMaintenance` |
| Census | `\Microsoft\Windows\Device Information\Device User` | - | `%windir%\system32\devicecensus.exe UserCxt` |
|  | `\Microsoft\Windows\Device Information\Device` | - | `%windir%\system32\devicecensus.exe SystemCxt` |
| Update Service | `\Microsoft\Windows\InstallService\ScanForUpdates` | - | `ClassId:{A558C6A5-B42B-4C98-B610-BF9559143139}` |
|  | `\Microsoft\Windows\InstallService\ScanForUpdatesAsUser` | - | `ClassId:{DDAFAEA2-8842-4E96-BADE-D44A8D676FDB}` |
|  | `\Microsoft\Windows\InstallService\SmartRetry` | - | `ClassId:{F3A219C3-2698-4CBF-9C07-037EDB8E72E6}` |
|  | `\Microsoft\Windows\InstallService\WakeUpAndContinueUpdates` | - | `ClassId:{0DC331EE-8438-49D5-A721-E10B937CE459}` |
|  | `\Microsoft\Windows\InstallService\WakeUpAndScanForUpdates` | - | `ClassId:{D5A04D91-6FE6-4FE4-A98A-FEB4500C5AF7}` |
| Localization | `\Microsoft\Windows\International\Synchronize Language Settings` | Synchronize User Language Settings from other devices. | `ClassId:{10D62541-90D0-42FE-848C-0DBC1AC42EDA}` |
|  | `\Microsoft\Windows\LanguageComponentsInstaller\Installation` | Install language components that match the user's language list. | `ClassId:{6F58F65F-EC0E-4ACA-99FE-FC5A1A25E4BE}` |
|  | `\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources` | Install language components that match the user's language list. | `ClassId:{D0582E3B-3126-4CAA-9155-AC37C912A489}` |
|  | `\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation` | Uninstall language components that are not in any user's language list. | `ClassId:{6F58F65F-EC0E-4ACA-99FE-FC5A1A25E4BE}` |
| Maps | `\Microsoft\Windows\Maps\MapsUpdateTask` | This task checks for updates to maps which you have downloaded for offline use. Disabling this task will prevent Windows from notifying you of updated maps. | `ClassId:{B9033E87-33CF-4D77-BC9B-895AFBBA72E4}` |
|  | `\Microsoft\Windows\Maps\MapsToastTask` | This task shows various Map related toasts | `ClassId:{9885AEF2-BD9F-41E0-B15E-B3141395E803}` |
| Sleep Study | `\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem` | This task analyzes the system looking for conditions that may cause high energy use. | `ClassId:{927EA2AF-1C54-43D5-825E-0074CE028EEE}` |
| Time Sync | `\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime` | This task performs time synchronization. | `ClassId:{A31AD6C2-FF4C-43D4-8E90-7101023096F9}` |
|  | `\Microsoft\Windows\Time Synchronization\SynchronizeTime` | Maintains date and time synchronization on all clients and servers in the network. If this service is stopped, date and time synchronization will be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start. | `%windir%\system32\sc.exe start w32time task_started` |
| Miscellaneous | `\Microsoft\Windows\Registry\RegIdleBackup` | Registry Idle Backup Task | `ClassId:{CA767AA8-9157-4604-B64B-40747123D5F2}` |
|  | `\Microsoft\Windows\RetailDemo\CleanupOfflineContent` | Auto cleanup RetailDemo Offline content | `ClassId:{61F77D5E-AFE9-400B-A5E6-E9E80FC8E601}` |
| WU | `\Microsoft\Windows\UpdateOrchestrator\Report policies` | - | `%WINDIR%\system32\usoclient.exe ReportPolicies` |
|  | `\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work` | - | `%WINDIR%\system32\usoclient.exe StartMaintenanceWork` |
|  | `\Microsoft\Windows\UpdateOrchestrator\Schedule Scan` | - | `%WINDIR%\system32\usoclient.exe StartScan` |
|  | `\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task` | This task performs a scheduled Windows Update scan. | `%WINDIR%\system32\usoclient.exe StartScan` |
|  | `\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work` | - | `%WINDIR%\system32\usoclient.exe StartWork` |
|  | `\Microsoft\Windows\UpdateOrchestrator\Schedule Work` | - | `%WINDIR%\system32\usoclient.exe StartWork` |
|  | `\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work` | This task performs a scheduled Windows Update scan. | `%WINDIR%\system32\usoclient.exe StartWork` |
|  | `\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_LicenseAccepted` | This task performs a scheduled Windows Update scan. | `%WINDIR%\system32\usoclient.exe StartOobeAppsScan` |
|  | `\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScanAfterUpdate` | This task performs a scheduled Windows Update scan. | `%WINDIR%\system32\usoclient.exe StartOobeAppsScanAfterUpdate` |
|  | `\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker` | This task triggers a system reboot following update installation. | `%WINDIR%\system32\MusNotification.exe` |
|  | `\Microsoft\Windows\UpdateOrchestrator\UUS Failover Task` | - | `%windir%\System32\MLEngineStub.exe HandleUusFailoverEvaluationSignalFromWnf` |
|  | `\Microsoft\Windows\WindowsUpdate\Scheduled Start` | This task is used to start the Windows Update service when needed to perform scheduled operations such as scans. | `%WINDIR%\System32\sc.exe start wuauserv` |
|  | `\Microsoft\Windows\WindowsUpdate\Refresh Group Policy Cache` | This task is used to refresh group policy cache in Windows Update | `ClassId:{07369A67-07A6-4608-ABEA-379491CB7C46}` |
| BitLocker | `\Microsoft\Windows\BitLocker\BitLocker Encrypt All Drives` | - | `ClassId:{61BCD1B9-340C-40EC-9D41-D7F1C0632F05}` |
|  | `\Microsoft\Windows\BitLocker\BitLocker MDM Policy Refresh` | - | - |
| Microsoft Account | `\Microsoft\Windows\AccountHealth\RecoverabilityToastTask` | AccountHealth Task Handler evaluates the state of a Microsoft Account and takes any necessary repair action | `ClassId:{B7F5B442-EBF8-46CD-9F0B-D8E45ED43492}` |
| Chkdsk | `\Microsoft\Windows\Chkdsk\ProactiveScan` | NTFS Volume Health Scan | `ClassId:{CF4270F5-2E43-4468-83B3-A8C45BB33EA1}` |
|  | `\Microsoft\Windows\Chkdsk\SyspartRepair` | - | `%windir%\system32\bcdboot.exe %windir% /sysrepair` |
| OneSettings | `\Microsoft\Windows\Flighting\OneSettings\RefreshCache` | Task periodically refreshing data for OneSettings clients. | `ClassId:{E07647F7-AED2-48D9-9720-939BC24A8A3C}` |
| Location Notification | `\Microsoft\Windows\Location\WindowsActionDialog` | Location Notification | `%windir%\System32\WindowsActionDialog.exe` |
| Memory Diagnostic | `\Microsoft\Windows\MemoryDiagnostic\AutomaticOfflineMemoryDiagnostic` | Schedules an offline memory diagnostic in response to system events. | `ClassId:{44F6C389-604A-4363-B09A-F38DA08E6079}` |
|  | `\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents` | Schedules a memory diagnostic in response to system events. | `ClassId:{8168E74A-B39F-46D8-ADCD-7BED477B80A3}` |
|  | `\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic` | Detects and mitigates problems in physical memory (RAM). | `ClassId:{8168E74A-B39F-46D8-ADCD-7BED477B80A3}` |
| Remote Assistance | `\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask` | Checks group policy for changes relevant to Remote Assistance | `%windir%\system32\RAServer.exe /offerraupdate` |
| SR | `\Microsoft\Windows\SystemRestore\SR` | This task creates regular system protection points. | `%windir%\system32\srtasks.exe ExecuteScheduledSPPCreation` |
| Windows Defender | `\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance` | Periodic maintenance task. | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25110.6-0\MpCmdRun.exe -IdleTask -TaskName WdCacheMaintenance` |
|  | `\Microsoft\Windows\Windows Defender\Windows Defender Cleanup` | Periodic cleanup task. | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25110.6-0\MpCmdRun.exe -IdleTask -TaskName WdCleanup` |
|  | `\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan` | Periodic scan task. | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25110.6-0\MpCmdRun.exe Scan -ScheduleJob -ScanTrigger 55 -IdleScheduledJob` |
|  | `\Microsoft\Windows\Windows Defender\Windows Defender Verification` | Periodic verification task. | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25110.6-0\MpCmdRun.exe -IdleTask -TaskName WdVerification` |
| AI | `\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration` | - | `ClassId:{709FD5EF-7296-4154-BD3A-E9830FCFA60A}` |
|  | `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` | - | `ClassId:{0BE6820D-B667-4CB6-931B-C153A77DA895}` |
|  | `\Microsoft\Windows\WindowsAI\Settings\InitialConfiguration` | - | `ClassId:{2886E5FB-4F01-4A89-9A0E-5D6A9C8048AC}` |
| Work Folders | `\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization` | This task initiates synchronization of Work Folders partnerships when a user logs onto the system. | `ClassId:{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}` |
|  | `\Microsoft\Windows\Work Folders\Work Folders Maintenance Work` | This task initiates maintenance work required for on-going good performance of data synchronization of Work Folders partnerships. | `ClassId:{63260BCE-A3FB-4A34-AA51-D4D8E877B62B}` |

# Disable Services/Drivers

I personally recommend using only the main option. This includes disabling telemetry/tracking/diagnostics/location/certain drivers/services, etc. It is not necessary to disable more than this, as most other features will not start automatically anyway. You can use the SUBOPTIONs if you want to disable specific services/drivers (e.g. *"Autoplay Service, Bluetooth Services, Camera Services, File/Printer Sharing Services, Printer Services, Store Services"*) for a specific reason (note that this may cause broken functionalities).

## Internals 'Windows services'

![](https://github.com/nohuto/win-config/blob/main/system/images/services1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/services2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/services3.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/services4.png?raw=true)

Read more about it in [Windows Internals E7, P2](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf) 'Windows services (P.426-474) section.

## Service/Driver Table

The suboptions probably overlap the documentation. If so, you can open the markdown file on my GitHub instead:
> https://github.com/nohuto/win-config/blob/main/system/desc.md#disable-servicesdrivers

See [services](https://github.com/nohuto/win-config/blob/main/system/assets/services.txt)/[drivers](https://github.com/nohuto/win-config/blob/main/system/assets/drivers.txt) for reference, these files were generated on a stock `W11 IoT Enterprise LTSC` installation via [serviwin](https://www.nirsoft.net/utils/serviwin.html).

| Option Name | Service/Driver | Description |
| --- | --- | --- |
| Activity Moderation | `bam` | Controls activity of background applications |
| Autoplay | `ShellHWDetection` | *Disabling causes CmdPal to not start directly after boot for whatever reason.* -Provides notifications for AutoPlay hardware events. |
| Beep | `Beep` | Legacy PC speaker/tone driver. It provides simple beeps for apps that call the Windows Beep API. |
| Biometrics | `WbioSrvc` | The Windows biometric service gives client applications the ability to capture, compare, manipulate, and store biometric data without gaining direct access to any biometric hardware or samples. The service is hosted in a privileged SVCHOST process. |
| Bluetooth | `BTAGService` | Service supporting the audio gateway role of the Bluetooth Handsfree Profile. |
|  | `BluetoothUserService_*` | The Bluetooth user service supports proper functionality of Bluetooth features relevant to each user session. |
|  | `BluetoothUserService` | The Bluetooth user service supports proper functionality of Bluetooth features relevant to each user session. |
|  | `BthA2dp` | Microsoft Bluetooth A2dp driver |
|  | `BthAvctpSvc` | This is Audio Video Control Transport Protocol service |
|  | `BthEnum` | Bluetooth Enumerator Service |
|  | `BthHFEnum` | Microsoft Bluetooth Hands-Free Profile driver |
|  | `BthLEEnum` | Bluetooth Low Energy Driver |
|  | `BthMini` | Bluetooth Radio Driver |
|  | `BTHMODEM` | Bluetooth Modem Communications Driver |
|  | `BTHPORT` | Bluetooth Port Driver |
|  | `bthserv` | The Bluetooth service supports discovery and association of remote Bluetooth devices. Stopping or disabling this service may cause already installed Bluetooth devices to fail to operate properly and prevent new devices from being discovered or associated. |
|  | `BTHUSB` | Bluetooth Radio USB Driver |
|  | `DeviceAssociationBrokerSvc` | Enables apps to pair devices |
|  | `DeviceAssociationService` | Enables pairing between the system and wired or wireless devices. |
|  | `Microsoft_Bluetooth_AvrcpTransport` | Microsoft Bluetooth Avrcp Transport Driver |
|  | `RFCOMM` | Bluetooth Device (RFCOMM Protocol TDI) |
| Broadcasts | `BcastDVRUserService` | This user service is used for Game Recordings and Live Broadcasts |
|  | `CaptureService_*` | Enables optional screen capture functionality for applications that call the Windows.Graphics.Capture API. |
|  | `AJRouter` | Routes AllJoyn messages for the local AllJoyn clients. If this service is stopped the AllJoyn clients that do not have their own bundled routers will be unable to run. |
|  | `CaptureService` | Enables optional screen capture functionality for applications that call the Windows.Graphics.Capture API. |
|  | `CDPSvc` | This service is used for Connected Devices Platform scenarios |
|  | `CDPUserSvc` | This user service is used for Connected Devices Platform scenarios |
|  | `DevicePickerUserSvc` | This user service is used for managing the Miracast, DLNA, and DIAL UI |
|  | `DevicesFlowUserSvc` | Allows ConnectUX and PC Settings to Connect and Pair with WiFi displays and Bluetooth devices. |
|  | `NcbService` | Brokers connections that allow packaged Microsoft Store apps to receive notifications from the internet. |
|  | `NcdAutoSetup` | Network Connected Devices Auto-Setup service monitors and installs qualified devices that connect to a qualified network. Stopping or disabling this service will prevent Windows from discovering and installing qualified network connected devices automatically. Users can still manually add network connected devices to a PC through the user interface. |
|  | `p2pimsvc` | Provides identity services for the Peer Name Resolution Protocol (PNRP) and Peer-to-Peer Grouping services. If disabled, the Peer Name Resolution Protocol (PNRP) and Peer-to-Peer Grouping services may not function, and some applications, such as HomeGroup and Remote Assistance, may not function correctly. |
|  | `p2psvc` | Enables multi-party communication using Peer-to-Peer Grouping. If disabled, some applications, such as HomeGroup, may not function. |
|  | `PNRPAutoReg` | This service publishes a machine name using the Peer Name Resolution Protocol. Configuration is managed via the netsh context `p2p pnrp peer`. |
|  | `PNRPsvc` | Enables serverless peer name resolution over the Internet using the Peer Name Resolution Protocol (PNRP). If disabled, some peer-to-peer and collaborative applications, such as Remote Assistance, may not function. |
| Camera | `FrameServer` | Enables multiple clients to access video frames from camera devices. |
|  | `FrameServerMonitor` | Monitors the health and state for the Windows Camera Frame Server service. |
|  | `StiSvc` | Provides image acquisition services for scanners and cameras |
| CDROM | `cdrom` | CD-ROM Driver |
| Clipboard | `cbdhsvc` | This user service is used for Clipboard scenarios |
| Cloud Filter | `CldFlt` | Cloud Files Mini Filter Driver |
| DHCP | `Dhcp` | Registers and updates IP addresses and DNS records for this computer. If this service is stopped, this computer will not receive dynamic IP addresses and DNS updates. If this service is disabled, any services that explicitly depend on it will fail to start. |
| Diagnostics | `DusmSvc` | Network data usage, data limit, restrict background data, metered networks. |
|  | `DPS` | The Diagnostic Policy Service enables problem detection, troubleshooting and resolution for Windows components. If this service is stopped, diagnostics will no longer function. |
|  | `diagsvc` | Executes diagnostic actions for troubleshooting support |
|  | `WdiServiceHost` | The Diagnostic Service Host is used by the Diagnostic Policy Service to host diagnostics that need to run in a Local Service context. If this service is stopped, any diagnostics that depend on it will no longer function. |
|  | `WdiSystemHost` | The Diagnostic System Host is used by the Diagnostic Policy Service to host diagnostics that need to run in a Local System context. If this service is stopped, any diagnostics that depend on it will no longer function. |
|  | `TroubleshootingSvc` | Enables automatic mitigation for known problems by applying recommended troubleshooting. If stopped, your device will not get recommended troubleshooting for problems on your device. |
| Domain/RPC | `Netlogon` | Maintains a secure channel between this computer and the domain controller for authenticating users and services. If this service is stopped, the computer may not authenticate users and services and the domain controller cannot register DNS records. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `MsRPC` | MsRPC |
|  | `RpcLocator` | In Windows 2003 and earlier versions of Windows, the Remote Procedure Call (RPC) Locator service manages the RPC name service database. In Windows Vista and later versions of Windows, this service does not provide any functionality and is present for application compatibility. |
| Edge | `MicrosoftEdgeElevationService` | Provides elevated privileges for Microsoft Edge. |
|  | `edgeupdate` | Keeps your Microsoft software up to date. If this service is disabled or stopped, your Microsoft software will not be kept up to date, meaning security vulnerabilities that may arise cannot be fixed and features may not work. This service uninstalls itself when there is no Microsoft software using it. |
|  | `edgeupdatem` | Keeps your Microsoft software up to date. If this service is disabled or stopped, your Microsoft software will not be kept up to date, meaning security vulnerabilities that may arise cannot be fixed and features may not work. This service uninstalls itself when there is no Microsoft software using it. |
| File/Printer Sharing | `LanmanServer` | Supports file, print, and named-pipe sharing over the network for this computer. If this service is stopped, these functions will be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `LanmanWorkstation` | Creates and maintains client network connections to remote servers using the SMB protocol. If this service is stopped, these connections will be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `CSC` | Allows network files to be used while the local computer is offline. |
|  | `CscService` | The Offline Files service performs maintenance activities on the Offline Files cache, responds to user logon and logoff events, implements the internals of the public API, and dispatches interesting events to those interested in Offline Files activities and changes in cache state. |
|  | `Dfsc` | Client driver for access to DFS Namespaces |
|  | `MRxDAV` | Network Redirector that provides WebDAV file access for the WebClient service |
|  | `mrxsmb` | Implements the framework for the SMB filesystem redirector |
|  | `mrxsmb20` | Implements the SMB 2.0 protocol, which provides connectivity to network resources on Windows Vista and later servers |
|  | `P9Rdr` | Plan 9 Redirector Driver |
|  | `P9RdrService` | Enables trigger-starting plan9 file servers. |
|  | `rdbss` | Provides the framework for network mini-redirectors |
|  | `TrkWks` | Maintains links between NTFS files within a computer or across computers in a network. |
|  | `WebClient` | Enables Windows-based programs to create, access, and modify Internet-based files. If this service is stopped, these functions will not be available. If this service is disabled, any services that explicitly depend on it will fail to start. |
| GameInput | `GameInputSvc` | Enables keyboards, mice, gamepads, and other input devices to be used with the GameInput API. |
| HyperV | `bttflt` | Microsoft Hyper-V VHDPMEM BTT Filter |
|  | `gencounter` | Microsoft Hyper-V Generation Counter |
|  | `hvcrash` | Hyper-V Crashdump |
|  | `HvHost` | Provides an interface for the Hyper-V hypervisor to provide per-partition performance counters to the host operating system. |
|  | `hvservice` | Microsoft Hypervisor Service Driver |
|  | `hyperkbd` | Microsoft VMBus Synthetic Keyboard Driver |
|  | `HyperVideo` | Microsoft VMBus Video Device Miniport Driver |
|  | `storflt` | Microsoft Hyper-V Storage Accelerator |
|  | `Vid` | Microsoft Hyper-V Virtualization Infrastructure Driver |
|  | `vmbus` | Virtual Machine Bus |
|  | `vmgid` | Microsoft Hyper-V Guest Infrastructure Driver |
|  | `vmicguestinterface` | Provides an interface for the Hyper-V host to interact with specific services running inside the virtual machine. |
|  | `vmicheartbeat` | Monitors the state of this virtual machine by reporting a heartbeat at regular intervals. This service helps you identify running virtual machines that have stopped responding. |
|  | `vmickvpexchange` | Provides a mechanism to exchange data between the virtual machine and the operating system running on the physical computer. |
|  | `vmicrdv` | Provides a platform for communication between the virtual machine and the operating system running on the physical computer. |
|  | `vmicshutdown` | Provides a mechanism to shut down the operating system of this virtual machine from the management interfaces on the physical computer. |
|  | `vmictimesync` | Synchronizes the system time of this virtual machine with the system time of the physical computer. |
|  | `vmicvmsession` | Provides a mechanism to manage virtual machine with PowerShell via VM session without a virtual network. |
|  | `vmicvss` | Coordinates the communications that are required to use Volume Shadow Copy Service to back up applications and data on this virtual machine from the operating system on the physical computer. |
|  | `vpci` | Microsoft Hyper-V Virtual PCI Bus |
| IPv6 | `Tcpip6` | @todo.dll,-100;Microsoft IPv6 Protocol Driver |
|  | `IpxlatCfgSvc` | Configures and enables translation from v4 to v6 and vice versa |
| IP Helper | `iphlpsvc` | Provides tunnel connectivity using IPv6 transition technologies (6to4, ISATAP, Port Proxy, and Teredo), and IP-HTTPS. If this service is stopped, the computer will not have the enhanced connectivity benefits that these technologies offer. |
| Kernel Debug Network | `kdnic` | Microsoft Kernel Debugger Network Miniport |
| Location | `lfsvc` | This service monitors the current location of the system and manages geofences (a geographical location with associated events). If you turn off this service, applications will be unable to use or receive notifications for geolocation or geofences. |
| Maps Manager | `MapsBroker` | Windows service for application access to downloaded maps. This service is started on-demand by application accessing downloaded maps. Disabling this service will prevent apps from accessing maps. |
| Network Discovery | `fdPHost` | The FDPHOST service hosts the Function Discovery (FD) network discovery providers. These FD providers supply network discovery services for the Simple Services Discovery Protocol (SSDP) and Web Services Discovery (WS-D) protocol. Stopping or disabling the FDPHOST service will disable network discovery for these protocols when using FD. When this service is unavailable, network services using FD and relying on these discovery protocols will be unable to find network devices or resources. |
|  | `FDResPub` | Publishes this computer and resources attached to this computer so they can be discovered over the network. If this service is stopped, network resources will no longer be published and they will not be discovered by other computers on the network. |
|  | `SSDPSRV` | Discovers networked devices and services that use the SSDP discovery protocol, such as UPnP devices. Also announces SSDP devices and services running on the local computer. If this service is stopped, SSDP-based devices will not be discovered. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `upnphost` | Allows UPnP devices to be hosted on this computer. If this service is stopped, any hosted UPnP devices will stop functioning and no additional hosted devices can be added. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `MsLldp` | Microsoft Link-Layer Discovery Protocol Driver |
|  | `rspndr` | Link-Layer Topology Discovery Responder |
|  | `lltdio` | Link-Layer Topology Discovery Mapper I/O Driver |
|  | `lltdsvc` | Creates a Network Map, consisting of PC and device topology (connectivity) information, and metadata describing each PC and device. If this service is disabled, the Network Map will not function properly. |
| Office | `ClickToRunSvc` | - |
| Telephony | `PhoneSvc` | Manages the telephony state on the device |
|  | `TapiSrv` | Provides Telephony API (TAPI) support for programs that control telephony devices on the local computer and, through the LAN, on servers that are also running the service. |
| Radio Management | `RmSvc` | Radio Management and Airplane Mode Service. |
| Parental Control | `WpcMonSvc` | Enforces parental controls for child accounts in Windows. If this service is stopped or disabled, parental controls may not be enforced. |
| Printer | `McpManagementService` | Universal Print Management Service |
|  | `PrintDeviceConfigurationService` | The Print Device Configuration Service manages the installation of IPP and UP printers. If this service is stopped, any printer installations that are in-progress may be canceled. |
|  | `PrintNotify` | This service opens custom printer dialog boxes and handles notifications from a remote print server or a printer. If you turn off this service, you wont be able to see printer extensions or notifications. |
|  | `PrintScanBrokerService` | Provides support for secure privileged operations needed by low priv spooler. |
|  | `PrintWorkflowUserSvc` | Provides support for Print Workflow applications. If you turn off this service, you may not be able to print successfully. |
|  | `Spooler` | This service spools print jobs and handles interaction with the printer. If you turn off this service, you won't be able to print or see your printers. |
|  | `usbprint` | Microsoft USB PRINTER Class |
| Recovery / Backup | `CloudBackupRestoreSvc` | Monitors the system for changes in application and setting states and performs cloud backup and restore operations when required. |
|  | `SDRSVC` | Provides Windows Backup and Restore capabilities. |
|  | `swprv` | Manages software-based volume shadow copies taken by the Volume Shadow Copy service. If this service is stopped, software-based volume shadow copies cannot be managed. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `VSS` | Manages and implements Volume Shadow Copies used for backup and other purposes. If this service is stopped, shadow copies will be unavailable for backup and the backup may fail. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `wbengine` | The WBENGINE service is used by Windows Backup to perform backup and recovery operations. If this service is stopped by a user, it may cause the currently running backup or recovery operation to fail. Disabling this service may disable backup and recovery operations using Windows Backup on this computer. |
| Remote Desktop | `SessionEnv` | Remote Desktop Configuration service (RDCS) is responsible for all Remote Desktop Services and Remote Desktop related configuration and session maintenance activities that require SYSTEM context. These include per-session temporary folders, RD themes, and RD certificates. |
|  | `TermService` | Allows users to connect interactively to a remote computer. Remote Desktop and Remote Desktop Session Host Server depend on this service. To prevent remote use of this computer, clear the checkboxes on the Remote tab of the System properties control panel item. |
|  | `UmRdpService` | Allows the redirection of Printers/Drives/Ports for RDP connections |
|  | `rdpbus` | Remote Desktop Device Redirector Bus Driver |
|  | `RDPDR` | Remote Desktop Device Redirector Driver |
|  | `terminpt` | Microsoft Remote Desktop Input Driver |
|  | `TsUsbFlt` | Remote Desktop USB Hub Class Filter Driver |
|  | `TsUsbGD` | Remote Desktop Generic USB Device |
|  | `tsusbhub` | Remote Desktop USB Hub |
| Sensor | `SensorDataService` | Delivers data from a variety of sensors |
|  | `SensrSvc` | Monitors various sensors in order to expose data and adapt to system and user state. If this service is stopped or disabled, the display brightness will not adapt to lighting conditions. Stopping this service may affect other system functionality and features as well. |
|  | `SensorService` | A service for sensors that manages different sensors' functionality. Manages Simple Device Orientation (SDO) and History for sensors. Loads the SDO sensor that reports device orientation changes. If this service is stopped or disabled, the SDO sensor will not be loaded and so auto-rotation will not occur. History collection from Sensors will also be stopped. |
|  | `perceptionsimulation` | Enables spatial perception simulation, virtual camera management and spatial input simulation. |
|  | `spectrum` | Enables spatial perception, spatial input, and holographic rendering. |
|  | `VacSvc` | Hosts spatial analysis for Mixed Reality audio simulation. |
| Sign-In Assistant | `wlidsvc` | Enables user sign-in through Microsoft account identity services. If this service is stopped, users will not be able to logon to the computer with their Microsoft account. |
|  | `NaturalAuthentication` | Signal aggregator service, that evaluates signals based on time, network, geolocation, bluetooth and cdf factors. Supported features are Device Unlock, Dynamic Lock and Dynamo MDM policies |
|  | `NgcCtnrSvc` | Manages local user identity keys used to authenticate user to identity providers as well as TPM virtual smart cards. If this service is disabled, local user identity keys and TPM virtual smart cards will not be accessible. It is recommended that you do not reconfigure this service. |
|  | `NgcSvc` | Provides process isolation for cryptographic keys used to authenticate to a user's associated identity providers. If this service is disabled, all uses and management of these keys will not be available, which includes machine logon and single-sign on for apps and websites. This service starts and stops automatically. It is recommended that you do not reconfigure this service. |
| Smart Card | `SCardSvr` | Manages access to smart cards read by this computer. If this service is stopped, this computer will be unable to read smart cards. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `ScDeviceEnum` | Creates software device nodes for all smart card readers accessible to a given session. If this service is disabled, WinRT APIs will not be able to enumerate smart card readers. |
|  | `SCPolicySvc` | Allows the system to be configured to lock the user desktop upon smart card removal. |
|  | `scfilter` | Smart card reader filter driver enabling smart card PnP. |
| SysMain | `SysMain` | SysMain (Superfetch) records app usage patterns, builds prefetch metadata (layout.ini), and warms the cache by preloading files/pages to cut boot and app startup latency; it also drives prefetcher behavior via EnablePrefetcher settings. ([Windows Internals, E7-P1](https://github.com/nohuto/windows-books/releases)) |
| Microsoft Store | `AppXSvc` | *Disabling breaks CmdPal and other store applications.* - Provides infrastructure support for deploying Store applications. This service is started on demand and if disabled Store applications will not be deployed to the system, and may not function properly. |
|  | `camsvc` | Provides facilities for managing UWP apps access to app capabilities as well as checking an app's access to specific app capabilities |
|  | `ClipSVC` | Provides infrastructure support for the Microsoft Store. This service is started on demand and if disabled applications bought using the Microsoft Store will not behave correctly. |
|  | `InstallService` | Provides infrastructure support for the Microsoft Store. This service is started on demand and if disabled then installations will not function properly. |
|  | `LicenseManager` | Provides infrastructure support for the Microsoft Store. This service is started on demand and if disabled then content acquired through the Microsoft Store will not function properly. |
|  | `PushToInstall` | Provides infrastructure support for the Microsoft Store. This service is started automatically and if disabled then remote installations will not function properly. |
| TCP/IP NetBIOS Helper | `lmhosts` | Provides support for the NetBIOS over TCP/IP (NetBT) service and NetBIOS name resolution for clients on the network, therefore enabling users to share files, print, and log on to the network. If this service is stopped, these functions might be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start. |
| Telemetry | `DiagTrack` | The Connected User Experiences and Telemetry service enables features that support in-application and connected user experiences. Additionally, this service manages the event driven collection and transmission of diagnostic and usage information (used to improve the experience and quality of the Windows Platform) when the diagnostics and usage privacy option settings are enabled under Feedback and Diagnostics. |
|  | `dmwappushservice` | Routes Wireless Application Protocol (WAP) Push messages received by the device and synchronizes Device Management sessions |
|  | `Ndu` | This service provides network data usage monitoring functionality |
|  | `InventorySvc` | This service performs background system inventory, compatibility appraisal, and maintenance used by numerous system components. |
|  | `PcaSvc` | This service provides support for the Program Compatibility Assistant (PCA). PCA monitors programs installed and run by the user and detects known compatibility problems. If this service is stopped, PCA will not function properly. |
|  | `wuqisvc` | A Microsoft service producing summary facts and insights related to usage and quality of experience. Facts are used to automate on-device self-healing and other optional workflows, such as Personalized offers. |
| Themes | `Themes` | Provides user experience theme management. |
| Time | `autotimesvc` | This service sets time based on NITZ messages from a Mobile Network |
|  | `tzautoupdate` | Automatically sets the system time zone. |
| Trusted Runtime | `WindowsTrustedRT` | Windows Trusted Runtime Interface Driver |
|  | `WindowsTrustedRTProxy` | Windows Trusted Runtime Service Proxy Driver |
|  | `PEAUTH` | Protected Environment Authentication and Authorization Export Driver |
| UAC | `luafv` | Virtualizes file write failures to per-user locations. |
| User Data & Sync Platform | `UnistoreSvc` | Handles storage of structured user data, including contact info, calendars, messages, and other content. If you stop or disable this service, apps that use this data might not work correctly. |
|  | `UserDataSvc` | Provides apps access to structured user data, including contact info, calendars, messages, and other content. If you stop or disable this service, apps that use this data might not work correctly. |
|  | `ConsentUxUserSvc` | Allows the system to request user consent to allow apps to access sensitive resources and information such as the device's location |
|  | `MessagingService` | Service supporting text messaging and related functionality. |
|  | `PimIndexMaintenanceSvc` | Indexes contact data for fast contact searching. If you stop or disable this service, contacts might be missing from your search results. |
| Virtual Bus | `CompositeBus` | Multi-Transport Composite Bus Enumerator |
|  | `umbus` | User-Mode Bus Enumerator |
|  | `vdrvroot` | Virtual Drive Root Enumerator |
|  | `NdisVirtualBus` | Microsoft Virtual Network Adapter Enumerator |
| WER | `WerSvc` | Allows errors to be reported when programs stop working or responding and allows existing solutions to be delivered. Also allows logs to be generated for diagnostic and repair services. If this service is stopped, error reporting might not work correctly and results of diagnostic services and repairs might not be displayed. |
|  | `wercplsupport` | This service provides support for viewing, sending and deletion of system-level problem reports for the Problem Reports control panel. |
| Wi-Fi | `WlanSvc` | The WLANSVC service provides the logic required to configure, discover, connect to, and disconnect from a wireless local area network (WLAN) as defined by IEEE 802.11 standards. It also contains the logic to turn your computer into a software access point so that other devices or computers can connect to your computer wirelessly using a WLAN adapter that can support this. Stopping or disabling the WLANSVC service will make all WLAN adapters on your computer inaccessible from the Windows networking UI. It is strongly recommended that you have the WLANSVC service running if your computer has a WLAN adapter. |
|  | `vwififlt` | Virtual WiFi Filter Driver |
|  | `wcncsvc` | WCNCSVC hosts the Windows Connect Now Configuration which is Microsoft's Implementation of Wireless Protected Setup (WPS) protocol. This is used to configure Wireless LAN settings for an Access Point (AP) or a Wireless Device. The service is started programmatically as needed. |
|  | `WFDSConMgrSvc` | Manages connections to wireless services, including wireless display and docking. |
|  | `NativeWifiP` | NativeWiFi Filter |
|  | `Wificx` | Wifi Network Adapter Class Extension |
| Windows Defender | `WinDefend` | Helps protect users from malware and other potentially unwanted software |
|  | `MsSecCore` | Microsoft Security Core Boot Driver |
|  | `wscsvc` | The WSCSVC (Windows Security Center) service monitors and reports security health settings on the computer.  The health settings include firewall (on/off), antivirus (on/off/out of date), antispyware (on/off/out of date), Windows Update (automatically/manually download and install updates), User Account Control (on/off), and Internet settings (recommended/not recommended). The service provides COM APIs for independent software vendors to register and record the state of their products to the Security Center service.  The Security and Maintenance UI uses the service to provide systray alerts and a graphical view of the security health states in the Security and Maintenance control panel.  Network Access Protection (NAP) uses the service to report the security health states of clients to the NAP Network Policy Server to make network quarantine decisions.  The service also has a public API that allows external consumers to programmatically retrieve the aggregated security health state of the system. |
|  | `WdFilter` | Microsoft Defender Antivirus On-Access Malware Protection Mini-Filter Driver |
|  | `WdBoot` | Microsoft Defender Antivirus Boot Driver |
|  | `WdNisSvc` | Helps guard against intrusion attempts targeting known and newly discovered vulnerabilities in network protocols |
|  | `WdNisDrv` | Helps guard against intrusion attempts targeting known and newly discovered vulnerabilities in network protocols |
|  | `SecurityHealthService` | Windows Security Service handles unified device protection and health information |
|  | `Sense` | Windows Defender Advanced Threat Protection service helps protect against advanced threats by monitoring and reporting security events that happen on the computer. |
|  | `MDCoreSvc` | Monitors the availability, health, and performance of various security components |
| Windows Insider | `wisvc` | Provides infrastructure support for the Windows Insider Program. This service must remain enabled for the Windows Insider Program to work. |
| Windows Search | `WSearch` | Provides content indexing, property caching, and search results for files, e-mail, and other content. |
| Windows Update | `WaaSMedicSvc` | Repairs damaged Windows Update components so that the computer can keep getting updates. |
|  | `UsoSvc` | Manages Windows Updates. If stopped, your devices will not be able to download and install the latest updates. |
|  | `wuauserv` | Enables the detection, download, and installation of updates for Windows and other programs. If this service is disabled, users of this computer will not be able to use Windows Update or its automatic updating feature, and programs will not be able to use the Windows Update Agent (WUA) API. |
| Xbox | `XboxGipSvc` | This service manages connected Xbox Accessories. |
|  | `xboxgip` | Xbox Game Input Protocol Driver |
|  | `XblAuthManager` | Provides authentication and authorization services for interacting with Xbox Live. If this service is stopped, some applications may not operate correctly. |
|  | `XblGameSave` | This service syncs save data for Xbox Live save enabled games. If this service is stopped, game save data will not upload to or download from Xbox Live. |
|  | `XboxNetApiSvc` | This service supports the Windows.Networking.XboxLive application programming interface. |
| VBox | `VBoxNetAdp` | VirtualBox NDIS 6.0 Host-Only Network Adapter Driver |
|  | `VBoxNetLwf` | VirtualBox NDIS 6.0 Lightweight Filter Driver  |
|  | `VBoxSup` | VirtualBox Support Driver |
|  | `VBoxUSBMon` | VirtualBox USB Monitor Driver |
|  | `VBoxSDS` | Used as a COM server for VirtualBox API. VirtualBox Global Interface. |
| VPN/RAS Services | `RemoteAccess` | Offers routing services to businesses in local area and wide area network environments. |
|  | `wanarp` | Remote Access IP ARP Driver |
|  | `wanarpv6` | Remote Access IPv6 ARP Driver |
|  | `RasMan` | Manages dial-up and virtual private network (VPN) connections from this computer to the Internet or other remote networks. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `RasAuto` | Creates a connection to a remote network whenever a program references a remote DNS or NetBIOS name or address. |
|  | `PptpMiniport` | WAN Miniport (PPTP) |
|  | `RasAgileVpn` | WAN Miniport (IKEv2) |
|  | `Rasl2tp` | WAN Miniport (L2TP) |
|  | `RasSstp` | WAN Miniport (SSTP) |
|  | `SstpSvc` | Provides support for the Secure Socket Tunneling Protocol (SSTP) to connect to remote computers using VPN. If this service is disabled, users will not be able to use SSTP to access remote servers. |
|  | `RasAcd` | Remote Access Auto Connection Driver |
| Media Sharing / Portable Devices | `WMPNetworkSvc` | Shares Windows Media Player libraries to other networked players and media devices using Universal Plug and Play |
|  | `WPDBusEnum` | Enforces group policy for removable mass-storage devices. Enables applications such as Windows Media Player and Image Import Wizard to transfer and synchronize content using removable mass-storage devices. |
| BranchCache | `PeerDistSvc` | This service caches network content from peers on the local subnet. |
| QoS/AV Streaming (qWave) | `QWAVE` | Quality Windows Audio Video Experience (qWave) is a networking platform for Audio Video (AV) streaming applications on IP home networks. qWave enhances AV streaming performance and reliability by ensuring network quality-of-service (QoS) for AV applications. It provides mechanisms for admission control, run time monitoring and enforcement, application feedback, and traffic prioritization. |
|  | `QWAVEdrv` | Quality Windows Audio/Video Experience component driver |
| NFC/Payments | `SEMgrSvc` | Manages payments and Near Field Communication (NFC) based secure elements. |
| Optimize Drives | `defragsvc` | Helps the computer run more efficiently by optimizing files on storage drives. |
| Mobile Hotspot / ICS Service | `icssvc` | Provides the ability to share a cellular data connection with another device. |
|  | `ALG` | Provides support for 3rd party protocol plug-ins for Internet Connection Sharing |
|  | `SharedAccess` | Provides network address translation, addressing, name resolution and/or intrusion prevention services for a home or small office network. |
| Network Capture Driver | `NdisCap` | Microsoft NDIS Capture |
| Container File System Drivers | `CimFS` | - |
|  | `wcifs` | Provides a virtual filesystem view for processes running within Windows Containers |
| Consumer IR Driver | `circlass` | Consumer IR Class Driver for eHome |
| iSCSI Driver | `msisadrv` | Disabling breaks laptop keyboards. |
| NetBIOS Driver | `NetBIOS` | NetBIOS Interface |
|  | `NetBT` | This service implements NetBios over TCP/IP. |
| Epic Games | `EpicGamesUpdater` | - |
|  | `EpicOnlineServices` | - |
| Logitech | `LGHUBUpdaterService` | LGHUB Updater Service |
|  | `logi_joy_bus_enum` | Logitech G HUB Virtual Bus Enumerator Driver |
|  | `logi_joy_vir_hid` | Logitech G HUB Virtual HID Device Driver |
|  | `logi_lamparray_service` | Provides HID LampArray Lighting support to Logitech devices. |
| SteelSeries | `SteelSeries_Sonar_VAD` | SteelSeries Sonar Driver |
|  | `SteelSeriesGGUpdateServiceProxy` | Launches the SteelSeries Update Service. |
|  | `ssdevfactory` | SteelSeries Device Factory Service |
| NVIDIA Container | `NVDisplay.ContainerLocalSystem` | Container service for NVIDIA root features, required for NVCPL to work. |
| Everything | `Everything (1.5a)` | Provides NTFS indexing, ReFS indexing and USN Journal services to the Everything search client. |
|  | `Everything` | ^ |
| App Deployment | `AppMgmt` | Processes installation, removal, and enumeration requests for software deployed through Group Policy. If the service is disabled, users will be unable to install, remove, or enumerate software deployed through Group Policy. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `AxInstSV` | Provides User Account Control validation for the installation of ActiveX controls from the Internet and enables management of ActiveX control installation based on Group Policy settings. This service is started on demand and if disabled the installation of ActiveX controls will behave according to default browser settings. |
|  | `BITS` | Transfers files in the background using idle network bandwidth. If the service is disabled, then any applications that depend on BITS, such as Windows Update or MSN Explorer, will be unable to automatically download programs and other information. |
|  | `EntAppSvc` | Enables enterprise application management. |
| Network Authentication | `dot3svc` | The Wired AutoConfig (DOT3SVC) service is responsible for performing IEEE 802.1X authentication on Ethernet interfaces. If your current wired network deployment enforces 802.1X authentication, the DOT3SVC service should be configured to run for establishing Layer 2 connectivity and/or providing access to network resources. Wired networks that do not enforce 802.1X authentication are unaffected by the DOT3SVC service. |
|  | `EapHost` | The Extensible Authentication Protocol (EAP) service provides network authentication in such scenarios as 802.1x wired and wireless, VPN, and Network Access Protection (NAP). EAP also provides application programming interfaces (APIs) that are used by network access clients, including wireless and VPN clients, during the authentication process. If you disable this service, this computer is prevented from accessing networks that require EAP authentication. |
| Network Profile & Connectivity UX | `NcaSvc` | Provides DirectAccess status notification for UI components |
|  | `NlaSvc` | Collects and stores configuration information for the network and notifies programs when this information is modified. If this service is stopped, configuration information might be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `Wcmsvc` | Makes automatic connect and disconnect decisions based on the network connectivity options currently available to the PC and enables management of network connectivity based on Group Policy settings. |
| Enterprise Transaction & Storage | `MSDTC` | Coordinates transactions that span multiple resource managers, such as databases, message queues, and file systems. If this service is stopped, these transactions will fail. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `MSiSCSI` | Manages Internet SCSI (iSCSI) sessions from this computer to remote iSCSI target devices. If this service is stopped, this computer will not be able to login or access iSCSI targets. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `smphost` | Host service for the Microsoft Storage Spaces management provider. If this service is stopped or disabled, Storage Spaces cannot be managed. |
| Management / Encryption Broker | `SNMPTRAP` | Receives trap messages generated by local or remote Simple Network Management Protocol (SNMP) agents and forwards the messages to SNMP management programs running on this computer. If this service is stopped, SNMP-based programs on this computer will not receive SNMP trap messages. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `WEPHOSTSVC` | Windows Encryption Provider Host Service brokers encryption related functionalities from 3rd Party Encryption Providers to processes that need to evaluate and apply EAS policies. Stopping this will compromise EAS compliancy checks that have been established by the connected Mail Accounts |
| Demo / Shared Device | `RetailDemo` | The Retail Demo service controls device activity while the device is in retail demo mode. |
|  | `shpamsvc` | Manages profiles and accounts on a SharedPC configured device |
| Graphics Compatibility | `WarpJITSvc` | Enables JIT compilation support in d3d10warp.dll for processes in which code generation is disabled. |
| Mobile Broadband | `wlpasvc` | This service provides profile management for subscriber identity modules |
|  | `WwanSvc` | This service manages mobile broadband (GSM & CDMA) data card/embedded module adapters and connections by auto-configuring the networks. It is strongly recommended that this service be kept running for best user experience of mobile broadband devices. |
| Miscellaneous | `WalletService` | Hosts objects used by clients of the wallet |
|  | `PenService` | Part of Windows Ink Services Platform Tablet Input Subsystem and is used to implement Microsoft Tablet PC functionality.  |
|  | `buttonconverter` | Service for Portable Device Control devices |
|  | `SmsRouter` | Routes messages based on rules to appropriate clients. |

Disabling `fvevol` (BitLocker Drive Encryption Filter Driver) / `rdyboost` (ReadyBoost) (rdyboost.sys) = `INACCESSIBLE_BOOT_DEVICE` BSoD.

# SCM Autostart Delay

Windows marks some services as delayed autostart to reduce boot contention. The Service Control Manager (SCM) waits before starting those services, the default delay is 120 seconds as shown below.

Windows Internals (E7, P2) puts this in the middle of the SCM boot sequence, so the delay only applies after normal autostart processing finishes.

1. SCM loops through service groups and starts autostart services, relooping groups until dependencies (DependOnService) are satisfied
2. It ignores Tag values for Windows services (Tag ordering is used by the I/O manager for boot/system-start drivers)
3. Once all groups listed in ServiceGroupOrder\\List are processed, it runs groups not listed there, then services without a group
4. After that, SCM calls ScInitDelayStart to queue a delayed work item for services marked DelayedAutostart

The delayed work item runs on a worker thread after the delay expires and performs the same actions as a normal autostart service start. The delay is a single global value 120000 ms, but it can be overridden.

Autostart services were originally meant for early boot dependencies (for example RPC), but many services are autostart only to run unattended after boot (for example update services). Marking these as delayed autostart lets critical services start faster and makes the desktop responsive sooner right after logon. Delayed autostart services are also started in background mode, which lowers their thread, I/O, and memory priority.

If a non delayed autostart service depends on a delayed autostart service, the delayed flag is ignored and the service is started immediately to satisfy the dependency.

When SCM finishes starting autostart services/drivers and schedules the delayed autostart work item, it signals \\BaseNamedObjects\\SC_AutoStartComplete.

```c
__int64 __fastcall CDelayStartContext::GetAutostartDelay(CDelayStartContext *this, __int64 a2, unsigned int a3)
{
  unsigned int v3; // ebx
  unsigned int v4; // eax
  int v7; // [rsp+40h] [rbp+8h] BYREF
  unsigned int v9; // [rsp+48h] [rbp+10h] BYREF
  unsigned int v10; // [rsp+50h] [rbp+18h] BYREF
  HANDLE Handle; // [rsp+58h] [rbp+20h] BYREF

  Handle = 0LL;
  v3 = 120000;
  v7 = 120000;
  v9 = 4;
  v4 = ScRegOpenKeyExW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control", a3, 0x20019u, (HKEY *)&Handle);
  if ( v4 )
  {
    //...
  }
  else
  {
    if ( !ScRegQueryValueExW((HKEY)Handle, L"AutostartDelay", 0LL, &v10, (unsigned __int8 *)&v7, &v9) && v10 == 4 )
      v3 = v7;
  }
  return v3;
}
```

## EnableAutostartEvents Notes

Note on a different option which I didn't implement (this information is based on Windows Internals E7 P2, P448-449):

By default the SCM logs events for services that start automatically at boot, which can flood the System event log. Setting this value to 0 suppresses autostart event logging while still keeping normal service start/stop/pause events. Read by SCM at startup = requires reboot to take effect.

"Note that the Service Control Manager by default logs all the events generated by services started automatically at system startup. This can generate an undesired number of events flooding the System event log. To mitigate the problem, you can disable SCM autostart events by creating a registry value named EnableAutostartEvents in the HKLM\System\CurrentControlSet\ Control key and set it to 0 (the default implicit value is 1 in both client and server SKUs). As a result, this will log only events generated by service applications when starting, pausing, or stopping a target service."

I didn't see any differences in the Event Viewer between setting them to `0`/`1` on my current system and on a 25H2 VM. The value exists and gets read:

```
\Registry\Machine\SYSTEM\ControlSet001\Control : EnableAutostartEvents
```
```c
void __fastcall ScCheckAutostartEventsEnabled(__int64 a1, __int64 a2, unsigned int a3)
{
  unsigned int v3; // eax
  unsigned int *v4; // r8
  int v6; // [rsp+40h] [rbp+8h] BYREF
  unsigned int v7; // [rsp+48h] [rbp+10h] BYREF
  unsigned int v8; // [rsp+50h] [rbp+18h] BYREF
  HANDLE Handle; // [rsp+58h] [rbp+20h] BYREF

  v6 = 0;
  Handle = 0LL;
  v7 = 4;
  v3 = ScRegOpenKeyExW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control", a3, 0x20019u, (HKEY *)&Handle);
  if ( v3 )
  {
    //...
  }
  else if ( !ScRegQueryValueExW((HKEY)Handle, L"EnableAutostartEvents", v4, &v8, (unsigned __int8 *)&v6, &v7) && v8 == 4 )
  {
    g_fEnableAutostartEvents = v6 != 0;
  }
}
```
```json
"Disable Autostart Events": {
  "apply": {
    "HKLM\\SYSTEM\\CurrentControlSet\\Control": {
      "EnableAutostartEvents": { "Type": "REG_DWORD", "Data": 0 }
    }
  },
  "revert": {
    "HKLM\\SYSTEM\\CurrentControlSet\\Control": {
      "EnableAutostartEvents": { "Action": "deletevalue" }
    }
  }
},
```

# Time Zone

| ID                              | Display Name                                                  | ID                              | Display Name                                              |
| ------------------------------- | ------------------------------------------------------------- | ------------------------------- | --------------------------------------------------------- |
| Afghanistan Standard Time       | (UTC+04:30) Kabul                                             | Alaskan Standard Time           | (UTC-09:00) Alaska                                        |
| Aleutian Standard Time          | (UTC-10:00) Aleutian Islands                                  | Altai Standard Time             | (UTC+07:00) Barnaul, Gorno-Altaysk                        |
| Arab Standard Time              | (UTC+03:00) Kuwait, Riyadh                                    | Arabian Standard Time           | (UTC+04:00) Abu Dhabi, Muscat                             |
| Arabic Standard Time            | (UTC+03:00) Baghdad                                           | Argentina Standard Time         | (UTC-03:00) City of Buenos Aires                          |
| Astrakhan Standard Time         | (UTC+04:00) Astrakhan, Ulyanovsk                              | Atlantic Standard Time          | (UTC-04:00) Atlantic Time (Canada)                        |
| AUS Central Standard Time       | (UTC+09:30) Darwin                                            | Aus Central W. Standard Time    | (UTC+08:45) Eucla                                         |
| AUS Eastern Standard Time       | (UTC+10:00) Canberra, Melbourne, Sydney                       | Azerbaijan Standard Time        | (UTC+04:00) Baku                                          |
| Azores Standard Time            | (UTC-01:00) Azores                                            | Bahia Standard Time             | (UTC-03:00) Salvador                                      |
| Bangladesh Standard Time        | (UTC+06:00) Dhaka                                             | Belarus Standard Time           | (UTC+03:00) Minsk                                         |
| Bougainville Standard Time      | (UTC+11:00) Bougainville Island                               | Canada Central Standard Time    | (UTC-06:00) Saskatchewan                                  |
| Cape Verde Standard Time        | (UTC-01:00) Cabo Verde Is.                                    | Caucasus Standard Time          | (UTC+04:00) Yerevan                                       |
| Cen. Australia Standard Time    | (UTC+09:30) Adelaide                                          | Central America Standard Time   | (UTC-06:00) Central America                               |
| Central Asia Standard Time      | (UTC+06:00) Nur-Sultan                                        | Central Brazilian Standard Time | (UTC-04:00) Cuiaba                                        |
| Central Europe Standard Time    | (UTC+01:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague | Central European Standard Time  | (UTC+01:00) Sarajevo, Skopje, Warsaw, Zagreb              |
| Central Pacific Standard Time   | (UTC+11:00) Solomon Is., New Caledonia                        | Central Standard Time           | (UTC-06:00) Central Time (US & Canada)                    |
| Central Standard Time (Mexico)  | (UTC-06:00) Guadalajara, Mexico City, Monterrey               | Chatham Islands Standard Time   | (UTC+12:45) Chatham Islands                               |
| China Standard Time             | (UTC+08:00) Beijing, Chongqing, Hong Kong, Urumqi             | Cuba Standard Time              | (UTC-05:00) Havana                                        |
| Dateline Standard Time          | (UTC-12:00) International Date Line West                      | E. Africa Standard Time         | (UTC+03:00) Nairobi                                       |
| E. Australia Standard Time      | (UTC+10:00) Brisbane                                          | E. Europe Standard Time         | (UTC+02:00) Chisinau                                      |
| E. South America Standard Time  | (UTC-03:00) Brasilia                                          | Easter Island Standard Time     | (UTC-06:00) Easter Island                                 |
| Eastern Standard Time           | (UTC-05:00) Eastern Time (US & Canada)                        | Eastern Standard Time (Mexico)  | (UTC-05:00) Chetumal                                      |
| Egypt Standard Time             | (UTC+02:00) Cairo                                             | Ekaterinburg Standard Time      | (UTC+05:00) Ekaterinburg                                  |
| Fiji Standard Time              | (UTC+12:00) Fiji                                              | FLE Standard Time               | (UTC+02:00) Helsinki, Kyiv, Riga, Sofia, Tallinn, Vilnius |
| Georgian Standard Time          | (UTC+04:00) Tbilisi                                           | GMT Standard Time               | (UTC+00:00) Dublin, Edinburgh, Lisbon, London             |
| Greenland Standard Time         | (UTC-02:00) Greenland                                         | Greenwich Standard Time         | (UTC+00:00) Monrovia, Reykjavik                           |
| GTB Standard Time               | (UTC+02:00) Athens, Bucharest                                 | Haiti Standard Time             | (UTC-05:00) Haiti                                         |
| Hawaiian Standard Time          | (UTC-10:00) Hawaii                                            | India Standard Time             | (UTC+05:30) Chennai, Kolkata, Mumbai, New Delhi           |
| Iran Standard Time              | (UTC+03:30) Tehran                                            | Israel Standard Time            | (UTC+02:00) Jerusalem                                     |
| Jordan Standard Time            | (UTC+03:00) Amman                                             | Kaliningrad Standard Time       | (UTC+02:00) Kaliningrad                                   |
| Kamchatka Standard Time         | (UTC+12:00) Petropavlovsk-Kamchatsky - Old                    | Korea Standard Time             | (UTC+09:00) Seoul                                         |
| Libya Standard Time             | (UTC+02:00) Tripoli                                           | Line Islands Standard Time      | (UTC+14:00) Kiritimati Island                             |
| Lord Howe Standard Time         | (UTC+10:30) Lord Howe Island                                  | Magadan Standard Time           | (UTC+11:00) Magadan                                       |
| Magallanes Standard Time        | (UTC-03:00) Punta Arenas                                      | Marquesas Standard Time         | (UTC-09:30) Marquesas Islands                             |
| Mauritius Standard Time         | (UTC+04:00) Port Louis                                        | Mid-Atlantic Standard Time      | (UTC-02:00) Mid-Atlantic - Old                            |
| Middle East Standard Time       | (UTC+02:00) Beirut                                            | Montevideo Standard Time        | (UTC-03:00) Montevideo                                    |
| Morocco Standard Time           | (UTC+01:00) Casablanca                                        | Mountain Standard Time          | (UTC-07:00) Mountain Time (US & Canada)                   |
| Mountain Standard Time (Mexico) | (UTC-07:00) La Paz, Mazatlan                                  | Myanmar Standard Time           | (UTC+06:30) Yangon (Rangoon)                              |
| N. Central Asia Standard Time   | (UTC+07:00) Novosibirsk                                       | Namibia Standard Time           | (UTC+02:00) Windhoek                                      |
| Nepal Standard Time             | (UTC+05:45) Kathmandu                                         | New Zealand Standard Time       | (UTC+12:00) Auckland, Wellington                          |
| Newfoundland Standard Time      | (UTC-03:30) Newfoundland                                      | Norfolk Standard Time           | (UTC+11:00) Norfolk Island                                |
| North Asia East Standard Time   | (UTC+08:00) Irkutsk                                           | North Asia Standard Time        | (UTC+07:00) Krasnoyarsk                                   |
| North Korea Standard Time       | (UTC+09:00) Pyongyang                                         | Omsk Standard Time              | (UTC+06:00) Omsk                                          |
| Pacific SA Standard Time        | (UTC-04:00) Santiago                                          | Pacific Standard Time           | (UTC-08:00) Pacific Time (US & Canada)                    |
| Pacific Standard Time (Mexico)  | (UTC-08:00) Baja California                                   | Pakistan Standard Time          | (UTC+05:00) Islamabad, Karachi                            |
| Paraguay Standard Time          | (UTC-04:00) Asuncion                                          | Qyzylorda Standard Time         | (UTC+05:00) Qyzylorda                                     |
| Romance Standard Time           | (UTC+01:00) Brussels, Copenhagen, Madrid, Paris               | Russia Time Zone 10             | (UTC+11:00) Chokurdakh                                    |
| Russia Time Zone 11             | (UTC+12:00) Anadyr, Petropavlovsk-Kamchatsky                  | Russia Time Zone 3              | (UTC+04:00) Izhevsk, Samara                               |
| Russian Standard Time           | (UTC+03:00) Moscow, St. Petersburg                            | SA Eastern Standard Time        | (UTC-03:00) Cayenne, Fortaleza                            |
| SA Pacific Standard Time        | (UTC-05:00) Bogota, Lima, Quito, Rio Branco                   | SA Western Standard Time        | (UTC-04:00) Georgetown, La Paz, Manaus, San Juan          |
| Sakhalin Standard Time          | (UTC+11:00) Sakhalin                                          | Saint Pierre Standard Time      | (UTC-03:00) Saint Pierre and Miquelon                     |
| Samoa Standard Time             | (UTC+13:00) Samoa                                             | Sao Tome Standard Time          | (UTC+00:00) Sao Tome                                      |
| Saratov Standard Time           | (UTC+04:00) Saratov                                           | SE Asia Standard Time           | (UTC+07:00) Bangkok, Hanoi, Jakarta                       |
| Singapore Standard Time         | (UTC+08:00) Kuala Lumpur, Singapore                           | South Africa Standard Time      | (UTC+02:00) Harare, Pretoria                              |
| South Sudan Standard Time       | (UTC+02:00) Juba                                              | Sri Lanka Standard Time         | (UTC+05:30) Sri Jayawardenepura                           |
| Sudan Standard Time             | (UTC+02:00) Khartoum                                          | Syria Standard Time             | (UTC+03:00) Damascus                                      |
| Taipei Standard Time            | (UTC+08:00) Taipei                                            | Tasmania Standard Time          | (UTC+10:00) Hobart                                        |
| Tocantins Standard Time         | (UTC-03:00) Araguaina                                         | Tokyo Standard Time             | (UTC+09:00) Osaka, Sapporo, Tokyo                         |
| Tomsk Standard Time             | (UTC+07:00) Tomsk                                             | Tonga Standard Time             | (UTC+13:00) Nuku'alofa                                    |
| Transbaikal Standard Time       | (UTC+09:00) Chita                                             | Turkey Standard Time            | (UTC+03:00) Istanbul                                      |
| Turks And Caicos Standard Time  | (UTC-05:00) Turks and Caicos                                  | Ulaanbaatar Standard Time       | (UTC+08:00) Ulaanbaatar                                   |
| US Eastern Standard Time        | (UTC-05:00) Indiana (East)                                    | US Mountain Standard Time       | (UTC-07:00) Arizona                                       |
| UTC                             | (UTC) Coordinated Universal Time                              | UTC+12                          | (UTC+12:00) Coordinated Universal Time+12                 |
| UTC+13                          | (UTC+13:00) Coordinated Universal Time+13                     | UTC-02                          | (UTC-02:00) Coordinated Universal Time-02                 |
| UTC-08                          | (UTC-08:00) Coordinated Universal Time-08                     | UTC-09                          | (UTC-09:00) Coordinated Universal Time-09                 |
| UTC-11                          | (UTC-11:00) Coordinated Universal Time-11                     | Venezuela Standard Time         | (UTC-04:00) Caracas                                       |
| Vladivostok Standard Time       | (UTC+10:00) Vladivostok                                       | Volgograd Standard Time         | (UTC+03:00) Volgograd                                     |
| W. Australia Standard Time      | (UTC+08:00) Perth                                             | W. Central Africa Standard Time | (UTC+01:00) West Central Africa                           |
| W. Europe Standard Time         | (UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna  | W. Mongolia Standard Time       | (UTC+07:00) Hovd                                          |
| West Asia Standard Time         | (UTC+05:00) Ashgabat, Tashkent                                | West Bank Standard Time         | (UTC+02:00) Gaza, Hebron                                  |
| West Pacific Standard Time      | (UTC+10:00) Guam, Port Moresby                                | Yakutsk Standard Time           | (UTC+09:00) Yakutsk                                       |
| Yukon Standard Time             | (UTC-07:00) Yukon                                             |                                 |                                                           |

Get a list of available timezones with more detail via:
```powershell
Get-TimeZone -ListAvailable
```

# Game Mode

Game Mode should: "Prevents Windows Update from performing driver installations and sending restart notifications" Does it work? Not really, in my experience it tends to lower the priority and prevent driver updates (correct me if you've experienced otherwise) - It may also mess with process/thread priorities. Not all games support it, generally leave it enabled or benchmark the differences in equal scenarios.

Enabling/disabling it via the system settings only switches `AutoGameModeEnabled`:
```powershell
HKCU\Software\Microsoft\GameBar\AutoGameModeEnabled	Type: REG_DWORD, Length: 4, Data: 1
```
The value doesn't exist by default (not existing = `1`).

## Pseudocode Interpretation

It might set CPU affinites (`AffinitizeToExclusiveCpus`, `CpuExclusivityMaskHig`, `CpuExclusivityMaskLow`) for the game process and the maximum amount of cores the game uses (`MaxCpuCount`). The percentage of GPU memory (`PercentGpuMemoryAllocatedToGame`), GPU time (`PercentGpuTimeAllocatedToGame`) & system compositor (`PercentGpuMemoryAllocatedToSystemCompositor`) that will be dedicated to the game. It may also create a list of processes (`RelatedProcessNames`) that are gaming related, which means that they won't be affected from the game mode. These are just assumptions, I haven't looked into it in detail yet (`GamingHandlers.c`).

Pavel Yosifovich says: "Game mode tries to kind of steer away the processors from your game so the system itself and all the kernel threads and stuff like that are not going to use some processors, so your game can use those processors exclusively."
> https://youtu.be/h6BXMcRqYhA?t=3251

> [system/assets | gamemode-GamingHandlers.c](https://github.com/nohuto/win-config/blob/main/system/assets/gamemode-GamingHandlers.c)  
> https://support.xbox.com/en-US/help/games-apps/game-setup-and-play/use-game-mode-gaming-on-pc  
> https://learn.microsoft.com/en-us/uwp/api/windows.gaming.preview.gamesenumeration?view=winrt-26100

# Disable Windows Search

## Suboptions

| **Suboption** | **Description** |
| ---- | ---- |
| **Disable SafeSearch** | Disables the SafeSearch filter for web search, preventing strict filtering of search results. |
| **Prevent Index on Battery** | Prevents Windows from indexing content while running on battery power, saving system resources. |
| **Disable Index Usage for System File Search** | Disables the use of the index when searching system files, requiring a full scan each time. |
| **Find Partial Matches** | Allows partial matches to be found when searching for files, enabling more flexible search results. |
| **Exclude System Directories** | Excludes system directories from search results, narrowing down the search to user files and folders. |
| **Exclude Archived Files** | Prevents archived files from being included in search results. |
| **Disable Natural Language Search** | Disables the use of natural language search, which allows more conversational queries for search results. |
| **Search Only in Indexed Locations** | Restricts searches in non-indexed locations to only file names, rather than searching both names and contents. |
| **Exclude System Directories** | Excludes system directories (e.g., Windows folders) in search results when searching non-indexed locations. |
| **Exclude Compressed Files** | Excludes compressed files (e.g., ZIP, CAB) in search results when searching non-indexed locations. |
| **Search Only in Indexed Locations** | Disables: "Ensures that file names and contents are always searched in non-indexed locations, which may take more time." |
| [**Disallow Indexing of Encrypted Items**](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search#allowindexingencryptedstoresoritems) | This policy setting allows encrypted items to be indexed. |
| [**Disable Language Detection**](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search#alwaysuseautolangdetection) | This policy setting determines when Windows uses automatic language detection results, and when it relies on indexing history. |
| [**Prevent Querying Index Remotely**](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search#preventremotequeries) | If enabled, clients will be unable to query this computer's index remotely. Thus, when they're browsing network shares that are stored on this computer, they won't search them using the index. If disabled, client search requests will use this computer's index. |
| [**Disable Web Results in Search**](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search#donotusewebresults) | This policy setting allows you to control whether or not Search can perform queries on the web, and if the web results are displayed in Search. |
| **Disable Search Highlights** | If enabled: "See content suggestions in the search boxi and in search home". |
| **Disable Web Search** | If disabled: "removes the option of searching the Web from Windows Desktop Search". |

## Search Indexing

Search indexing builds a database of file names, properties, and contents to speed up searches, runs as `SearchIndexer.exe`, updates automatically. Disabling it slows down searches, but as shows below you should use everything anyway. Additionally you can disable content and property indexing per drive, by right clicking on the drive, then unticking the box as shown in the picture.

> https://learn.microsoft.com/en-us/windows/win32/search/-search-indexing-process-overview  
> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search

![](https://github.com/nohuto/win-config/blob/main/system/images/searchindex.png?raw=true)

Instead of using the explorer to search for a file or folder, use [`Everything`](https://www.voidtools.com/downloads/), it's a lot faster.

The `WSearch` service is needed for CmdPals `File Search` extension to work.

## Windows Policies

```json
{
  "File": "Search.admx",
  "CategoryName": "Search",
  "PolicyName": "SearchPrivacy",
  "NameSpace": "FullArmor.Policies.3B9EA2B5_A1D1_4CD5_9EDE_75B22990BC21",
  "Supported": "WinBlueExclusive - Microsoft Windows 8.1. Not supported on Windows 10 or later",
  "DisplayName": "Set what information is shared in Search",
  "ExplainText": "This policy setting allows you to control what information is shared with Bing in Search. If you enable this policy setting, you can specify one of four settings, which users won't be able to change: -User info and location: Share a user's search history, some Microsoft account info, and specific location to personalize their search and other Microsoft experiences. -User info only: Share a user's search history and some Microsoft account info to personalize their search and other Microsoft experiences. -Anonymous info: Share usage information but don't share search history, Microsoft account info or specific location. If you disable or don't configure this policy setting, users can choose what information is shared in Search.",
  "KeyPath": [
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search"
  ],
  "Elements": [
    { "Type": "Enum", "ValueName": "ConnectedSearchPrivacy", "Items": [
        { "DisplayName": "User info and location", "Data": "1" },
        { "DisplayName": "User info only", "Data": "2" },
        { "DisplayName": "Anonymous info", "Data": "3" }
      ]
    }
  ]
},
```

## Miscellaneous Notes

Exists in [Search Policies](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search), but isn't present anymore on 24H2 and probably versions above.

```c
// Disabling this setting turns off search highlights in the start menu search box and in search home. Enabling or not configuring this setting turns on search highlights in the start menu search box and in search home.
"Disable Search Highlights": {
  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search": {
    "EnableDynamicContentInWSB": { "Type": "REG_DWORD", "Data": 0 }
  }
}
```

It probably got replaced by:
```c
// Privacy & security > Search - Show search highlights
SystemSettings.exe	RegSetValue	HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings\IsDynamicSearchBoxEnabled	Type: REG_DWORD, Length: 4, Data: 0
```

# Enable HAGS

HAGS feature is introduced specifically for the WDDM. If disabled the CPU manages the GPU scheduling via a high-priority kernel thread, GPU context switches and task scheduling are handled by the CPU (CPU offloads graphics intensive tasks to the GPU for rendering). If enabled the GPU handles its own scheduling using a built in scheduler processor, context switching between GPU tasks is done directly on the GPU. It is especially beneficial, if you've a slow CPU, or if the CPU is heavily loaded with other tasks.

"It depends on your hardware, if you want HAGS to be enabled or not. E.g if using a old GPU, it may not fully support the new scheduler."

HAGS should be enabled.

> https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/  
> https://maxcloudon.com/hardware-accelerated-gpu-scheduling/

## SystemSettings Records

Enable HAGS:
```powershell
SystemSettingsAdminFlows.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\HwSchMode	Type: REG_DWORD, Length: 4, Data: 2
```
Disable HAGS:
```powershell
SystemSettingsAdminFlows.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\HwSchMode	Type: REG_DWORD, Length: 4, Data: 1
```

# Disable Storage Sense

Storage Sense deletes temporary files automatically - revert it by changing it back to `1`.

![](https://github.com/nohuto/win-config/blob/main/system/images/storagesen1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/storagesen2.png?raw=true)

`ConfigStorageSenseCloudContentDehydrationThreshold` should also exist in the key, but since I'm not sure yet I didn't add it.
```c
v30 = 0;
if ( (int)CLowDiskSpaceUI_GetIsMDMConfigured(
            (CLowDiskSpaceUI )a1,
            LConfigStorageSenseCloudContentDehydrationThreshold,
            &v30)  0
    !v30 )
```

## Windows Policies

```json
{
  "File": "StorageSense.admx",
  "CategoryName": "StorageSense",
  "PolicyName": "SS_AllowStorageSenseGlobal",
  "NameSpace": "Microsoft.Policies.StorageSense",
  "Supported": "Windows_10_0_RS6",
  "DisplayName": "Allow Storage Sense",
  "ExplainText": "Storage Sense can automatically clean some of the user\u2019s files to free up disk space. By default, Storage Sense is automatically turned on when the machine runs into low disk space and is set to run whenever the machine runs into storage pressure. This cadence can be changed in Storage settings or set with the \"Configure Storage Sense cadence\" group policy. Enabled: Storage Sense is turned on for the machine, with the default cadence as \u2018during low free disk space\u2019. Users cannot disable Storage Sense, but they can adjust the cadence (unless you also configure the \"Configure Storage Sense cadence\" group policy). Disabled: Storage Sense is turned off the machine. Users cannot enable Storage Sense. Not Configured: By default, Storage Sense is turned off until the user runs into low disk space or the user enables it manually. Users can configure this setting in Storage settings.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\StorageSense"
  ],
  "ValueName": "AllowStorageSenseGlobal",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "StorageSense.admx",
  "CategoryName": "StorageSense",
  "PolicyName": "SS_AllowStorageSenseTemporaryFilesCleanup",
  "NameSpace": "Microsoft.Policies.StorageSense",
  "Supported": "Windows_10_0_RS6",
  "DisplayName": "Allow Storage Sense Temporary Files cleanup",
  "ExplainText": "When Storage Sense runs, it can delete the user\u2019s temporary files that are not in use. If the group policy \"Allow Storage Sense\" is disabled, then this policy does not have any effect. Enabled: Storage Sense will delete the user\u2019s temporary files that are not in use. Users cannot disable this setting in Storage settings. Disabled: Storage Sense will not delete the user\u2019s temporary files. Users cannot enable this setting in Storage settings. Not Configured: By default, Storage Sense will delete the user\u2019s temporary files. Users can configure this setting in Storage settings.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\StorageSense"
  ],
  "ValueName": "AllowStorageSenseTemporaryFilesCleanup",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```

# Reduce Shutdown Time

Forces hung apps and services to terminate faster.

```
\Registry\Machine\SYSTEM\ControlSet001\Control : WaitToKillServiceTimeout
\Registry\User\S-ID\Control Panel\Desktop : WaitToKillTimeout
\Registry\User\S-ID\Control Panel\Desktop : HungAppTimeout
\Registry\User\S-ID\Control Panel\Desktop : AutoEndTasks
```
`HungAppTimeout`-> `1500` (`1.5` sec; default is `5` sec)
`WaitToKillTimeout`-> `2500` (`2.5` sec)
`WaitToKillServiceTimeout`-> `2500` (`2.5` sec; default is `5` sec)
`WaitToKillAppTimeout` seems to not be used anymore (would have a default of `20000` (`20` sec))

More timeout related values located in `HKCU\Control Panel\Desktop`: `CriticalAppShutdownCleanupTimeout`, `CriticalAppShutdownTimeout`, `QuickResolverTimeout`, `ActiveWndTrkTimeout`, `CaretTimeout`, `ForegroundLockTimeout`, `LowLevelHooksTimeout`. I may add information about some of them soon.

> https://github.com/nohuto/win-registry/blob/main/records/ControlPanel-Desktop.txt

# Disable FTH

Used for preventing legacy or unstable applications from crashing, read through the picture below for more detailed information (`Windows Internals 7th Edition, Part 1, Page 347`).

> https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf  
> https://learn.microsoft.com/en-us/windows/win32/win7appqual/fault-tolerant-heap  
> https://www.youtube.com/watch?v=4SvNNXAwoqE

## Windows Internals

![](https://github.com/nohuto/win-config/blob/main/system/images/fth.png?raw=true)

# Disable Accessibility Features

Disables all kind of accessibility features such as `Voice Access`, `Live Captions`, `Narrator`, `Magnifier`, `OSK` (only via suboption) etc. (`SystemSettings > Accessibility`/`Control Panel > All Control Panel Items > Ease of Access Center`).

## Suboptions

| Suboption | Description |
| --- | --- |
| Audio Description | Hear descriptions of what's happening in videos (when available). |
| Dynamic Scrollbars | "Always show scrollbars", `On` dynamically hide them. |
| [Voice Access](https://support.microsoft.com/en-us/topic/use-voice-access-to-control-your-pc-author-text-with-your-voice-4dcd23ee-f1b9-4fd1-bacc-862ab611f55d) | Modern voice command feature to help you interact with your PC and dictate text. |
| Live Captions | Audio and video will be captioned live on your screen. |
| Notification Box Visbility Time | Time how long the Windows notification boxes should stay opened. |
| Narrator | Narrator reads aloud any text on the screen. You will need speakers. |
| Sound Sentry | Visual notifications for sounds (this option chooses 'None' as visual warning). |
| Color Filters | "Use a color filter to make colors on your screen easier to see and differentiate." |
| Mono Audio | Combine left and right audio channels into one. |
| Magnifier | Magnifier zooms in anywhere on the screen, and makes everything in that area larger. You can move Magnifier around, lock it in one place, or resize it. |
| On-Screen Keyboard | Tyoe using the mouse or another pointing device such as a joystick by selecting keys from a picture of a keyboard. |
| [Accessibility Insights Telemetry](https://github.com/microsoft/accessibility-insights-windows/blob/main/docs/TelemetryOverview.md#control-of-telemery) | "Accessibility Insights for Windows uses telemetry to better understand what features are most helpful to users, as well as to help identify potential issues that users are experiencing." |

# Detailed Verbose Messages

Enables detailed messages at restart, shut down, sign out, and sign in, which can be helpful.

"If verbose logging isn't enabled, you'll still receive normal status messages such as "Applying your personal settings..." or "Applying computer settings..." when you start up, shut down, log on, or log off from the computer. However, if verbose logging is enabled, you'll receive additional information, such as "RPCSS is starting" or "Waiting for machine group policies to finish...."."

"This policy setting directs the system to display highly detailed status messages.This policy setting is designed for advanced users who require this information.If you enable this policy setting, the system displays status messages that reflect each step in the process of starting, shutting down, logging on, or logging off the system. If you disable or do not configure this policy setting, only the default status messages are displayed to the user during these processes.
Note: This policy setting is ignored if the \"Remove Boot/Shutdown/Logon/Logoff status messages" policy setting is enabled."

> https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/enable-verbose-startup-shutdown-logon-logoff-status-messages

## Windows Policies

```json
{
  "File": "Logon.admx",
  "CategoryName": "System",
  "PolicyName": "VerboseStatus",
  "NameSpace": "Microsoft.Policies.WindowsLogon",
  "Supported": "Win2k",
  "DisplayName": "Display highly detailed status messages",
  "ExplainText": "This policy setting directs the system to display highly detailed status messages. This policy setting is designed for advanced users who require this information. If you enable this policy setting, the system displays status messages that reflect each step in the process of starting, shutting down, logging on, or logging off the system. If you disable or do not configure this policy setting, only the default status messages are displayed to the user during these processes. Note: This policy setting is ignored if the \"\"Remove Boot/Shutdown/Logon/Logoff status messages\"\" policy setting is enabled.",
  "KeyPath": [
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
  ],
  "ValueName": "VerboseStatus",
  "Elements": []
},
```

# Disable Aero Shake

Prevents windows from being minimized or restored when the active window is shaken back and forth with the mouse.

`SystemSettings > System > Multitasking: Title bar window shake`.

![](https://www.techjunkie.com/wp-content/uploads/2018/10/windows-aero-shake-example.gif)

## Windows Policies

```json
{
  "File": "Desktop.admx",
  "CategoryName": "Desktop",
  "PolicyName": "NoWindowMinimizingShortcuts",
  "NameSpace": "Microsoft.Policies.WindowsDesktop",
  "Supported": "Windows7",
  "DisplayName": "Turn off Aero Shake window minimizing mouse gesture",
  "ExplainText": "Prevents windows from being minimized or restored when the active window is shaken back and forth with the mouse. If you enable this policy, application windows will not be minimized or restored when the active window is shaken back and forth with the mouse. If you disable or do not configure this policy, this window minimizing and restoring gesture will apply.",
  "KeyPath": [
    "HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer"
  ],
  "ValueName": "NoWindowMinimizingShortcuts",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```

# Disable JPEG Reduction

Windows reduces the quality of JPEG images you set as the desktop background to `85%` by default, you can set it to `100%` via the option switch.

### TranscodeImage

```c
if ( JPEGImportQuality not present or error )
    v54 = 85.0f;
else
    v54 = max(JPEGImportQuality, 60.0f);
    if (v54 > 100.0f)
        v54 = 100.0f;
```
Default value is `85` -> `85%` (gets used if value isn't present), clamp range is `60-100`, if set above `100` it gets clamped to `100`, if set below `60`, it gets clamped to `60`.

> [system/assets | jpeg-TranscodeImage.c](https://github.com/nohuto/win-config/blob/main/system/assets/jpeg-TranscodeImage.c)

# Enable Segment Heap

"With the introduction of Windows 10, Segment Heap, a new native heap implementation was also introduced. It is currently the native heap implementation used in Windows apps (formerly called Modern/Metro apps) and in certain system processes, while the older native heap implementation (NT Heap) is still the default for traditional applications."

Allows modern apps to use a more efficient memory allocator.

Windows Internals (E7-P1, Segment heap): UWP apps default to segment heaps, while desktop apps keep the NT heap for compatibility. Segment heaps separate metadata from user data and can reduce overhead, but they are not compatible with all heap patterns.

### Default Values

```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
    "HeapDeCommitFreeBlockThreshold" = 4096; // qword_140FC3210 dq 1000
    "HeapDeCommitTotalFreeThreshold" = 65536; // qword_140FC3218 dq 10000
    "HeapSegmentCommit" = 8192; // qword_140FC3220 dq 2000
    "HeapSegmentReserve" = 1048576; // qword_140FC3228 dq 100000

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Segment Heap";
    "Enabled" = 0; // if present with DataLength==4 and nonzero type:
                    //    RtlpLowFragHeapGlobalFlags |= 0x10;  // global segment heap enable
                    //    if (value & 0x2)                      // low byte, bit 1
                    //        RtlpLowFragHeapGlobalFlags |= 0x20; // extra option ?
                    // if the value exists but is stored as REG_NONE (type==0):
                    //    RtlpLowFragHeapGlobalFlags |= 0x8;   // global disable/override
```
> https://github.com/nohuto/win-registry#session-manager-values  
> [system/assets | segment-RtlpHpApplySegmentHeapConfigurations.c](https://github.com/nohuto/win-config/blob/main/system/assets/segment-RtlpHpApplySegmentHeapConfigurations.c)

For a specific executeable:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
Image File Execution Options\(executable)
FrontEndHeapDebugOptions = (DWORD)
Bit 2 (0x04): Disable Segment Heap
Bit 3 (0x08): Enable Segment Heap
```
Globally:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Segment Heap
Enabled = (DWORD)
0 : Disable Segment Heap
(Not 0): Enable Segment Heap
```
Enabling segment heap globally forces the system to use the newer segmented allocation model, which can end up with errors (`The exception unknown software exception (0xc000000d) occurred in the application at location 0x00007FFF1E13FF03`).

> https://blog.s-schoener.com/2024-11-05-segment-heap/  
> https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals-wp.pdf  
> https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf (Page `334`f.)  

## Windows Internals

![](https://github.com/nohuto/win-config/blob/main/system/images/segment1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/segment2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/segment3.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/segment4.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/segment5.png?raw=true)

# Disable Notifications

## Option/Suboptions

| Option | Description |
| ---- | ---- |
| Main | Disables all kind of notifications completely. |
| Disable Low Disk Space Checks | Disables the `Low Disk Space` notification. ![](https://github.com/nohuto/win-config/blob/main/system/images/lowdiskspace.jpg?raw=true) |
| Hide all Windows Security notifications | Disables all notifications via the `DisableNotifications`  policy (this probably overrides all other security notifications below). |
| Hide non-critical Windows Security notifications | Disables non-critical/enhanced notifications via the Windows Security and Microsoft Defender Antivirus `DisableEnhancedNotifications` policies. |
| Disable Enhanced Phishing Protection warnings | Disables the Enhanced Phishing Protection warning prompts for malicious sites, password reuse, and unsafe apps. |
| Disable Virus & threat protection notifications | Disables all in `Windows Security > Settings > Manage notifications: Virus & threat protection notifications` |
| Disable Account protection notifications | Disables all in `Windows Security > Settings > Manage notifications: Account protection notifications` |
| Disable Firewall & network protection notifications | Disables all in `Windows Security > Settings > Manage notifications: Firewall & network protection notifications` |
| Disable Security & Maintenance Notifications | Disables it via `SystemSettings > System > Notifications: Security and Maintenance` |
| Disable Sync Provider Notifications | Disables it via `Explorer > View > Options > View: Show sync provider notifications` |
| Disable account-related notifications | Disables it via `SystemSettings > Personalization > Start: Show account related notifications occasionally in Start` |
| Disable Clock Change notifications | Disables it via `Control Panel > Clock and Region > Date and Time: Notify me when the clock chanes` |
| Hide Notification Center | Works via `NoAutoTrayNotify`/`DisableNotificationCenter` policies and `SystemSettings > System > Notifications: Show notification bell icon` |
| Disable Notification Sound | Disables it via `SystemSettings > System > Notifications > Allow notifications to play sound` |
| Disable Lockscreen Notifications | Works via `DisableLockScreenAppNotifications` policy and `SystemSettings > System > Notifications: Show notifications on the lock screen + Show reminders and incoming VoIP calls on the lock screen` |
| Turn off access to the Store | `NoUseStoreOpenWith` policy - "*This policy setting specifies whether to use the Store service for finding an application to open a file with an unhandled file type or protocol association. When a user opens a file type or protocol that is not associated with any applications on the computer, the user is given the choice to select a local application or use the Store service to find an application. If you enable this policy setting, the "Look for an app in the Store" item in the Open With dialog is removed. If you disable or do not configure this policy setting, the user is allowed to use the Store service and the Store item is available in the Open With dialog.*" |
| Hide Time in Notification Center | Works via `SystemSettings > Time & language > Date & time: Show time and date in the System tray` |


## All NOC_GLOBAL_SETTING Values

All `NOC_GLOBAL_SETTING_*` I found in `NotificationController.dll`:
```c
"HKLM\\SOFTWARE\\Microsoft\\WINDOWS\\CurrentVersion\\Notifications\\Settings"
  'NOC_GLOBAL_SETTING_SUPRESS_TOASTS_WHILE_DUPLICATING'; // Hide notifications when I'm duplicating my screen
  'NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK'; // Show notifications on the lock screen
  'NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK'; // Show reminders and incoming VoIP calls on the lock screen
  'NOC_GLOBAL_SETTING_CORTANA_MANAGED_NOTIFICATIONS';
  'NOC_GLOBAL_SETTING_ALLOW_ACTION_CENTER_ABOVE_LOCK';
  'NOC_GLOBAL_SETTING_HIDE_NOTIFICATION_CONTENT';
  'NOC_GLOBAL_SETTING_TOASTS_ENABLED';
  'NOC_GLOBAL_SETTING_BADGE_ENABLED'; // Don't show number of notifications
  'NOC_GLOBAL_SETTING_GLEAM_ENABLED'; // App icons (Action Center)
  'NOC_GLOBAL_SETTING_ALLOW_HMD_NOTIFICATIONS'; // Show notifications on my head mounted display
  'NOC_GLOBAL_SETTING_ALLOW_CONTROL_CENTER_ABOVE_LOCK';
  'NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND'; // Allow notification to play sounds
```
The options I've commented on are included in the options under `System > Notifications`/right click menu of notification center.

## Miscellaneous Notes

### WnsEndpoint

"`WnsEndpoint` (`REG_SZ`) determines which Windows Notification Service (WNS) endpoint will be used to connect for Windows push notifications. If you disable or don't configure this setting, the push notifications will connect to the default endpoint of `client.wns.windows.com`. " Located in `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications`. Block `client.wns.windows.com` via the hosts file.

### Registry Research

Since `BackupReminderToastCount` isn't a well known value, I've done quick research where it exists and if it does exist. While doing so I found different values:
```c
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy";
    "StoragePoliciesNotified" = 0; // REG_DWORD, default 0 if missing, range: 0-1
    "StoragePoliciesChanged" = 0; // REG_DWORD, default 0 if missing, range: 0-1
    "OptinToastFired" = 0; // REG_DWORD, default 0 if missing, range: 0-1
    "FirstLaunchToastFired" = 0; // REG_DWORD, default 0 if missing, range: 0-1
    "CloudfilePolicyConsent" = 0; // REG_DWORD, default 0 if missing, range: 0-1
    "CloudConsentToastCount" = 0; // REG_DWORD, default 0 if missing, range: 0-3
    "OptOutButtonClicked" = 0; // REG_DWORD, default 0 if missing, range: 0-1

"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DiskSpaceChecking";
    "LastInstallTimeLowStorageNotify" = 0; // REG_QWORD FILETIME, range: FILETIME, ComparedTo: OneDay
    "NumWinOldLowStorageNotify" = 0; // REG_DWORD, default 0 if missing, range: 0-3

"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion";
    "InstallTime" = 0; // REG_QWORD FILETIME, range: FILETIME, ComparedTo: TwoHours

"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\BackupReminder";
    "TestBackupReminderToast" = 0; // REG_DWORD, default 0 if missing, range: 0-2?

"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\BackupReminder";
    "FirstProfileSeenTime" = 0; // REG_QWORD FILETIME, default set to current system time if missing, range: FILETIME, ComparedTo: FourMinutes
    "BackupReminderToastCount" = 0; // REG_DWORD, default 0 if missing, range: 0-3
    "LastTimeBackupReminderNotify" = 0; // REG_QWORD FILETIME, range: FILETIME, ComparedTo: TwoMinutes

// FILETIME THRESHOLDS
"OneDay" = 0xC92A69C000; // Seconds: 86400, 1 day, LastInstallTimeLowStorageNotify
"TwoHours" = 0x10C388D000; // Seconds: 7200, 2 hours, InstallTime
"FourMinutes" = 0x8F0D1800; // Seconds: 240, 4 minutes, FirstProfileSeenTime
"TwoMinutes" = 0x47868C00; // Seconds: 120, 2 minutes, LastTimeBackupReminderNotify
```

See [system/assets | noti-CLowDiskSpaceUI_CanShowStorageSenseToast.c](https://github.com/nohuto/win-config/blob/main/system/assets/noti-CLowDiskSpaceUI_CanShowStorageSenseToast.c) for used pseudocode. Note that I added my chosen values to the `Disable Low Disk Space Checks` suboption for safety reasons.

```c
"HKCU\\Control Panel\\Accessibility";
  // Dismiss notifications after this amount of time
  "MessageDuration" = 5; // REG_DWORD, range 5-300(s) - According to pseudocode, it has a range from `0` to `0xFFFFFFFF`. Fallback of `5`, SystemSettings supports ranges from `5` (5 seconds) to `300` (5 minutes). Anything above/below will likely be limited (haven't tested it yet).

"HKCU\\Software\\Microsoft\\Windows\\MiracastDiscovery"
  "DisableNotification" = 0; // read on boot - "HKCU\Software\Microsoft\Windows\MiracastDiscovery\DisableNotification","Type: REG_DWORD, Length: 4, Data: 0"
  "NotificationCount" = 0; // read on boot - "HKCU\Software\Microsoft\Windows\MiracastDiscovery\NotificationCount","Type: REG_DWORD, Length: 4, Data: 0"

// miscellaneous procmon boot trace values
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\IsDebugEnabled","Length: 16"
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\SmartOptOut\\InitialTimerCooldown","Length: 20"
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\SmartOptOut\\PeriodicTimerCooldown","Length: 20"
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\SmartOptOut\\SmartOptOutRevision","Type: REG_QWORD, Length: 8, Data: "
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\TimestampWhenSeen","Length: 20"
```

## Windows Policies

```json
{
  "File": "WindowsDefenderSecurityCenter.admx",
  "CategoryName": "Notifications",
  "PolicyName": "Notifications_DisableEnhancedNotifications",
  "NameSpace": "Microsoft.Policies.WindowsDefenderSecurityCenter",
  "Supported": "Windows_10_0_RS3",
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
  "File": "WindowsDefender.admx",
  "CategoryName": "Reporting",
  "PolicyName": "Reporting_DisableEnhancedNotifications",
  "NameSpace": "Microsoft.Policies.WindowsDefender",
  "Supported": "Windows_10_0",
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
  "File": "WindowsDefenderSecurityCenter.admx",
  "CategoryName": "Notifications",
  "PolicyName": "Notifications_DisableNotifications",
  "NameSpace": "Microsoft.Policies.WindowsDefenderSecurityCenter",
  "Supported": "Windows_10_0_RS3",
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
  "File": "ICM.admx",
  "CategoryName": "InternetManagement_Settings",
  "PolicyName": "ShellNoUseStoreOpenWith_2",
  "NameSpace": "Microsoft.Policies.InternetCommunicationManagement",
  "Supported": "Windows8",
  "DisplayName": "Turn off access to the Store",
  "ExplainText": "This policy setting specifies whether to use the Store service for finding an application to open a file with an unhandled file type or protocol association. When a user opens a file type or protocol that is not associated with any applications on the computer, the user is given the choice to select a local application or use the Store service to find an application. If you enable this policy setting, the \"Look for an app in the Store\" item in the Open With dialog is removed. If you disable or do not configure this policy setting, the user is allowed to use the Store service and the Store item is available in the Open With dialog.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\Explorer"
  ],
  "ValueName": "NoUseStoreOpenWith",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WPN.admx",
  "CategoryName": "NotificationsCategory",
  "PolicyName": "NoTileNotification",
  "NameSpace": "Microsoft.Policies.Notifications",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Turn off tile notifications",
  "ExplainText": "This policy setting turns off tile notifications. If you enable this policy setting, applications and system features will not be able to update their tiles and tile badges in the Start screen. If you disable or do not configure this policy setting, tile and badge notifications are enabled and can be turned off by the administrator or user. No reboots or service restarts are required for this policy setting to take effect.",
  "KeyPath": [
    "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications"
  ],
  "ValueName": "NoTileApplicationNotification",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WPN.admx",
  "CategoryName": "NotificationsCategory",
  "PolicyName": "NoNotificationMirroring",
  "NameSpace": "Microsoft.Policies.Notifications",
  "Supported": "Windows_10_0 - At least Windows Server 2016, Windows 10",
  "DisplayName": "Turn off notification mirroring",
  "ExplainText": "This policy setting turns off notification mirroring. If you enable this policy setting, notifications from applications and system will not be mirrored to your other devices. If you disable or do not configure this policy setting, notifications will be mirrored, and can be turned off by the administrator or user. No reboots or service restarts are required for this policy setting to take effect.",
  "KeyPath": [
    "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications"
  ],
  "ValueName": "DisallowNotificationMirroring",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WPN.admx",
  "CategoryName": "NotificationsCategory",
  "PolicyName": "NoToastNotification",
  "NameSpace": "Microsoft.Policies.Notifications",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Turn off toast notifications",
  "ExplainText": "This policy setting turns off toast notifications for applications. If you enable this policy setting, applications will not be able to raise toast notifications. Note that this policy does not affect taskbar notification balloons. Note that Windows system features are not affected by this policy. You must enable/disable system features individually to stop their ability to raise toast notifications. If you disable or do not configure this policy setting, toast notifications are enabled and can be turned off by the administrator or user. No reboots or service restarts are required for this policy setting to take effect.",
  "KeyPath": [
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
    "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications"
  ],
  "ValueName": "NoToastApplicationNotification",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WPN.admx",
  "CategoryName": "NotificationsCategory",
  "PolicyName": "NoLockScreenToastNotification",
  "NameSpace": "Microsoft.Policies.Notifications",
  "Supported": "Windows8 - At least Windows Server 2012, Windows 8 or Windows RT",
  "DisplayName": "Turn off toast notifications on the lock screen",
  "ExplainText": "This policy setting turns off toast notifications on the lock screen. If you enable this policy setting, applications will not be able to raise toast notifications on the lock screen. If you disable or do not configure this policy setting, toast notifications on the lock screen are enabled and can be turned off by the administrator or user. No reboots or service restarts are required for this policy setting to take effect.",
  "KeyPath": [
    "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications"
  ],
  "ValueName": "NoToastApplicationNotificationOnLockScreen",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```

# Export Explorer/Taskbar Pins

Can be useful when creating your own image and trying to automate the installation and configuration part.

### Quick Access Pins

Quick access pins are saved in a file named `f01b4d95cf55d32a.automaticDestinations-ms`, located at:
```bat
%appdata%\Microsoft\Windows\Recent\AutomaticDestinations
```
You can either terminate `explorer` while copying it to the path, or just restart it afterwards.
```bat
copy /y ".\f01b4d95cf55d32a.automaticDestinations-ms" "%appdata%\Microsoft\Windows\Recent\AutomaticDestinations"
```

### Taskbar Pins

Taskbar pins are saved in a folder and a key, the folder includes the shortcuts:
```bat
%appdata%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar
```
```powershell
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband # Only "Favorites" is needed
```
You can convert the exported `.reg` to `.ps1` with:
> https://reg2ps.azurewebsites.net/

Post install example (copy the `TaskBar` folder to any folder):
```powershell
del "$env:appdata\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" -Recurse -Force
xcopy ".\TaskBar" "%appdata%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" /e /i /y
```
> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/xcopy

The option gets current values of `Favorites` (taskbar pins) & `UIOrderList` (system tray icons) and copies all necessary files to `$home\Desktop` (edit `$dest` & `$bat` to whatever you want).

# Disable Timestamp Interval

Disables the interval at which reliability events are timestamped (will not log regular timestamped reliability events).

```c
if ( !RegQueryValueExW(hKey[0], "TimeStampEnabled", 0LL, 0LL, (LPBYTE)&Data, &cbData) )
if ( !RegQueryValueExW(hKey[0], "TimeStampInterval", 0LL, 0LL, (LPBYTE)&v4, &cbData) && v4 <= 0x15180 ) // 86400 seconds = 24h?
```
`TimeStampInterval` has a max value of `86400` dec = 24h, `TimeStampEnabled` can probably be set to `0`/`1`.

```
\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability : TimeStampInterval
```
Only this path gets read, `TimeStampEnabled` doesn't get read?

> [system/assets | timestamp-OsEventsTimestampInterval.c](https://github.com/nohuto/win-config/blob/main/system/assets/timestamp-OsEventsTimestampInterval.c)

# Disable Prefetch & Superfetch

Disables prefetcher (includes disabling `ApplicationLaunchPrefetching` & `ApplicationPreLaunch`) features, used to speed up the boot process and application startup by preloading data - **shouldn't be disabled**, leaving it for documentation reasons. Read through the pictures for more detailed information.

Windows Internals (E7-P1, Prefetcher): the prefetcher traces roughly the first 10 seconds of app startup and writes trace files to `%SystemRoot%\\Prefetch`. The Superfetch service consumes those traces and issues clustered reads on subsequent starts. `EnablePrefetcher` controls the boot/app prefetch modes.

## Value Meanings

- `EnablePrefetcher` is a setting in the File-Based Write Filter (FBWF) and Enhanced Write Filter with HORM (EWF) packages. It specifies how to run Prefetch, a tool that can load application data into memory before it is demanded.
- `EnableSuperfetch` is a setting in the File-Based Write Filter (FBWF) and Enhanced Write Filter with HORM (EWF) packages. It specifies how to run SuperFetch, a tool that can load application data into memory before it is demanded. SuperFetch improves on Prefetch by monitoring which applications that you use the most and preloading those into system memory.
- `SfTracingState` belongs to `sftracing.exe`. This file most often belongs to product Office Server Search. This file most often has  description Office Server Search.
- `EnableBoottrace` is used to trace the startup, `1`= enabled, `0` = disabled.

```
0 - Disables Prefetch
1 - Enables Prefetch when the application starts
2 - Enables Prefetch when the device starts up
3 - Enables Prefetch when the application or device starts up
```
The same applies to superfetch.

> https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ff794235(v=winembedded.60)?redirectedfrom=MSDN  
> https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ff794183(v=winembedded.60)?redirectedfrom=MSDN  
> https://learn.microsoft.com/en-us/powershell/module/mmagent/disable-mmagent?view=windowsserver2025-ps

## Windows Internals

More detailed information about prefetch and superfetch on page `413`f & `472`f.
> https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf

![](https://github.com/nohuto/win-config/blob/main/system/images/prefetch1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/prefetch2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/prefetch3.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/prefetch4.png?raw=true)

# Optimize File System

Small documentation on several values the option applies, see links below for more details.

### Registry Values

| Value | Description |
| ----- | ------------ |
| `DisableDeleteNotification` | 0 = TRIM/UNMAP enabled, 1 = disabled. Controls whether delete operations send trim/unmap notifications to the underlying storage. |
| `DontVerifyRandomDrivers` | 0 = Driver Verifier may pick random drivers, 1 = random selection suppressed, so only explicitly chosen drivers are verified. |
| `LongPathsEnabled` | 0 = legacy `MAX_PATH` limit, 1 = Win32 long paths enabled (paths up to ~32k characters for apps and policies that opt in). |
| `NtfsAllowExtendedCharacter8dot3Rename` | 0 = 8.3 short names restricted to basic ASCII, 1 = extended characters (including diacritics). |
| `NtfsBugcheckOnCorrupt` | 0 = NTFS attempts self healing without forcing a bugcheck, 1 = triggers a bugcheck when corruption is detected on an NTFS volume, avoiding "silent" data loss with self healing NTFS. |
| `NtfsDisable8dot3NameCreation` | Disables the creation of 8.3 character-length file names on FAT- and NTFS-formatted volumes.<br>0: Enables 8dot3 name creation for all volumes on the system.<br>1: Disables 8dot3 name creation for all volumes on the system.<br>2: Sets 8dot3 name creation on a per volume basis.<br>3: Disables 8dot3 name creation for all volumes except the system volume. |
| `NtfsDisableCompression` | 0 = NTFS compression allowed, 1 = new compressed files/folders cannot be created (existing compressed data remains readable). |
| `NtfsDisableCompressionLimit` | 0 = when a compressed file gets highly fragmented, NTFS stops compressing new extents so the file can grow larger uncompressed, 1 = disables this behavior and enforces the internal compression limit. |
| `NtfsDisableEncryption` | 0 = NTFS EFS file/folder encryption available, 1 = EFS disabled on NTFS volumes. |
| `NTFSDisableLastAccessUpdate` | Controls Last Access Time updates on NTFS files/directories. |
| `NtfsDisableSpotCorruptionHandling` | 0 = NTFS spot corruption handling active, 1 = disabled, so NTFS relies on manual tools. Also allows running CHKDSK to analyze a volume online without taking it offline. |
| `NtfsEncryptPagingFile` | 0 = pagefile.sys stored unencrypted, 1 = paging file encrypted. |
| `NtfsMemoryUsage` | Configures the internal cache levels of NTFS paged-pool memory and NTFS nonpaged-pool memory. |
| `NtfsMftZoneReservation` | Sets reserved NTFS MFT zone size as 200 MB x value: 1 = 200 MB (default), up to 4 = 800 MB. Larger values reduce MFT fragmentation on volumes with many small files. |
| `RefsDisableLastAccessUpdate` | Related to NTFSDisableLastAccessUpdate (both get set via disablelastaccess). |
| `SymlinkXToXEvaluation` | 0 = x->x symlinks not followed, 1 = resolved (X = Local/Remote). |
| `Win31FileSystem` | 0 = standard modern FAT behavior (long filenames, richer timestamps), 1 = legacy Windows 3.1–compatible mode with stricter 8.3 naming and older timestamp semantics. |

Scan current 8dot3 files names: `fsutil 8dot3name scan C:\`

Symlinksare shortcuts or references that point to a file or folder in another location, like a portal. They're not duplicates, just pointers.
File at: `C:\Projects\Game\assets\logo.png`
Symlink: `C:\Users\YourName\Desktop\logo.png`

> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior  
> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-8dot3name  
> https://github.com/MicrosoftDocs/windows-driver-docs/blob/5e03e46194f2a977da34fdf453f2703262370a23/windows-driver-docs-pr/ifs/offloaded-data-transfers.md?plain=1#L104  
> https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry  
> https://github.com/nohuto/win-registry/blob/main/records/FileSystem.txt

> [system/assets | filesystem-NtfsUpdateDynamicRegistrySettings.c](https://github.com/nohuto/win-config/blob/main/system/assets/filesystem-NtfsUpdateDynamicRegistrySettings.c)

# Disable Clipboard

If you copy or cut something it gets stored to your clipboard.

Miscellaneous notes:
```c 
"HKLM\SOFTWARE\Microsoft\Clipboard\ClipboardSvcDebugWaitInSec","Length: 16"
"HKLM\SOFTWARE\Microsoft\Clipboard\IsClipboardSignalProducingFeatureAvailable","Type: REG_DWORD, Length: 4, Data: 1"
"HKLM\SOFTWARE\Microsoft\Clipboard\IsCloudAndHistoryFeatureAvailable","Type: REG_DWORD, Length: 4, Data: 1"

"HKCU\Software\Microsoft\Clipboard\ClipboardTipRequired","Length: 16"
"HKCU\Software\Microsoft\Clipboard\CloudClipRDPOverride","Length: 16"
"HKCU\Software\Microsoft\Clipboard\CloudClipboardAutomaticUpload","Length: 16"
"HKCU\Software\Microsoft\Clipboard\CloudContentRemoteOverrideValueWindowInSec","Length: 16"
"HKCU\Software\Microsoft\Clipboard\CloudContentValueWindowInSec","Length: 16"
"HKCU\Software\Microsoft\Clipboard\DoubleCopyGestureEnabled","Length: 16"
"HKCU\Software\Microsoft\Clipboard\EnableClipboardHistory","Length: 16"
"HKCU\Software\Microsoft\Clipboard\PastedFromClipboardUI","Length: 16"
"HKCU\Software\Microsoft\Clipboard\ShellHotKeyUsed","Length: 16"
```

## Windows Policies

```json
{
  "File": "TerminalServer.admx",
  "CategoryName": "TS_REDIRECTION",
  "PolicyName": "TS_CLIENT_CLIPBOARD",
  "NameSpace": "Microsoft.Policies.TerminalServer",
  "Supported": "WindowsXP",
  "DisplayName": "Do not allow Clipboard redirection",
  "ExplainText": "This policy setting specifies whether to prevent the sharing of Clipboard contents (Clipboard redirection) between a remote computer and a client computer during a Remote Desktop Services session. You can use this setting to prevent users from redirecting Clipboard data to and from the remote computer and the local computer. By default, Remote Desktop Services allows Clipboard redirection. If you enable this policy setting, users cannot redirect Clipboard data. If you disable this policy setting, Remote Desktop Services always allows Clipboard redirection. If you do not configure this policy setting, Clipboard redirection is not specified at the Group Policy level.",
  "KeyPath": [
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
  ],
  "ValueName": "fDisableClip",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsSandbox.admx",
  "CategoryName": "WindowsSandbox",
  "PolicyName": "AllowClipboardRedirection",
  "NameSpace": "Microsoft.Policies.WindowsSandbox",
  "Supported": "Windows_11_0_NOSERVER_ENTERPRISE_EDUCATION_PRO_SANDBOX",
  "DisplayName": "Allow clipboard sharing with Windows Sandbox",
  "ExplainText": "This policy setting enables or disables clipboard sharing with the sandbox. If you enable this policy setting, copy and paste between the host and Windows Sandbox are permitted. If you disable this policy setting, copy and paste in and out of Sandbox will be restricted. If you do not configure this policy setting, clipboard sharing will be enabled.",
  "KeyPath": [
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Sandbox"
  ],
  "ValueName": "AllowClipboardRedirection",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "OSPolicy.admx",
  "CategoryName": "PolicyPolicies",
  "PolicyName": "AllowCrossDeviceClipboard",
  "NameSpace": "Microsoft.Policies.OSPolicy",
  "Supported": "Windows_10_0",
  "DisplayName": "Allow Clipboard synchronization across devices",
  "ExplainText": "This policy setting determines whether Clipboard contents can be synchronized across devices. If you enable this policy setting, Clipboard contents are allowed to be synchronized across devices logged in under the same Microsoft account or Azure AD account. If you disable this policy setting, Clipboard contents cannot be shared to other devices. Policy change takes effect immediately.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\System"
  ],
  "ValueName": "AllowCrossDeviceClipboard",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "OSPolicy.admx",
  "CategoryName": "PolicyPolicies",
  "PolicyName": "AllowClipboardHistory",
  "NameSpace": "Microsoft.Policies.OSPolicy",
  "Supported": "Windows_10_0",
  "DisplayName": "Allow Clipboard History",
  "ExplainText": "This policy setting determines whether history of Clipboard contents can be stored in memory. If you enable this policy setting, history of Clipboard contents are allowed to be stored. If you disable this policy setting, history of Clipboard contents are not allowed to be stored. Policy change takes effect immediately.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\System"
  ],
  "ValueName": "AllowClipboardHistory",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```

# Disable Memory Compression

Memory compression compresses rarely used or less frequently accessed data in RAM so it takes up less space. Windows does this to keep more data in physical memory and avoid writing to the pagefile, which reduces disk I/O. When the data is needed again, it's decompressed. It's faster than paging to disk, but it costs CPU.

Windows Internals (E7-P1, Memory compression): compressed pages are stored in a dedicated "Memory Compression" process managed by the Store Manager. The memory manager compresses modified list pages into that store and later decompresses them on demand, this is enabled by default on client SKUs.

Example:  
1. System looks for cold/rarely used data in RAM
2. It compresses that data, e.g. 24 MB -> 7 MB
3. The 17 MB saved is used for active apps
4. When the data is needed again, it's decompressed back to 24 MB

See the current memory compresstion state on your system via:
```powershell
Get-MMAgent
```
```powershell
ApplicationLaunchPrefetching : True
ApplicationPreLaunch         : True
MaxOperationAPIFiles         : 512
MemoryCompression            : True # Enabled
OperationAPI                 : True
PageCombining                : True
PSComputerName               :
```

## Windows Internals

![](https://github.com/nohuto/win-config/blob/main/system/images/memcompress1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/memcompress2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/memcompress3.png?raw=true)

> https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf (P. 449)  
> https://learn.microsoft.com/en-us/powershell/module/mmagent/disable-mmagent?view=windowsserver2025-ps

# Disable Page Combining

Page combining spots identical RAM pages across processes and merges them into a single shared page. Instead of keeping 50 copies of the same DLL/data page, the memory manager keeps one, maps it to everyone, and marks it `copy-on-write`. As long as nobody changes it, everyone shares the same physical page and RAM usage drops. If a process writes to it, Windows gives that process its own private copy and leaves the shared one intact. It's a background RAM deduplicator, basically.

Windows Internals (E7-P1, Memory combining): the memory manager can be instructed to combine identical pages across the system, and Superfetch can trigger combining when the system is idle. The feature can be disabled via `DisablePageCombining` in the memory manager settings.

`Disable-MMAgent -PageCombining` toggles the state shown in `Get-MMAgent` but does not write the `DisablePageCombining` registry value on recent builds, so it's most likely deprecated.

```c
INIT:0000000140B9C340                 dq offset aSessionManager_7 ; "Session Manager\\Memory Management"
INIT:0000000140B9C348                 dq offset aDisablepagecom ; "DisablePageCombining"
INIT:0000000140B9C350                 dq offset dword_140D1D1C8

ALMOSTRO:0000000140D1D1C8 dword_140D1D1C8 dd 0                    ; DATA XREF: MiCombineIdenticalPages:loc_1407F7E3A↑r
```

See the current page combining state on your system via:
```powershell
Get-MMAgent
```
```powershell
ApplicationLaunchPrefetching : True
ApplicationPreLaunch         : True
MaxOperationAPIFiles         : 512
MemoryCompression            : True
OperationAPI                 : True
PageCombining                : True # Enabled
PSComputerName               :
```

## Windows Internals

![](https://github.com/nohuto/win-config/blob/main/system/images/pagecomb1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/pagecomb2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/pagecomb3.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/pagecomb4.png?raw=true)

> https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf (P. 459)  
> https://learn.microsoft.com/en-us/powershell/module/mmagent/disable-mmagent?view=windowsserver2025-ps

# Enable Detailed BSoD

| Aspect                    | New BSoD (Windows 8/10/11)                      | Old BSoD (Windows 7/classic)                                                      |
| ------------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------- |
| Main look                 | Big blue screen, sad face, simple text, QR code | Plain blue text screen, no icons                                                  |
| Stop code shown           | e.g. CRITICAL_PROCESS_DIED                      | e.g. STOP 0x0000007E                                                              |
| Hex parameters            | Hidden                                          | Shown: (0x00000000, 0x00000000...)                                                |
| Faulty driver/module name | Hidden                                          | Often shown (e.g. nvlddmkm.sys)                                                   |
| Extra help                | QR code + link                                  | Text-only advice                                                                  |
| Purpose                   | Less scary, easier to tell support the code     | See the actual debug information                                                  |

Enabling the options includes setting `AutoReboot` to `0` ("The option specifies that Windows automatically restarts your computer").

> https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options#registry-values-for-startup-and-recovery  
> https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/configure-system-failure-and-recovery-options

# Display Scaling

Changes the size of text, apps, and other items. Note that on laptops the default display scaling might not be `100%`. You can set a custom scaling size via `System > Display > Custom scaling`:

![](https://github.com/nohuto/win-config/blob/main/system/images/displayscaling.png?raw=true)

## SystemSettings Captures

```c
// 100%
SystemSettings.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\ScaleFactors\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 0
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\PerMonitorSettings\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 0

// 125%
SystemSettings.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\ScaleFactors\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 1
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\PerMonitorSettings\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 1

// 150%
SystemSettings.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\ScaleFactors\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 2
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\PerMonitorSettings\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 2

// 175%
SystemSettings.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\ScaleFactors\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 3
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\PerMonitorSettings\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 3

// 200%
SystemSettings.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\ScaleFactors\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 4
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\PerMonitorSettings\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 4

// 225%
SystemSettings.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\ScaleFactors\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 5
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\PerMonitorSettings\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 5
```

## Suboption

`Prevent Window Minimization on Monitor Disconnection` disables `Minimize windows then a monitor is diconnected` (`System > Display`).

```c
// Enabled
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\MonitorRemovalRecalcBehavior	Type: REG_DWORD, Length: 4, Data: 0

// Disabled
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\MonitorRemovalRecalcBehavior	Type: REG_DWORD, Length: 4, Data: 1
```

# BCD Edits

BCDEdit is the CL editor for the Boot Configuration Database (BCD), a registry hive under `HKLM\BCD00000000` backed by a hidden BCD file (UEFI: `\EFI\Microsoft\Boot\BCD`). The BCD replaced `boot.ini` (before Windows Vista) and stores per installation boot configuration. Each entry is a BCD object (GUID) under `Objects`, and each object has `Elements` subkeys with numeric element IDs. The `Element` value is the data that maps to a readable BCDEdit option or boot parameter. BCDEdit exposes symbolic names for objects/elements and can edit online or offline stores (`/store`), and the same data can be modified by loading the BCD hive (including remote hives).

BCDEdit is primarily used for boot troubleshooting, recovery, debugging, and security/boot behavior changes (Safe Mode, driver loading, hypervisor settings). Some may not be used on latest Windows versions anymore (e.g. HalpTscSyncPolicy, see pseudocode below).

BitLocker validates a subset of BCD settings at boot to detect security sensitive changes. The validated set can be extended or reduced via policy, and the hex value of a triggering setting is logged (event ID 523). Friendly names can be listed with `bcdedit /enum all`, but some settings have no friendly name and must be configured by hex. BCD settings are also scoped to specific boot applications (for example, `winload`, `winresume`, `bootmgr`), policy entries can be prefixed with the target application (for example, `winload:nx` or `all:locale`). When secure boot is used for integrity validation, the enhanced BCD validation profile policy is ignored, and secure boot enforces its own BCD rules.

## Key & Value Structure

As kind of everything else, BCD edits are also stored in the registry:
```c
HKLM\BCD00000000\Objects

// Structure
HKLM\BCD00000000\Objects\{GUID} // {GUID} depends on the object, e.g. {bootmgr}, {current}, {globalsettings}
HKLM\BCD00000000\Objects\{GUID}\Elements\XXXXXXXX // XXXXXXXX is a specific setting for the object (8 digit)
HKLM\BCD00000000\Objects\{GUID}\Elements\XXXXXXXX : Element // (REG_BINARY/REG_MULTI_SZ/REG_SZ - depends on the setting) this value includes the state of the setting
```

See all object identifiers via `bcdedit /enum all /v` (`identifier`). Note that the list below uses `{bootmgr}`, `{current}` etc. which must be replaced by the actual GUID (see block above).

See win-registry repo for a list of `HKLM\\BCD00000000\\Objects\\...` values/defaults/notes:
> https://github.com/nohuto/win-registry#bcd-edits

## Miscellaneous Notes

Personal notes on several features, used pseudocode:
> [system/assets | bcdedit-HalpMiscGetParameters.c](https://github.com/nohuto/win-config/blob/main/system/assets/bcdedit-HalpMiscGetParameters.c)

```c
lkd> db HalpInterruptX2ApicPolicy l1
fffff807`8d20a5dc  01

if ( strstr(v3, "X2APICPOLICY=ENABLE") )
    HalpInterruptX2ApicPolicy = 1;

if ( strstr(v3, "X2APICPOLICY=DISABLE") )
    HalpInterruptX2ApicPolicy = 0;

if ( strstr(v3, "USELEGACYAPICMODE") )
    HalpInterruptX2ApicPolicy = 0; // force disable
```
```c
lkd> db HalpTscSyncPolicy l1
Couldnt resolve error at HalpTscSyncPolicy // doesn't exist

HalpTscSyncPolicy = 1; // TSCSYNCPOLICY=LEGACY
HalpTscSyncPolicy = 2; // TSCSYNCPOLICY=ENHANCED
```

`bcdedit /set loadoptions SYSTEMWATCHDOGPOLICY=DISABLED`
```c
if ( strstr(v3, "SYSTEMWATCHDOGPOLICY=DISABLED") )
{
    HalpTimerWatchdogDisable = 1;
}
else if ( strstr(v3, "SYSTEMWATCHDOGPOLICY=PHYSICALONLY") )
{
    HalpTimerWatchdogPhysicalOnly = 1;
}

lkd> db HalpTimerWatchdogDisable l1
fffff803`d21c0712  00 // default
```
```c
lkd> db HalpTimerPlatformSourceForced l1
fffff803`d21c25d0  00
lkd> db HalpTimerPlatformClockSourceForced l1
fffff803`d21c2678  00

if ( strstr(v3, "USEPLATFORMCLOCK") )
    HalpTimerPlatformSourceForced = 1;

if ( strstr(v3, "USEPLATFORMTICK") )
    HalpTimerPlatformClockSourceForced = 1;
```
```c
v17 = strstr(v3, "GROUPSIZE");
if ( v17 )
{
    while ( 1 )
    {
        v18 = *v17;
        if ( !*v17 || v18 == 32 || (unsigned __int8)(v18 - 48) <= 9u )
            break;
        ++v17;
    }
    HalpMaximumGroupSize = atoi(v17);
    if ( (unsigned int)(HalpMaximumGroupSize - 1) > 0x3F )
        HalpMaximumGroupSize = 64; // clamp to 1..64
}

strstr(v3, "HALTPROFILINGPOLICY=BLOCKED");
strstr(v3, "HALTPROFILINGPOLICY=RELAXED");
return strstr(v3, "HALTPROFILINGPOLICY=RESTRICTED"); // only returns pointer if present
```
```c
lkd> db HalpMiscDiscardLowMemory l1
fffff803`d21bff79  01 // USENONE / USEPRIVATE?
lkd> db HalpHvCpuManager l1
fffff804`c27c0490  00

if ( (unsigned int)HalpInterruptModel() == 1 )
    HalpMiscDiscardLowMemory = 1; // default if HalpInterruptModel() == 1

if ( HalpHvCpuManager )
{
    v19[0] = 0;
    if ( (unsigned __int8)HalpGetCpuInfo(0LL, 0LL, 0LL, v19) )
    {
        if ( v19[0] == 2 && (__readmsr(0xFEu) & 0x8000) != 0 )
        HalpMiscDiscardLowMemory = 1; // 1 if HV CPU manager + CPU type 2 + MSR 0xFE bit 15 set
    }
}
if (strstr(BootOptions, "FIRSTMEGABYTEPOLICY=USEALL") || // one of them have to be true to get 0
    (HalpIsMicrosoftCompatibleHvLoaded() && !HalpHvCpuManager)) // system running under hypervisor & not HalpHvCpuManager
{
    HalpMiscDiscardLowMemory = 0; // forced 0 if above is true
}
```
```c
v3 = *(const char **)(a1 + 216);
if ( v3 )
{
    strstr(*(const char **)(a1 + 216), "SAFEBOOT:"); // does nothing here

    if ( strstr(v3, "ONECPU") )
        HalpInterruptProcessorCap = 1;

    if ( strstr(v3, "USEPHYSICALAPIC") )
        HalpInterruptPhysicalModeOnly = 1;

    if ( strstr(v3, "BREAK") )
        HalpMiscDebugBreakRequested = 1;
}
```
```c
v4 = strstr(v3, "MAXPROCSPERCLUSTER");
if ( v4 )
{
    while ( 1 )
    {
        v5 = *v4;
        if ( !*v4 || v5 == 32 || (unsigned __int8)(v5 - 48) <= 9u )
            break;
        ++v4;
    }
    v6 = atoi(v4);
    HalpInterruptForceClusterMode(v6);
}

v7 = strstr(v3, "MAXAPICCLUSTER");
if ( v7 )
{
    while ( 1 )
    {
        v8 = *v7;
        if ( !*v7 || v8 == 32 || (unsigned __int8)(v8 - 48) <= 9u )
            break;
        ++v7;
    }
    v9 = atoi(v7);
    if ( v9 )
        LODWORD(HalpInterruptMaxCluster) = v9;
}
```
```c
if ( strstr(v3, "CONFIGACCESSPOLICY=DISALLOWMMCONFIG") )
    HalpAvoidMmConfigAccessMethod = 1; // force avoid
```
```c
if ( strstr(v3, "MSIPOLICY=FORCEDISABLE") ) // HalpInterruptSetMsiOverride(0)
{
    v10 = 0LL;
}
else
{
    if ( !strstr(v3, "FORCEMSI") ) // HalpInterruptSetMsiOverride(1)
        goto LABEL_46;
    LOBYTE(v10) = 1;
}
HalpInterruptSetMsiOverride(v10);
```

## Custom Edits

`custom:16000067 true` disables the Windows logo while booting:

![](https://github.com/nohuto/win-config/blob/main/system/images/logo.png?raw=true)

`custom:16000069 true` disables the loading circle while booting:

![](https://github.com/nohuto/win-config/blob/main/system/images/load.png?raw=true)

## Default Entries

Default entries (25H2, Build 26200.6584) including WinRE:
```powershell
Windows Boot Manager
--------------------
identifier              {9dea862c-5cdd-4e70-acc1-f32b344d4795}
device                  partition=\Device\HarddiskVolume1
description             Windows Boot Manager
locale                  en-US
inherit                 {7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}
default                 {0fd8694a-e7fe-11f0-91cd-eabb9ab44a94}
resumeobject            {0fd86949-e7fe-11f0-91cd-eabb9ab44a94}
displayorder            {0fd8694a-e7fe-11f0-91cd-eabb9ab44a94}
toolsdisplayorder       {b2721d73-1db4-4c62-bf78-c548a880142d}
timeout                 30

Windows Boot Loader
-------------------
identifier              {0fd8694a-e7fe-11f0-91cd-eabb9ab44a94}
device                  partition=C:
path                    \WINDOWS\system32\winload.exe
description             Windows 11
locale                  en-US
inherit                 {6efb52bf-1766-41db-a6b3-0ee5eff72bd7}
recoverysequence        {0fd8694b-e7fe-11f0-91cd-eabb9ab44a94}
displaymessageoverride  Recovery
recoveryenabled         Yes
allowedinmemorysettings 0x15000075
osdevice                partition=C:
systemroot              \WINDOWS
resumeobject            {0fd86949-e7fe-11f0-91cd-eabb9ab44a94}
nx                      OptIn
bootmenupolicy          Standard

Windows Boot Loader
-------------------
identifier              {0fd8694b-e7fe-11f0-91cd-eabb9ab44a94}
device                  ramdisk=[\Device\HarddiskVolume3]\Recovery\WindowsRE\Winre.wim,{0fd8694c-e7fe-11f0-91cd-eabb9ab44a94}
path                    \windows\system32\winload.exe
description             Windows Recovery Environment
locale                  en-US
inherit                 {6efb52bf-1766-41db-a6b3-0ee5eff72bd7}
displaymessage          Recovery
osdevice                ramdisk=[\Device\HarddiskVolume3]\Recovery\WindowsRE\Winre.wim,{0fd8694c-e7fe-11f0-91cd-eabb9ab44a94}
systemroot              \windows
nx                      OptIn
bootmenupolicy          Standard
winpe                   Yes
custom:46000010         Yes

Resume from Hibernate
---------------------
identifier              {0fd86949-e7fe-11f0-91cd-eabb9ab44a94}
device                  partition=C:
path                    \WINDOWS\system32\winresume.exe
description             Windows Resume Application
locale                  en-US
inherit                 {1afa9c49-16ab-4a5c-901b-212802da9460}
recoverysequence        {0fd8694b-e7fe-11f0-91cd-eabb9ab44a94}
recoveryenabled         Yes
allowedinmemorysettings 0x15000075
filedevice              partition=C:
custom:21000026         partition=C:
filepath                \hiberfil.sys
bootmenupolicy          Standard
debugoptionenabled      No

Windows Memory Tester
---------------------
identifier              {b2721d73-1db4-4c62-bf78-c548a880142d}
device                  partition=\Device\HarddiskVolume1
path                    \boot\memtest.exe
description             Windows Memory Diagnostic
locale                  en-US
inherit                 {7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}
badmemoryaccess         Yes

EMS Settings
------------
identifier              {0ce4991b-e6b3-4b16-b23c-5e0d9250e5d9}
bootems                 No

Debugger Settings
-----------------
identifier              {4636856e-540f-4170-a130-a84776f4c654}
debugtype               Local

RAM Defects
-----------
identifier              {5189b25c-5558-4bf2-bca4-289b11bd29e2}

Global Settings
---------------
identifier              {7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}
inherit                 {4636856e-540f-4170-a130-a84776f4c654}
                        {0ce4991b-e6b3-4b16-b23c-5e0d9250e5d9}
                        {5189b25c-5558-4bf2-bca4-289b11bd29e2}

Boot Loader Settings
--------------------
identifier              {6efb52bf-1766-41db-a6b3-0ee5eff72bd7}
inherit                 {7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}
                        {7ff607e0-4395-11db-b0de-0800200c9a66}

Hypervisor Settings
-------------------
identifier              {7ff607e0-4395-11db-b0de-0800200c9a66}
hypervisordebugtype     Serial
hypervisordebugport     1
hypervisorbaudrate      115200

Resume Loader Settings
----------------------
identifier              {1afa9c49-16ab-4a5c-901b-212802da9460}
inherit                 {7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}

Device options
--------------
identifier              {0fd8694c-e7fe-11f0-91cd-eabb9ab44a94}
description             Windows Recovery
ramdisksdidevice        partition=\Device\HarddiskVolume3
ramdisksdipath          \Recovery\WindowsRE\boot.sdi
```

# Disable Autoruns

The `Open` buttons downloads & executes [`Autoruns.exe`](https://live.sysinternals.com/Autoruns.exe). It's recommended to disable all kind of autoruns in the `Logon` section that you don't need, examples:
```c
OneDrive
Spotify
Discord
Steam
WingetUI
Lghub
SecurityHealth

Microsoft Edge // preferable remove edge from the mounted image, otherwise it'll create keys/values in many different places
```

Try to minimize the amount of applications that run automatically on system startup. You can go trough the other sections, but this option was created for the `Logon` section, see `Disable Scheduled Tasks`/`Disable Services`.

See your current autoruns of installed apps:
```powershell
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```
```powershell
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

> https://live.sysinternals.com/  
> https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns

# Enable FSO

This may not be accurate yet, it's preferable to disable FSO per application via the compability section. Disabling this option won't revert the changes like all other ones do, it'll disable FSO.

### FSE (Fullscreen Exclusive)

Game takes exclusive control of the display.
- App sets display mode directly
- No desktop compositor in the path (DWM)
- Bad for Alt-Tab, overlays, and multi monitor

### FSO (Fullscreen Optimizations)

Windows feature that makes borderless/windowed behave like fullscreen.
- Runs as a flip-model, borderless window may be composed by DWM?
- Still allows overlays, Game Bar, better Alt-Tab
- Tries to give fullscreen-like latency and performance without true exclusive control

DX12 games don't support FSE.

![](https://github.com/nohuto/win-config/blob/main/system/images/swapchain.jpg?raw=true)

## ResourcePolicyServer

All values I found that are `GameDVR` related in `ResourcePolicyServer.dll`:
```c
GameDVR_DXGIHonorFSEWindowsCompatible
// 0 = FSO on
// 1 = FSO off

GameDVR_EFSEFeatureFlags
// 1 = EFSE on
// 0 = EFSE off

GameDVR_FSEBehavior
// 0 = FSO on
// 2 = FSO off

GameDVR_FSEBehaviorMode
// 0 = FSO on
// 2 = FSO off

GameDVR_HonorUserFSEBehaviorMode
// 0 = FSO on
// 1 = FSO off
```

`GameDVR_DSEBehavior` doesn't exist on my current system.

## Compability Captures

Disable/enable FSO for a specific application via `Properties > Compatibility > Change settings for all users` - `Disable fullscreen optimizations` or do it per user one step before.

```c
// User
HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers\C:\Program Files (x86)\Steam\steamapps\common\Battlefield 6\bf6.exe	Type: REG_SZ, Length: 66, Data: ~ DISABLEDXMAXIMIZEDWINDOWEDMODE

// Machine
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers\C:\Program Files (x86)\Steam\steamapps\common\Battlefield 6\bf6.exe	Type: REG_SZ, Length: 66, Data: ~ DISABLEDXMAXIMIZEDWINDOWEDMODE
```

> https://devblogs.microsoft.com/directx/demystifying-full-screen-optimizations/
> https://wiki.special-k.info/en/SwapChain
> https://wiki.special-k.info/Presentation_Model

# App Archive

"Automatically archive your infrequently used apps to save storage and internet bandwidth. Your files and data will still be saved, and the app's full version will be restored on your next use if it's still available."

If enabled, the system will periodically check for such infrequently used apps. By default app archiving is turned on.

## SystemSettings Records

Toggling the option via `Apps > Advanced app settings`:
```c
// On
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\Stubification\S-{ID}\EnableAppOffloading    Type: REG_DWORD, Length: 4, Data: 1

// Off
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\Stubification\S-{ID}\EnableAppOffloading    Type: REG_DWORD, Length: 4, Data: 0
```

## Windows Policies

```json
{
  "File": "AppxPackageManager.admx",
  "CategoryName": "AppxDeployment",
  "PolicyName": "AllowAutomaticAppArchiving",
  "NameSpace": "Microsoft.Policies.Appx",
  "Supported": "Windows_10_0 - At least Windows Server 2016, Windows 10",
  "DisplayName": "Archive infrequently used apps",
  "ExplainText": "This policy setting controls whether the system can archive infrequently used apps. If you enable this policy setting, then the system will periodically check for and archive infrequently used apps. If you disable this policy setting, then the system will not archive any apps. If you do not configure this policy setting (default), then the system will follow default behavior, which is to periodically check for and archive infrequently used apps, and the user will be able to configure this setting themselves.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\Appx"
  ],
  "ValueName": "AllowAutomaticAppArchiving",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```

# Page File

Several notes I took while reading trough `Windows Internals Part 1, Edition 7`, everything written below is based on it.

**You should calculate it while daily workload, or your peak value won't be accurate.**

Paging files are configured via `System > Advanced system settings > Performance > Advanced > Virtual memory`, but they are only one component of virtual memory. Even with no paging file, every process still uses virtual address space managed by the memory manager. Private pages must always live somewhere. RAM holds them while they are in use, and paging files act as disk backed storage so the memory manager can reclaim physical pages when demand grows.

Windows tracks private committed memory as the "commit charge" and enforces a "commit limit" equal to available RAM plus the total size of all paging files. This ensures Windows never promises more pageable storage than it can keep either in memory or in paging files. When commit charge climbs toward the limit, the modified page writer (`MiModifiedPageWriter`) flushes dirty pages to paging files so their physical frames can be reused. If the limit is reached and paging files can't grow, further private allocations fail until memory is freed. Task manager's performance tab/process explorer's system information window/system informers system information display current commit, the commit limit, and the peak value so you can see how much paging file space recent workloads required.

Size calculation if leaving it system managed and RAM as base would be if RAM <= 1 GB, then size = 1 GB. If RAM > 1 GB, then add 1/8 GB for every extra gigabyte of RAM, up to a maximum of 32 GB.

## How the option calculates it

If peak commit is below physical memory, no paging file would have been necessary (the option won't set it to 0, if you do there's literally nowhere to place additional committed pages, so allocations fail and you can even hit a bugcheck). If it exceeds RAM, the difference is the minimum disk backed capacity needed so the commit limit (RAM + paging files) stays above demand. Reads `\Process(_Total)\Page File Bytes Peak`, computes the Smss RAM baseline (`1 GB + 1/8 GB per extra GB of RAM`, capped at 32 GB), and checks whether `peak – RAM` is positive. If the workload never exceeded RAM, it keeps the Smss baseline. Otherwise, it uses the excess value (and currently a safety buffer of 10%, clamped to 1GB if RAM is >= 10 GB).

## Clearing Page File on Shutdown

Windows Internals: Paging files can contain fragments of process or kernel data. Enabling the option mitigates offline data exposure at the cost of longer shutdowns.

Local Security Policy:
"This security setting determines whether the virtual memory pagefile is cleared when the system is shut down.

Virtual memory support uses a system pagefile to swap pages of memory to disk when they are not used. On a running system, this pagefile is opened exclusively by the operating system, and it is well protected. However, systems that are configured to allow booting to other operating systems might have to make sure that the system pagefile is wiped clean when this system shuts down. This ensures that sensitive information from process memory that might go into the pagefile is not available to an unauthorized user who manages to directly access the pagefile.

When this policy is enabled, it causes the system pagefile to be cleared upon clean shutdown. If you enable this security option, the hibernation file (hiberfil.sys) is also zeroed out when hibernation is disabled."

> https://github.com/nohuto/windows-books/releases

# Disable Mobility Center

Note that this is a laptop only feature. The "Mobility Center" is a feature that includes controls for screen brightness, power options, volume, battery status, wireless network status, external display settings, and more.

![](https://github.com/nohuto/win-config/blob/main/system/images/mobility-center.png?raw=true)

## Windows Policies

```json
{
  "File": "MobilePCMobilityCenter.admx",
  "CategoryName": "MobilityCenterCat",
  "PolicyName": "MobilityCenterEnable_2",
  "NameSpace": "Microsoft.Policies.MobilePCMobilityCenter",
  "Supported": "WindowsVista - At least Windows Vista",
  "DisplayName": "Turn off Windows Mobility Center",
  "ExplainText": "This policy setting turns off Windows Mobility Center. If you enable this policy setting, the user is unable to invoke Windows Mobility Center. The Windows Mobility Center UI is removed from all shell entry points and the .exe file does not launch it. If you disable this policy setting, the user is able to invoke Windows Mobility Center and the .exe file launches it. If you do not configure this policy setting, Windows Mobility Center is on by default.",
  "KeyPath": [
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\MobilityCenter"
  ],
  "ValueName": "NoMobilityCenter",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```

### Miscellaneous Values

```c
"HKCU\Software\Microsoft\Windows\CurrentVersion\Mobility\LastResumeOnPCInteractionTime","Length: 20"
"HKCU\Software\Microsoft\Windows\CurrentVersion\Mobility\LastResumeOnPCTime","Length: 20"
"HKCU\Software\Microsoft\Windows\CurrentVersion\Mobility\OptedIn","Length: 16"
```

# Disable Hyper-V

"Many third-party virtualization applications don't work together with Hyper-V. Affected applications include VMware Workstation and VirtualBox. These applications might not start virtual machines, or they may fall back to a slower, emulated mode. Many virtualization applications depend on hardware virtualization extensions that are available on most modern processors. It includes Intel VT-x and AMD-V. Only one software component can use this hardware at a time. The hardware cannot be shared between virtualization applications."

> https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/virtualization-apps-not-work-with-hyper-v

## Service/Driver Table

| Option Name | Service/Driver | Description |
| --- | --- | --- |
| HyperV | `bttflt` | Microsoft Hyper-V VHDPMEM BTT Filter |
|  | `gencounter` | Microsoft Hyper-V Generation Counter |
|  | `hvcrash` | Hyper-V Crashdump |
|  | `HvHost` | Provides an interface for the Hyper-V hypervisor to provide per-partition performance counters to the host operating system. |
|  | `hvservice` | Microsoft Hypervisor Service Driver |
|  | `hyperkbd` | Microsoft VMBus Synthetic Keyboard Driver |
|  | `HyperVideo` | Microsoft VMBus Video Device Miniport Driver |
|  | `storflt` | Microsoft Hyper-V Storage Accelerator |
|  | `Vid` | Microsoft Hyper-V Virtualization Infrastructure Driver |
|  | `vmbus` | Virtual Machine Bus |
|  | `vmgid` | Microsoft Hyper-V Guest Infrastructure Driver |
|  | `vmicguestinterface` | Provides an interface for the Hyper-V host to interact with specific services running inside the virtual machine. |
|  | `vmicheartbeat` | Monitors the state of this virtual machine by reporting a heartbeat at regular intervals. This service helps you identify running virtual machines that have stopped responding. |
|  | `vmickvpexchange` | Provides a mechanism to exchange data between the virtual machine and the operating system running on the physical computer. |
|  | `vmicrdv` | Provides a platform for communication between the virtual machine and the operating system running on the physical computer. |
|  | `vmicshutdown` | Provides a mechanism to shut down the operating system of this virtual machine from the management interfaces on the physical computer. |
|  | `vmictimesync` | Synchronizes the system time of this virtual machine with the system time of the physical computer. |
|  | `vmicvmsession` | Provides a mechanism to manage virtual machine with PowerShell via VM session without a virtual network. |
|  | `vmicvss` | Coordinates the communications that are required to use Volume Shadow Copy Service to back up applications and data on this virtual machine from the operating system on the physical computer. |
|  | `vpci` | Microsoft Hyper-V Virtual PCI Bus |
