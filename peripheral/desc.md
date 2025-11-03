# Mouse Values

```bat
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v MouseWheelRouting /t REG_DWORD /d 0 /f
```
Disables the scroll functionality in inactive windows. 
`0` - Off
`2` - On

`MouseHoverTime` gets set to `100` (0.1 seconds), the default is `400`. It changes the time how long you have to be on a folder, to see related information. You may want to increase it.
```c
g_lMenuPopupTimeout = 4 * GetDoubleClickTime() / 5; // 400
```
Type: `String`
Min: `0`
Max: `65534`? - It uses `StrToIntW` to read the value

> https://learn.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-strtointw  
> https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdoubleclicktime

`RawMouseThrottleDuration` controls the throttle interval (in ms) for delivering raw mouse input to background windows. "We set out to reduce the amount of processing time it took to handle input requests by throttling and coalescing background raw mouse listeners and capping their message rate." 

Validate the changes with [MouseTester](https://github.com/valleyofdoom/MouseTester), move `MouseTester.exe` to the background after starting it by opening a different window.
```c
*(_QWORD *)&v13 = 0LL;                      // Forced = 0 (default)
*((_QWORD *)&v11 + 1) = 1LL;                // Enabled = 1 (default)
*(_QWORD *)&v11 = L"RawMouseThrottleEnabled";
*((_QWORD *)&v12 + 1) = L"RawMouseThrottleForced";
*(_QWORD *)&v14 = L"RawMouseThrottleDuration";
*(_QWORD *)&v12 = 1LL;                      // Enabled = 1 (maximum)
*((_QWORD *)&v13 + 1) = 1LL;                // Forced = 1
*((_QWORD *)&v14 + 1) = 0x100000008LL;      // Duration = 8 (default, 125Hz)
*(_QWORD *)&v15 = 20LL;                     // Duration = 20 (maximum)
*((_QWORD *)&v15 + 1) = L"RawMouseThrottleLeeway";
*(_QWORD *)&v16 = 2LL;                      // Leeway = 2 (default)
*((_QWORD *)&v16 + 1) = 5LL;                // Leeway = 5 (maximum)
```
`GetRawMouseThrottlingThresholds.c` includes more detail and my notes. `RawMouseThrottleDuration` has a minumum of `1` (`1000` Hz).

> https://blogs.windows.com/windowsdeveloper/2023/05/26/delivering-delightful-performance-for-more-than-one-billion-users-worldwide/  
> https://github.com/valleyofdoom/PC-Tuning#1150-background-window-message-rate-permalink  
> [peripheral/assets | mouse-GetRawMouseThrottlingThresholds.c](https://github.com/5Noxi/win-config/blob/main/peripheral/assets/mouse-GetRawMouseThrottlingThresholds.c)

![](https://github.com/5Noxi/win-config/blob/main/peripheral/images/mousevalues.png?raw=true)

# Keyboard Values

Remove hotkey for input language switching with:
```bat
reg add "HKCU\Keyboard Layout\Toggle" /v Hotkey /t REG_SZ /d 3 /f
reg add "HKCU\Keyboard Layout\Toggle" /v Language Hotkey /t REG_SZ /d 3 /f
reg add "HKCU\Keyboard Layout\Toggle" /v Layout Hotkey /t REG_SZ /d 3 /f
```
`Time & language > Typing > Advanced keyboard settings : Input language hot keys`, `Between input languages` to `Not assigned` (`None`):
```ps
rundll32.exe	RegSetValue	HKCU\Keyboard Layout\Toggle\Language Hotkey	Type: REG_SZ, Length: 4, Data: 3
rundll32.exe	RegSetValue	HKCU\Keyboard Layout\Toggle\Hotkey	Type: REG_SZ, Length: 4, Data: 3
rundll32.exe	RegSetValue	HKCU\Keyboard Layout\Toggle\Layout Hotkey	Type: REG_SZ, Length: 4, Data: 3
```

# Disable Audio Ducking

"*Windows audio ducking is a dynamic audio processing technique that enables the **automatic adjustment of audio levels** between different audio sources on a Windows-based computer or operating system.*"
> https://multimedia.easeus.com/ai-article/windows-audio-ducking.html

Go into your sound settings (`mmsys.cpl`), click on the `Communications` tab and select `Do nothing`:
```bat
reg add "HKCU\Software\Microsoft\Multimedia\Audio" /v UserDuckingPreference /t REG_DWORD /d 3 /f
```

`Mute all other sounds`:
```ps
RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\UserDuckingPreference	Type: REG_DWORD, Length: 4, Data: 0
```
`Reduce the volume of other sounds by 80%` (default):
```ps
RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\UserDuckingPreference	Type: REG_DWORD, Length: 4, Data: 1
```
`Reduce the volume of other sounds by 50%`:
```ps
RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\UserDuckingPreference	Type: REG_DWORD, Length: 4, Data: 2
```
`Do nothing`:
```ps
RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\UserDuckingPreference	Type: REG_DWORD, Length: 4, Data: 3
```

![](https://github.com/5Noxi/win-config/blob/main/peripheral/images/audioducking.png?raw=true)

# Disable Audio Enhancements

The difference is minor (picture), preferable just disable them. Open `mmsys.cpl`, go into propeties of your used device, click on the `Advanced` tab and disable all enhancements. Run `Disable-Exclusive-Mode.bat` with [powerrun](https://www.sordum.org/downloads/?power-run), otherwise the values won't get applied.

```ps
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render\{4bff9f8d-ead4-4ae3-962e-10358e158daf}\Properties\{b3f8fa53-0004-438e-9003-51a46e139bfc},3","Type: REG_DWORD, Length: 4, Data: 0"
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render\{4bff9f8d-ead4-4ae3-962e-10358e158daf}\Properties\{b3f8fa53-0004-438e-9003-51a46e139bfc},4","Type: REG_DWORD, Length: 4, Data: 0"
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture\{6119fee4-d49c-474d-978c-0e5f9a67acb3}\Properties\{b3f8fa53-0004-438e-9003-51a46e139bfc},3","Type: REG_DWORD, Length: 4, Data: 0"
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture\{6119fee4-d49c-474d-978c-0e5f9a67acb3}\Properties\{b3f8fa53-0004-438e-9003-51a46e139bfc},4","Type: REG_DWORD, Length: 4, Data: 0"
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture\{6119fee4-d49c-474d-978c-0e5f9a67acb3}\FxProperties\{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},5","Type: REG_DWORD, Length: 4, Data: 1"
```

![](https://github.com/5Noxi/win-config/blob/main/peripheral/images/audioenhance.png?raw=true)

# Disable Spatial Audio

Spatial audio positions sounds in 3D space around you, surround sound mainly anchors audio to speaker directions.

> https://github.com/5Noxi/wpr-reg-records/blob/main/records/Audio.txt  
> https://www.dolby.com/experience/home-entertainment/articles/what-is-spatial-audio/

![](https://github.com/5Noxi/win-config/blob/main/peripheral/images/spatial.jpeg?raw=true)

---

Miscellaneous notes:
```ps
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio" /v DisableSpatialOnLowLatency /t REG_DWORD /d 1 /f
```

# Disable System Sounds

Disables system sounds and removes sound events. I did use the keys, which Windows would disable:
```ps
"HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Close\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Maximize\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\MenuCommand\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\MenuPopup\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Minimize\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Open\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\PrintComplete\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\AppGPFault\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\SystemQuestion\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\RestoreDown\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\RestoreUp\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\CCSelect\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\ShowBand\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\ChangeTheme\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\BlockedPopup\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\ActivatingDocument\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\EmptyRecycleBin\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\FeedDiscovered\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\MoveMenuItem\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\SecurityBand\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\Navigating\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current\(Default)","Type: REG_SZ, Length: 0"
```

The revert data is based on `W11 LTSC IoT Enterprise 2024` defaults.

`DisableStartupSound` is set to `1` by default (`LogonUI\BootAnimation`).

# Disable AutoPlay/Autorun

"AutoPlay lets you choose an action for different kinds of media when you plug in a device or insert media. You can set AutoPlay to open different kinds of content, such as photos, music, and video on different kinds of media, such as drives, CDs, DVDs, cameras, and phones. For example, you can use AutoPlay to select an app that will automatically open photos on a removable drive when you plug it into your PC. With AutoPlay, you don't have to open the same app or reselect preferences every time you plug in a certain device."

> https://www.tenforums.com/tutorials/101962-enable-disable-autoplay-all-drives-windows.html  
> https://geekrewind.com/how-to-turn-enable-or-disable-autoplay-in-windows-11/

# Disk Write Cache Policy 
Enables write cache & turns off write cache buffer flushing on all connected disks.

```
\Registry\Machine\SYSTEM\ControlSet001\Enum\SCSI\Disk&Ven_NVMe&Prod_Samsung_SSD_990\5&33c33320&0&000000\Device Parameters\disk : CacheIsPowerProtected
\Registry\Machine\SYSTEM\ControlSet001\Enum\SCSI\Disk&Ven_NVMe&Prod_Samsung_SSD_990\5&33c33320&0&000000\Device Parameters\disk : UserWriteCacheSetting
```
> https://learn.microsoft.com/en-us/previous-versions/troubleshoot/windows-server/turn-disk-write-caching-on-off  
> [peripheral/assets | diskwritecache.c](https://github.com/5Noxi/win-config/blob/main/peripheral/assets/diskwritecache.c)

# Disable Bluetooth

Self explaining.

# M/K DQS

The value exists by default and is set to `100` decimal (`64` hex). Reducing it doesn't reduce your latency, leave it default.

"Specifies the number of mouse events to be buffered internally by the driver, in nonpaged pool. The allocated size, in bytes, of the internal buffer is this value times the size of the MOUSE_INPUT_DATA structure (defined in NTDDMOU.H)."

```c
v11 = *((_DWORD *)&WPP_MAIN_CB.Reserved + 2); // MouseDataQueueSize value
if (!v11)
{
    // Set default to 100 if value was 0
    v11 = 100;
}
else if (v11 > 0xAAAAAAA) // ≈ 178956970
{
    v12 = 2400;
}
else
{
    v12 = 24 * v11;
}
*((_DWORD *)&WPP_MAIN_CB.Reserved + 2) = v12;

```
__Scenarios:__
Exists & > 0 -> `v11 = reg value`
Value == 0 -> `v11 = 100`
Value not present -> `v11 = 288` ?
Value > `0xAAAAAAA` ->  Clamped to `2400`
Otherwise `v11 * 24`

> https://www.betaarchive.com/wiki/index.php/Microsoft_KB_Archive/102990  
> [peripheral/assets | mkdata-MouConfiguration.c](https://github.com/5Noxi/win-config/blob/main/peripheral/assets/mkdata-MouConfiguration.c)  
> [peripheral/assets | mkdata-KbdConfiguration.c](https://github.com/5Noxi/win-config/blob/main/peripheral/assets/mkdata-KbdConfiguration.c)

# Sample Rate

For your knowledge: The sample rate is the amount of times (in a second) an audio singal is measured. The amount of bits that are used to represent each sample (higher bit range = higher dynamic range and volume potential). The best sample rate and bit depth depends on what you're doing, the most commonly used sample rate for production and similar is `44.1` kHz.

`44.1` kHz = `44,100` times per second

As you may know a bit can be `0` or `1`, means (bit depth * `6` = dB):
`8` bit = `256` values
`16` bit = `65536` values
`24` bit = `16777216` values

`44.1` kHz with a bit depth of `16` is more than enough for general usage.

> https://noirsonance.com/bit-depth-calculator-visualizer/  
> https://de.wikipedia.org/wiki/Nyquist-Shannon-Abtasttheorem

![](https://github.com/5Noxi/win-config/blob/main/peripheral/images/samplerate.png?raw=true)

# Mouse DPI

Use `800` or `1600`. Going too low will have worse results, as shown in the pictures ([source 1](https://www.youtube.com/watch?v=mwf_F2VboFQ&t=458s), [source 2](https://www.youtube.com/watch?v=imYBTj2RXFs&t=274s))

![](https://github.com/5Noxi/win-config/blob/main/peripheral/images/dpi1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/peripheral/images/dpi2.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/peripheral/images/dpi3.png?raw=true)

# Polling Rate

Higher sampling rates reduce jitter and latency and ensure more accurate cursor positioning (first image), but may affect performance depending on the hardware (CPU cycles) - [source](https://www.youtube.com/watch?v=jtATbpMqbL4). Using `4 kHz` on a mid-tier PC should not be a problem. Run benchmarks on your system to check whether your PC can handle this rate. It should always be `1 kHz+`. You can use [MouseTester](https://github.com/valleyofdoom/MouseTester/releases) to check if your current polling rate is stable.

![](https://github.com/5Noxi/win-config/blob/main/peripheral/images/polling1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/peripheral/images/polling2.png?raw=true)

# Device Manager

The `Clean` option removes non present devices (`-PresentOnly:$false`/`Status -eq 'Unknown'`) via `/remove-device` ([`pnputil`](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax)).

`Microphone`, `Speakers`, `High Definition Audio Controller`  - Disable unused ones  
`Generic Monitor`  - You can try disabling it, but this may restrict functionality (resolution, brightness on laptop?)  
`WAN Miniports` - Virtual network adapters, used for VPN protocols, remote access etc.  
`Microsoft ISATAP Adapter` - Disabled, enables transport IPv6 traffic over an IPv4 infrastructure  
`SM Bus Controller` - Used for communication with onboard sensors and devices for system monitoring...  
`Microsoft iSCSI Initiator` - Disabled, connect to storage devices over a network  
`Microsoft Virtual Drive Enumerator` - Disabled, breaks `diskmgmt.msc`  
`Microsoft RRAS Root Enumerator` - Disabled, driver that helps initialize older or virtual devices during system boot  
`Microsoft System Management BIOS Driver` - Disabling it breaks GTA5 and maybe other system info fetching  
`System Speaker` - Disabling breaks monitor audio  
`AMD/Intel PSP (ME)` - Platform Security Processor  

---

Click on `View` > `Devices by connection`.

- Go into `PCI Bus` / `PCI Express Root Complex`
    - Disable all `PCI-to-PCI Bridge` devices, which are unused (`PCI Express Downstream Switch Port`)

![](https://github.com/5Noxi/win-config/blob/main/peripheral/images/devman.png?raw=true)

> https://learn.microsoft.com/en-us/powershell/module/pnpdevice/get-pnpdevice?view=windowsserver2025-ps  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax

# Disable Touch & Tablet

```
\Registry\Machine\SOFTWARE\Microsoft\TabletTip\1.7 : TouchKeyboardTapInvoke
\Registry\User\S-ID\SOFTWARE\Microsoft\TabletTip\1.7 : TouchKeyboardTapInvoke
\Registry\User\S-ID\SOFTWARE\Microsoft\TabletTip\1.7 : EnableAutoShiftEngage
\Registry\User\S-ID\SOFTWARE\Microsoft\TabletTip\1.7 : EnableDoubleTapSpace
```
Disable the touch screen feature of your device with:
```bat
devmanview /disable "HID-compliant touch screen"
```
> https://www.nirsoft.net/utils/device_manager_view.html

"Tablet mode makes Windows more touch friendly and is helpful on touch capable devices."

> https://support.microsoft.com/en-us/windows/turn-tablet-mode-on-or-off-in-windows-add3fbce-5cb5-bf76-0f9c-8d7b30041f30  
> https://superuser.com/questions/1194038/windows-10-command-line-to-enable-disable-tablet-mode  
> [peripheral/assets | touch-IsTouchDisabled.c](https://github.com/5Noxi/win-config/blob/main/peripheral/assets/touch-IsTouchDisabled.c)

---

Miscellaneous notes:
```
TabletModeActivated
TabletModeCoverWindow
TabletModeInputHandler
```

# Disable Wake on Input

```bat
powercfg /devicequery wake_programmable
powercfg /devicequery wake_armed
```
`powercfg /devicequery wake_programmable` -> devices that are user-configurable to wake the system from a sleep state
`powercfg /devicequery wake_armed` -> currently configured to wake the system from any sleep state

```bat
powercfg /devicedisablewake device
```
Disables the device (replace '*Device*' with the device name) from waking the system from any sleep state. 

> https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#availablesleepstates-or-a

`WakeOnInputDeviceTypes.bat` probably disables wake on input behavior for all input devices - each bit represents a input device type? Since `\SYSTEM\INPUT` only queries two values I'll add the second on in here.
```
\Registry\Machine\SYSTEM\INPUT : UnDimOnInputDeviceTypes
\Registry\Machine\SYSTEM\INPUT : WakeOnInputDeviceTypes
```
`UnDimOnInputDeviceTypes` probably refers to any dimmed elemets (pure speculation)? Disabling it wouldn't make sense.

Default values:
```c
WakeOnInputDeviceTypes = 6
UnDimOnInputDeviceTypes = -1  // 0xFFFFFFFF
```
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/Input.txt  
> [peripheral/assets | wakedev-WakeOnInputDeviceTypes.c](https://github.com/5Noxi/win-config/blob/main/peripheral/assets/wakedev-WakeOnInputDeviceTypes.c)

--- 

All available flags (`powercfg /devicequery query_flag`):

| `query_flag`             | Description                                                                      |
| ------------------------ | -------------------------------------------------------------------------------- |
| `wake_from_S1_supported` | Returns all devices that support waking the system from a light sleep state.     |
| `wake_from_S2_supported` | Returns all devices that support waking the system from a deeper sleep state.    |
| `wake_from_S3_supported` | Returns all devices that support waking the system from the deepest sleep state. |
| `wake_from_any`          | Returns all devices that support waking the system from any sleep state.         |
| `S1_supported`           | Lists devices supporting light sleep.                                            |
| `S2_supported`           | Lists devices supporting deeper sleep.                                           |
| `S3_supported`           | Lists devices supporting deepest sleep.                                          |
| `S4_supported`           | Lists devices supporting hibernation.                                            |
| `wake_programmable`      | Lists devices that are user-configurable to wake the system from a sleep state.  |
| `wake_armed`             | Lists devices currently configured to wake the system from any sleep state.      |
| `all_devices`            | Returns all devices present in the system.                                       |

# Enable MSI Mode

Enables MSI for USB, video, network, and IDE PCI devices & sets them to undefined. Setting the priority to high can be beneficial, but needs benchmarking. Removes `MessageNumberLimit`, so device uses the maximum MN itself.

> https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/enabling-message-signaled-interrupts-in-the-registry  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-message-signaled-interrupts  
> https://github.com/5Noxi/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf

"Interrupt affinity defines which logical processors handle a device's interrupts, using the `KAFFINITY` bitmask in the `AssignmentSetOverride` registry value (bit 0 = CPU 0, bit 1 = CPU 1, etc.). To apply it, `DevicePolicy` must be set to `4` (`IrqPolicySpecifiedProcessors`). Interrupt priority controls the urgency of handling and is set in KMDF drivers via `WdfInterruptSetPolicy`, using values like `WdfIrqPriorityHigh`. Both affinity and priority are stored in the `u.Interrupt` resource descriptor and apply to line-based and MSI/MSI-X interrupts. These settings optimize performance by balancing load and improving locality on multi-core systems."
> https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/kernel/interrupt-affinity-and-priority.md

Example:
```bat
delete "\Affinity Policy" /v DevicePriority /f
:: IrqPolicySpecifiedProcessors
add "\Affinity Policy" /v DevicePolicy /t REG_DWORD /d 4 /f
:: CPU 5
add "\Affinity Policy" /v AssignmentSetOverride /t REG_BINARY /d 2000000000000000 /f
add "\MessageSignaledInterruptProperties" /v MSISupported /t REG_DWORD /d 1 /f
delete "\MessageSignaledInterruptProperties" /v MessageNumberLimit /f
```
`AssignmentSetOverride` calculation:
```ps
$cpus = @(5)
$mask = 0
$cpus | % { $mask = $mask -bor (1 -shl $_) }
'{0:X16}' -f $mask
```
> https://github.com/BoringBoredom/Windows-MultiTool  
> [peripheral/assets | MSI-Paper.pdf](https://github.com/5Noxi/win-config/blob/main/peripheral/assets/MSI-Paper.pdf)

# Disable Dynamic Lighting

"Dynamic Lighting is a feature that allows you to control LED-powered devices such as keyboards, mice, and other illuminated accessories. This feature enables you to coordinate the colors of LEDs, creating a unified lighting experience both within Windows and across all your devices."

| Value  | Type      | Values                                                                                                                                                                                                   | Ranges                     | Notes                                                                 |
| ---------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------------------------------------------- |
| `AmbientLightingEnabled`                   | REG_DWORD | `0 = off`, `1 = on`                                                                                                                                                                                      | `0–1`                      | Master toggle for Dynamic Lighting.                                   |
| `UseSystemAccentColor`                     | REG_DWORD | `0 = use custom Color/Color2`, `1 = match Windows accent`                                                                                                                                                | `0–1`                      | When `1`, `Color` is ignored.                                         |
| `Color`                                    | REG_DWORD | `COLORREF (RGB)`                                                                                                                                                                                         | `0x00000000–0x00FFFFFF`    | Format `0x00BBGGRR`. Used when `UseSystemAccentColor = 0`.            |
| `Color2`                                   | REG_DWORD | `COLORREF (RGB)`                                                                                                                                                                                         | `0x00000000–0x00FFFFFF`    | Secondary color for some effects.                                     |
| `EffectType`                               | REG_DWORD | `0 = Solid`, `1 = Breathing`, `2 = Rainbow`, `4 = Wave`, `5 = Wheel`, `6 = Gradient`                                                                                                                     | `discrete enum`            | Defines animation.                                                    |
| `Speed`                                    | REG_DWORD | `integer`                                                                                                                                                                                                | `1–10`                     | Higher = faster.                                                      |
| `EffectMode`                               | REG_DWORD | Rainbow: `0 = Forward`, `1 = Reverse` · Wave: `0 = Right`, `1 = Left`, `2 = Down`, `3 = Up` · Wheel: `0 = Clockwise`, `1 = Counterclockwise` · Gradient: `0 = Horizontal`, `1 = Vertical`, `2 = Outward` | `discrete enum per effect` | Depends on `EffectType`.                                              |
| `Brightness`                              | REG_DWORD | `integer (%)`                                                                                                                                                                                            | `0–100`                    | - |
| `ControlledByForegroundApp`               | REG_DWORD | `0 = ignore apps`, `1 = apps can take control`                                                                                                                                                           | `0–1`                      | -     |


> https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/dynamic-lighting-devices  
> https://support.microsoft.com/en-us/windows/control-dynamic-lighting-devices-in-windows-8e8f22e3-e820-476c-8f9d-9ffc7b6ffcd2

# Disable Printing

Disables printer related services (`Spooler`, `PrintWorkFlowUserSvc`, `StiSvc`, `PrintNotify`, `usbprint`, `McpManagementService`, `PrintScanBrokerService`, `PrintDeviceConfigurationService`), and various optional features / scheduled tasks.

Remove the `Print` option from the context menu:
```
Remove-Item "Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\batfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\cmdfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\contact_wab_auto_file\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\emffile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\fonfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\group_wab_auto_file\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\htmlfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\IE.AssocFile.HTM\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\IE.AssocFile.SVG\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\IE.AssocFile.URL\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\IE.AssocFile.XHT\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\inffile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\inifile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\InternetShortcut\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\JSEFile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\JSFile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\opensearchresult\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\otffile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\PBrush\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\pfmfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\regfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\rlefile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\svgfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.avci\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.avcs\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.avif\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.avifs\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.heic\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.heics\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.heif\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.heifs\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.hif\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.jxl\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\image\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\ttcfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\ttffile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\txtfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\VBEFile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\VBSFile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\wdpfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\wmffile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\WSFFile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\xhtmlfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\zapfile\shell\print" -Force -Recurse
```

This list was created on a stock `W11 LTSC IoT Enterprise 2024` installation via:
```ps
dir Registry::HKEY_CLASSES_ROOT -Recurse -ea SilentlyContinue | ? { $_.Name -like '*\shell\print' } | select -ExpandProperty Name
```

---

List all printer connections:
```ps
Get-Printer
```
> https://learn.microsoft.com/en-us/powershell/module/printmanagement/get-printer?view=windowsserver2025-ps

Remove a specific printer using it's name:
```ps
Remove-Printer -Name "Printer Name"
```
> https://learn.microsoft.com/en-us/powershell/module/printmanagement/remove-printer?view=windowsserver2025-ps