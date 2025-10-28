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

![](https://github.com/5Noxi/win-config/blob/main/peipheral/images/mousevalues.png?raw=true)

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

# Audio Ducking

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

![](https://github.com/5Noxi/win-config/blob/main/peipheral/images/audioducking.png?raw=true)

# Disable Audio Enhancements

The difference is minor (picture), preferable just disable them. Open `mmsys.cpl`, go into propeties of your used device, click on the `Advanced` tab and disable all enhancements. Run `Disable-Exclusive-Mode.bat` with [powerrun](https://www.sordum.org/downloads/?power-run), otherwise the values won't get applied.

```ps
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render\{4bff9f8d-ead4-4ae3-962e-10358e158daf}\Properties\{b3f8fa53-0004-438e-9003-51a46e139bfc},3","Type: REG_DWORD, Length: 4, Data: 0"
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render\{4bff9f8d-ead4-4ae3-962e-10358e158daf}\Properties\{b3f8fa53-0004-438e-9003-51a46e139bfc},4","Type: REG_DWORD, Length: 4, Data: 0"
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture\{6119fee4-d49c-474d-978c-0e5f9a67acb3}\Properties\{b3f8fa53-0004-438e-9003-51a46e139bfc},3","Type: REG_DWORD, Length: 4, Data: 0"
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture\{6119fee4-d49c-474d-978c-0e5f9a67acb3}\Properties\{b3f8fa53-0004-438e-9003-51a46e139bfc},4","Type: REG_DWORD, Length: 4, Data: 0"
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture\{6119fee4-d49c-474d-978c-0e5f9a67acb3}\FxProperties\{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},5","Type: REG_DWORD, Length: 4, Data: 1"
```

![](https://github.com/5Noxi/win-config/blob/main/peipheral/images/audioenhance.png?raw=true)

# Disable Spatial Audio

Spatial audio positions sounds in 3D space around you, surround sound mainly anchors audio to speaker directions.

> https://github.com/5Noxi/wpr-reg-records/blob/main/records/Audio.txt  
> https://www.dolby.com/experience/home-entertainment/articles/what-is-spatial-audio/

![](https://github.com/5Noxi/win-config/blob/main/peipheral/images/spatial.jpeg?raw=true)

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

`DisableStartupSound` is set to `1` by default (`LogonUI\BootAnimation`).

# Disable Autoplay/Autorun

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

![](https://github.com/5Noxi/win-config/blob/main/peipheral/images/samplerate.png?raw=true)

# Mouse DPI

Use `800` or `1600`. Going too low will have worse results, as shown in the pictures ([source 1](https://www.youtube.com/watch?v=mwf_F2VboFQ&t=458s), [source 2](https://www.youtube.com/watch?v=imYBTj2RXFs&t=274s))

![](https://github.com/5Noxi/win-config/blob/main/peipheral/images/dpi1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/peipheral/images/dpi2.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/peipheral/images/dpi3.png?raw=true)

# Polling Rate

Higher sampling rates reduce jitter and latency and ensure more accurate cursor positioning (first image), but may affect performance depending on the hardware (CPU cycles) - [source](https://www.youtube.com/watch?v=jtATbpMqbL4). Using `4 kHz` on a mid-tier PC should not be a problem. Run benchmarks on your system to check whether your PC can handle this rate. It should always be `1 kHz+`. You can use [MouseTester](https://github.com/valleyofdoom/MouseTester/releases) to check if your current polling rate is stable.

![](https://github.com/5Noxi/win-config/blob/main/peipheral/images/polling1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/peipheral/images/polling2.png?raw=true)