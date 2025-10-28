# Debloated Driver

Complete NVIDIA driver preparation tool.
> https://github.com/5Noxi/win-config/blob/main/nvidia/assets/nvidia-tool.ps1

**Main menu:**  
`1` - Debloat driver (includes optional DDU clean uninstall)  
`2` - Install driver directly  

**Driver debloat option:**  
- Opens [www.techpowerup.com | nvidia-drivers](https://www.techpowerup.com/download/nvidia-geforce-graphics-drivers/)
- Removes all non-essential folders except `Display.Driver`, `NVI2`, `setup.cfg`, and `setup.exe`
- Cleans up `.xml` and `.cfg` files by removing telemetry, EULA, and web-link entries
- Miscellaenous theme configurations

**Optional DDU cleanup:**  
- Downloads [`NV-DDU.zip`](https://github.com/5Noxi/files/releases/download/driver) and [`NV-DDU.ps1`](https://github.com/5Noxi/files/releases/download/driver), enables Safe Boot, and reboots

**Driver installation:**  
- Runs `setup.exe`

# NVCPL Settings

The following includes details of how the panel sets the changes and more, a lot of it is for informational purposes only.

- 3D Settings
  - [Adjust image settings with preview](https://github.com/5Noxi/win-config/blob/main/nvidia/desc.md#3d-settings--adjust-image-settings-with-preview)
  - [Manage 3D settings](https://github.com/5Noxi/win-config/blob/main/nvidia/desc.md#3d-settings--manage-3D-settings)
  - [Configure Surround, PhysX](https://github.com/5Noxi/win-config/blob/main/nvidia/desc.md#3d-settings--configure-surround-physx)
- Display
  - Change resolution
  - [Adjust desktop color settings](https://github.com/5Noxi/win-config/blob/main/nvidia/desc.md#display--adjust-desktop-color-settings)
  - [Rotate display](https://github.com/5Noxi/win-config/blob/main/nvidia/desc.md#display--rotate-display)
  - View HDCP status
  - Set up digital audio
  - [Adjust desktop size and position](https://github.com/5Noxi/win-config/blob/main/nvidia/desc.md#display--adjust-desktop-size-and-position)
  - Set up multiple displays
- Developer
  - [Manage GPU Performance Counters](https://github.com/5Noxi/win-config/blob/main/nvidia/desc.md#developer--manage-gpu-performance-counters)
- Video
  - [Adjust video color settings](https://github.com/5Noxi/win-config/blob/main/nvidia/desc.md#video--adjust-video-color-settings)
  - [Adjust video image settings](https://github.com/5Noxi/win-config/blob/main/nvidia/desc.md#video--adjust-video-image-settings)

## 3D Settings > Adjust image settings with preview

![](https://github.com/5Noxi/win-config/blob/main/nvidia/images/nvcpl1.png?raw=true)  

## 3D Settings > Manage 3D settings

More information - [discord notes](https://discord.com/channels/836870260715028511/1375059420970487838/1412446705869394071)
- [NVIDIA Profile Inspector](https://github.com/Orbmu2k/nvidiaProfileInspector)  
- [NVIDIA Profile Inspector (all settings)](https://github.com/Ixeoz/nvidiaProfileInspector-UNLOCKED)  
- [Profile ReBar OFF](https://github.com/5Noxi/Files/releases/download/Fortnite/NV-ROFF.nip)  
- [Profile ReBar ON](https://github.com/5Noxi/Files/releases/download/Fortnite/NV-RON.nip)  

## 3D Settings > Configure Surround, PhysX

Select your GPU.

"NVIDIA PhysX is a powerful physics engine that can utilize GPU acceleration to provide amazing real-time physics effects. PhysX GPU acceleration is available on GeForce 8 series and later GPUs. In order to enable PhysX GPU acceleration, all the GPUs in your system must be PhysX-capable."

I'm unsure how the `physxGpuId` gets set, but it's not the same for everyone .It gets read in the NVAPI key and is a `REG_BINARY` type. If `CPU` is selected, it zeros itself (`00 00 00 00`), if `Auto` (supported)/`GPU` it changes the ID. `nvapi.h` includes some notes.

`Auto-select`:
```ps
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Services\nvlddmkm\Global\NVTweak\NvCplPhysxAuto    Type: REG_DWORD, Length: 4, Data: 1
```
`GPU`:
```ps
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Services\nvlddmkm\Global\NVTweak\NvCplPhysxAuto    Type: REG_DWORD, Length: 4, Data: 0
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Services\nvlddmkm\NVAPI\physxGpuId    Type: REG_BINARY, Length: 4, Data: 00 07 00 00
```
`CPU`:
```ps
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Services\nvlddmkm\Global\NVTweak\NvCplPhysxAuto    Type: REG_DWORD, Length: 4, Data: 0
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Services\nvlddmkm\NVAPI\physxGpuId    Type: REG_BINARY, Length: 4, Data: 00 00 00 00
```
> [nvidia/assets | physx-nvapi.h](https://github.com/5Noxi/win-config/blob/main/nvidia/assets/physx-nvapi.h)

![](https://github.com/5Noxi/win-config/blob/main/nvidia/images/nvcpl2.png?raw=true)  

## Display > Adjust desktop color settings 

Increase `Digital vibrance` up to a level you prefer.
```ps
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITOR : SaturationRegistryKey
```

Location (the ID may differ):
```ps
HKCU\Software\NVIDIA Corporation\Global\NVTweak\Devices\1364265386-0\Color
```
`3538946`, `3538947`, `3538948` seem to handle the brightness (`100 Dec` = `50%`, `80 Dec` = `0%`, `120 Dec` = `100%`). 
`3538949`, `3538950`, `3538951` handle the contrast, same value range as the brightness. 
`3538952`, `3538953`, `3538954` handles the gamma value (`30-180 Dec`, `100 Dec = 1.00`). 
`3538970` `1` = `Override to reference mode - Off`, `2` = `Override to reference mode - On`
`NvCplGammaSet` is also located in the key, but seems to be at `1` all of the time (`DesktopColor.cpp`). If set to non zero, it uses the saved parameters (values from registry), if its `0` it'll use the default values?

```ps
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITOR : SaturationRegistryKey
```
Controls the `Digital vibrance`, decimal value = percentage. `MONITOR` depends on your monitor.

```ps
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITOR : HueRegistryKey
```
`HueRegistryKey` controls the `Hue` options, it is a `REG_BINARY` type ([`displayDB.cpp`](https://github.com/5Noxi/win-config/blob/main/nvidia/desc.md/blob/main/files/displayDB.cpp)):
```c
// 0°
HKLM\System\CurrentControlSet\Services\nvlddmkm\State\DisplayDatabase\MSI3CB01222_2E_07E4_FF\HueRegistryKey    Type: REG_BINARY, Length: 20, Data: DB 01 00 00 14 00 00 00 10 27 00 00 00 00 00 00
```
```c
// 359°
HKLM\System\CurrentControlSet\Services\nvlddmkm\State\DisplayDatabase\MSI3CB01222_2E_07E4_FF\HueRegistryKey    Type: REG_BINARY, Length: 20, Data: DB 01 00 00 14 00 00 00 0E 27 00 00 52 FF FF FF
```
The calculation works via `cosHue_x10K` (cosinus), `sinHue_x10K` (sinus) and a checksum. `0°`:
```ps
cos(0) = 1
1 * 10000 = 10000 = 0x00002710 hex
sin(0) = 0  = 0x00000000 hex
= last 2 bytes
```
- [nvDisplay.cpp#L293](https://github.com/pbatard/nvBrightness/blob/8f4a183532f1048375608fc70ad03c38652fc140/src/nvDisplay.cpp#L293)  
- [displayDB.cpp](https://github.com/5Noxi/win-config/blob/main/nvidia/assets/color-displayDB.cpp)  
- [DesktopColors.cpp](https://github.com/5Noxi/win-config/blob/main/nvidia/assets/color-DesktopColors.cpp)  
- [nvlddmkm Trace](https://github.com/5Noxi/wpr-reg-records/blob/main/records/nvlddmkm.txt)

```ps
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\ADAPTER_10DE_2482_00000007_00000000 : StereoPreferredTargetIdRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7103 : ConnectorWarpResamplingMethod
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase : 1641970VRcontext
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase : EdidLockData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\ADAPTER_10DE_2482_00000007_00000000 : MergedDisplayDataRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\ADAPTER_10DE_2482_00000007_00000000 : StreamCloneState
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7100 : ConnectorAudioData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7100 : ConnectorAudioDpAddress
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7100 : DEStateRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7101 : ConnectorAudioData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7101 : ConnectorAudioDpAddress
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7101 : DEStateRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7102 : ConnectorAudioData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7102 : ConnectorAudioDpAddress
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7102 : DEStateRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7103 : ConnectorAudioData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7103 : ConnectorAudioDpAddress
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7103 : DEStateRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7104 : ConnectorAudioData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7104 : ConnectorAudioDpAddress
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7104 : DEStateRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7105 : ConnectorAudioData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7105 : ConnectorAudioDpAddress
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7105 : DEStateRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7106 : ConnectorAudioData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7106 : ConnectorAudioDpAddress
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\CONNECTOR_10DE_2482_00000007_00000000_7106 : DEStateRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : BrightnessCalibrationDataRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : ColorformatConfig
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : ColorspaceConfig
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : DitherRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : DPLinkConfigDataRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : HueRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : MonitorAudioData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : MonitorDataRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : SaturationRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : ScalingConfig
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : SmoothScalingData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : SmoothScalingMultiplierData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : UpScalingData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : UpScalingMultiplierData
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\ADAPTER_10DE_2482_00000007_00000000 : StereoPreferredTargetIdRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : ColorspaceConfig
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : MonitorDataRegistryKey
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : ScalingConfig
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX_XX_XXXX_XX : ScalingConfig
```

![](https://github.com/5Noxi/win-config/blob/main/nvidia/images/nvcpl3.png?raw=true)  

## Display > Rotate display

You've to edit the `Rotation` value to change the orientation, `DefaultSettings.Orientation` gets reset to the `Rotation` state if changing it. The IDs will obviously not be the same for you.

```ps
"dwm.exe","RegSetValue","HKLM\System\CurrentControlSet\Control\UnitedVideo\CONTROL\VIDEO\{0096AEE5-861E-11F0-896E-806E6F6E6963}\0000\DefaultSettings.Orientation","Type: REG_DWORD, Length: 4, Data: 0"
```
`0` = Landscape
`1` = Portrait
`2` = Landscape (flipped)
`3` = Portrait (flipped)

```ps
"svchost.exe","RegSetValue","HKLM\System\CurrentControlSet\Control\GraphicsDrivers\Configuration\MSI3CB01222_2E_07E4_FF^28BF11A4ED9F56277B96046CA0884335\00\00\Rotation","Type: REG_DWORD, Length: 4, Data: 1"
```
`1` = Landscape
`2` = Portrait
`3` = Landscape (flipped)
`4` = Portrait (flipped)

`Landscape`:
```bat
reg add "HKLM\System\CurrentControlSet\Control\UnitedVideo\CONTROL\VIDEO\{0096AEE5-861E-11F0-896E-806E6F6E6963}\0000" /v DefaultSettings.Orientation /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers\Configuration\MSI3CB01222_2E_07E4_FF^28BF11A4ED9F56277B96046CA0884335\00\00" /v Rotation /t REG_DWORD /d 1 /f
```

## Display > Adjust desktop size and position

```ps
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\MONITORXXXXX : ScalingConfig
```
`ScalingConfig` = `Scaling Mode`, `Perform Scaling on`, `Override the scaling mode...` (includes all settings?)

![](https://github.com/5Noxi/win-config/blob/main/nvidia/images/nvcpl4.png?raw=true)  

## Developer > Manage GPU Performance Counters

"GPU performance counters are used by NVIDIA GPU profiling tools such as NVIDIA Nsight. These tools enable developers debug, profile and develop software for NVIDIA GPUs."
```c
{
"Name":  "RmProfilingAdminOnly",
"Comment":  [
     "Type DWORD",
     "This regkey restricts profiling capabilities (creation of profiling objects",
     "and access to profiling-related registers) to admin only.",
     "0 - (default - disabled)",
     "1 - Enables admin check"
 ],
"Elements":  [
      {"Name":  "FALSE","Value":  "0"},
      {"Name":  "TRUE","Value":  "1"}
  ]
},
```
Changing it via NVCPL:
```ps
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Services\nvlddmkm\Global\NVTweak\RmProfilingAdminOnly    Type: REG_DWORD, Length: 4, Data: 1
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\RmProfilingAdminOnly    Type: REG_DWORD, Length: 4, Data: 1
```
`Restrict access to the GPU performance counters to admin users only` = `1`
`Allow access to the GPU performance counters to all users` = `0`
```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\XXXX" /v RmProfilingAdminOnly /t REG_DWORD /d X /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v RmProfilingAdminOnly /t REG_DWORD /d X /f
```
Change `XXXX` to the correct key and `X` to `1`/`0`.
- [Control-Panel-Help](https://www.nvidia.com/content/Control-Panel-Help/vLatest/en-us/index.htm#t=mergedProjects%2FDeveloper%2FManage_Performance_Counters_-_Reference.htm&rhsearch=counters)  
- [Bitmask Calculator](https://github.com/5Noxi/bitmask-calc)  

![](https://github.com/5Noxi/win-config/blob/main/nvidia/images/nvcpl5.png?raw=true)  

## Video > Adjust video color settings

Personal preference.
```ps
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\_User_SUB0_DFP1_XALG_Color_Range    Type: REG_BINARY, Length: 8, Data: 00 00 00 00 00 00 00 00
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\_User_SUB0_DFP1_XEN_Color_Range    Type: REG_DWORD, Length: 4, Data: 2147483649
```
![](https://github.com/5Noxi/win-config/blob/main/nvidia/images/nvcpl6.png?raw=true)  

## Video > Adjust video image settings
```ps
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v _User_Global_VAL_SuperResolution /t REG_DWORD /d 0 /f
```

`On` & `Auto`:
```ps
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\_User_Global_VAL_SuperResolution    Type: REG_DWORD, Length: 4, Data: 5
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\_User_Global_DAT_SuperResolution    Type: REG_BINARY, Length: 128, Data: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\_User_Global_XEN_SuperResolution    Type: REG_DWORD, Length: 4, Data: 2147483649
```
`Off` = `_User_Global_VAL_SuperResolution` - `0`  
Quality:
`Auto` = `_User_Global_VAL_SuperResolution` - `5`  
`1` = `_User_Global_VAL_SuperResolution` - `1`  
`2` = `_User_Global_VAL_SuperResolution` - `2`  
`3` = `_User_Global_VAL_SuperResolution` - `3`  
`4` = `_User_Global_VAL_SuperResolution` - `4`  
A system restart is required to see the changes in nvcpl.

---

### Noise Reduction

Path (Change `XXXX` to the correct key name):
```ps
HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\XXXX
```
`Use the video player setting`:
```ps
_User_SUB0_DFP1_XALG_Noise_Reduce    Type: REG_BINARY, Length: 8, Data: 00 00 00 00 00 00 00 00
_User_SUB0_DFP1_XEN_Noise_Reduce    Type: REG_DWORD, Length: 4, Data: 0
_User_SUB0_DFP1_VAL_Noise_Reduce    Type: REG_DWORD, Length: 4, Data: 0
_User_SUB0_DFP1_XALG_Cadence    Type: REG_BINARY, Length: 8, Data: 00 00 00 00 00 00 00 00
_User_SUB0_DFP1_XEN_Cadence    Type: REG_DWORD, Length: 4, Data: 2147483649
```
`Use NVIDIA setting`:
```ps
_User_SUB0_DFP1_XALG_Noise_Reduce    Type: REG_BINARY, Length: 8, Data: 00 00 00 00 00 00 00 00
_User_SUB0_DFP1_VAL_Noise_Reduce    Type: REG_DWORD, Length: 4, Data: 5
_User_SUB0_DFP1_XEN_Noise_Reduce    Type: REG_DWORD, Length: 4, Data: 2147483649
_User_SUB0_DFP1_XALG_Cadence    Type: REG_BINARY, Length: 8, Data: 00 00 00 00 00 00 00 00
_User_SUB0_DFP1_XEN_Cadence    Type: REG_DWORD, Length: 4, Data: 2147483649
```
`_User_SUB0_DFP1_VAL_Noise_Reduce` controls the percentage, e.g. `5%` = `5 Dec` until `49%`. Nvcpl skips `50%`, which means that everything above `50` is `X - 1`, range `0-99`.

![](https://github.com/5Noxi/win-config/blob/main/nvidia/images/nvcpl7.png?raw=true)

# Temporary NVCPL

`NVDisplay.Container.exe` is required for nvcpl to start. [`nvcpl.ps1`](https://github.com/5Noxi/win-config/blob/main/nvidia/assets/nvcpl.ps1) starts them, waits till you close the program, and then terminates them.

Download location:
```ps
$env:appdata\Noverse
```
Shortcut location:
```ps
$home\Desktop\Nvcpl.lnk
```

# Performance State (P0)

```c
{
"Name":  "DisableDynamicPstate",
"Comment":  [
         "Type Dword",
         "1 = Disable dynamic P-State/adaptive clocking",
         "0 = Do not disable dynamic P-State/adaptive clocking (default)"
     ],
"Configured":  "1",
"Elements":  [
          {"Name":  "DISABLE","Value":  "0"},
          {"Name":  "ENABLE","Value":  "1"}
      ]
},
```
Other value:
```c
{
"Name":  "DisableAsyncPstates",
"Comment":  [
         "Type Dword",
         "Encoding Numeric Value",
         "Determines whether or not asynchronous p-states should be disabled",
         "1 - Disables asynchronous p-state changes",
         "0 - (default) Leaves asynchronous p-state changes enabled"
     ],
"Configured":  "1",
"Elements":  [
          {"Name":  "DISABLE","Value":  "1"},
          {"Name":  "ENABLE","Value":  "0"},
          {"Name":  "DEFAULT","Value":  "0"}
      ]
},
```
See your current performance state with (`nvidia-smi.exe` has to be in `Windows\System32`):
```ps
nvidia-smi --query-gpu=name,pstate --format=noheader
```
It shows the current performance state. States range from P0 (maximum performance) to P12 (minimum performance).
> https://docs.nvidia.com/deploy/nvidia-smi/index.html

Or use [NvApiSwak.exe](https://discord.com/channels/836870260715028511/1375059420970487838/1420721787678752818) and look at the `NvAPI_GPU_GetCurrentPstate` function.
```h
{
    NVAPI_GPU_PERF_PSTATE_P0 = 0,
    NVAPI_GPU_PERF_PSTATE_P1,
    NVAPI_GPU_PERF_PSTATE_P2,
    NVAPI_GPU_PERF_PSTATE_P3,
    NVAPI_GPU_PERF_PSTATE_P4,
    NVAPI_GPU_PERF_PSTATE_P5,
    NVAPI_GPU_PERF_PSTATE_P6,
    NVAPI_GPU_PERF_PSTATE_P7,
    NVAPI_GPU_PERF_PSTATE_P8,
    NVAPI_GPU_PERF_PSTATE_P9,
    NVAPI_GPU_PERF_PSTATE_P10,
    NVAPI_GPU_PERF_PSTATE_P11,
    NVAPI_GPU_PERF_PSTATE_P12,
    NVAPI_GPU_PERF_PSTATE_P13,
    NVAPI_GPU_PERF_PSTATE_P14,
    NVAPI_GPU_PERF_PSTATE_P15,
    NVAPI_GPU_PERF_PSTATE_UNDEFINED = NVAPI_MAX_GPU_PERF_PSTATES,

}
```

# Disable HDCP

HDCP protects digital content from being copied while it's transmitted between devices like a computer and a TV - would leave it enabled.

```c
{
"Name":  "RMHdcpKeyglobZero",
"Comment":  [
         "Type DWORD",
         "Encoding: 1 means Keyglob will be forced to zero"
     ],
"Elements":  [
          {"Name":  "TRUE","Value":  "1"},
          {"Name":  "FALSE", "Value":  "0"}
         ]
},
```
> https://en.wikipedia.org/wiki/High-bandwidth_Digital_Content_Protection

# Disable ECC

Some GPUs don't support it, disabling is also not really needed. You can test it by disabling it via the control panel.

> https://www.nvidia.com/content/control-panel-help/vlatest/en-us/mergedprojects/nv3d/To_turn_your_GPU_ECC_on_or_off.htm  
> https://www.nvidia.com/content/control-panel-help/vlatest/en-us/mergedprojects/nv3d/Change_ECC_State.htm

```
-e,   --ecc-config=         Toggle ECC support: 0/DISABLED, 1/ENABLED
-p,   --reset-ecc-errors=   Reset ECC error counts: 0/VOLATILE, 1/AGGREGATE
```
"Set the ECC mode for the target GPUs. See the (GPU ATTRIBUTES) section for a description of ECC mode. Requires root. Will impact all GPUs unless a single GPU is specified using the -i argument. This setting takes effect after the next reboot and is persistent.
Reset the ECC error counters for the target GPUs. See the (GPU ATTRIBUTES) section for a description of ECC error counter types. Available arguments are 0\|VOLATILE or 1\|AGGREGATE. Requires root. Will impact all GPUs unless a single GPU is specified using the -i argument. The effect of this operation is immediate. Clearing aggregate counts is not supported on Ampere+"
> https://docs.nvidia.com/deploy/nvidia-smi/index.html

from `nvidia-smi.exe -h`:
```c
nvidia-smi.exe -e 0

// Query current state
nvidia-smi -q -d ecc
```

More about `nvidia-smi`:
> https://discord.com/channels/836870260715028511/1375059420970487838/1375935298093191189  
> https://www.nvidia.com/content/Control-Panel-Help/vLatest/en-us/mergedProjects/3D%20Settings/Change_ECC_State.htm

Other ECC related features can be found using [`bitmask-calc`](https://github.com/5Noxi/bitmask-calc) - e.g. `RMNoECCFuseCheck`.

![](https://github.com/5Noxi/win-config/blob/main/nvidia/images/ecc.png?raw=true)

# Hide NVIDIA Tray Icon

```
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\Global\NVTweak : HideXGpuTrayIcon
\Registry\Machine\SOFTWARE\NVIDIA Corporation\Global\CoProcManager : ShowTrayIcon
```
> https://forums.developer.nvidia.com/t/hide-nvidia-tray-icon/162739

Other values I found:

?
```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v HideManufacturerFromMonitorName /t REG_DWORD /d 1 /f
```

Hides the icon from the context menu (2nd one is probably related to optimus):
```bat
reg add "HKCU\Software\NVIDIA Corporation\Global\NvCplApi\Policies" /v ContextUIPolicy /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\NVIDIA Corporation\Global\RunOpenGLOn" /v ShowContextMenu /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\NVIDIA Corporation\Global\CoProcManager" /v ShowContextMenu /t REG_DWORD /d 0 /f
```

> [nvidia/assets | HideManufacturer.c](https://github.com/5Noxi/win-config/blob/main/nvidia/assets/trayicon-HideManufacturer.c)  
> [nvidia/assets | notes.cpp](https://github.com/5Noxi/win-config/blob/main/nvidia/assets/trayicon-notes.cpp)  
> [nvidia/assets | nvcpl.c](https://github.com/5Noxi/win-config/blob/main/nvidia/assets/trayicon-nvcpl.c)

# Disable DLSS Indicator

Disable:
```bat
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NGXCore" /v ShowDlssIndicator /t REG_DWORD /d 0 /f
```
Enable:
```bat
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NGXCore" /v ShowDlssIndicator /t REG_DWORD /d 1024 /f
```

---

### From NVIDIA documentations:  

`turn-dlss-indicator-off`
```ps
[HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NGXCore]
"ShowDlssIndicator"=dword:00000000
```
`turn-dlss-indicator-on-center`
```ps
[HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NGXCore]
"ShowDlssIndicator"=dword:00000001
```
`turn-dlss-indicator-on-top-left`
```ps
[HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NGXCore]
"ShowDlssIndicator"=dword:00000002
```

> [nvidia/assets | dlss.c](https://github.com/5Noxi/win-config/blob/main/nvidia/assets/dlss.c)  
> [nvidia/assets | dlss-NGXCubinGeneric.cpp](https://github.com/5Noxi/win-config/blob/main/nvidia/assets/dlss-NGXCubinGeneric.cpp)

# Disable Display Power Savings

```
\Registry\Machine\SOFTWARE\NVIDIA Corporation\Global\NVTweak : DisplayPowerSaving
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\Global\NVTweak : DisplayPowerSaving
```

You can find it in `nvsvc64.dll`.

> [nvidia/assets | disppower-nvsvc64.c](https://github.com/5Noxi/win-config/blob/main/nvidia/assets/disppower-nvsvc64.c)  
> [nvidia/assets | disppower-nvsvc64gv.c](https://github.com/5Noxi/win-config/blob/main/nvidia/assets/disppower-nvsvc64gv.c)

# Disable NVIDIA Driver Notification

Disables the notification (GeForce), whenever a new driver is available.

# Disable Logging

```cpp
{ L"LogEventEntries", NV_DECLARE_REG_VAR(logSizes[LOG_EVENT]) },  // Maximum number of event log entries (global)
{ L"LogErrorEntries", NV_DECLARE_REG_VAR(logSizes[LOG_ERROR]) },  // Maximum number of error log entries (global)
{ L"LogWarningEntries", NV_DECLARE_REG_VAR(logSizes[LOG_WARNING]) },  // Maximum number of warning log entries (global)
{ L"LogPagingEntries", NV_DECLARE_REG_VAR(logSizes[LOG_PAGING]) },  // Maximum number of paging log entries (global)
```
```c
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\Parameters : LogErrorEntries
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\Parameters : LogEventEntries
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\Parameters : LogPagingEntries
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\Parameters : LogWarningEntries
```

# RMPowerFeature

`ELPG` - Engine-Level Power Gating  
`BLCG` - Block Level Clock Gating  
`FSPG` - Floorsweep Power Gating  

Disabling all of it will increase the wattage usage noticeable.

```json
{
  "Name":  "RMPowerFeature",
  "Comment":  [
                  "Type DWORD",
                  "For elpg, blcg, fspg",
                  "0 : Keep the vbios default for all engines",
                  "1 : Disable for all engines",
                  "2 : Per unit/engine settings (Look at engine specific RegKeys below)",
                  "3 : Enable for all engines",
                  "For elcg,",
                  "0 : Keep the vbios default for all engines i.e Feature ON",
                  "1 : feature off for all engines",
                  "3 : engine disabled for all engines",
                  "for the rest of the features, the following convention applies",
                  "0 : Keep the vbios default",
                  "1 : Disable feature",
                  "3 : Enable feature",
                  "BLCG: this uses 4 bits, where the bottom two bits decide",
                  "if the feature needs to be on/off/default for all engines or engine specific",
                  "Top two bits decide the level(STALL, IDLE, QUIESCENT) if on/default for all engines"
              ],
}

{
  "Name":  "RMPowerFeature2",
  "Comment":  [
                  "the following convention applies to _FLCG",
                  "0 : Keep default for all engines",
                  "1 : Disable FLCG for all engines",
                  "2 : Per unit/engine settings (Look at engine specific regkey FLCG)",
                  "3 : Enable  FLCG for all engines",
                  "If _MSCG_SETTINGS_OWNER is set to _RM, RM will program the MSCG watermarks,",
                  "and will control the enabling and disabling of MSCG for modeswitches and",
                  "pstate transitions.  If it is set to _PMU, the PMU will control the enabling",
                  "and disabling of MSCG for modeswitches and pstate transitions, and the PMU",
                  "will program the watermarks using values provided by RM.",
                  "_RM is the initial default; this is expected to change when _PMU support",
                  "becomes available.",
                  "the following convention applies to _OPERATION_MODE",
                  "0 : choose default GPU Operation mode",
                  "1 : Disable all GPU Operation modes - force power up of all GPU Operation Mode units after boot",
                  "2 : Enable GPU Operation mode as per mask - keep power gated after boot as per RmGpuOperationMode mask",
                  "the following convention applies to _SLCG",
                  "1 : Disable SLCG for all engines",
                  "2 : Per unit/engine settings (Look at engine specific regkey SLCG)",
                  "3 : Enable  SLCG for all engines",
                  "The following convention applies to _CLK_NDIV_SLIDING:",
                  "0 : Keep the vbios default",
                  "1 : Disable feature for all clock domains",
                  "2 : Per clock domain settings (Look at clock domain specific regkey below - NV_REG_STR_RM_CLK_NDIV_SLIDING)",
                  "3 : Enable for all clock domains",
                  "The following convention applies to _NVVDD_PSI:",
                  "1 : Disable feature",
                  "3 : Enable feature",
                  "The following convention applies to GC6_ROMLESS:",
                  "The following convention applies to GC6_ROM:",
                  "The following convention applies to DIDLE-SSC:",
                  "This flag overwrites all the other flags  while arming DIDLE-OS",
                  "if it is disabled here, DI-OS will not be Entered. However if it enabled",
                  "DI-OS will be only Entered, if all other Preconditions are met.",
                  "The following convention applies to GC4:",
                  "This flag overwrites all the other flags  while enabling L1 substates",
                  "if it is disabled here, L1 Substates will not be Entered. However if it enabled",
                  "L1 Substates will be only Entered, if root port supports it and enabled in VBIOS",
                  "The following convention applies to L1 Substates:",
                  "The following convention applies to LPWR oneshot:",
                  "The following convention applies to RPPG:",
                  "The following convention applies to IST clock gating:",
                  "0 : Keep the IST gating enabled by default"
              ],
}

# Disable Power Savings

Sets `RmDisableACPI`, `RMDisableGpuASPMFlags`, `RMFspg`, `RMBlcg`, `RMElcg`, `RmElpg`, `RMSlcg`, `RMOPSB`, `RMLpwrArch`. See [`bitmask-calc`](https://github.com/5Noxi/bitmask-calc) for more details of what the data does.

# Disable Scheduled Tasks

# Disable Telemetry

---

Block NVIDIA telemetry domains (`C:\Windows\System32\drivers\etc\hosts`):
```
0.0.0.0 accounts.nvgs.nvidia.cn
0.0.0.0 accounts.nvgs.nvidia.com
0.0.0.0 api.commune.ly
0.0.0.0 assets.nvidiagrid.net
0.0.0.0 events.gfe.nvidia.com
0.0.0.0 gfe.geforce.com
0.0.0.0 gfe.nvidia.com
0.0.0.0 gfwsl.geforce.com
0.0.0.0 images.nvidia.com
0.0.0.0 images.nvidiagrid.net
0.0.0.0 img.nvidiagrid.net
0.0.0.0 login.nvgs.nvidia.cn
0.0.0.0 login.nvgs.nvidia.com
0.0.0.0 ls.dtrace.nvidia.com
0.0.0.0 nvidia.com.edgesuite.net
0.0.0.0 nvidia.telemetry.internet.microsoft.com
0.0.0.0 nvidia.tt.omtrdc.net
0.0.0.0 ota-downloads.nvidia.com
0.0.0.0 ota.nvidia.com
0.0.0.0 rds-assets.nvidia.com
0.0.0.0 services.gfe.nvidia.com
0.0.0.0 telemetry.gfe.nvidia.com
0.0.0.0 telemetry.nvidia.com
```
> https://github.com/ravetank/nvidia-telemetry-blocklist

# Disable Preemption

# Enable Developer Settings

Enables `Enable Developer Settings` in the NVIDIA control panel.

```h
//Profile info related
#define NV_REG_CPL_PERFCOUNT_RESTRICTION  "RmProfilingAdminOnly"
#define NV_REG_CPL_DEVTOOLS_VISIBLE       "NvDevToolsVisible"
```

![](https://github.com/5Noxi/win-config/blob/main/nvidia/images/nvcploptions.png?raw=true)

# Remove Context Menu Entry

Disables `Add Desktop Context Menu` in the NVIDIA control panel.

![](https://github.com/5Noxi/win-config/blob/main/nvidia/images/nvcploptions.png?raw=true)

# GPU Performance Counters
"GPU performance counters are used by NVIDIA GPU profiling tools such as NVIDIA Nsight. These tools enable developers debug, profile and develop software for NVIDIA GPUs."
```c
{
"Name":  "RmProfilingAdminOnly",
"Comment":  [
     "Type DWORD",
     "This regkey restricts profiling capabilities (creation of profiling objects",
     "and access to profiling-related registers) to admin only.",
     "0 - (default - disabled)",
     "1 - Enables admin check"
 ],
"Elements":  [
      {"Name":  "FALSE","Value":  "0"},
      {"Name":  "TRUE","Value":  "1"}
  ]
},
```
Changing it via NVCPL:
```ps
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Services\nvlddmkm\Global\NVTweak\RmProfilingAdminOnly    Type: REG_DWORD, Length: 4, Data: 1
NVDisplay.Container.exe    RegSetValue    HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\RmProfilingAdminOnly    Type: REG_DWORD, Length: 4, Data: 1
```
`Restrict access to the GPU performance counters to admin users only` = `1`
`Allow access to the GPU performance counters to all users` = `0`
```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\XXXX" /v RmProfilingAdminOnly /t REG_DWORD /d X /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v RmProfilingAdminOnly /t REG_DWORD /d X /f
```
Change `XXXX` to the correct key and `X` to `1`/`0`.
> https://www.nvidia.com/content/Control-Panel-Help/vLatest/en-us/index.htm#t=mergedProjects%2FDeveloper%2FManage_Performance_Counters_-_Reference.htm&rhsearch=counters
> https://github.com/5Noxi/bitmask-calc