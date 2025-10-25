# Performance State

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
```json
{
  "NVIDIA": {
    "DisableDynamicPstate": {
      "Action": "nvidia key",
      "Type": "REG_DWORD",
      "Data": 1
    }
  }
}
```

# High-bandwidth Digital Content Protection (HDCP)

HDCP protects digital content from being copied while it's transmitted between devices like a computer and a TV - would leave it enabled.

```json
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

```json
{
  "NVIDIA": {
    "RMHdcpKeyglobZero": {
      "Action": "nvidia key",
      "Type": "REG_DWORD",
      "Data": 1
    }
  }
}
```

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
```json
{
  "HKLM\\SOFTWARE\\NVIDIA Corporation\\NvTray": {
    "StartOnLogin": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  },
  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\Global\\NVTweak": {
    "HideXGpuTrayIcon": {
      "Type": "REG_DWORD",
      "Data": 1
    }
  },
  "HKLM\\SOFTWARE\\NVIDIA Corporation\\Global\\CoProcManager": {
    "ShowTrayIcon": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  }
}
```

# Disable DLSS Indicator

Disable:
```bat
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NGXCore" /v ShowDlssIndicator /t REG_DWORD /d 0 /f
```
Enable:
```bat
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NGXCore" /v ShowDlssIndicator /t REG_DWORD /d 1024 /f
```

From NVIDIA documentations:
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
```json
{
  "HKLM\\SOFTWARE\\NVIDIA Corporation\\Global\\NGXCore": {
    "ShowDlssIndicator": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  }
}
```

# Display Powersaving

```
\Registry\Machine\SOFTWARE\NVIDIA Corporation\Global\NVTweak : DisplayPowerSaving
\Registry\Machine\SYSTEM\ControlSet001\Services\nvlddmkm\Global\NVTweak : DisplayPowerSaving
```

You can find it in `nvsvc64.dll`.

```json
{
  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\Global\\NVTweak": {
    "DisplayPowerSaving": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  },
  "HKLM\\Software\\NVIDIA Corporation\\Global\\NVTweak": {
    "DisplayPowerSaving": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  }
}
```

# Disable NVIDIA Driver Notification

Disables the notification (GeForce), whenever a new driver is available.


```json
{
  "HKCU\\SOFTWARE\\NVIDIA Corporation\\Global\\GFExperience": {
    "NotifyNewDisplayUpdates": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  }
}
```

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
```json
{
  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\Parameters": {
    "LogWarningEntries": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "LogPagingEntries": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "LogEventEntries": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "LogErrorEntries": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  }
}
```

# Control Panel 'Desktop Options'

Enables `Enable Developer Settings`, disables `Add Dekstop Context Menu` and `Show Notification Tray Icon`.

```h
//Profile info related
#define NV_REG_CPL_PERFCOUNT_RESTRICTION  "RmProfilingAdminOnly"
#define NV_REG_CPL_DEVTOOLS_VISIBLE       "NvDevToolsVisible"
```

# GPU Performance Counters
"GPU performance counters are used by NVIDIA GPU profiling tools such as NVIDIA Nsight. These tools enable developers debug, profile and develop software for NVIDIA GPUs."
```json
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

```json
{
  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\Global\\NVTweak": {
    "RmProfilingAdminOnly": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  }
}
```

# Noise Reduction

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

# Rotate Display - Orientation

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