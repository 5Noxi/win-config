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