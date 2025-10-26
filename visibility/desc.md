# Explorer Options

It changes every setting, which is shown in the `Folder Options` window. Some are personal preference.

Enable compact mode:
```bat
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v UseCompactMode /t REG_DWORD /d 1
```
Set it to `0` to get the default mode back.

Show hidden & protected files/folders:
```bat
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
```
Set `Hidden` to `2` and `ShowSuperHidden` to `0` to disable it.

# Enable Dark Theme

`darktheme-GetThemeFromUnattendSetup.c` for information about the comments, otherwise ignore them.

> [visibility/assets | darktheme-GetThemeFromUnattendSetup.c](https://github.com/5Noxi/win-config/blob/main/visibility/assets/darktheme-GetThemeFromUnattendSetup.c)

The pictures below show: `Dark Theme`, `Light Theme`.

Change accent color via registry (ARGB):
```bat
reg add "HKCU\Software\Microsoft\Windows\DWM" /v ColorizationColor /t REG_DWORD /d 3292809298 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v ColorizationAfterglow /t REG_DWORD /d 3292809298 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v AccentPalette /t REG_BINARY /d 646a79ff575c68ff4d525dff444852ff3a3d46ff30333bff23252aff88179800 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v StartColorMenu /t REG_DWORD /d 4282793274 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v AccentColorMenu /t REG_DWORD /d 4283582532 /f
```
This would apply dark nord color scheme.
> https://www.nordtheme.com/

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/darktheme1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/visibility/images/darktheme2.png?raw=true)


# Disable Transparency

The pictures below show: `Transparency On`, `Transparency Off`.

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/transpa1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/visibility/images/transpa2.png?raw=true)

# Remove Home & Gallery

Remove the recycle bin icon (desktop) with:
```bat
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v {645FF040-5081-101B-9F08-00AA002F954E} /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v {645FF040-5081-101B-9F08-00AA002F954E} /t REG_DWORD /d 1 /f
```
Remove the network sharing folder with:
```bat
reg add "HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f
```

---

Miscellaneous comments:
```ps
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v HubMode /t REG_DWORD /d 1 /f
```

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/homegal.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/visibility/images/homenet.png?raw=true)