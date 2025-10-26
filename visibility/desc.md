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

# Classic Context Menu

Use it on W11, unless you like the new menu - remove the key, to revert it.

Before & after:

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/classiconb.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/visibility/images/classicona.png?raw=true)

``` ```
# Disable Animation

Minimize, Maximize, Taskbar Animations / First Sign-In Animations. These options are also changeable via `SystemPropertiesPerformance` (`WIN + R`) - first three.

`MaxAnimate` doesn't exist, windows only uses `MinAnimate`
```
SystemPropertiesAdvanced.exe	RegSetValue	HKCU\Control Panel\Desktop\WindowMetrics\MinAnimate	Type: REG_SZ, Length: 4, Data: 1
```
Disable logon animations, which would remove the animation (picture), instead shows the windows default background wallpaper: (first sign-in):
```
This policy controls whether users see the first sign-in animation when signing in for the first time, including both the initial setup user and those added later. It also determines if Microsoft account users receive the opt-in prompt for services. If enabled, Microsoft account users see the opt-in prompt and other users see the animation. If disabled, neither the animation nor the opt-in prompt appears. If not configured, the first user sees the animation during setup; later users won’t see it if setup was already completed. This policy has no effect on Server editions.
```
```bat
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableFirstLogonAnimation /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v EnableFirstLogonAnimation /t REG_DWORD /d 0 /f
```
First one is the value, which gets used by windows (`Computer Configuration > Administrative Templates > System > Logon : Show first sign-in animation`, the second one does exist:
```c
CMachine::RegQueryDWORD(
  v62,
  L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
  L"EnableFirstLogonAnimation",
  0,
  &v117);
v118 = 1;

CMachine::RegQueryDWORD(
  v63,
  L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
  L"EnableFirstLogonAnimation",
  1u,
  &v118);
```
`AnimationAfterUserOOBE` & `SkipNextFirstLogonAnimation` (`CurrentVersion\Winlogon`) also exist.

> https://github.com/5Noxi/wpr-reg-records/blob/main/records/ControlPanel-Desktop.txt  
> [visibility/assets | animation-WinMain.c](https://github.com/5Noxi/win-config/blob/main/visibility/assets/animation-WinMain.c)

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/animation.png?raw=true)

```json
{
    "File":  "Explorer.admx",
    "NameSpace":  "Microsoft.Policies.WindowsExplorer2",
    "Class":  "User",
    "CategoryName":  "WindowsExplorer",
    "DisplayName":  "Turn off common control and window animations",
    "ExplainText":  "This policy is similar to settings directly available to computer users. Disabling animations can improve usability for users with some visual disabilities as well as improving performance and battery life in some scenarios.",
    "Supported":  "WindowsVista",
    "KeyPath":  "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
    "KeyName":  "TurnOffSPIAnimations",
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
    "File":  "Logon.admx",
    "NameSpace":  "Microsoft.Policies.WindowsLogon",
    "Class":  "Machine",
    "CategoryName":  "Logon",
    "DisplayName":  "Show first sign-in animation ",
    "ExplainText":  "This policy setting allows you to control whether users see the first sign-in animation when signing in to the computer for the first time. This applies to both the first user of the computer who completes the initial setup and users who are added to the computer later. It also controls if Microsoft account users will be offered the opt-in prompt for services during their first sign-in.If you enable this policy setting, Microsoft account users will see the opt-in prompt for services, and users with other accounts will see the sign-in animation.If you disable this policy setting, users will not see the animation and Microsoft account users will not see the opt-in prompt for services.If you do not configure this policy setting, the user who completes the initial Windows setup will see the animation during their first sign-in. If the first user had already completed the initial setup and this policy setting is not configured, users new to this computer will not see the animation. Note: The first sign-in animation will not be shown on Server, so this policy will have no effect.",
    "Supported":  "Windows8",
    "KeyPath":  "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    "KeyName":  "EnableFirstLogonAnimation",
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
    "File":  "DWM.admx",
    "NameSpace":  "Microsoft.Policies.DesktopWindowManager",
    "Class":  "User",
    "CategoryName":  "CAT_DesktopWindowManager",
    "DisplayName":  "Do not allow window animations",
    "ExplainText":  "This policy setting controls the appearance of window animations such as those found when restoring, minimizing, and maximizing windows. If you enable this policy setting, window animations are turned off. If you disable or do not configure this policy setting, window animations are turned on. Changing this policy setting requires a logoff for it to be applied.",
    "Supported":  "WindowsVista",
    "KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\DWM",
    "KeyName":  "DisallowAnimations",
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