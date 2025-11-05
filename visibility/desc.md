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

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/explorer.png?raw=true)

---

Miscellaneous notes:
```ps
"TaskbarDa": { "Type": "REG_DWORD", "Data": 0 } # Access denied

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShellState /t REG_BINARY /d 24,00,00,00,3e,20,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01,00,00,00,13,00,00,00,00,00,00,00,42,00,00,00 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" /v Settings /t REG_BINARY /d 0c,00,02,00,0a,01,00,00,60,00,00,00 /f
```

```json
{
    "File":  "WindowsConnectNow.admx",
    "NameSpace":  "Microsoft.Policies.WindowsConnectNow",
    "Class":  "Machine",
    "CategoryName":  "WCN_Category",
    "DisplayName":  "Prohibit access of the Windows Connect Now wizards",
    "ExplainText":  "This policy setting prohibits access to Windows Connect Now (WCN) wizards. If you enable this policy setting, the wizards are turned off and users have no access to any of the wizard tasks. All the configuration related tasks, including \"Set up a wireless router or access point\" and \"Add a wireless device\" are disabled. If you disable or do not configure this policy setting, users can access the wizard tasks, including \"Set up a wireless router or access point\" and \"Add a wireless device.\" The default for this policy setting allows users to access all WCN wizards.",
    "Supported":  "WindowsVista",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\WCN\\UI",
    "KeyName":  "DisableWcnUi",
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

> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsconnectnow

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

# Disable Audio / Video Preview

Disables the preview function for (extensions):
```
3gp aac avi flac m4a m4v mkv mod mov mp3 mp4 mpeg mpg ogg ts vob wav webm wma wmv
```
`{E357FCCD-A995-4576-B01F-234630154E96}` - Thumbnail Provider (Thumbnail image handler)
`{BB2E617C-0920-11D1-9A0B-00C04FC2D6C1}` - Extract Image (Image handler)
`{9DBD2C50-62AD-11D0-B806-00C04FD706EC}` - Default shell extension handler for thumbnails
> https://learn.microsoft.com/en-us/windows/win32/shell/handlers#handler-names  
> https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailprovider  
> https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-iextractimage

Enabled:

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/audiovidpreon.png?raw=true)

Disabled:

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/audiovidpreonoff.png?raw=true)

---

Hide preview pane:
```ps
"Explorer.EXE","RegSetValue","HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Modules\GlobalSettings\Sizer\DetailsContainerSizer","Type: REG_BINARY, Length: 16, Data: 15 01 00 00 00 00 00 00 00 00 00 00 6B 03 00 00"
"Explorer.EXE","RegSetValue","HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Modules\GlobalSettings\DetailsContainer\DetailsContainer","Type: REG_BINARY, Length: 8, Data: 02 00 00 00 02 00 00 00"
```

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

# Disable Animations

Minimize, Maximize, Taskbar Animations / First Sign-In Animations. These options are also changeable via `SystemPropertiesPerformance` (`WIN + R`) - first three.

`MaxAnimate` doesn't exist, windows only uses `MinAnimate`
```
SystemPropertiesAdvanced.exe	RegSetValue	HKCU\Control Panel\Desktop\WindowMetrics\MinAnimate	Type: REG_SZ, Length: 4, Data: 1
```
Disable logon animations, which would remove the animation (picture), instead shows the windows default background wallpaper: (first sign-in):
```
This policy controls whether users see the first sign-in animation when signing in for the first time, including both the initial setup user and those added later. It also determines if Microsoft account users receive the opt-in prompt for services. If enabled, Microsoft account users see the opt-in prompt and other users see the animation. If disabled, neither the animation nor the opt-in prompt appears. If not configured, the first user sees the animation during setup; later users won't see it if setup was already completed. This policy has no effect on Server editions.
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

# Disable Automatic Folder Type Discovery

"Folder discovery is a feature that customizes the view settings of folders based on their content. For example, a folder with images might display thumbnails, while a folder with documents might show a list view. While this can be useful, it can also be frustrating if you prefer a uniform view for all folders."

Removing the `Bags` & `BagMRU` key resets all folder settings (view, size,...), `NotSpecified` sets the template to `General Items`. The other templates would be `Documents`, `Music`, `Videos` (folder: `Properties > Customize > Optimize this folder for:`)

The revert may not work correctly yet, as it only creates the `Bags`/`BagsMRU` keys.

> https://www.insomniacgeek.com/posts/how-to-disable-windows-folder-discovery/  
> https://github.com/LesFerch/WinSetView

# Hide Language Bar

Topic should speak for itself.

> https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Software/Microsoft/CTF/LangBar/index  
> https://gist.github.com/omar-irizarry/d469e1642e3b27df1eebd1e907ffe61d

# OEM Information

Set your own support information in `System > About` (or `Control Panel > System and Security > System`. All values are saved in:
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation
```
You used to change the logo with:
```ps
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Logo /t REG_SZ /d "path\OEM.bmp" /f
```
But it seems deprecated (doesn't work for me). Limitation were `120x120` pixels, `.bmp` file & `32-bit` color depth.

Edit registered owner/orga (visible in `winver`) with:
```ps
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d Nohuxi /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOrganization /t REG_SZ /d Noverse /f
```
Edit miscellaneous things in `winver.exe` using (`basebrd.dll`/`basebrd.dll.mui`):
> https://www.angusj.com/resourcehacker/

---

Example:
```ps
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Manufacturer" /t REG_SZ /d "Noverse" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Model" /t REG_SZ /d "Windows 11" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportHours" /t REG_SZ /d "24 Hours" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportPhone" /t REG_SZ /d "noverse@gmail.com" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportURL" /t REG_SZ /d "https://discord.gg/noverse" /f
```

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/oem.png?raw=true)


# System Clock Seconds

"Uses more power" (in relation to laptops).

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/clock.png?raw=true)

# Taskbar Settings

Removes the search box, moves the taskbar to the left, removes badges, disables the orange flashes on the app icons, removes the "Task View" button. (`Personalization > Taskbar`)

Remove the `End Task` option to the taskbar right click menu with:
```bat
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v TaskbarEndTask /f
```
Enabling it via `System > For developers`:
```ps
SystemSettings.exe	RegSetValue	HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings\TaskbarEndTask	Type: REG_DWORD, Length: 4, Data: 1
```

`TaskbarSd` adds/removes the block in the right corner, which shows the desktop (picture).

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/taskbar.png?raw=true)

# Optimize Visual Effects

Open `SystemPropertiesPerformance.exe` & apply the following settings, turning on/off other options is personal preference. A system restart may be required to apply the changes:
```bat
shutdown -r -t 0
```
`Perf-Options.bat` leaves font smoothing on (improves the appearance of text on screens by softening the edges of characters), if you want to disable it (for whatever reason):
```bat
reg add "HKCU\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v FontSmoothingType /t REG_DWORD /d 1 /f
```

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/visual1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/visibility/images/visual2.png?raw=true)

# Hide Shortcut Icon

Disables the `- Shortcut` text, hides the shortcut & compression arrows.

# 'New' Context Menu

Instead of creating a `.txt` file, then renaming it to e.g. `.bat` / `.ps1`, you can add these options to the 'new' context menu. This may also change the `Type` shown in the explorer (only `.bat` is affected of the three).

Edit the text, by editing `Default` (value empty) and `FriendlyTypeName`:
```ps
:: PowerShell
reg add "HKCR\ps1legacy" /ve /d "pwsh" /f
reg add "HKCR\ps1legacy" /v FriendlyTypeName /t REG_SZ /d "pwsh" /f
:: Text
reg add "HKCR\txtlegacy" /ve /d "txt" /f
reg add "HKCR\txtlegacy" /v FriendlyTypeName /t REG_SZ /d "txt" /f
:: Batch
reg add "HKCR\batfile" /ve /d "bat" /f
reg add "HKCR\batfile" /v FriendlyTypeName /t REG_SZ /d "bat" /f
```
Remove a specific block from `New-Context-Menu.bat`, or add a different one - personal preference.

Additionaly I added `Classic-Context-Menu`, which gets rid of the compact menu (W11). It's personal preference, but it's a "must do" in my opinion.

Enable the classic context menu with:
```bat
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve
```
Remove `Add to Favorites` option with:
```bat
reg delete "HKCR\*\shell\pintohomefile" /f
```
Remove `Share` option with:
```bat
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\ModernSharing" /f
```
Remove `Send to` option with:
```bat
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo" /f
```
Remove miscellaneous stock windows context menu options:
```bat
reg delete "HKCR\.bmp\ShellNew" /f
reg delete "HKCR\.zip\CompressedFolder\ShellNew" /f
```

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/newcontext1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/visibility/images/newcontext2.png?raw=true)

# Desktop Icon Spacing

Location:
```
\Registry\User\S-ID\Control Panel\Desktop\WindowMetrics : IconSpacing
\Registry\User\S-ID\Control Panel\Desktop\WindowMetrics : IconVerticalSpacing
```
`IconSpacing` = Horizontal
`IconVerticalSpacing` = Vertical

Default: `75px` (`-1125`)
Min: `32px` (`-480`)
Max: `182px` (`-2730`)

Personal preference - `100px` horizontal, `75px` vertical:

```bat
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v IconSpacing /t REG_SZ /d -1500 /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v IconVerticalSpacing /t REG_SZ /d -1125 /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v IconTitleWrap /t REG_SZ /d 0 /f
```

Value gets calculated with:
```c
-15*px

-15*75 = -1125 // default
```
I created a small tool for fun, since it's a lot easier to quickly change and test the different icon spacing. You've to log out after applying, otherwise it won't update instantly. (the images show vertical `75px` & `100px` difference)

Set the icon view size to `Small` with:
```bat
reg add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v IconSize /t REG_DWORD /d 32 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v Mode /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v LogicalViewMode /t REG_DWORD /d 3 /f
```
`75px`:

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/iconspacing75.png?raw=true)

`100px`:

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/iconspacing100.png?raw=true)

---

Not implemented yet caused by missing parser support:

```json
"apply": {
    "SUBOPTION": {
    "100px Horizonzal - 75px Vertical": {
        "HKCU\\Control Panel\\Desktop\\WindowMetrics": {
        "IconSpacing": { "Type": "REG_SZ", "Data": "-1500" },
        "IconVerticalSpacing": { "Type": "REG_SZ", "Data": "-1125" },
        "IconTitleWrap": { "Type": "REG_SZ", "Data": "0" }
        }
    }
    }
},
"revert": {
    "SUBOPTION": {
    "100px Horizonzal - 75px Vertical": {
        "HKCU\\Control Panel\\Desktop\\WindowMetrics": {
        "IconSpacing": { "Action": "deletevalue"},
        "IconVerticalSpacing": { "Action": "deletevalue" },
        "IconTitleWrap": { "Action": "deletevalue" }
        }
    }
    }
}
```

# Settings Page Visibility 

It controls which pages in the windows settings app are visible (blocked pages are removed from view and direct access redirects to the main settings page).

```
This policy allows an administrator to block a given set of pages from the System Settings app. Blocked pages will not be visible in the app, and if all pages in a category are blocked the category will be hidden as well. Direct navigation to a blocked page via URI, context menu in Explorer or other means will result in the front page of Settings being shown instead.
```
Path (`String Value`):
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer : SettingsPageVisibility
```
`showonly:` followed by a semicolon separated list of page identifiers to allow
`hide:` followed by a list of pages to block

Page identifiers are the part after `ms-settings:` in a settings URI.

Example:
`showonly:bluetooth` only shows the `Bluetooth` page
`hide:bluetooth;windowsdefender` hides the `Bluetooth` & `Windows Security` pages

All categories of `ms-settings` URIs:
> https://learn.microsoft.com/en-us/windows/apps/develop/launch/launch-settings-app#ms-settings-uri-scheme-reference

Example value:
```bat
hide:sync;signinoptions-launchfaceenrollment;signinoptions-launchfingerprintenrollment;maps;maps-downloadmaps;mobile-devices;family-group;deviceusage;findmydevice
```
It depends on the user what he wants to see and what not, so I won't upload a batch for it.

# Detailed File Transfer

When you copy, move, or delete a file or folder, a progress dialog appears. You can switch between `More details` and `Fewer details`. By default, the dialog opens in the same view you last used (if you didn't switch it yet, `0` is used).

`EnthusiastMode` - `0` = fewer detailes:

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/filetransfer0.png?raw=true)

`EnthusiastMode` - `1` = more details:

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/filetransfer1.png?raw=true)

# Classic Task Switcher

It won't work on 24H2.

New (delete `AltTabSettings`):

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/taskswitchnew.png?raw=true)

Classic (`AltTabSettings` - `1`):

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/taskswitchold.png?raw=true)


# Remove Quick Access

Removes the `Quick access` in the File Explorer & sets `Open File Exporer to` to `This PC`.

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/quickaccess.png?raw=true)

# System Fonts / Text Size

W11 uses `Segoe UI` by default. You can change it via registry edits, the selected font will be used for desktop interfaces, explorer, some apps (`StartAllBack` will use it), but won't get applied for e.g., `SystemSettings.exe` and app fonts in general. Some fonts will cause issues - `Yu Gothic UI Light` uses `¥` instead of `\` (picture).

Either select a installed font with the command shown below or install new fonts via e.g.:
> https://www.nerdfonts.com/font-downloads

Apply the selected font replacing the data (`Replace` in the example below):
```ps
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black Italic (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold Italic (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Historic (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Italic (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light Italic (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold Italic (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight Italic (TrueType)" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Symbol (TrueType)" /t REG_SZ /d "" /f

:: Replace "Yu Gothic UI Light"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes" /v "Segoe UI" /t REG_SZ /d "Yu Gothic UI Light" /f

::shutdown -l
```
Applying a new font needs a restart or logout, reverting doesn't.
```ps
shutdown -l # logout
```
List all available font families on your system with the `Open` option, or via `Personalization > Fonts`:
```ps
Add-Type -AssemblyName System.Drawing;[System.Drawing.FontFamily]::Families | % {$_.Name}
```
Revert the changes using:
```ps
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI (TrueType)" /t REG_SZ /d "segoeui.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black (TrueType)" /t REG_SZ /d "seguibl.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black Italic (TrueType)" /t REG_SZ /d "seguibli.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold (TrueType)" /t REG_SZ /d "segoeuib.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold Italic (TrueType)" /t REG_SZ /d "segoeuiz.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Historic (TrueType)" /t REG_SZ /d "seguihis.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Italic (TrueType)" /t REG_SZ /d "segoeuii.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light (TrueType)" /t REG_SZ /d "segoeuil.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light Italic (TrueType)" /t REG_SZ /d "seguili.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold (TrueType)" /t REG_SZ /d "seguisb.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold Italic (TrueType)" /t REG_SZ /d "seguisbi.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight (TrueType)" /t REG_SZ /d "segoeuisl.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight Italic (TrueType)" /t REG_SZ /d "seguisli.ttf" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Symbol (TrueType)" /t REG_SZ /d "seguisym.ttf" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes" /v "Segoe UI" /f
```

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/font1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/visibility/images/font2.png?raw=true)

Edit text sizes via `TextScaleFactor`, valid ranges are `100-225` (DWORD).
> https://learn.microsoft.com/en-us/uwp/api/windows.ui.viewmanagement.uisettings.textscalefactor?view=winrt-26100#windows-ui-viewmanagement-uisettings-textscalefactor
```c
  v10 = 0;
  if ( (int)SHRegGetDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Accessibility", L"TextScaleFactor", &v10) < 0
    || (v6 = v10, v10 - 101 > 0x7C) ) // valid range: [101, 225] -> v10 - 101 > 124  -> v10 > 225
  {
    v6 = 100LL; // fallback to 100 if missing or out of range (<100 / >225)
  }
```
Applying changes via `Accessibility > Text size`:
```c
// 100%
RegSetValue    HKCU\Software\Microsoft\Accessibility\TextScaleFactor    Type: REG_DWORD, Length: 4, Data: 100

// 225%
RegSetValue    HKCU\Software\Microsoft\Accessibility\TextScaleFactor    Type: REG_DWORD, Length: 4, Data: 225
```
Depending on the selected size, `CaptionFont`, `SmCaptionFont`, `MenuFont`, `StatusFont`, `MessageFont`, `IconFont` (located in `HKCU\Control Panel\Desktop\WindowMetrics`) will also change. Not every % increase will edit them, I may add exact data soon. Example of `100%`/`225%`:

```c
// 100%
IconFont    Type: REG_BINARY, Length: 92, Data: F4 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
CaptionFont    Type: REG_BINARY, Length: 92, Data: F4 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
SmCaptionFont    Type: REG_BINARY, Length: 92, Data: F4 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
MenuFont    Type: REG_BINARY, Length: 92, Data: F4 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
StatusFont    Type: REG_BINARY, Length: 92, Data: F4 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
MessageFont    Type: REG_BINARY, Length: 92, Data: F4 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00

// 225%
CaptionFont    Type: REG_BINARY, Length: 92, Data: E5 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
SmCaptionFont    Type: REG_BINARY, Length: 92, Data: E5 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
MenuFont    Type: REG_BINARY, Length: 92, Data: E5 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
StatusFont    Type: REG_BINARY, Length: 92, Data: E5 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
MessageFont    Type: REG_BINARY, Length: 92, Data: E5 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
IconFont    Type: REG_BINARY, Length: 92, Data: E5 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
```
> [visibility/assets | textsize-TextScaleDialogTemplate.c](https://github.com/5Noxi/win-config/blob/main/visibility/assets/textsize-TextScaleDialogTemplate.c)

# Hide Lock Screen

Disables the lock screen (skips the lock screen and go directly to the login screen). Revert it by removing the value (2nd command).

```json
{
    "File":  "ControlPanelDisplay.admx",
    "NameSpace":  "Microsoft.Policies.ControlPanelDisplay",
    "Class":  "Machine",
    "CategoryName":  "Personalization",
    "DisplayName":  "Do not display the lock screen",
    "ExplainText":  "This policy setting controls whether the lock screen appears for users.If you enable this policy setting, users that are not required to press CTRL + ALT + DEL before signing in will see their selected tile after locking their PC.If you disable or do not configure this policy setting, users that are not required to press CTRL + ALT + DEL before signing in will see a lock screen after locking their PC. They must dismiss the lock screen using touch, the keyboard, or by dragging it with the mouse.",
    "Supported":  "Windows8",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\Personalization",
    "KeyName":  "NoLockScreen",
    "Elements":  [

                    ]
}, 
{
    "File":  "ControlPanelDisplay.admx",
    "NameSpace":  "Microsoft.Policies.ControlPanelDisplay",
    "Class":  "Machine",
    "CategoryName":  "Personalization",
    "DisplayName":  "Force a specific default lock screen and logon image",
    "ExplainText":  "This setting allows you to force a specific default lock screen and logon image by entering the path (location) of the image file. The same image will be used for both the lock and logon screens.This setting lets you specify the default lock screen and logon image shown when no user is signed in, and also sets the specified image as the default for all users (it replaces the inbox default image).To use this setting, type the fully qualified path and name of the file that stores the default lock screen and logon image. You can type a local path, such as C:\\Windows\\Web\\Screen\\img104.jpg or a UNC path, such as \\\\Server\\Share\\Corp.jpg.This can be used in conjunction with the \"Prevent changing lock screen and logon image\" setting to always force the specified lock screen and logon image to be shown.Note: This setting only applies to Enterprise, Education, and Server SKUs.",
    "Supported":  "Windows8",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows",
    "KeyName":  "Personalization",
    "Elements":  [
                        {
                            "ValueName":  "LockScreenImage",
                            "Type":  "Text"
                        },
                        {
                            "ValueName":  "LockScreenOverlaysDisabled",
                            "FalseValue":  "0",
                            "TrueValue":  "1",
                            "Type":  "Boolean"
                        }
                    ]
},
```

---

Miscellaneous (`ControlPanelDisplay.admx`):  

Prevent lock screen background motion:
```bat
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v AnimateLockScreenBackground /t REG_DWORD /d 1 /f
```
Prevent enabling lock screen slide show:
```bat
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v NoLockScreenSlideshow /t REG_DWORD /d 1 /f
```
Show clear logon background:
```bat
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v DisableAcrylicBackgroundOnLogon /t REG_DWORD /d 1 /f
```

# Hide Most Used Apps

Hide recently added apps with:
```bat
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v HideRecentlyAddedApps /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Start" /v ShowRecentList /t REG_DWORD /d 0 /f
```
Remove frequently used programs list from the start menu with:
```bat
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMFUprogramsList /t REG_DWORD /d 1 /f
```
Hide new apps notification with ("`You have new apps that can open this type of file`"):
```bat
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v NoNewAppAlert /t REG_DWORD /d 1 /f
```
```c
dq offset POLID_NoNewAppAlert
dq offset aExplorer     ; "Explorer"
dq offset aNonewappalert ; "NoNewAppAlert"
```

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/mostused.jpg?raw=true)

```json
{
    "File":  "StartMenu.admx",
    "NameSpace":  "Microsoft.Policies.StartMenu",
    "Class":  "Both",
    "CategoryName":  "StartMenu",
    "DisplayName":  "Hide",
    "ExplainText":  "If you enable this policy setting, you can configure Start menu to show or hide the list of user\u0027s most used apps, regardless of user settings.Selecting \"Show\" will force the \"Most used\" list to be shown, and user cannot change to hide it using the Settings app.Selecting \"Hide\" will force the \"Most used\" list to be hidden, and user cannot change to show it using the Settings app.Selecting \"Not Configured\", or if you disable or do not configure this policy setting, all will allow users to turn on or off the display of \"Most used\" list using the Settings app. This is default behavior.Note: configuring this policy to \"Show\" or \"Hide\" on supported versions of Windows 10 will supercede any policy setting of \"Remove frequent programs list from the Start Menu\" (which manages same part of Start menu but with fewer options).",
    "Supported":  "Windows_10_0_21H2",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows",
    "KeyName":  "Explorer",
    "Elements":  [
                      {
                          "Type":  "Enum",
                          "ValueName":  "ShowOrHideMostUsedApps",
                          "Items":  [
                                        {
                                            "DisplayName":  "Not Configured",
                                            "Value":  "0"
                                        },
                                        {
                                            "DisplayName":  "Show",
                                            "Value":  "1"
                                        },
                                        {
                                            "DisplayName":  "Hide",
                                            "Value":  "2"
                                        }
                                    ]
                      }
                  ]
},
{
    "File":  "StartMenu.admx",
    "NameSpace":  "Microsoft.Policies.StartMenu",
    "Class":  "Both",
    "CategoryName":  "StartMenu",
    "DisplayName":  "Remove frequent programs list from the Start Menu",
    "ExplainText":  "If you enable this setting, the frequently used programs list is removed from the Start menu.If you disable this setting or do not configure it, the frequently used programs list remains on the simple Start menu.",
    "Supported":  "Windows7ToXPAndWindows10",
    "KeyPath":  "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
    "KeyName":  "NoStartMenuMFUprogramsList",
    "Elements":  [

                  ]
},
{
    "File":  "StartMenu.admx",
    "NameSpace":  "Microsoft.Policies.StartMenu",
    "Class":  "User",
    "CategoryName":  "StartMenu",
    "DisplayName":  "Turn off user tracking",
    "ExplainText":  "This policy setting allows you to turn off user tracking.If you enable this policy setting, the system does not track the programs that the user runs, and does not display frequently used programs in the Start Menu.If you disable or do not configure this policy setting, the system tracks the programs that the user runs. The system uses this information to customize Windows features, such as showing frequently used programs in the Start Menu.Also, see these related policy settings: \"Remove frequent programs liist from the Start Menu\" and \"Turn off personalized menus\".This policy setting does not prevent users from pinning programs to the Start Menu or Taskbar. See the \"Remove pinned programs list from the Start Menu\" and \"Do not allow pinning programs to the Taskbar\" policy settings.",
    "Supported":  "WindowsVistaTo2k",
    "KeyPath":  "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
    "KeyName":  "NoInstrumentation",
    "Elements":  [

                  ]
},
```

# Disable Spotlight

Spotlight is used to provide new pictures on your lock screen.

> https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight/?pivots=windows-11#policy-settings  
> https://www.dev2qa.com/how-to-show-or-hide-the-windows-spotlight-learn-about-this-picture-icon-on-windows-11-desktop/

```json
{
    "File":  "CloudContent.admx",
    "NameSpace":  "Microsoft.Policies.CloudContent",
    "Class":  "User",
    "CategoryName":  "CloudContent",
    "DisplayName":  "Turn off all Windows spotlight features",
    "ExplainText":  "This policy setting lets you turn off all Windows Spotlight features at once.If you enable this policy setting, Windows spotlight on lock screen, Windows tips, Microsoft consumer features and other related features will be turned off. You should enable this policy setting if your goal is to minimize network traffic from target devices.If you disable or do not configure this policy setting, Windows spotlight features are allowed and may be controlled individually using their corresponding policy settings.",
    "Supported":  "Windows_10_0_NOSERVER",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\CloudContent",
    "KeyName":  "DisableWindowsSpotlightFeatures",
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
    "File":  "CloudContent.admx",
    "NameSpace":  "Microsoft.Policies.CloudContent",
    "Class":  "User",
    "CategoryName":  "CloudContent",
    "DisplayName":  "Turn off the Windows Welcome Experience",
    "ExplainText":  "This policy setting lets you turn off the Windows Spotlight Windows Welcome experience. This feature helps onboard users to Windows, for instance launching Microsoft Edge with a web page highlighting new features.If you enable this policy, the Windows Welcome Experience will no longer display when there are updates and changes to Windows and its apps.If you disable or do not configure this policy, the Windows Welcome Experience will be launched to help onboard users to Windows telling them about what\u0027s new, changed, and suggested.",
    "Supported":  "Windows_10_0_RS2",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\CloudContent",
    "KeyName":  "DisableWindowsSpotlightWindowsWelcomeExperience",
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
    "File":  "CloudContent.admx",
    "NameSpace":  "Microsoft.Policies.CloudContent",
    "Class":  "User",
    "CategoryName":  "CloudContent",
    "DisplayName":  "Turn off Windows Spotlight on Action Center",
    "ExplainText":  "If you enable this policy, Windows Spotlight notifications will no longer be shown on Action Center.If you disable or do not configure this policy, Microsoft may display notifications in Action Center that will suggest apps or features to help users be more productive on Windows.",
    "Supported":  "Windows_10_0_RS2",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\CloudContent",
    "KeyName":  "DisableWindowsSpotlightOnActionCenter",
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
    "File":  "CloudContent.admx",
    "NameSpace":  "Microsoft.Policies.CloudContent",
    "Class":  "User",
    "CategoryName":  "CloudContent",
    "DisplayName":  "Turn off Windows Spotlight on Settings",
    "ExplainText":  "If you enable this policy, Windows Spotlight suggestions will no longer be shown in Settings app.If you disable or do not configure this policy, Microsoft may suggest apps or features in Settings app to help users be productive on Windows or their linked phone.",
    "Supported":  "Windows_10_0_RS4",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\CloudContent",
    "KeyName":  "DisableWindowsSpotlightOnSettings",
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
    "File":  "CloudContent.admx",
    "NameSpace":  "Microsoft.Policies.CloudContent",
    "Class":  "User",
    "CategoryName":  "CloudContent",
    "DisplayName":  "Turn off Spotlight collection on Desktop",
    "ExplainText":  "This policy setting removes the Spotlight collection setting in Personalization, rendering the user unable to select and subsequentyly download daily images from Microsoft to desktop.If you enable this policy, \"Spotlight collection\" will not be available as an option in Personalization settings.If you disable or do not configure this policy, \"Spotlight collection\" will appear as an option in Personalization settings, allowing the user to select \"Spotlight collection\" as the Desktop provider and display daily images from Microsoft on the desktop.",
    "Supported":  "Windows_10_0_NOSERVER",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\CloudContent",
    "KeyName":  "DisableSpotlightCollectionOnDesktop",
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
    "File":  "CloudContent.admx",
    "NameSpace":  "Microsoft.Policies.CloudContent",
    "Class":  "User",
    "CategoryName":  "CloudContent",
    "DisplayName":  "Do not suggest third-party content in Windows spotlight",
    "ExplainText":  "If you enable this policy, Windows spotlight features like lock screen spotlight, suggested apps in Start menu or Windows tips will no longer suggest apps and content from third-party software publishers. Users may still see suggestions and tips to make them more productive with Microsoft features and apps.If you disable or do not configure this policy, Windows spotlight features may suggest apps and content from third-party software publishers in addition to Microsoft apps and content.",
    "Supported":  "Windows_10_0_NOSERVER",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\CloudContent",
    "KeyName":  "DisableThirdPartySuggestions",
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
    "File":  "CloudContent.admx",
    "NameSpace":  "Microsoft.Policies.CloudContent",
    "Class":  "User",
    "CategoryName":  "CloudContent",
    "DisplayName":  "Configure Windows spotlight on lock screen",
    "ExplainText":  "This policy setting lets you configure Windows spotlight on the lock screen.If you enable this policy setting, \"Windows spotlight\" will be set as the lock screen provider and users will not be able to modify their lock screen. \"Windows spotlight\" will display daily images from Microsoft on the lock screen.Additionally, if you check the \"Include content from Enterprise spotlight\" checkbox and your organization has setup an Enterprise spotlight content service in Azure, the lock screen will display internal messages and communications configured in that service, when available. If your organization does not have an Enterprise spotlight content service, the checkbox will have no effect.If you disable this policy setting, Windows spotlight will be turned off and users will no longer be able to select it as their lock screen. Users will see the default lock screen image and will be able to select another image, unless you have enabled the \"Prevent changing lock screen image\" policy.If you do not configure this policy, Windows spotlight will be available on the lock screen and will be selected by default, unless you have configured another default lock screen image using the \"Force a specific default lock screen and logon image\" policy.Note: This policy is only available for Enterprise SKUs",
    "Supported":  "Windows_10_0_NOSERVER",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\CloudContent",
    "KeyName":  "ConfigureWindowsSpotlight",
    "Elements":  [
                      {
                          "ValueName":  "IncludeEnterpriseSpotlight",
                          "FalseValue":  "0",
                          "TrueValue":  "1",
                          "Type":  "Boolean"
                      },
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

# Black PS Background

Since `powershell.exe` has default color of white (foreground) and white (background), some may want to change it.

`ScreenColors` value, located in `HKCU\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe`
> `0-3` bit = `Foreground color`
> `4-7` bit = `Background color`

Valid colors bits - `binary` (`dec`):
Black: `0000` (`0`)
DarkBlue: `0001` (`1`)
DarkGreen: `0010` (`2`)
DarkCyan: `0011` (`3`)
DarkRed: `0100` (`4`)
DarkMagenta: `0101` (`5`)
DarkYellow: `0110` (`6`)
Gray: `0111` (`7`)
DarkGray: `1000` (`8`)
Blue: `1001` (`9`)
Green: `1010` (`10`)
Cyan: `1011` (`11`)
Red: `1100` (`12`)
Magenta: `1101` (`13`)
Yellow: `1110` (`14`)
White: `1111` (`15`)

Calculate it on your own, by using <#1371478333585363034> - e.g. set bit `1-3` and `7`, to get `Yellow` (foreground) and `DarkGray` (background).

If you've set a custom foreground/background color, they won't override the colors changed within the code, e.g.:
```ps
Write-Host "Noverse"
```
-> `Noverse` will have use foreground & background color of `ScreenColors`
```ps
Write-Host "Noverse" -ForegroundColor Blue
```
-> `Noverse` will be blue, `ScreenColors` gets skipped.
```ps
[console]::BackgroundColor = 'Black'
```
-> If it doesn't get changed within the code, it'll use the background color set by `ScreenColor`.

`System-Color.bat` uses `Black` (background) and `Gray` (foreground), since it is personal preference change it to whatever you want using the information above.

Add the `-NoLogo` parameter to the powershell shortcut in the start menu with the command below. It hides the startup banner:
```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\Nohuxi>
```
```ps
for %%L in ("%APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\*.lnk") do powershell -NoLogo -NoProfile -Command "$s=New-Object -ComObject WScript.Shell; $lnk=$s.CreateShortcut('%%~fL'); $lnk.TargetPath='%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe'; $lnk.Arguments='-NoLogo'; $lnk.Save()"
```

# Disable Theme Mouse Changes

Prevent Themes from changing the mouse cursor.

`Disable Theme Desktop Icons Changes` prevent themes from changing desktop icons.

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/thememouse.png?raw=true)

# Hide Disabled/Disconnected Devices

Hides disabled/disconnected devices in the `mmsys.cpl` window.

![](https://github.com/5Noxi/win-config/blob/main/visibility/images/hidedevices.png?raw=true)

```c
// Show disabled/disconnected devices
rundll32.exe	RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\DeviceCpl\ShowHiddenDevices	Type: REG_DWORD, Length: 4, Data: 1
rundll32.exe	RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\DeviceCpl\ShowDisconnectedDevices	Type: REG_DWORD, Length: 4, Data: 1

// Hide disabled/diconnected devices
rundll32.exe	RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\DeviceCpl\ShowHiddenDevices	Type: REG_DWORD, Length: 4, Data: 0
rundll32.exe	RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\DeviceCpl\ShowDisconnectedDevices	Type: REG_DWORD, Length: 4, Data: 0
```

# Global Account Picture

"This policy setting allows an administrator to standardize the account pictures for all users on a system to the default account picture."

Edit account picture/desktop wallpaper via (edit `C:\Path`/`Wallpaper.png`):
```bat
:: Account Picture
del "C:\ProgramData\Microsoft\User Account Pictures\user.png" /f /q
del "C:\ProgramData\Microsoft\User Account Pictures\user.bmp" /f /q
copy "C:\Path\user.png" "C:\ProgramData\Microsoft\User Account Pictures\"
copy "C:\Path\user.bmp" "C:\ProgramData\Microsoft\User Account Pictures\"

:: Desktop Wallpaper
reg add "HKCU\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d ""C:\Path\Wallpaper.png"" /f
```

```json
{
    "File":  "Cpls.admx",
    "NameSpace":  "Microsoft.Policies.ControlPanel2",
    "Class":  "Machine",
    "CategoryName":  "Users",
    "DisplayName":  "Apply the default account picture to all users",
    "ExplainText":  "This policy setting allows an administrator to standardize the account pictures for all users on a system to the default account picture. One application for this policy setting is to standardize the account pictures to a company logo.Note: The default account picture is stored at %PROGRAMDATA%\\Microsoft\\User Account Pictures\\user.jpg. The default guest picture is stored at %PROGRAMDATA%\\Microsoft\\User Account Pictures\\guest.jpg. If the default pictures do not exist, an empty frame is displayed.If you enable this policy setting, the default user account picture will display for all users on the system with no customization allowed.If you disable or do not configure this policy setting, users will be able to customize their account pictures.",
    "Supported":  "WindowsVista",
    "KeyPath":  "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
    "KeyName":  "UseDefaultTile",
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