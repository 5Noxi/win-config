# win-config
Parsing tests


## Explorer Options

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

```json
{"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer":{"ShowFrequent":{"Type":"REG_DWORD","Data":0},"ShowRecent":{"Type":"REG_DWORD","Data":0},"ShowCloudFilesInQuickAccess":{"Type":"REG_DWORD","Data":0},"ShowDriveLettersFirst":{"Type":"REG_DWORD","Data":0}},"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced":{"IconsOnly":{"Type":"REG_DWORD","Data":0},"UseCompactMode":{"Type":"REG_DWORD","Data":1},"ShowTypeOverlay":{"Type":"REG_DWORD","Data":0},"FolderContentsInfoTip":{"Type":"REG_DWORD","Data":0},"Hidden":{"Type":"REG_DWORD","Data":2},"HideDrivesWithNoMedia":{"Type":"REG_DWORD","Data":0},"HideFileExt":{"Type":"REG_DWORD","Data":0},"HideMergeConflicts":{"Type":"REG_DWORD","Data":0},"ShowSuperHidden":{"Type":"REG_DWORD","Data":0},"SeparateProcess":{"Type":"REG_DWORD","Data":0},"PersistBrowsers":{"Type":"REG_DWORD","Data":0},"ShowEncryptCompressedColor":{"Type":"REG_DWORD","Data":0},"ShowInfoTip":{"Type":"REG_DWORD","Data":0},"ShowPreviewHandlers":{"Type":"REG_DWORD","Data":0},"ShowStatusBar":{"Type":"REG_DWORD","Data":1},"ShowSyncProviderNotifications":{"Type":"REG_DWORD","Data":0},"AutoCheckSelect":{"Type":"REG_DWORD","Data":0},"SharingWizardOn":{"Type":"REG_DWORD","Data":0},"TypeAhead":{"Type":"REG_DWORD","Data":0},"NavPaneExpandToCurrentFolder":{"Type":"REG_DWORD","Data":0},"NavPaneShowAllCloudStates":{"Type":"REG_DWORD","Data":0},"NavPaneShowAllFolders":{"Type":"REG_DWORD","Data":0},"TaskbarDa":{"Type":"REG_DWORD","Data":0}}}
```

# Disable Hibernation / Hiberboot, Remove Power Options

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
> https://discord.com/channels/836870260715028511/1371224441568231516/1372986527411470377

Disable fast startup:
```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f
```
Remove `Hibernate`, `Lock`, `Sleep` power options:
```bat
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v ShowHibernateOption /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v ShowLockOption /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v ShowSleepOption /t REG_DWORD /d 0 /f
```
```json
{"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power":{"HibernateEnabled":{"Type":"REG_DWORD","Data":0},"HibernateEnabledDefault":{"Type":"REG_DWORD","Data":0},"AllowHibernate":{"Type":"REG_DWORD","Data":0}}}
```

# Disable UAC

Disabling UAC stops the prompts for administrative permissions, allowing programs and processes to run with elevated rights without user confirmation. Save `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` before running it.

Remove the `Run as Administrator` context menu option (`.bat`, `.cmd` files) with:
```bat
reg delete "HKCR\batfile\shell\runas" /f
reg delete "HKCR\cmdfile\shell\runas" /f
```
Will cause issues like shows in the picture below, the two ones above might cause similar issues (if the app requests elevated permissions?). __Rather leave them alone.__
```
reg delete "HKCR\exefile\shell\runas" /f
```

__UAC Values (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`) - `UserAccountControlSettings.exe`:__
`Always notify me when: ...`
```ps
EnableLUA - Data: 1
ConsentPromptBehaviorAdmin - Data: 2
PromptOnSecureDesktop - Data: 1
```
`Notify me only when apps try to make changes to my computer (default)`
```ps
EnableLUA - Data: 1
ConsentPromptBehaviorAdmin - Data: 5
PromptOnSecureDesktop - Data: 1
```
`Notify me only when apps try to make changes to my computer (do not dim my desktop)`
```ps
EnableLUA - Data: 1
ConsentPromptBehaviorAdmin - Data: 5
PromptOnSecureDesktop - Data: 0
```
`Never notify me when: ...`
```ps
EnableLUA - Data: 1
ConsentPromptBehaviorAdmin - Data: 0
PromptOnSecureDesktop - Data: 0
```
```json
{"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System":{"ValidateAdminCodeSignatures":{"Type":"REG_DWORD","Data":0},"ConsentPromptBehaviorAdmin":{"Type":"REG_DWORD","Data":0},"ConsentPromptBehaviorUser":{"Type":"REG_DWORD","Data":0},"PromptOnSecureDesktop":{"Type":"REG_DWORD","Data":0},"EnableLUA":{"Type":"REG_DWORD","Data":0}}}
```