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