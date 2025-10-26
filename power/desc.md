# Disable Hibernation

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

# Remove Power Options

Removes the `Hibernate`, `Lock`, `Sleep` power options.

# Disable Hiberboot

```json
{
    "File":  "WinInit.admx",
    "NameSpace":  "Microsoft.Policies.WindowsInitialization",
    "Class":  "Machine",
    "CategoryName":  "ShutdownOptions",
    "DisplayName":  "Require use of fast startup",
    "ExplainText":  "This policy setting controls the use of fast startup. If you enable this policy setting, the system requires hibernate to be enabled.If you disable or do not configure this policy setting, the local setting is used.",
    "Supported":  "Windows8",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\System",
    "KeyName":  "HiberbootEnabled",
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

# Disable Power Throttling

```
Power throttling, introduced in W10 and present in W11, limits CPU usage for background or minimized applications. It reduces the processing power available to these apps while allowing active applications to run normally.
```
You can see processes, which use power throttling by enabling the column (`Details` > `Select Column`) or add it to the active columns in system informer via the `Choose columns...` window (picture).
> https://discord.com/channels/836870260715028511/1296968338504945684/1371451927006810223

```c
dq offset aPowerPowerthro ; "Power\\PowerThrottling"
dq offset aPowerthrottlin ; "PowerThrottlingOff"
dq offset PpmPerfQosGroupPolicyDisable

PpmPerfQosGroupPolicyDisable dd 0 // Throttling enabled
```

![](https://github.com/5Noxi/win-config/blob/main/power/images/powerth.png?raw=true)