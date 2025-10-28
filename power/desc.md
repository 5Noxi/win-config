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
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/Power.txt

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
> https://systeminformer.io/

```c
dq offset aPowerPowerthro ; "Power\\PowerThrottling"
dq offset aPowerthrottlin ; "PowerThrottlingOff"
dq offset PpmPerfQosGroupPolicyDisable

PpmPerfQosGroupPolicyDisable dd 0 // Throttling enabled
```

![](https://github.com/5Noxi/win-config/blob/main/power/images/powerth.png?raw=true)

# Disable Energy Estimation

Not needed, if you disable energy estimation:
```
\Registry\Machine\SYSTEM\ControlSet001\Control\Power\EnergyEstimation\TaggedEnergy : DisableTaggedEnergyLogging
\Registry\Machine\SYSTEM\ControlSet001\Control\Power\EnergyEstimation\TaggedEnergy : TelemetryMaxApplication
\Registry\Machine\SYSTEM\ControlSet001\Control\Power\EnergyEstimation\TaggedEnergy : TelemetryMaxTagPerApplication
```
```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v DisableTaggedEnergyLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v TelemetryMaxApplication /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v TelemetryMaxTagPerApplication /t REG_DWORD /d 0 /f
```

> [power/assets | jpeg-TranscodeImage.c](https://github.com/5Noxi/win-config/blob/main/power/assets/energyesti-PtInitializeTelemetry.c)

![](https://github.com/5Noxi/win-config/blob/main/power/images/energyesti.png?raw=true)

# Powerplan

Use the commands below, to import power plans by double-clicking them. Modify the powerplan via `PowerSettingsExplorer.exe`.
> http://www.mediafire.com/file/wt37sbsejk7iepm/PowerSettingsExplorer.zip

```ps
reg add "HKCR\.pow" /ve /t REG_SZ /d "Power Plan" /f
reg add "HKCR\.pow" /v FriendlyTypeName /t REG_SZ /d "Power Plan" /f
reg add "HKCR\.pow\DefaultIcon" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\powercfg.cpl,-202" /f
reg add "HKCR\.pow\shell\Import" /f
reg add "HKCR\.pow\shell\Import\command" /ve /t REG_SZ /d "powercfg /import \"%%1\"" /f
```
Remove default powerplans with:
```bat
powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a
powercfg -delete e9a42b02-d5df-448d-aa00-03f14749eb61
```
> https://bitsum.com/known-windows-power-guids/