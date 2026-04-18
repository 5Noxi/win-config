---
title: Low battery warning | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/battery-settings-low-battery-warning
description: Specifies whether the OS displays a UI warning at the batter meter when the battery capacity crosses the low battery threshold.
---

# Low battery warning | Microsoft Learn

Specifies whether the OS displays a UI warning at the batter meter when the battery capacity crosses the low battery threshold.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Battery\LowBatteryWarning`
- **PowerCfg:**`BATFLAGSLOW     `
- **GUID:** bcded951-187b-4d05-bccc-f7e51960c258
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | Disabled | The OS does not display a UI warning when the battery capacity crosses the low battery threshold. |
| 1 | Enabled | The OS displays a UI warning when the battery capacity crosses the low battery threshold. |

## Applies to

Available in Windows Vista and later versions of Windows.