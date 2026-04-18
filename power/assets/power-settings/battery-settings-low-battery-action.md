---
title: Low battery action | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/battery-settings-low-battery-action
description: Specifies the action to take when the low batter level is reached.
---

# Low battery action | Microsoft Learn

Specifies the action to take when the low batter level is reached.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Battery\LowAction`
- **PowerCfg:**`BATACTIONLOW`
- **GUID:** d8742dcb-3e6a-4b3c-b3fe-374623cdcf06
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | Do Nothing | No action is taken when the low battery level is reached. |
| 1 | Sleep | The system enters sleep when the low battery level is reached. |
| 2 | Hibernate | The system enters hibernate when the low battery level is reached. |
| 3 | Shut Down | The system shuts down when the low battery level is reached. |

## Applies to

Available in Windows Vista and later versions of Windows.