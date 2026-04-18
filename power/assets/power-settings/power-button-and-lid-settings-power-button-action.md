---
title: Power button action | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/power-button-and-lid-settings-power-button-action
description: Specifies the action to take when the system power button is pressed.
---

# Power button action | Microsoft Learn

Specifies the action to take when the system power button is pressed.

## Aliases and setting visibility

- **Windows Provisioning:**`Common\Power\Policy\Settings\Button\PowerButtonAction`
- **PowerCfg:**`PBUTTONACTION         `
- **GUID:** 7648efa3-dd9c-4e3e-b566-50f929386280
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | Do Nothing | No action is taken when the power button is pressed. |
| 1 | Sleep | The system enters sleep when the power button is pressed. |
| 2 | Hibernate | The system enters hibernate when the power button is pressed. |
| 3 | Shut Down | The system shuts down when the power button is pressed. |

## Applies to

Available in Windows Vista and later versions of Windows.