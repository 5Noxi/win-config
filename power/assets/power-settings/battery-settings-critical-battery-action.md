---
title: Critical battery action | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/battery-settings-critical-battery-action
description: Specifies the action to take when the critical batter level is reached.
---

# Critical battery action | Microsoft Learn

Specifies the action to take when the critical battery level is reached.

## Aliases and setting visibility

- **PowerCfg:**`BATACTIONCRIT`
- **GUID:** 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | Do Nothing | No action is taken when the critical battery level is reached. |
| 1 | Sleep | The system enters sleep when the critical battery level is reached. |
| 2 | Hibernate | The system enters hibernate when the critical battery level is reached. |
| 3 | Shut Down | The system shuts down when the critical battery level is reached. |

## Applies to

Available in Windows Vista and later versions of Windows.