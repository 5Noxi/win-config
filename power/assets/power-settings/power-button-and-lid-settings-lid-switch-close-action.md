---
title: Lid switch close action | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/power-button-and-lid-settings-lid-switch-close-action
description: Specifies the action to take when the system lid is closed.
---

# Lid switch close action | Microsoft Learn

Specifies the action to take when the system lid is closed.

## Aliases and setting visibility

- **Windows Provisioning:**`Common\Power\Policy\Settings\ButtonLidAction`
- **PowerCfg:**`LIDACTION       `
- **GUID:** 5ca83367-6e45-459f-a27b-476b1d01c936
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | Do Nothing | No action is taken when the system lid is closed. |
| 1 | Sleep | The system enters sleep when the system lid is closed. |
| 2 | Hibernate | The system enters hibernate when the system lid is closed. |
| 3 | Shut Down | The system shuts down when the system lid is closed. |

## Applies to

Available in Windows Vista and later versions of Windows.