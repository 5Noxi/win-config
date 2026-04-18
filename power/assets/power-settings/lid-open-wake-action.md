---
title: Lid open wake action | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/lid-open-wake-action
description: Specifies the action to take when the system lid is opened.
---

# Lid open wake action | Microsoft Learn

Specifies the action to take when the system lid is opened.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Button\LidOpenWake`
- **PowerCfg:**`LIDOPENWAKE       `
- **GUID:** 99ff10e7-23b1-4c07-a9d1-5c3206d741b4
- **Hidden setting:** Yes
- **Current AC power setting index:** 0x00000001
- **Current DC power setting index:** 0x00000001

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | Do Nothing | No action is taken when the system lid is opened. |
| 1 | Turn on the display | The OS turns on the display when the system lid is opened. |

## Applies to

Available in Windows 10, version 1607 and later versions of Windows.