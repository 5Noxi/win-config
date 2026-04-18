---
title: Dim annoyance timeout | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/display-settings-dim-annoyance-timeout
description: This setting denotes the user annoyance detection threshold. It specifies the duration between automatic display brightness level reduction and user input to consider the automatic display brightness level reduction as an annoyance to the user.
---

# Dim annoyance timeout | Microsoft Learn

This setting denotes the user annoyance detection threshold. It specifies the duration between automatic display brightness level reduction and user input to consider the automatic display brightness level reduction as an annoyance to the user.

This setting applies only to portable computers that support Windows control of the brightness level of an integrated display device. In most situations, you should not change the default value of this setting.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Display\AdapativeIncrease`
- **PowerCfg:**`VIDEOADAPTINC       `
- **GUID:** 82dbcf2d-cd67-40c5-bfdc-9f1a5ccd4663
- **Hidden setting:** Yes

## Values

The value denotes the number of seconds.

| Minimum value | 0 (Do not detect user annoyance.) |
| --- | --- |
| Maximum value | Maximum integer |

## Applies to

Available in Windows 7 and later versions of Windows.