---
title: Automatically wake for tasks | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-automatically-wake-for-tasks
description: Specifies whether the system uses the system-wide wake-on-timer capability. The system can automatically use wake-on-timer on capable hardware to perform scheduled tasks. For example, the system might wake automatically to install updates.
---

# Automatically wake for tasks | Microsoft Learn

Specifies whether the system uses the system-wide wake-on-timer capability.

The system can automatically use wake-on-timer on capable hardware to perform scheduled tasks. For example, the system might wake automatically to install updates.

## Aliases and setting visibility

- **PowerCfg:**`RTCWAKE `
- **GUID:** bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | No | Wake on timer is disabled. |
| 1 | Yes | Wake on timer is enabled. |
| 2 | Important | Wake on internal system timers only. |

## Applies to

Available in Windows Vista and later versions of Windows.