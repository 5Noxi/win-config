---
title: SchedulingPolicy | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/configuration-for-hetero-power-scheduling-schedulingpolicy
description: SchedulingPolicy specifies the preference (or constraint) in processor scheduling on systems with processors with heterogeneous architecture.
---

# SchedulingPolicy | Microsoft Learn

`SchedulingPolicy` specifies the preference (or constraint) in processor scheduling for long running threads on systems with processors with heterogeneous architecture. See [ShortThreadRuntimeThreshold](configuration-for-hetero-power-scheduling-shortthreadruntimethreshold.md) for configuring the threshold for determination of short versus long running.

Value of Automatic lets the OS determines the policy based on system configuration and QoS type.

## Aliases and setting visibility

- **Windows Provisioning:**`Common\Power\Policy\Settings\Processor\SchedulingPolicy`
- **PowerCfg:**`SCHEDPOLICY`
- **Hidden setting:** Yes

## Values

| Index | Description |
| --- | --- |
| 0 | All processors |
| 1 | Performant processors |
| 2 | Prefer performant processors |
| 3 | Efficient processors |
| 4 | Prefer efficient processors |
| 5 | Automatic |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 10 for desktop editions (Home, Pro, Enterprise, and Education) | Supported | Supported | Supported |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |
