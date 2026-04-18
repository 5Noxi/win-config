---
title: ShortThreadRuntimeThreshold | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/configuration-for-hetero-power-scheduling-shortthreadruntimethreshold
description: ShortThreadRuntimeThreshold specifies the runtime threshold for distinguishing a short versus long running thread.
---

# ShortThreadRuntimeThreshold | Microsoft Learn

`ShortThreadRuntimeThreshold` specifies the runtime threshold for distinguishing a short versus long running thread. Threads with an expected runtime less than this value are considered short running and have scheduling configured by [ShortSchedulingPolicy](configuration-for-hetero-power-scheduling-shortschedulingpolicy) on systems with processors with heterogeneous architecture.

## Aliases and setting visibility

- **Windows Provisioning:**`Common\Power\Policy\Settings\Processor\ShortThreadRuntimeThreshold`
- **PowerCfg:**`SHORTTHREADRUNTIMETHRESHOLD`
- **Hidden setting:** Yes

## Values

The value denotes microseconds (us).

| Minimum value | 100 |
| --- | --- |
| Maximum value | 100000 |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |