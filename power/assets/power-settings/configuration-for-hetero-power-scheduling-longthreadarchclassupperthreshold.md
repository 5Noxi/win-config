---
title: LongThreadArchClassUpperThreshold | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/configuration-for-hetero-power-scheduling-longthreadarchclassupperthreshold
description: LongThreadArchClassUpperThreshold specify the upper limit of processor architecture class for long running threads on systems with processors with heterogeneous architecture. See  [ShortThreadRuntimeThreshold](configuration-for-hetero-power-scheduling-shortthreadruntimethreshold.md) for configuring the threshold for determination of short versus long running. Long running threads cannot be run on cores whose normalized architectural class is higher than this limit.
---

# LongThreadArchClassUpperThreshold | Microsoft Learn

`LongThreadArchClassUpperThreshold` specify the upper limit of processor architecture class for long running threads on systems with processors with heterogeneous architecture. See [ShortThreadRuntimeThreshold](configuration-for-hetero-power-scheduling-shortthreadruntimethreshold) for configuring the threshold for determination of short versus long running. Long running threads cannot be run on cores whose normalized architectural class is higher than this limit.

## Aliases and setting visibility

- **Windows Provisioning:**`Common\Power\Policy\Settings\Processor\LongThreadArchClassUpperThreshold`
- **PowerCfg:**`LongThreadArchClassUpperThreshold`
- **Hidden setting:** Yes

## Values

| Index | Description |
| --- | --- |
| 0 | Minimum value can be 0 and Maximum value can be 255. This value indicates processor architecture class. For example for dual core system Maximum value can be 2 and for tri-core system maximum value can be 3. |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |