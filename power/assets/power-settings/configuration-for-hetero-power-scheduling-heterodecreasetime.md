---
title: HeteroDecreaseTime | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/configuration-for-hetero-power-scheduling-heterodecreasetime
description: HeteroDecreaseTime specifies the minimum amount of time that must elapse before additional efficiency class 1 logical processors can be transitioned from the unparked state to the parked state. The time is specified in performance time check intervals.
---

# HeteroDecreaseTime | Microsoft Learn

`HeteroDecreaseTime` specifies the minimum amount of time that must elapse before additional efficiency class 1 logical processors can be transitioned from the unparked state to the parked state. The time is specified in performance time check intervals.

## Aliases and setting visibility

- **Windows Provisioning:**`Common\Power\Policy\Settings\Processor\HeteroDecreaseTime`
- **PowerCfg:**`HETERODECREASETIME`
- **Hidden setting:** Yes

## Values

The value denotes time check intervals.

| Minimum value | 0 |
| --- | --- |
| Maximum value | 100 |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 10 for desktop editions (Home, Pro, Enterprise, and Education) | Supported | Supported | N/A |
| Windows 10 Mobile | N/A | N/A | Supported |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |