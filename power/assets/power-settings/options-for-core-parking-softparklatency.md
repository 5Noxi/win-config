---
title: SoftParkLatency | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/options-for-core-parking-softparklatency
description: SoftParkLatency specifies the anticipated execution latency at which a soft parked core can be used by the scheduler.
---

# SoftParkLatency | Microsoft Learn

`SoftParkLatency` specifies the anticipated execution latency at which a soft parked core can be used by the scheduler in microseconds.

This works in conjunction with other parking mechanisms. When `SoftParkLatency` is greater than 0, some parked cores can be selected as soft-parked while other conditions are met. When `SoftParkLatency` is 0, soft parking is disabled

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Processor\SoftParkLatency`
- **PowerCfg:**`SoftParkLatency`
- **Hidden setting:** Yes

## Values

The value denotes microseconds.

| Minimum value | 0 |
| --- | --- |
| Maximum value | 4294967295 |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 10 for desktop editions (Home, Pro, Enterprise, and Education) | Supported | Supported | Supported |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |