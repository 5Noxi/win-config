---
title: CpLatencyHintUnpark | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/options-for-core-parking-cplatencyhintunpark
description: CPLatencyHintUnpark specifies the minimum number of unparked cores when a system low latency hint is detected.
---

# CpLatencyHintUnpark | Microsoft Learn

`CPLatencyHintUnpark` specifies the minimum number of unparked cores when a system low latency hint is detected. Such hints are generated when an event preceding an expected latency-sensitive operation is detected. Examples include mouse button up events (for all mouse buttons), touch gesture start and gesture stop (finger down and finger up), and keyboard enter key down.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Processor\CpLatencyHintUnpark`, `Common\Power\Policy\Settings\Processor\CpLatencyHintUnpark1`
- **PowerCfg:**`LATENCYHINTUNPARK`, `LATENCYHINTUNPARK1`
- **Hidden setting:** Yes

## Values

The value denotes percentage (%).

| Minimum value | 0 |
| --- | --- |
| Maximum value | 100 |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 10 for desktop editions (Home, Pro, Enterprise, and Education) | Supported | Supported | N/A |
| Windows 10 Mobile | N/A | N/A | Supported |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |