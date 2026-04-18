---
title: HeteroClass0FloorPerf | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/configuration-for-hetero-power-scheduling-heteroclass0floorperf
description: HeteroClass0FloorPerf specifies the performance level floor, in percentage, to use for efficiency class 0 processors if there is at least one unparked efficiency class 1 processor.
---

# HeteroClass0FloorPerf | Microsoft Learn

`HeteroClass0FloorPerf` specifies the performance level floor, in percentage, to use for efficiency class 0 processors if there is at least one unparked efficiency class 1 processor.

Not applicable with [Quality of Service](/en-us/windows/win32/procthread/quality-of-service).

## Aliases and setting visibility

- **Windows Provisioning:**`Common\Power\Policy\Settings\Processor\HeteroClass0FloorPerf`
- **PowerCfg:**`HETEROCLASS0FLOORPERF`
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