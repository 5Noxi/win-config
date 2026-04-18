---
title: PerfIncreaseThreshold | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/options-for-perf-state-engine-perfincreasethreshold
description: PerfIncreaseThreshold specifies the percentage of processor utilization, in terms of the maximum processor utilization, that is required to increase the processor to a higher performance state.
---

# PerfIncreaseThreshold | Microsoft Learn

`PerfIncreaseThreshold` specifies the percentage of processor utilization, in terms of the maximum processor utilization, that is required to increase the processor to a higher performance state.

Not applicable to [Enabled](options-for-perf-state-engine-perfautonomousmode) autonomous performance states systems.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Processor\PerfIncreaseThreshold`, `Common\Power\Policy\Settings\Processor\PerfIncreaseThreshold1`
- **PowerCfg:**`PERFINCTHRESHOLD`, `PERFINCTHRESHOLD1`
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