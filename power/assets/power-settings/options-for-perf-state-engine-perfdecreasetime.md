---
title: PerfDecreaseTime | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/options-for-perf-state-engine-perfdecreasetime
description: PerfDecreaseTime specifies minimum amount of time that must elapse between subsequent reductions in the processor performance state. The time is specified in units of the number of processor performance time check intervals.
---

# PerfDecreaseTime | Microsoft Learn

`PerfDecreaseTime` specifies minimum amount of time that must elapse between subsequent reductions in the processor performance state. The time is specified in units of the number of processor performance time check intervals.

Not applicable to [Enabled](options-for-perf-state-engine-perfautonomousmode.md) autonomous performance states systems.

## Aliases and setting visibility

- **Windows provisioning:**

`Common\Power\Policy\Settings\Processor\PerfDecreaseTime`, `Common\Power\Policy\Settings\Processor\PerfDecreaseTime1`

- **PowerCfg:**`PERFDECTIME`, `PERFDECTIME1`
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
