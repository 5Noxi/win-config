---
title: PerfEnergyPreference | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/options-for-perf-state-engine-perfenergypreference
description: PerfEnergyPreference specifies the value to program in the energy performance preference register on systems that implement version 2 of the CPPC interface and have autonomous mode Enabled.
---

# PerfEnergyPreference | Microsoft Learn

`PerfEnergyPreference` specifies the value to program in the energy performance preference register on systems that implement version 2 of the CPPC interface and have autonomous mode [Enabled](options-for-perf-state-engine-perfautonomousmode.md).

When set to 0, the energy performance preference register is programmed to 0 to favor performance. When set to 100, the energy performance preference register is set to 255 to favor energy savings. When set to an intermediate value, the energy performance preference register is programmed to the value: (setting \* 255) / 100.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Processor\PerfEnergyPreference`, `Common\Power\Policy\Settings\Processor\PerfEnergyPreference1`
- **PowerCfg:**`PERFEPP`, `PERFEPP1`
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
