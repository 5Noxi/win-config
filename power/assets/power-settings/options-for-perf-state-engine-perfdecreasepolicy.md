---
title: PerfDecreasePolicy | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/options-for-perf-state-engine-perfdecreasepolicy
description: PerfDecreasePolicy specifies the algorithm used to select a new performance state when the ideal performance state is lower than the current performance state.
---

# PerfDecreasePolicy | Microsoft Learn

`PerfDecreasePolicy` specifies the algorithm used to select a new performance state when the ideal performance state is lower than the current performance state. The ideal state is such that the utilization would be between the decrease and increase thresholds.

Not applicable to [Enabled](options-for-perf-state-engine-perfautonomousmode) autonomous performance states systems.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Processor\PerfDecreasePolicy`, `Common\Power\Policy\Settings\Processor\PerfDecreasePolicy1`
- **PowerCfg:**`PERFDECPOL`, `PERFDECPOL1`
- **Hidden setting:** Yes

## Values

| Index | Description |
| --- | --- |
| 0 | Select the ideal processor performance state. |
| 1 | Select the processor performance state one closer to ideal than the current processor performance state. |
| 2 | Select the lowest speed/power processor performance state. |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |