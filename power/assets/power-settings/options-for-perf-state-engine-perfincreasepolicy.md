---
title: PerfIncreasePolicy | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/options-for-perf-state-engine-perfincreasepolicy
description: PerfIncreasePolicy specifies the algorithm used to select a new performance state when the ideal performance state is higher than the current performance state.
---

# PerfIncreasePolicy | Microsoft Learn

`PerfIncreasePolicy` specifies the algorithm used to select a new performance state when the ideal performance state is higher than the current performance state. The ideal state is such that the utilization would be between the decrease and increase thresholds. When optimized for responsiveness, the policy can select a higher state such that the utilization would be closer to the decrease threshold.

Not applicable to [Enabled](options-for-perf-state-engine-perfautonomousmode.md) autonomous performance states systems.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Processor\PerfIncreasePolicy`, `Common\Power\Policy\Settings\Processor\PerfIncreasePolicy1`
- **PowerCfg:**`PERFINCPOL`, `PERFINCPOL1`
- **Hidden setting:** Yes

## Values

| Index | Description |
| --- | --- |
| 0 | Select the ideal processor performance state. |
| 1 | Select the processor performance state one closer to ideal than the current processor performance state. |
| 2 | Select the highest speed/power processor performance state. |
| 3 | Select the ideal processor performance state optimized for responsiveness. |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |
