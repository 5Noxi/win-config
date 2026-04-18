---
title: IdlePromoteThreshold | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/options-for-perf-state-engine-idlepromotethreshold
description: IdlePromoteThreshold specifies the amount of processor idleness that is required before a processor is set to the next lower power processor idle state. When the processor idleness goes above the value of this setting, the processor transitions to the next higher indexed idle state.
---

# IdlePromoteThreshold | Microsoft Learn

`IdlePromoteThreshold` specifies the amount of processor idleness that is required before a processor is set to the next lower power processor idle state. When the processor idleness goes above the value of this setting, the processor transitions to the next higher indexed idle state.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Processor\IdlePromoteThreshold`
- **PowerCfg:**`IDLEPROMOTE`
- **Hidden setting:** Yes

## Values

The value denotes percentage (%).

| Minimum value | 0 |
| --- | --- |
| Maximum value | 100 |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |