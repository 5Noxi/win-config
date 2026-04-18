---
title: PerfAutonomousMode | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/options-for-perf-state-engine-perfautonomousmode
description: PerfAutonomousMode controls whether autonomous mode is enabled on systems that implement version 2 of the CPPC interface, and determines whether desired performance requests should be provided to the platform.
---

# PerfAutonomousMode | Microsoft Learn

`PerfAutonomousMode` controls whether autonomous mode is enabled on systems that implement version 2 of the CPPC interface, and determines whether desired performance requests should be provided to the platform. On systems with other performance state interfaces, this setting has no effect.

**Note** Platforms that support CPPC version 2 may only support autonomous disabled or autonomous enabled mode. If only one mode is supported, the OS uses that mode and ignores the `PerfAutonomousMode` power setting.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Processor\PerfAutonomousMode`
- **PowerCfg:**`PERFAUTONOMOUS`
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | Disabled | The performance state engine disables autonomous mode, determines desired performance levels, and conveys those performance levels to the platform. |
| 1 | Enabled | The performance state engine enables autonomous mode and stops providing desired performance levels to the platform. |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 10 for desktop editions (Home, Pro, Enterprise, and Education) | Supported | Supported | N/A |
| Windows 10 Mobile | N/A | N/A | Supported |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |