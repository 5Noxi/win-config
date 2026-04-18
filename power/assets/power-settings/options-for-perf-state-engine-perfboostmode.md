---
title: PERFBOOSTMODE | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/options-for-perf-state-engine-perfboostmode
description: PERFBOOSTMODE determines how processors select a performance level when current operating conditions allow for boosting performance above the nominal level.
---

# PERFBOOSTMODE | Microsoft Learn

`PERFBOOSTMODE` determines how processors select a performance level when current operating conditions allow for boosting performance above the nominal level.

For non-autonomous CPPC/PEP, the OS selects a target boost performance when Enabled and selects the maximum boost performance when Aggressive.

## GUID, alias, and setting visibility

- **GUID:** be337238-0d82-4146-a960-4f3749d470c7
- **PowerCfg alias:**`PERFBOOSTMODE`
- **Hidden setting:** Yes

## Values

| Index | ACPI P-State | CPPC/PEP | Autonomous CPPC/PEP |
| --- | --- | --- | --- |
| 0 | Disabled | Disabled | Disabled |
| 1 | Enabled | Enabled | Enabled |
| 2 | Enabled | Aggressive | Enabled |
| 3 | Same as 1 | Same as 1 | Same as 1 |
| 4 | Same as 2 | Same as 2 | Same as 2 |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 10 for desktop editions (Home, Pro, Enterprise, and Education) | Supported | Supported | N/A |
| Windows 10 Mobile | N/A | N/A | Supported |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |