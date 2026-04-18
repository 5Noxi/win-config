---
title: ModuleUnparkPolicy | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/options-for-perf-state-engine-moduleunparkpolicy
description: A module is defined as logical processors sharing same L2 cache. ModuleUnparkPolicy specifies the module unparking policy. As per this policy Lp is unparked as per value selected for this policy.
---

# ModuleUnparkPolicy | Microsoft Learn

`ModuleUnparkPolicy` A module is defined as logical processors sharing same L2 cache. ModuleUnparkPolicy specifies the module unparking policy. As per this policy Lp is unparked as per value selected for this policy.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Processor\ModuleUnparkPolicy`
- **PowerCfg:**`ModuleUnparkPolicy`
- **Hidden setting:** Yes

## Values

| Index | Description |
| --- | --- |
| 0 | No unparking preference for unparking logical processors from modules. |
| 1 | Use round robin policy to unpark logical processors among modules. |
| 2 | Use sequential policy to unpark one by one logical processors from a module, before moving to another module. |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |