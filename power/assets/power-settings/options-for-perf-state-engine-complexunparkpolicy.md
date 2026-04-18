---
title: ComplexUnparkPolicy | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/options-for-perf-state-engine-complexunparkpolicy
description: A complex is defined as logical processors sharing same LLC cache. ComplexUnparkPolicy specifies the complex unparking policy. As per this policy Lp is unparked as per value selected for this policy.
---

# ComplexUnparkPolicy | Microsoft Learn

`ComplexUnparkPolicy` A complex is defined as logical processors sharing same LLC cache. ComplexUnparkPolicy specifies the complex unparking policy. As per this policy Lp is unparked as per value selected for this policy.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Processor\ComplexUnparkPolicy`
- **PowerCfg:**`ComplexUnparkPolicy`
- **Hidden setting:** Yes

## Values

| Index | Description |
| --- | --- |
| 0 | No unparking preference for unparking Lps from complexes. |
| 1 | Use round robin policy to unpark Lps among complexes. |
| 2 | Use sequential policy to unpark one by one Lp from a complex, before moving to another complex. |

## Applies to

| Windows edition | x86-based devices | x64-based devices | Arm-based devices |
| --- | --- | --- | --- |
| Windows 11 for desktop editions (Home, Pro, Enterprise, and Education) | N/A | Supported | Supported |