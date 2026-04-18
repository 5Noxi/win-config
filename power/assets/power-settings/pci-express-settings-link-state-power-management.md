---
title: Link state power management | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/pci-express-settings-link-state-power-management
description: Specifies the personality of the power plan.
---

# Link state power management | Microsoft Learn

Specifies the personality of the power plan.

**Warning** System administrators should not change the power plan personality settings.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\PCIExpress\ASPM`
- **PowerCfg:**`ASPM`
- **GUID:** ee12f906-d277-404b-b6da-e5fa1a576df5
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | None | The power plan is a Power Saver plan. |
| 1 | Moderate Power Savings | The system attempts to use the L0 state when the link is idle. |
| 2 | Maximum Power Savings | The system attempts to use the L1 state when the link is idle. |

## Applies to

Available in Windows Vista and later versions of Windows.