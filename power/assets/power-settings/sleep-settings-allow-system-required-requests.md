---
title: Allow system required requests | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-allow-system-required-requests
description: Configures the power manager to accept or ignore application system required requests. These requests prevent the system from automatically entering sleep after a period of user inactivity.
---

# Allow system required requests | Microsoft Learn

Configures the power manager to accept or ignore application system required requests. These requests prevent the system from automatically entering sleep after a period of user inactivity.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Sleep\AllowSystemRequired`
- **PowerCfg:**`SYSTEMREQUIRED `
- **GUID:** a4b195f5-8225-47d8-8012-9d41369786e2
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | No | Application system required requests will be ignored. |
| 1 | Yes | Application system required requests will be accepted. |

## Applies to

Available in Windows 7 and later versions of Windows.