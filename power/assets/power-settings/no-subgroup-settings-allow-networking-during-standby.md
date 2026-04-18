---
title: Allow networking during standby | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/no-subgroup-settings-allow-networking-during-standby
description: Specifies whether to allow networking during standby.
---

# Allow networking during standby | Microsoft Learn

Specifies whether to allow networking during standby.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Misc\ConnectivityInStandby`
- **GUID:** f15576e8-98b7-4186-b944-eafa664402d9
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | Disabled | The system will disconnect from the network during standby. |
| 1 | Enabled | The system will stay connected to the network during standby. |
| 2 | Managed by Windows | Windows will manage network connectivity during standby. |

## Applies to

Available in Windows Vista through Windows 10, version 1909.

Note

Deprecated starting in Windows 10, version 2004.

For more information about network connectivity in Modern Standby, refer to [Network connectivity](/en-us/windows-hardware/design/device-experiences/modern-standby-network-connectivity).