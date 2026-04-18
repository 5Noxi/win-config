---
title: Allow sleep with open remote files | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-allow-sleep-with-open-remote-files
description: Configures the network file system to prevent the computer from automatically entering sleep when remote network files are open.
---

# Allow sleep with open remote files | Microsoft Learn

Configures the network file system to prevent the computer from automatically entering sleep when remote network files are open.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Sleep\AllowRemoteOpenSleep`
- **PowerCfg:**`ALLOWREMOTEOPENSLEEP`
- **GUID:** d4c1d4c8-d5cc-43d3-b83e-fc51215cb04d
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | Off | Prevents automatic sleep when remote network files are open. However, if the open files are stored in Offline Files and are backed by the Offline File cache, automatic sleep is allowed. |
| 1 | On | Prevents automatic sleep when remote network files are open. However, if the open files are stored in Offline Files or the open files have not been updated since they were originally opened, automatic sleep is allowed. |

## Applies to

Available in Windows Vista and later versions of Windows.