---
title: Prompt for password on resume | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/no-subgroup-settings-prompt-for-password-on-resume
description: Specifies whether the user must enter a password at the secure desktop when the system resumes from sleep.Note  All Windows desktop editions have this setting enabled by default.
---

# Prompt for password on resume | Microsoft Learn

Specifies whether the user must enter a password at the secure desktop when the system resumes from sleep.

**Note** All Windows desktop editions have this setting enabled by default. This is a change from Windows 8.1 and earlier which had the setting disabled by default on some editions.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Misc\LockConsoleOnWake`
- **PowerCfg:**`CONSOLELOCK     `
- **GUID:** 0e796bdb-100d-47d6-a2d5-f7d2daa51f51
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | Disabled | The system returns to the desktop when resuming from sleep. |
| 1 | Enabled | The system returns to the secure desktop, and the user must enter a password when the system resumes from sleep. |

## Applies to

Available in Windows Vista and later versions of Windows.