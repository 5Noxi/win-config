---
title: Adaptive display idle timeout | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/display-settings-adaptive-display-idle-timeout
description: Specifies whether the OS automatically scales the display idle time-out based on user activity.
---

# Adaptive display idle timeout | Microsoft Learn

Specifies whether the OS automatically scales the display idle time-out based on user activity.

If the user provides input to the system shortly after the display idle timeout is reached, Windows automatically extends the display idle time-out to deliver a better user experience.

## Aliases and setting visibility

- **Windows provisioning:**`Common\Power\Policy\Settings\Display\AdaptiveTimeout `
- **PowerCfg:**`VIDEOADAPT`
- **GUID:** 90959d22-d6a1-49b9-af93-bce885ad335b
- **Hidden setting:** Yes

## Values

| Index | Name | Description |
| --- | --- | --- |
| 0 | Disabled | Windows does not adaptively extend the display idle timeout. |
| 1 | Enabled | Windows adaptively extends the display idle timeout. |

## Applies to

Available in Windows Vista and later versions of Windows.