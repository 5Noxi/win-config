# Win32PrioritySeparation

"The value of this entry determines, in part, how much processor time the threads of a process receive each time they are scheduled, and how much the allotted time can vary. It also affects the relative priority of the threads of foreground and background processes. The value of this entry is a 6-bit bitmask consisting of three sets of two bits (AABBCC). Each set of two bits determines a different characteristic of the optimizing strategy.
- The highest two bits (AABBCC) determine whether each processor interval is relatively long or short.
- The middle two bits (AABBCC) determine whether the length of the interval varies or is fixed.
- The lowest two bits (AABBCC) determine whether the threads of foreground processes get more processor time than the threads of background processes each time they run."

Read trough the `.pdf` file, if you want to get more information about the bitmask. Calculate it yourself with [`bitmask-calc`](https://github.com/5Noxi/bitmask-calc).

```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 24 /f
```
-> `0x00000018` = Long, Fixed Quantum, no boost. Using a boost (bit `1-2`) would set the threads of foreground processes (game/csrss/(dwm?)) `2-3` times higher than from background processes, which can cause issues. `26` dec would use a boost of `3x`.

As you can see in this [table](https://github.com/djdallmann/GamingPCSetup/blob/d865b755a9b6af65a470b8840af54729c75a6ae7/CONTENT/RESEARCH/FINDINGS/win32prisep0to271.csv), the values repeat. Using a extremely high number therefore won't do anything else. `Win32PrioritySeparation.ps1` can be used to get the info, increase `for ($i=0; $i -le 271; $i++) {` (`271`), if you want to see more. It's a lighter version of [win32prisepcalc](https://github.com/djdallmann/GamingPCSetup/blob/master/CONTENT/SCRIPTS/win32prisepcalc.ps1).

Paste it into a terminal to see a table with all values:
```ps
for ($i=0; $i -le 271; $i++) {
    $bin = [Convert]::ToString($i,2).PadLeft(6,'0')[-6..-1]
    $interval = if (('00','10','11' -contains ($bin[0,1] -join''))) {'Shorter'} else {'Longer'}
    $time = if (('00','01','11' -contains ($bin[2,3] -join''))) {'Variable'} else {'Fixed'}
    $boost = switch ($bin[4,5] -join'') {'00' {'Equal and Fixed'} '01' {'2:1'} default {'3:1'}}
    if ($time -eq 'Fixed') {$qrvforeground = $qrvbackground = if ($interval -eq 'Longer') {36} else {18}} else {
        $values = @{ 
            'Shorter' = @{ '3:1' = @(18,6); '2:1' = @(12,6); 'Equal and Fixed' = @(6,6) }
            'Longer'  = @{ '3:1' = @(36,12); '2:1' = @(24,12); 'Equal and Fixed' = @(12,12) }
        }
        if ($values[$interval].ContainsKey($boost)) {$qrvforeground, $qrvbackground = $values[$interval][$boost]} else {$qrvforeground, $qrvbackground = $values[$interval]['Equal and Fixed']}
    }
	Write-Output "$i,0x$($i.ToString('X')),$interval,$time,$qrvforeground,$qrvbackground"
}
```

![](https://github.com/5Noxi/win-config/blob/main/system/images/w32ps.png?raw=true)

> [system/assets | Win32PrioritySeparation.pdf](https://github.com/5Noxi/win-config/blob/main/system/assets/Win32PrioritySeparation.pdf)

# Disable UAC

Disabling UAC stops the prompts for administrative permissions, allowing programs and processes to run with elevated rights without user confirmation. Save `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` before running it.

Remove the `Run as Administrator` context menu option (`.bat`, `.cmd` files) with:
```bat
reg delete "HKCR\batfile\shell\runas" /f
reg delete "HKCR\cmdfile\shell\runas" /f
```
Will cause issues like shows in the picture below, the two ones above might cause similar issues (if the app requests elevated permissions?). __Rather leave them alone.__
```
reg delete "HKCR\exefile\shell\runas" /f
```

UAC Values (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`) - `UserAccountControlSettings.exe`:
`Always notify me when: ...`
```ps
EnableLUA - Data: 1
ConsentPromptBehaviorAdmin - Data: 2
PromptOnSecureDesktop - Data: 1
```
`Notify me only when apps try to make changes to my computer (default)`
```ps
EnableLUA - Data: 1
ConsentPromptBehaviorAdmin - Data: 5
PromptOnSecureDesktop - Data: 1
```
`Notify me only when apps try to make changes to my computer (do not dim my desktop)`
```ps
EnableLUA - Data: 1
ConsentPromptBehaviorAdmin - Data: 5
PromptOnSecureDesktop - Data: 0
```
`Never notify me when: ...`
```ps
EnableLUA - Data: 1
ConsentPromptBehaviorAdmin - Data: 0
PromptOnSecureDesktop - Data: 0
```

Value: `FilterAdministratorToken`

| Value        | Meaning                                                                                                                                          |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `0x00000000` | Only the built-in administrator account (RID 500) should be placed into Full Token mode.                                                         |
| `0x00000001` | Only the built-in administrator account (RID 500) is placed into Admin Approval Mode. Approval is required when performing administrative tasks. |

Value: `ConsentPromptBehaviorAdmin`

| Value        | Meaning                                                                                                              |
| ------------ | -------------------------------------------------------------------------------------------------------------------- |
| `0x00000000` | Allows the admin to perform operations that require elevation without consent or credentials.                        |
| `0x00000001` | Prompts for username and password on the secure desktop when elevation is required.                                  |
| `0x00000002` | Prompts the admin to Permit or Deny an elevation request (secure desktop). Removes the need to re-enter credentials. |
| `0x00000003` | Prompts for credentials (admin username/password) when elevation is required.                                        |
| `0x00000004` | Prompts the admin to Permit or Deny elevation (non-secure desktop).                                                  |
| `0x00000005` | Default: Prompts admin to Permit or Deny elevation for non-Windows binaries on the secure desktop.                   |

Value: `ConsentPromptBehaviorUser`

| Value        | Meaning                                                                       |
| ------------ | ----------------------------------------------------------------------------- |
| `0x00000000` | Any operation requiring elevation fails for standard users.                   |
| `0x00000001` | Standard users are prompted for an admin’s credentials to elevate privileges. |

Value: `EnableInstallerDetection`

| Value        | Meaning                                                            |
| ------------ | ------------------------------------------------------------------ |
| `0x00000000` | Disables automatic detection of installers that require elevation. |
| `0x00000001` | Enables heuristic detection of installers needing elevation.       |

Value: `ValidateAdminCodeSignatures`

| Value        | Meaning                                                                        |
| ------------ | ------------------------------------------------------------------------------ |
| `0x00000000` | Does not enforce cryptographic signatures on elevated apps.                    |
| `0x00000001` | Enforces cryptographic signatures on any interactive app requesting elevation. |

Value: `EnableLUA`

| Value        | Meaning                                                                             |
| ------------ | ----------------------------------------------------------------------------------- |
| `0x00000000` | Disables the “Administrator in Admin Approval Mode” user type and all UAC policies. |
| `0x00000001` | Enables the “Administrator in Admin Approval Mode” and activates all UAC policies.  |

Value: `PromptOnSecureDesktop`

| Value        | Meaning                                                                        |
| ------------ | ------------------------------------------------------------------------------ |
| `0x00000000` | Disables secure desktop prompting — prompts appear on the interactive desktop. |
| `0x00000001` | Forces all UAC prompts to occur on the secure desktop.                         |

Value: `EnableVirtualization`

| Value        | Meaning                                                                                       |
| ------------ | --------------------------------------------------------------------------------------------- |
| `0x00000000` | Disables data redirection for interactive processes.                                          |
| `0x00000001` | Enables file and registry redirection for legacy apps to allow writes in user-writable paths. |

> https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/12867da0-2e4e-4a4f-9dc4-84a7f354c8d9  
> https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration?tabs=reg

# Lock Screen

Disables the lock screen (skips the lock screen and go directly to the login screen). Revert it by removing the value (2nd command).

__Miscellaneous (`ControlPanelDisplay.admx`):__
Prevent lock screen background motion:
```bat
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v AnimateLockScreenBackground /t REG_DWORD /d 1 /f
```
Prevent enabling lock screen slide show:
```bat
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v NoLockScreenSlideshow /t REG_DWORD /d 1 /f
```
Show clear logon background:
```bat
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v DisableAcrylicBackgroundOnLogon /t REG_DWORD /d 1 /f
```

# Enable Game Mode

Game Mode should: "Prevents Windows Update from performing driver installations and sending restart notifications" Does it work? Not really, in my experience it tends to lower the priority and prevent driver updates (correct me if you've experienced otherwise) - It may also mess with process/thread priorities. Not all games support it, generally leave it enabled or benchmark the differences in equal scenarios.

It might set CPU affinites (`AffinitizeToExclusiveCpus`, `CpuExclusivityMaskHig`, `CpuExclusivityMaskLow`) for the game process and the maximum amount of cores the game uses (`MaxCpuCount`). The percentage of GPU memory (`PercentGpuMemoryAllocatedToGame`), GPU time (`PercentGpuTimeAllocatedToGame`) & system compositor (`PercentGpuMemoryAllocatedToSystemCompositor`) that will be dedicated to the game. It may also create a list of processes (`RelatedProcessNames`) that are gaming related, which means that they won't be affected from the game mode. These are just assumptions, I haven't looked into it in detail yet (`GamingHandlers.c`).

Disable game mode:
```bat
reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 0 /f
```
Enable game mode (switch on/off):
```bat
reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f
```
Enabling/disabling it via the system settings only switches `AutoGameModeEnabled`:
```ps
SystemSettings.exe  HKCU\Software\Microsoft\GameBar\AutoGameModeEnabled	Type: REG_DWORD, Length: 4, Data: 1
```
The value doesn't exist by default (not existing = `1`). Ignore `GameBar.txt`, it shows read values.

> [system/assets | gamemode-GamingHandlers.c](https://github.com/5Noxi/win-config/blob/main/system/assets/gamemode-GamingHandlers.c)  
> https://support.xbox.com/en-US/help/games-apps/game-setup-and-play/use-game-mode-gaming-on-pc  
> https://learn.microsoft.com/en-us/uwp/api/windows.gaming.preview.gamesenumeration?view=winrt-26100

---

Miscellaneous notes:
```ps
\Registry\User\S-ID\SOFTWARE\Microsoft\GameBar : GamepadDoublePressIntervalMs
\Registry\User\S-ID\SOFTWARE\Microsoft\GameBar : GamepadShortPressIntervalMs
```

# Disable Search Indexing

It builds a database of file names, properties, and contents to speed up searches, runs as `SearchIndexer.exe`, updates automatically. Disabling it slows down searches, but as shows below you should use everything anyway. Additionally you can disable content and property indexing per drive, by right clicking on the drive, then unticking the box as shown in the picture.

> https://learn.microsoft.com/en-us/windows/win32/search/-search-indexing-process-overview

![](https://github.com/5Noxi/win-config/blob/main/system/images/searchindex.png?raw=true)

Instead of using the explorer to search for a file or folder, use everything. It's a lot faster:
> https://www.voidtools.com/downloads/

The command below includes some of my personal settings. They're saved in:
```
%appdata%\Everything\Everything.ini
```
If you want to revert the changes, either remove the `Everything.ini` file or restore the settings via the options (`STRG + P`).
```ps
$nvp = "$env:appdata\Everything\Everything.ini";(gc $nvp) -replace '^normal_background_color=.*', 'normal_background_color=#353535' -replace '^normal_foreground_color=.*', 'normal_foreground_color=#ffffff' -replace '^single_click_open=.*', 'single_click_open=2' -replace '^hide_empty_search_results=.*', 'hide_empty_search_results=1' -replace '^double_click_path=.*', 'double_click_path=1' -replace '^show_mouseover=.*', 'show_mouseover=1' -replace '^show_number_of_results_with_selection=.*', 'show_number_of_results_with_selection=1' -replace '^tooltips=.*', 'tooltips=0' -replace '^search_history_enabled=.*', 'search_history_enabled=0' -replace '^run_history_enabled=.*', 'run_history_enabled=0' -replace '^index_date_modified=.*', 'index_date_modified=0' -replace '^exclude_list_enabled=.*', 'exclude_list_enabled=0' -replace '^language=.*', 'language=1033' | sc $nvp
```

The `WSearch` service is needed for CmdPals `File Search` extension to work.

# Enable HAGS

HAGS feature is introducedspecifically for the WDDM. If disables the CPU manages the GPU scheduling via a high-priority kernel thread, GPU context switches and task scheduling are handled by the CPU (CPU offloads graphics intensive tasks to the GPU for rendering). If enabled the GPU handles its own scheduling using a built in scheduler processor, context switching between GPU tasks is done directly on the GPU. It is especially beneficial, if you've a slow CPU, or if the CPU is heavily loaded with other tasks. 
"It depends on your hardware, if you want HAGS to be enabled or not. E.g if using a old GPU, it may not fully support the new scheduler."

HAGS should be enabled, there're many reasons like different threads... may add more information here soon.

> https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/
> https://maxcloudon.com/hardware-accelerated-gpu-scheduling/

# Remove Windows.old

Removes old/previous windows installation files from `Windows.old`.

```
Ten days after you upgrade to Windows, your previous version of Windows will be automatically deleted from your PC. However, if you need to free up drive space, and you’re confident that your files and settings are where you want them to be in Windows, you can safely delete it yourself.

If it’s been fewer than 10 days since you upgraded to Windows, your previous version of Windows will be listed as a system file you can delete. You can delete it, but keep in mind that you'll be deleting your Windows.old folder, which contains files that give you the option to go back to your previous version of Windows. If you delete your previous version of Windows, this can't be undone (you won't be able to go back to your previous version of Windows).
```
> https://support.microsoft.com/en-us/windows/delete-your-previous-version-of-windows-f8b26680-e083-c710-b757-7567d69dbb74

# Disable Storage Sense

Storage Sense deletes temporary files automatically - revert it by changing it back to `1`.

![](https://github.com/5Noxi/win-config/blob/main/system/images/storagesen1.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/system/images/storagesen2.png?raw=true)