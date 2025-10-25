# Win32PrioritySeparation

"The value of this entry determines, in part, how much processor time the threads of a process receive each time they are scheduled, and how much the allotted time can vary. It also affects the relative priority of the threads of foreground and background processes. The value of this entry is a 6-bit bitmask consisting of three sets of two bits (AABBCC). Each set of two bits determines a different characteristic of the optimizing strategy.
- The highest two bits (AABBCC) determine whether each processor interval is relatively long or short.
- The middle two bits (AABBCC) determine whether the length of the interval varies or is fixed.
- The lowest two bits (AABBCC) determine whether the threads of foreground processes get more processor time than the threads of background processes each time they run."

Read trough the `.pdf` file, if you want to get more information about the bitmask. Calculate it yourself with <#1371478333585363034>.

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

![](https://github.com/5Noxi/win-config/blob/main/network/images/w32ps.png?raw=true)

> [network/assets | Win32PrioritySeparation.pdf](https://github.com/5Noxi/win-config/blob/main/network/assets/Win32PrioritySeparation.pdf)

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
```json
{
  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": {
    "ValidateAdminCodeSignatures": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "ConsentPromptBehaviorAdmin": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "ConsentPromptBehaviorUser": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "PromptOnSecureDesktop": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "EnableLUA": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  }
}
```

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
```json
{
  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization": {
    "NoLockScreen": {
      "Type": "REG_DWORD",
      "Data": 1
    }
  }
}
```