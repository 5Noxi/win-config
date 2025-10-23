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
{"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System":{"ValidateAdminCodeSignatures":{"Type":"REG_DWORD","Data":0},"ConsentPromptBehaviorAdmin":{"Type":"REG_DWORD","Data":0},"ConsentPromptBehaviorUser":{"Type":"REG_DWORD","Data":0},"PromptOnSecureDesktop":{"Type":"REG_DWORD","Data":0},"EnableLUA":{"Type":"REG_DWORD","Data":0}}}
```