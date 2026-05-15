# Quantum/Priority Separation

A quantum is the amount of time a thread is permitted to run before Windows checks to see whether another thread at the same priority is waiting to run. If a thread completes its quantum and there are no other threads at its priority, Windows permits the thread to run for another quantum.

You can calculate the clock cycles per quantum by dumping the value of `KiCyclesPerClockQuantum` (`dd nt!KiCyclesPerClockQuantum L1`), or follow the 'EXPERIMENT: Determining the clock cycles per quantum' in [Windows Internals E7, P1](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf).

Gets applied with:
```c
PsChangeQuantumTable(0, PsRawPrioritySeparation);
```

Only the first 6 bits are used (`PsChangeQuantumTable` = `a2 & 3` (bit 0/1), `a2 & 0xC` (bit 2/3), `a2 & 0x30` (bit 4/5)).

Client defaults are short + variable. Server defaults are long + fixed.

## Bits 0/1

For each extra priority level (up to 2), another quantum is given to the thread. For example, if the thread receives a boost of one priority level, it receives an extra quantum as well. By default, Windows sets the maximum possible priority boost to foreground threads, meaning that the priority separation will be 2, which means quantum index 2 is selected in the variable quantum table. This leads to the thread receiving two extra quantums, for a total of three quantums.

Clamped to `2`:
```c
v3 = a2 & 3;
if ( v3 >= 2 )
  v3 = 2;
PsPrioritySeparation = v3;
```

`00` = `0`: no foreground quantum advantage, foreground priority adds `+0` in boost part ("*The threads of foreground processes get the same amount of processor time as the threads of background processes and as the threads of processes with a priority class of Idle.*")  
`01` = `1`: foreground priority adds `+1` ("*2:1. The threads of foreground processes get twice the processor time as the threads of background processes each time they are scheduled for the processor.*")  
`10` = `2`: foreground priority adds `+2` ("*3:1. The threads of foreground processes get three times the processor time as the threads of background processes each time they are scheduled for the processor.*")  
`11` = `2`: same behavior as `10` because of the clamp.

### Watching the Boost

This follows the 'EXPERIMENT: Watching foreground priority boosts and decays' guide of [Windows Internals E7, P1](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf).

1. Download [CPUSTRES](https://live.sysinternals.com/CPUSTRES.EXE)
2. Set bits 1/0 to the state you want to look at, in this test we will use `PsPrioritySeparation` = `2` (means bit `10`/`11`)
3. Open CPUSTRES & `perfmon`, change activity lebel of first thread to '*Busy*'
4. Open '*Performance Monitor*' tab in perfmon
5. Right click on the graph -> `Add Counters` -> `Thread` -> `Priority Current`
6. Select `<All instances>` in the combobox, click '*Search*'
7. Select `CPUSTRES/1` (`CPUSTRES/0` = GUI thread) -> '*Add*' -> '*OK*'
8. Right click graph -> Properties -> Graph -> Verical scale maximum to `16`
9. Unselect `Processor Time` counter, move CPUSTRES to FG/BG

By doing so you'll see that `PsPrioritySeparation` = `2` causes the priority of the first thread to get boosted by `2`:

![](https://github.com/nohuto/win-config/blob/main/system/images/PsPrioritySeparation2.png?raw=true)

If doing the same but with `PsPrioritySeparation` = `0` (e.g. `Win32PrioritySeparation` = `0x18`), the priority will stay the same (doesn't get a boost when being moved to FG):

![](https://github.com/nohuto/win-config/blob/main/system/images/PsPrioritySeparation0.png?raw=true)

## Bits 2/3

Determine whether the length of processor time varies or is fixed. It also determines whether the threads of foreground processes have longer processor intervals than those of background processes. If the processor interval is fixed, that interval applies equally to the threads of foreground and background processes. If the processor interval varies, the length of time each thread runs varies, but the ratio of processor time of foreground threads to background threads is fixed.

If a variable interval is specified, the ratio of foreground thread processor time to background thread processor time is determined by the value of the lowest set of bits.

```c
v5 = a2 & 0xC;
if ( (a2 & 0xC) != 0 )
{
  if ( v5 == 4 ) // 01
  {
    v8 = (char *)&PspVariableQuantums;
    goto LABEL_7;
  }
  if ( v5 == 8 ) // 10
  {
    v8 = PspFixedQuantums;
    goto LABEL_7;
  }
}
IsThisAnNtAsSystem = MmIsThisAnNtAsSystem();
v7 = (__int64 *)PspFixedQuantums;
if ( !IsThisAnNtAsSystem )
  v7 = &PspVariableQuantums;
v8 = (char *)v7;
```

`00` (`0x0`): server selects fixed table, client selects variable table.  
`01` (`0x4`): forces PspVariableQuantums.  
`10` (`0x8`): forces PspFixedQuantums.  
`11` (`0xC`): same as `00`.

## Bits 4/5

Determine how long the threads of processes are permitted to run each time they are scheduled. This interval is specified as a range because threads can be preempted and processor time is not precisely determined.

```c
LABEL_7:
  v9 = a2 & 0x30;
  if ( !v9 )
  {
LABEL_8:
    if ( !MmIsThisAnNtAsSystem() )
      goto LABEL_9;
    goto LABEL_22;
  }
  if ( v9 != 16 )
  {
    if ( v9 == 32 )
      goto LABEL_9;
    goto LABEL_8;
  }
LABEL_22:
  v8 += 3;
LABEL_9:
  PspForegroundQuantum = *(_WORD *)v8;
  result = v8[2];
```

`00` (`0x0`): server `goto LABEL_22` (longer intervals), client `goto LABEL_9` (shorter intervals).  
`01` (`0x10`): longer intervals.  
`10` (`0x20`): goes directly to `LABEL_9` = shorter intervals.  
`11` (`0x30`): falls to `LABEL_8`, so same behavior as `00`.

Note that everything above is based on 23H2 and is not complete yet.

I won't add much more details here since [Windows Internals E7, P1](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf) contains details, see 'Quantum / Priority Boosts' (Chapter 3).

- [ntoskrnl/PsChangeQuantumTable.c](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/PsChangeQuantumTable.c)
- [ntoskrnl/PspComputeQuantum.c](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/PspComputeQuantum.c)
- [ntoskrnl/PspInitPhase0.c](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/PspInitPhase0.c)
- [ntoskrnl/MmIsThisAnNtAsSystem.c](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/MmIsThisAnNtAsSystem.c)
- [ntoskrnl/KeSetQuantumProcess.c](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/KeSetQuantumProcess.c)
- [ntoskrnl/KeStartThread.c](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/KeStartThread.c)
- [ntoskrnl/KiSetQuantumTargetThread.c](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/KiSetQuantumTargetThread.c)
- [ntoskrnl/KiInitializeForegroundBoostThread.c](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/KiInitializeForegroundBoostThread.c)
- [ntoskrnl/NtSetSystemInformation.c](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/KiComputeEffectivePriority.c)
- [ntoskrnl/NtSetSystemInformation.c](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/NtSetSystemInformation.c)
- [ntoskrnl/CmInitSystem0.c](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/CmInitSystem0.c)
- [ntoskrnl/CmpGetSystemControlValues.c](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/CmpGetSystemControlValues.c)

---

Miscellaneous notes:
```c
// from procmon boot trace
"HKLM\\System\\CurrentControlSet\\Control\\PriorityControl";
    "ConvertibilityEnabled" = ?;
    "ConvertibleSlateMode" = 0; // REG_DWORD
    "SystemDockMode" = ?;
    "Win32PrioritySeparation" = 2;
```

# Game Mode

Game Mode is a RM (Resource Manager) feature for a foreground process that Windows identifies as a game through `expandedResources` (or GCS data). Note that everything below is based on pseudocode (from 23H2, things might've changed in newer builds, see [bin-diff](https://www.noverse.dev/bin-diff.html)) and interpretations, this isn't official documentation just a personal attempt to document how Game Mode works, mistakes may exist and feel free to correct me. I don't claim that anything below is correct nor complete, that's just how I understood the sequence of Game Mode initialization + (un)registration. I've tried to link all functions that I used, for anyone who wants to take a look for themselves.

It can apply CPU set policy, GPU scheduler/budget policy, optional process priority, optional Game Mode power profile notification, global Game Mode active state, optional expanded resource extension notification. The global state is updated through `WNF_RM_GAME_MODE_ACTIVE` (`RM` prefix in `WNF_RM_GAME_MODE_ACTIVE` = '*Game Mode Resource Manager*').

This means that we can check the game mode state via `WNF_RM_GAME_MODE_ACTIVE`. `PsmServiceExtHost.dll` writes this state from [`RmpSystemPublishGlobalGameModeState`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpSystemPublishGlobalGameModeState@@YAXK@Z.c). The public [`HasExpandedResources`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/gamemode/HasExpandedResources.c) API reads the same state and returns true only when the value equals the current PID.

Note that you don't have to restart your PC/game when going from disabled to enabled (since it registers the PID when game gets in FG), but you need to restart the game when going from enabled to disabled (since the PID stays registered, which is why restarting the game is enough as that causes the PID to change).

```c
// RmpSystemPublishGlobalGameModeState
v3 = a1; // active Game Mode PID or 0 when no process is active (GameModeActivePid=0 in gm_effects)
if ( (int)RtlPublishWnfStateData(WNF_RM_GAME_MODE_ACTIVE, 0LL, &v3, 4LL, 0LL) < 0
```

```c
// HasExpandedResources
if ( (int)NtQueryWnfStateData(&WNF_RM_GAME_MODE_ACTIVE, 0LL, 0LL, &v6, &v4, &v5) >= 0 )
{
  LOBYTE(v1) = GetCurrentProcessId() == v4; // true only for the active Game Mode PID
  *hasExpandedResources = v1;
}
```

## gm_effects

I've created [`gm_effects.exe`](https://github.com/nohuto/win-config/blob/main/system/assets/gm_effects.exe), which reads the current foreground PID, active Game Mode PID, process default CPU sets (and CPU set IDs), and the Game Mode power profile WNF low value. You can either use the prebuild binary, or build it yourself from [source](https://github.com/nohuto/win-config/blob/main/system/assets/gm_effects):

```powershell
cmake -S . -B build
cmake --build build --config Release

.\build\Release\gm_effects.exe
```

If you want it to loop faster/slower, change `Sleep(1000)`, it also support a `--pid` argument which lets you track a single PID instead of the current foreground process.

Microsoft also documents behavior that I didn't find in the RM functions, so I guess it's handled somewhere else, such as "Game Mode can suppress Windows Update driver installs and Windows Update restart notifications while a game is running".

## Registry Values

The `AllowAutoGameMode` value gets read by [`EvaluateAppForGameMode`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-EvaluateAppForGameMode@BroadcastDVRComponent@@AEAAXPEAUIApplicationView@@PEAUBroadcastDVRActive.c), but isn't present in the default LGPE policy list ([policies.json](https://raw.githubusercontent.com/nohuto/admx-parser/refs/heads/main/assets/policies.json)). Other registry values are used in [`GetGameModeRequest`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-GetGameModeRequest@BroadcastDVRComponent@@AEAAXW4GameModeReason@@PEAUGameConfigInfo@@PEAU_RM_GA.c) and [`RmpGameModeIsResourceRequestValid`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeIsResourceRequestValid@@YAEPEAU_RM_SERVICE_GLOBALS@@PEAU_RM_GAME_MODE_RESOURCE_REQUE.c).

```c
"HKCU\\Software\\Microsoft\\GameBar";
    "AutoGameModeEnabled" = 1; // missing/nonzero allows registration
    "GpuGameMemoryBudgetPercentage" = 50; // fallback game GPU memory budget percent
    "GpuDwmMemoryBudgetPercentage" = 30; // fallback system compositor GPU memory budget percent
    "GpuYieldPercentage" = 2; // fallback GPU yield percent, range 2-10
    "DisallowSystemAllowedCpuSets" // nonzero disallows system allowed CPU set policy

"HKLM\\Software\\Policies\\Microsoft\\Windows\\GameDVR";
    "AllowAutoGameMode" = 1; // missing/nonzero allows registration, adding this with a value of 0 would hide the Game Mode part in system settings
```

## Game Mode Process

Obviously, this doesn't include every single part, rather I've tried to keep it simple and focus on the main parts.

### 1 - Shell Entry

It starts in `twinui.pcshell.dll`, [`BroadcastDVRComponent::EvaluateAppForGameMode`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-EvaluateAppForGameMode@BroadcastDVRComponent@@AEAAXPEAUIApplicationView@@PEAUBroadcastDVRActive.c) is called if application change, application view change, Game Mode enable change tasks happen.

The application change task calls `EvaluateAppForGameMode` after it has updated the active app information for the changed application view:

```c
// BroadcastDVRComponent::ApplicationChangedTask
BroadcastDVRComponent::EvaluateAppForGameMode((BroadcastDVRComponent *)a1, v7, v13); // v7 = application view, v13 = active app info
```

The application view change task uses the same function when the changed view is already known to the BroadcastDVR component:

```c
// BroadcastDVRComponent::OnApplicationViewChangedGameMode
BroadcastDVRComponent::EvaluateAppForGameMode((BroadcastDVRComponent *)a1, a2, (HWND *)v8); // a2 = application view, v8 = active app info
```

When the user enables Game Mode for the active window, [`OnGameModeEnableChangeTask`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-OnGameModeEnableChangeTask@BroadcastDVRComponent@@AEAAXPEAUHWND__@@_N@Z.c) refreshes the GCS (game config store) state and then calls the same Game Mode check:

```c
// BroadcastDVRComponent::OnGameModeEnableChangeTask
BroadcastDVRComponent::EvaluateAppForGameMode(this, v6, (HWND *)v7); // v6 = application view, v7 = active app info
```

### 2 - Get Values

`EvaluateAppForGameMode` first gets the two values, a missing value passes, `0` blocks registration. Means if you set one of these values to `0`, all steps below won't run.

```c
// BroadcastDVRComponent::EvaluateAppForGameMode

v29 = 0;
if ( (SHRegGetDWORD(
        HKEY_LOCAL_MACHINE,
        L"Software\\Policies\\Microsoft\\Windows\\GameDVR",
        L"AllowAutoGameMode",
        &v29) < 0
    || v29)
&& (SHRegGetDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\GameBar", L"AutoGameModeEnabled", &v29) < 0 || v29) )
```

Note that this is a AND logic (`&&`) so both must either be `1` or not present.

### 3 - Check expandedResources

`EvaluateAppForGameMode` first checks whether the active view has the `expandedResources` capability through [`BroadcastDVRComponent::IsExpandedResources`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-IsExpandedResources@BroadcastDVRComponent@@AEAAJPEAUIApplicationView@@PEA_N@Z.c) (this is separate from the public [`HasExpandedResources`](https://learn.microsoft.com/en-us/windows/win32/api/expandedresources/nf-expandedresources-hasexpandedresources) API in `gamemode.dll`).

If `expandedResources` is present, it continues with Game Mode reason `5`. If it's not present it calls [`IsGameModeGame`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-IsGameModeGame@BroadcastDVRComponent@@AEAA_NPEAUGameConfigInfo@@PEAW4GameModeReason@@@Z.c), which uses GCS data filled by [`EvaluateIfViewIsGame`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-EvaluateIfViewIsGame@BroadcastDVRComponent@@AEAAXPEAUIApplicationView@@PEAUGameConfigInfo@@PEA_.c). If `IsGameModeGame` returns false, the function exits before process registration, so all steps below won't run again.

```c
// BroadcastDVRComponent::EvaluateAppForGameMode
IsExpandedResources = BroadcastDVRComponent::IsExpandedResources(v6, a2, &v27); // v27 = has expandedResources
v12 = v27 ? 5 : 0; // reason 5
if ( !v27 ) // fallback to GCS
{
  if ( !BroadcastDVRComponent::IsGameModeGame(v11, v7, (enum GameModeReason *)&v30) )
    return; // not a Game Mode game
  v12 = (unsigned int)v30; // Game Mode reason returned by IsGameModeGame
}
```

### 4 - Resolve the Process

It converts the active HWND (window handle) to a PID with [`GetWindowThreadProcessId`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowthreadprocessid). If the same PID is already registered, it doesn't register the primary process again.

For a new PID, it opens the process with [`PROCESS_QUERY_LIMITED_INFORMATION`](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) ("*Required to retrieve certain information about a process (see [GetExitCodeProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess), [GetPriorityClass](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getpriorityclass), [IsProcessInJob](https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob), [QueryFullProcessImageName](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamea))*"). If the active view is a WinRT (Windows Runtime) application, it reads the process image name and skips `applicationframehost.exe` since that's the UWP frame host.

```c
// BroadcastDVRComponent::EvaluateAppForGameMode
if ( v8 )
  v9 = v8; // v9 = HWND
GetWindowThreadProcessId(v9, &v28); // v28 = active process ID
if ( v28 )
{
  if ( v28 == *((_DWORD *)this + 114) ) // already registered primary PID
  {
    BroadcastDVRComponent::GetNonServiceProcessListAndIds(this, &v33);
    BroadcastDVRComponent::ApplyGameRelatedForGameModeProcess((__int64)this, v28, &v33);
    BroadcastDVRComponent::TelemetryLogProcessesLaunchedAfterGame(v15, &v35);
    return;
  }
}
```

```c
// BroadcastDVRComponent::EvaluateAppForGameMode
hProcess = 0LL;
v18 = OpenProcess(0x1000u, 0, v28); // 0x1000 = PROCESS_QUERY_LIMITED_INFORMATION, v28 = PID
wil::details::unique_storage<wil::details::handle_null_resource_policy<int (*)(void *),&int CloseHandle(void *)>>::reset(&hProcess, v18);
v20 = (char *)hProcess; // process handle used below
```

```c
// BroadcastDVRComponent::EvaluateAppForGameMode
if ( a2 )
{
  if ( (int)Microsoft::WRL::ComPtr<IApplicationView>::As<IWinRTApplicationView>(&v30, (__int64)&v31) >= 0 )
  {
    if ( K32GetModuleFileNameExW(v20, 0LL, Filename, 0x104u) )
    {
      FileNameW = PathFindFileNameW(Filename);
      if ( CompareStringOrdinal(FileNameW, -1, L"applicationframehost.exe", -1, 1) == 2 )
        goto LABEL_28; // skip the UWP frame host process
    }
  }
}
```

### 5 - Build the Request

It initializes a RM request, asks the service for the current request limits, then adds GCS and registry values in [`GetGameModeRequest`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-GetGameModeRequest@BroadcastDVRComponent@@AEAAXW4GameModeReason@@PEAUGameConfigInfo@@PEAU_RM_GA.c).

```c
// BroadcastDVRComponent::EvaluateAppForGameMode
v35 = 0LL;
v36 = 0LL;
v37 = 0LL;
RmGameModeInitializeResourceRequest(&v35); // v35 = resource request buffer
LargestValidResourceRequest = RmGameModeGetLargestValidResourceRequest(&v35);
if ( LargestValidResourceRequest < 0 )
{
  wil::details::in1diag3::_Log_Hr(
    retaddr,
    (void *)0x825,
    (int)"pcshell\\twinui\\broadcastdvrcomponent\\lib\\broadcastdvrprovider.cpp",
    (const char *)(LargestValidResourceRequest | 0x10000000u));
  goto LABEL_28;
}
BroadcastDVRComponent::GetGameModeRequest(this, v12, v7, &v35);
v23 = RmGameModeRegisterProcess(v20, &v35, 0LL);
```

In `rmclient.dll`, [`RmGameModeRegisterProcess`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/rmclient/RmGameModeRegisterProcess.c) sends the process handle and Game Mode request to the RM service through RPC.

```c
// RmGameModeRegisterProcess
if ( (int)sub_180005FC0(&unk_180022A10, Binding) >= 0 )
{
  v6 = 1;
  v10 = a3;
  v8.Pointer = NdrClientCall3((MIDL_STUBLESS_PROXY_INFO *)&stru_180020F80, 0, 0LL, Binding[0], a1, a2, v10).Pointer;
  Pointer = (unsigned int)v8.Pointer;
  Binding[1] = v8.Pointer;
  if ( SLODWORD(v8.Simple) >= 0 )
    Pointer = 0;
}
```

### 6 - Set Defaults

[`RmGameModeInitializeResourceRequest`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/rmclient/RmGameModeInitializeResourceRequest.c) writes the default values into the request.

```c
// RmGameModeInitializeResourceRequest
__int64 __fastcall RmGameModeInitializeResourceRequest(__int64 a1)
{
  __int64 result; // rax

  result = 0LL;
  *(_OWORD *)a1 = 0LL;
  *(_OWORD *)(a1 + 16) = 0LL;
  *(_QWORD *)(a1 + 32) = 0LL;
  *(_DWORD *)a1 = 6; // request version
  *(_DWORD *)(a1 + 16) = 10; // GPU yield percentage
  *(_DWORD *)(a1 + 20) = 50; // game GPU memory budget
  *(_DWORD *)(a1 + 24) = 30; // system compositor GPU memory budget
  return result;
}
```

### 7 - Validate in the Service

[`RmSrvGameModeRegisterProcess`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmSrvGameModeRegisterProcess@@YAJPEAU_RM_SERVICE_GLOBALS@@PEAXPEAU_RM_GAME_MODE_RESOURCE_REQUES.c) receives the registration request inside the service, it validates the request in [`RmpGameModeIsResourceRequestValid`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeIsResourceRequestValid@@YAEPEAU_RM_SERVICE_GLOBALS@@PEAU_RM_GAME_MODE_RESOURCE_REQUE.c), then calls [`RmpGameModeRegisterProcess`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeRegisterProcess@@YAJPEAU_RM_GAME_MODE_CONTEXT@@PEAXPEAU_RM_GAME_MODE_RESOURCE_REQUES.c).

- Request version must be `6`
- GPU yield must be `2-10`
- Game and system compositor memory percentages must total `<= 100`
- Priority class may be unset or one of `2`, `3`, `6`

```c
// RmSrvGameModeRegisterProcess
if ( a4 )
{
  v8 = -1073741583;
}
else if ( RmpGameModeIsResourceRequestValid(v4, a3) ) // a3 = Game Mode request
{
  v8 = RmpGameModeRegisterProcess((struct _RM_SERVICE_GLOBALS *)((char *)v4 + 2096), a2, a3); // a2 = process handle
  if ( v8 >= 0 )
    v8 = 0;
}
else
{
  v8 = -1073741584; // invalid request
}
```

The validator has two parts, the first part accepts a default request only when the CPU allocation fields are empty and the graphics values still match the base defaults, the second part checks the normal limits for CPU count, CPU set mask, priority class, GPU yield, and GPU memory budgets.

```c
// RmpGameModeIsResourceRequestValid
if ( *(_DWORD *)a2 == 6 ) // request version
{
  v6 = *((_DWORD *)a2 + 8) & 5; // selects which request form is being validated
  if ( v6 != 4
    && (v6 != 1
     || !*((_DWORD *)a2 + 1) // cannot carry an CPU count
     && !*((_QWORD *)a2 + 1) // cannot carry an CPU set mask
     && *((_DWORD *)a2 + 4) == 10 // GPU yield must stay at default
     && *((_DWORD *)a2 + 5) == 50 // game GPU memory budget must stay at default
     && *((_DWORD *)a2 + 6) == 30 // system compositor GPU memory budget must stay at default
     && (*((_BYTE *)a2 + 32) & 8) == 0) ) // graphics priority cant be set
  {
    v7 = RtlNumberOfSetBitsUlongPtr(*((_QWORD *)a2 + 1), a2, a3, a4); // number of CPUs in the CPU set mask
    v8 = *((_DWORD *)a2 + 1); // requested exclusive CPU count
    if ( v8 >= v7
      && v8 <= 0x40
      && RmpCpuSetManagerIsGameModeRequestSatisfiable(
           (struct _RM_SERVICE_GLOBALS *)((char *)a1 + 680),
           (*((_DWORD *)a2 + 7) & 0x40) != 0, // CPU count increase
           v8,
           *((_QWORD *)a2 + 1)) // CPU set mask
      && (!*((_BYTE *)a2 + 36) || *((_BYTE *)a2 + 36) == 2 || *((_BYTE *)a2 + 36) == 3 || *((_BYTE *)a2 + 36) == 6) // priority class
      && (unsigned int)(*((_DWORD *)a2 + 4) - 2) <= 8 // GPU yield range = 2-10
      && (unsigned int)(*((_DWORD *)a2 + 5) + *((_DWORD *)a2 + 6)) <= 0x64 // GPU memory budgets = total 100 or less
      && (*((_BYTE *)a2 + 28) & 0x18) != 0x18 )
    {
      return 1;
    }
  }
}
```

### 8 - Create Process State

After validation [`RmpGameModeRegisterProcess`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeRegisterProcess@@YAJPEAU_RM_GAME_MODE_CONTEXT@@PEAXPEAU_RM_GAME_MODE_RESOURCE_REQUES.c) turns the request into a service managed process state. The request is copied by [`RmpGameModeInitializeRecipientProcess`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeInitializeRecipientProcess@@YAXPEAU_RM_GAME_MODE_CONTEXT@@PEAU_RM_GAME_MODE_RESOURCE.c), then [`RmpGameModeFindProcessOrCompleteInsertion`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeFindProcessOrCompleteInsertion@@YAJPEAU_RM_GAME_MODE_CONTEXT@@PEAXPEAU_RM_GAME_MODE_.c) checks whether that PID is already known to the service.

If it's a new PID, [`RmpGameModeAllocateObjectsForRecipientProcess`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeAllocateObjectsForRecipientProcess@@YAJPEAU_RM_GAME_MODE_RECIPIENT_PROCESS@@PEAX@Z.c) prepares the service state for it, it creates the process exit wait object, opens its own process handle and stores the PID. [`RmpGameModeInsertRecipientProcess`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeInsertRecipientProcess@@YAXPEAU_RM_GAME_MODE_RECIPIENT_PROCESS@@@Z.c) then adds that process state to the Game Mode context, starts the exit wait, and queues the policy worker.

### 9 - Apply Resource Policies

[`RmpGameModePolicyWorker`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModePolicyWorker@@YAXPEAU_TP_CALLBACK_INSTANCE@@PEAXPEAU_TP_WORK@@@Z.c) applies Game Mode policy. For newly registered processes it can acquire global resources (`RmpGameModeAcquireGlobalResources`), apply per process policies (`RmpGameModeApplyNewRecipientPolicies`), apply global policies (`RmpGameModeApplyGlobalPolicies`), release unused global resources (`RmpGameModeReleaseUnusedGlobalResources`).

```c
// RmpGameModePolicyWorker
if ( v14 )
  RmpGameModeNotifyExtensionRecipientsPresent((struct _RM_GAME_MODE_CONTEXT *)a2, v14 != 0);
if ( v47.Flink != &v47 ) // v47 = list of processes that need policy work
{
  RmpGameModeAcquireGlobalResources((struct _RM_GAME_MODE_CONTEXT *)a2, &v47);
  RmpGameModeApplyNewRecipientPolicies((struct _RM_GAME_MODE_CONTEXT *)a2, &v47);
  RmpGameModeApplyGlobalPolicies((struct _RM_GAME_MODE_CONTEXT *)a2);
  RmpGameModeReleaseUnusedGlobalResources((struct _RM_GAME_MODE_CONTEXT *)a2);
}
```

```c
// RmpGameModeApplyNewRecipientPolicies
while ( a2->Flink != a2 ) // a2 = list of processes waiting for policy application
{
  v4 = CempListRemoveHeadAndClear(a2); // remove one process from the work list
  RmpGameModeAcquireAndApplyRecipientResources(a1, (struct _RM_GAME_MODE_RECIPIENT_PROCESS *)(v4 - 11)); // run the policy table for that process
  *((_BYTE *)v4 + 83) &= ~1u;
  v5 = (char *)a1 + 16 * *((int *)v4 + 4) + 88;
```

[`RmpGameModeAcquireAndApplyRecipientResources`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeAcquireAndApplyRecipientResources@@YAXPEAU_RM_GAME_MODE_CONTEXT@@PEAU_RM_GAME_MODE_R.c) uses five resource policy entries and calls the apply function for each active entry. 

More detail about them in [CPU set policy](https://www.noverse.dev/docs/win-config/system/game-mode/#cpu-sets), [GPU policy](https://www.noverse.dev/docs/win-config/system/game-mode/#gpu-scheduler--gpu-memory-budget), [power profile state](https://www.noverse.dev/docs/win-config/system/game-mode/#game-mode-power-profile-wnf-state), [process priority](https://www.noverse.dev/docs/win-config/system/game-mode/#process-priority-class), [extension state](https://www.noverse.dev/docs/win-config/system/game-mode/#expanded-resource-extension-notification).

```c
// RmpGameModeAcquireAndApplyRecipientResources
v2 = 0;
v3 = off_1800B40C0; // Game Mode resource policies
for ( i = 0; i < 5; ++i )
{
  v7 = 1 << i; // one bit per policy entry
  if ( *((_BYTE *)v3 + 33) )
    goto LABEL_11;
  if ( !*v3 )
    goto LABEL_10;
  if ( *((_BYTE *)v3 + 32) )
  {
    if ( (v7 & *((_DWORD *)a1 + 32)) == 0 )
      goto LABEL_11;
    goto LABEL_10;
  }
  v8 = (*v3)(a1, a2); // apply one policy entry to process
  if ( v8 >= 0 && v8 != 255 )
  {
    *((_DWORD *)a2 + 40) |= v7; // remember that policy was applied
LABEL_10:
    v2 |= v7; // remember that policy was handled in this pass
  }
LABEL_11:
  v3 += 5;
}
```

### 10 - Register Related Processes

After primary registration, `twinui.pcshell.dll` stores the registered PID, gets the current non service process list and calls [`ApplyGameRelatedForGameModeProcess`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-ApplyGameRelatedForGameModeProcess@BroadcastDVRComponent@@AEAAXKAEBV-$vector@U-$pair@KVString@I.c). It asks the game manager for related process names, compares process image names, and calls [`ApplyGameRelatedForRelatedProcess`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-ApplyGameRelatedForRelatedProcess@BroadcastDVRComponent@@AEAAXKGK@Z.c) for matches.

See more detail in [Related Processes](https://www.noverse.dev/docs/win-config/system/game-mode/#related-processes).

```c
// BroadcastDVRComponent::EvaluateAppForGameMode
*((_DWORD *)this + 114) = v28; // remember primary PID
v33 = 0LL;
v34 = 0LL;
BroadcastDVRComponent::GetNonServiceProcessListAndIds(this, &v33);
BroadcastDVRComponent::ApplyGameRelatedForGameModeProcess((__int64)this, v28, &v33); // register matching related processes
std::vector<Windows::Internal::String>::clear((char *)this + 352);
BroadcastDVRComponent::GetSortedUniqueProcessList(v25, &v33, (char *)this + 352);
BroadcastDVRComponent::TelemetryLogProcessesLaunchedWithGame(v26, (char *)this + 352);
```

### 11 - Pair Auxiliary Processes

Related processes are paired with the primary process through `RmGameModeRegisterPairedAuxiliaryProcess`, they're matched by process image name against the related process list returned by the GCS/game manager.

### 12 - End by Toggle Disable

When Game Mode is disabled for the active HWND/PID, [`OnGameModeEnableChangeTask`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-OnGameModeEnableChangeTask@BroadcastDVRComponent@@AEAAXPEAUHWND__@@_N@Z.c) calls `RmGameModeDisableForRegisteredProcess`, then `RmGameModeUnregisterProcess`.

```c
// BroadcastDVRComponent::OnGameModeEnableChangeTask
v14 = RmGameModeDisableForRegisteredProcess(pv); // disable Game Mode policy
if ( v14 < 0 )
  goto LABEL_26;
v14 = RmGameModeUnregisterProcess(v13); // remove process
```

### 13 - End by Process Exit or Focus Change

The service also watches process lifetime with a threadpool wait. When the process terminates, paired auxiliary processes are cleared and the process is removed from Game Mode service state ([`RmpGameModeRecipientProcessTerminationCallback`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeRecipientProcessTerminationCallback@@YAXPEAU_TP_CALLBACK_INSTANCE@@PEAXPEAU_TP_WAIT@.c)). Input focus changes queue the same policy worker so the active Game Mode state can move to another registered primary process ([`RmpSystemNotificationInputFocusChangeCallback`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpSystemNotificationInputFocusChangeCallback@@YAJU_WNF_STATE_NAME@@KPEAU_WNF_TYPE_ID@@PEAXPEBX.c)).

This can be validated using [`gm_effects`](https://www.noverse.dev/docs/win-config/system/game-mode#gm_effects) with the `--pid` argument, so you enable Game Mode, start the game, use `--pid` with the PID of the game, move the game to FG/BG. By doing so you'll see that the state changes.

```ini
; not in FG
Timestamp=20:47:10.665
FGPid=3996
GameModeActivePid=0
PowerProfileLowValue=1
TargetPid=9968
ProcessImage=Overwatch.exe
ProcessPath=C:\Program Files (x86)\Steam\steamapps\common\Overwatch\Overwatch.exe
DefaultCpuSetCount=0

; in FG
Timestamp=20:47:11.668
FGPid=9968
GameModeActivePid=9968
ProcessImage=Overwatch.exe
ProcessPath=C:\Program Files (x86)\Steam\steamapps\common\Overwatch\Overwatch.exe
DefaultCpuSetCount=0
PowerProfileLowValue=3
TargetPid=9968
ProcessImage=Overwatch.exe
ProcessPath=C:\Program Files (x86)\Steam\steamapps\common\Overwatch\Overwatch.exe
DefaultCpuSetCount=0

Timestamp=20:47:12.670
FGPid=9968
GameModeActivePid=9968
ProcessImage=Overwatch.exe
ProcessPath=C:\Program Files (x86)\Steam\steamapps\common\Overwatch\Overwatch.exe
DefaultCpuSetCount=0
PowerProfileLowValue=3
TargetPid=9968
ProcessImage=Overwatch.exe
ProcessPath=C:\Program Files (x86)\Steam\steamapps\common\Overwatch\Overwatch.exe
DefaultCpuSetCount=0

; not in FG
Timestamp=20:47:13.685
FGPid=3372
GameModeActivePid=0
PowerProfileLowValue=1
TargetPid=9968
ProcessImage=Overwatch.exe
ProcessPath=C:\Program Files (x86)\Steam\steamapps\common\Overwatch\Overwatch.exe
DefaultCpuSetCount=0
```

## Effect Details

### Process Priority Class

Game Mode can temporarily change a registered process priority class if the request priority byte is nonzero (`2`/`6`/`3`, see below).

The request byte is the native `ProcessPriorityClass` value used by `NtSetInformationProcess`.

> "*Each thread has a base priority that is a function of its process priority class and its relative thread priority.*"
>
> "*Scheduling decisions are made based on the current priority.*"
>
> — Microsoft, [Windows Internals E7, P1: Chapter 4, Threads](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

That means a process priority class isn't the final scheduling value by itself. It sets the base priority that the process threads start from, the scheduler then uses each thread's current priority, which can include wait completion boosts, GUI boosts, MMCSS boosts, etc.

| Request byte | Public class | Thread base |
| --- | --- | --- |
| `0` | - | - |
| `2` | `NORMAL_PRIORITY_CLASS` | `8` |
| `6` | `ABOVE_NORMAL_PRIORITY_CLASS` | `10` |
| `3` | `HIGH_PRIORITY_CLASS` | `13` |

The accepted classes stay in the dynamic priority range, they obviously don't enter the real time range.

For the primary game process, [`BroadcastDVRComponent::GetGameModeRequest`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-GetGameModeRequest@BroadcastDVRComponent@@AEAAXW4GameModeReason@@PEAUGameConfigInfo@@PEAU_RM_GA.c) sets priority byte `2`. That means the primary game process is set to normal process priority class by Game Mode unless another component changes it later.

Example with a game that sets itself to real time (there're probably any game devs who do that without thinking about the impact) priority before Game Mode registers it:

1. The game starts as `REALTIME_PRIORITY_CLASS`
2. Game Mode registers the primary game process
3. The service saves the old priority class
4. The service writes `NORMAL_PRIORITY_CLASS`
5. When Game Mode is removed, the service can restore the saved old class

```c
// BroadcastDVRComponent::GetGameModeRequest
*(_BYTE *)(a4 + 36) = 2; // primary game request priority class
```

#### FG Boost with Game Mode

Foreground boost is separate from process priority class, it's a temporary current priority increase for threads that belong to the foreground process. See [quantum-priority-separation/#bits-01](https://www.noverse.dev/docs/win-config/system/quantum-priority-separation/#bits-01) for more details on the topic itself. 

You can test it by following the [watching-the-boost](https://www.noverse.dev/docs/win-config/system/quantum-priority-separation/#watching-the-boost) guide while using the main game thread instead of the first CPUSTRES thread, get the instance name of a TID via e,g,:

```powershell
$TID = # add TID
Get-CimInstance Win32_PerfRawData_PerfProc_Thread | Where-Object { $_.IDThread -eq $TID } | Select-Object Name #, IDProcess, IDThread
```

> "*Whenever a thread in the foreground process completes a wait operation on a kernel object, the kernel boosts its current (not base) priority by the current value of PsPrioritySeparation.*"
>
> "*The windowing system is responsible for determining which process is considered to be in the foreground.*"
>
> — Microsoft, [Windows Internals E7, P1: Chapter 4, Threads](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

I've done it using Overwatch, both times I switched the state between FG/BG:

![](https://github.com/nohuto/win-config/blob/main/system/images/gamemodeprioboost.png?raw=true)

One of my testers replicated it on 25H2 and it doesn't seem to exist there (FG boost works when game mode is enabled). I'll very likely look more into that soon, as the cause of this is probably that Game Mode messes with the FG state means that the windowing system doesn't see the game as FG anymore.

#### Related Processes

[`ApplyGameRelatedForGameModeProcess`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-ApplyGameRelatedForGameModeProcess@BroadcastDVRComponent@@AEAAXKAEBV-$vector@U-$pair@KVString@I.c) compares running process image names against the related process list returned by the GCS/game manager. For matches, [`ApplyGameRelatedForRelatedProcess`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-ApplyGameRelatedForRelatedProcess@BroadcastDVRComponent@@AEAAXKGK@Z.c) builds the related process request. 

Related processes can get the normal, above normal, or high process priority class.

```c
// BroadcastDVRComponent::ApplyGameRelatedForRelatedProcess
if ( (a3 & 4) != 0 )
{
  BYTE4(v20) = 6; // above normal priority
}
else
{
  v14 = 2; // default normal priority
  if ( (a3 & 8) != 0 )
    v14 = 3; // high priority
  BYTE4(v20) = v14;
}
```

### CPU Sets

Game Mode can request CPU set allocation and apply CPU set restrictions and defaults to the registered process. A CPU set ID usually means one logical processor, and a process or thread can be assigned a list of CPU set IDs. Game Mode uses this to give the game a preferred or limited processor selection while moving selected system activity away from those CPU sets.

> "*Game mode tries to kind of steer away the processors from your game so the system itself and all the kernel threads and stuff like that are not going to use some processors, so your game can use those processors exclusively.*"
>
> — Pavel Yosifovich, [Windows Internals](https://youtu.be/h6BXMcRqYhA?t=3251)

> "*You've seen how affinity (sometimes referred to as hard affinity) can limit threads to certain processors, which is always honored by the scheduler. The ideal processor mechanism tries to run threads on their ideal processors (sometimes referred to as soft affinity), generally expecting to have the thread's state be part of the processor's cache. The ideal processor may or may not be used, and it does not prevent the thread from being scheduled on other processors. Both these mechanisms don't work on system-related activity, such as system threads activity. Also, there is no easy way to set hard affinity to all processes on a system in one stroke. Even walking the process would not work. System processes are generally protected from external affinity changes because they require the PROCESS_SET_INFORMATION access right, which is not granted for protected processes.*
> *Windows 10 and Server 2016 introduce a mechanism called CPU sets. These are a form of affinity that you can set for use by the system as a whole (including system threads activity), processes, and even individual threads. For example, a low-latency audio application may want to use a processor exclusively while the rest of the system is diverted to use other processors. CPU sets provide a way to achieve that.*
> *The documented user mode API is somewhat limited at the time of this writing. [GetSystemCpuSetInformation](https://learn.microsoft.com/en-us/windows/win32/procthread/getsystemcpusetinformation) returns an array of [SYSTEM_CPU_SET_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-system_cpu_set_information) that contains data for each CPU set. In the current implementation, a CPU set is equivalent to a single CPU. This means the returned array's length is the number of logical processors on the system. Each CPU set is identified by its ID, which is arbitrarily selected to be 256 (0x100) plus the CPU index (0, 1, ...). These IDs are the ones that must be passed to [SetProcessDefaultCpuSets](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessdefaultcpusets) and [SetThreadSelectedCpuSets](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadselectedcpusets) functions to set default CPU sets for a process and a CPU set for a specific thread, respectively. An example for setting thread CPU set would be for an "important" thread that should not be interrupted if possible. This thread could have a CPU set that contains one CPU, while setting the default process CPU set to include all other CPUs. One missing function in the Windows API is the ability to reduce the system CPU set. This can be achieved by a call to the [NtSetSystemInformation](https://learn.microsoft.com/en-us/windows/win32/sysinfo/ntsetsysteminformation) system call. For this to succeed, the caller must have SeIncreaseBasePriorityPrivilege.*
>
> — Microsoft, [Windows Internals E7, P1: 'Chapter 4, Multiprocessor systems'](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

I've tried to see differences between on/off within Overwatch/CS2, but `GetProcessDefaultCpuSets` returned `DefaultCpuSetCount=0` even while Game Mode was active. Other games I tested were Forza Horizon 5/Cyberpunk 2077 which don't register with Game Mode at all.

During registration ([9 - Apply Resource Policies](https://www.noverse.dev/docs/win-config/system/game-mode/#9---apply-resource-policies)), [`RmpGameModeAcquireCpuSetAllocation`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeAcquireCpuSetAllocation@@YAJPEAU_RM_GAME_MODE_CONTEXT@@PEAU_RM_GAME_MODE_RECIPIENT_P.c) asks the CPU set manager for a valid allocation, the CPU set manager chooses the actual CPU sets from the request and current system CPU set state, then [`RmpCpuSetManagerApplySystemAllowedMask`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpCpuSetManagerApplySystemAllowedMask@@YAJPEAU_RM_CPU_SET_MANAGER@@@Z.c) can reduce the CPU sets available to general system activity. [`RmpGameModeTryApplyCpuSetAllocation`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeTryApplyCpuSetAllocation@@YAJPEAU_RM_GAME_MODE_CONTEXT@@PEAU_RM_GAME_MODE_RECIPIENT_.c) then applies that allocation to the registered process.

The final calls are [`RmpSystemSetProcessDefaultCpuSets`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpSystemSetProcessDefaultCpuSets@@YAJPEAXPEA_K@Z.c) (preferred selection), [`RmpSystemSetProcessConstrainedCpuSets`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpSystemSetProcessConstrainedCpuSets@@YAJPEAXE@Z.c) (limit to selected CPU sets), [`RmpSystemSetProcessAllowedCpuSets`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpSystemSetProcessAllowedCpuSets@@YAJPEAXPEA_K@Z.c) (updated when the allocation changes).

When Game Mode is removed from the process, [`RmpGameModeUnapplyCpuSetAllocation`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeUnapplyCpuSetAllocation@@YAXPEAU_RM_GAME_MODE_CONTEXT@@PEAU_RM_GAME_MODE_RECIPIENT_P.c) clears default CPU sets etc.

### GPU scheduler & GPU memory budget

Game Mode changes graphics policy through D3DKMT calls, the service applies a scheduler yield percentage with `D3DKMTSetYieldPercentage` and a GPU memory budget target with `D3DKMTSetMemoryBudgetTarget`.

| Part | Description |
| --- | --- |
| GPU yield percentage | Scheduler policy value passed to `D3DKMTSetYieldPercentage`, Game Mode accepts `2-10`. From my understanding a lower yield value means that the game yields less GPU scheduling time in relation to other work and the opposite. |
| Game GPU memory budget percentage | First budget target passed to `D3DKMTSetMemoryBudgetTarget`, the default fallback is `50`. Note that this is a "target" not a reservation of VRAM. |
| System compositor GPU memory budget percentage | Second budget target passed to `D3DKMTSetMemoryBudgetTarget`, the default fallback is `30`. |

The RM initializer starts with `10/50/30`, but the shell request builder normally uses the HKCU fallback values `2/50/30` when no valid per game profile is present (see below). 

The stored GPU profile is created as four bytes, but the Game Mode service only receives the yield byte, the game budget byte, the system compositor budget byte, the fourth byte is calculated by [`GameModeConfigurationServer::_SaveToGameConfigStore`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/Windows-Gaming-Preview/-_SaveToGameConfigStore@GameModeConfigurationServer@GamesEnumeration@Preview@Gaming@Windows@@AEA.c) as `100 - game - system compositor`. [`GameModeConfigurationServer::_LoadPropertyValues`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/Windows-Gaming-Preview/-_LoadPropertyValues@GameModeConfigurationServer@GamesEnumeration@Preview@Gaming@Windows@@AEAAJX.c) shows only the top three bytes again, I'll just call the fourth byte the stored remainder.

```c
// SetGameGpuProfile
if ( a4 + a6 + (unsigned __int8)a5 != 100 ) // game budget + system compositor budget + stored remainder == 100
{
  v6 = -2147024809;
  v7 = 397LL;
LABEL_7:
  wil::details::in1diag3::Return_Hr(
    retaddr,
    (void *)v7,
    (int)"onecoreuap\\xbox\\windows.gaming.preview\\dll\\gameconfigutils.cpp",
    (const char *)v6);
  return v6;
}
if ( a3 > 0x64u ) // yield byte <= 100
{
  v6 = -2147024809;
  v7 = 402LL;
  goto LABEL_7;
}
v9 = (__int128)*a2;
a5 = a6 | (((unsigned __int8)a5 | ((a4 | (a3 << 8)) << 8)) << 8); // yield, game budget, system compositor budget, stored remainder
```

`GetGameModeRequest` then builds the service request from either the per game profile or the HKCU fallback values, if the per game profile is absent or invalid, it uses the fallback values.

```c
// RmGameModeInitializeResourceRequest
*(_DWORD *)(a1 + 16) = 10; // GPU yield
*(_DWORD *)(a1 + 20) = 50; // game GPU memory budget
*(_DWORD *)(a1 + 24) = 30; // system compositor GPU memory budget
```

```c
// BroadcastDVRComponent::GetGameModeRequest
DWORD = SHRegGetDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\GameBar", L"GpuGameMemoryBudgetPercentage", &v53);
v10 = 50;
if ( DWORD >= 0 )
  v10 = v53;
v46 = v10;
v11 = SHRegGetDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\GameBar", L"GpuDwmMemoryBudgetPercentage", &v53);
v12 = 30;
if ( v11 >= 0 )
  v12 = v53;
v47 = v12;
v13 = SHRegGetDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\GameBar", L"GpuYieldPercentage", &v53);
v14 = 2;
if ( v13 >= 0 )
  v14 = v53;
v45 = v14;
```

```c
// BroadcastDVRComponent::GetGameModeRequest
if ( !v15 )
  goto LABEL_44; // no GPU profile, use HKCU fallback values
*v33 = HIBYTE(v15); // GPU yield
if ( HIBYTE(v15) > 0xAu )
  *v34 = 100 - HIBYTE(v15);
v35 = v45;
*(_DWORD *)(a4 + 20) = BYTE2(v15); // GPU memory budget
v36 = BYTE1(v15);
*(_DWORD *)(a4 + 24) = BYTE1(v15); // system compositor budget
LABEL_45:
v37 = *(_DWORD *)(a4 + 20);
if ( !v37 && !v36 )
{
  v38 = 1;
LABEL_81:
  v17 = 0;
  goto LABEL_82;
}
v38 = 0;
if ( v37 < 0x64 && v36 < 0x64 )
  goto LABEL_81;
LABEL_82:
if ( v38 || v17 || v37 + v36 >= 0x64 ) // invalid pair falls back to HKCU values
{
  *(_DWORD *)(a4 + 20) = v46;
  *(_DWORD *)(a4 + 24) = v47;
}
result = *v34 - 2;
if ( (unsigned int)result > 8 )
  *v34 = v35; // invalid yield falls back to HKCU value
```

The service validates the final request in [`RmpGameModeIsResourceRequestValid`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeIsResourceRequestValid@@YAEPEAU_RM_SERVICE_GLOBALS@@PEAU_RM_GAME_MODE_RESOURCE_REQUE.c) with ranges listed in [7 - Validate in the Service](https://www.noverse.dev/docs/win-config/system/game-mode/#7---validate-in-the-service). The actual graphics update is in [`RmpGameModeTryApplyGraphicsPriority`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeTryApplyGraphicsPriority@@YAJPEAU_RM_GAME_MODE_CONTEXT@@PEAU_RM_GAME_MODE_RECIPIENT_.c), Game Mode saves the original graphics settings during initialization, applies the Game Mode values while active, and restores the saved values when Game Mode is removed.

```c
// RmpGameModeTryApplyGraphicsPriority
v7 = *v3;
v20 = 0;
v21 = 0;
v22 = v7; // accepted GPU yield value
v19 = 16;
v6 = D3DKMTSetYieldPercentage(&v19);
v8 = v3;
if ( v6 < 0 )
  goto LABEL_6;
v9 = *((_DWORD *)a2 + 33);
v20 = 0;
v2 = 1;
v21 = v9; // accepted game budget target
v22 = *((_DWORD *)a2 + 34); // accepted system compositor budget target
v19 = 16;
v6 = D3DKMTSetMemoryBudgetTarget(&v19);
```

### Game Mode Power Profile WNF State

Game Mode can update `WNF_SEB_GAME_MODE` through [`RmpSystemEnableDisableGameModePowerProfile`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpSystemEnableDisableGameModePowerProfile@@YAJE@Z.c), the apply function is [`RmpGameModeTryApplyPowerProfile`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeTryApplyPowerProfile@@YAJPEAU_RM_GAME_MODE_CONTEXT@@PEAU_RM_GAME_MODE_RECIPIENT_PROC.c), it applies only to the primary process and only when the request builder asks for this policy.

WNF = Windows Notification Facility

> "*The Windows Notification Facility, or WNF, is the core underpinning of a modern registrationless publisher/subscriber mechanism*"
>
> "*The ability to define a state name that can be subscribed to, or published to by arbitrary processes*"
>
> "*The ability to associate such a state name with a payload of up to 4 KB*"
>
> "*The Power Manager and various related components use WNF to signal actions*"
>
> - Microsoft, [Windows Internals E7, P2: Chapter 8, System mechanisms](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf)

That is why the Game Mode power part uses WNF, it writes `WNF_SEB_GAME_MODE`, and the power/SEB side can get that state and apply the `GameMode` processor power profile.

Microsoft documents `GameMode` as a processor power management profile that OEMs can configure through provisioning packages.

> "*The power profiles are used by the power processor engine to adapt the performance and parking algorithm on various system use cases.*"
> "*GameMode profile is enabled when the 'Game Mode' setting toggle is turned on and the user is playing a game.*"
>
> — Microsoft, [Processor power management options](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md#power-profiles)

> "*Power profiles provide system wide configuration of processor power management, impacting all running workloads equally.*"
>
> — Microsoft, [Processor power management options](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md#quality-of-service)

```c
// RmpGameModeTryApplyPowerProfile
if ( *((_DWORD *)a2 + 26) || (*((_BYTE *)a2 + 144) & 8) == 0 )
  return 255LL;
v2 = RmpSystemEnableDisableGameModePowerProfile(1u);
if ( v2 < 0 )
  MicrosoftTelemetryAssertTriggeredNoArgs();
```

```c
// RmpSystemEnableDisableGameModePowerProfile
v2 = 0xFFFFFFFF00000001uLL;
if ( a1 )
  LODWORD(v2) = 3;
return NtUpdateWnfStateData(&WNF_SEB_GAME_MODE, &v2, 8LL, 0LL, 0LL, 0, 0);
```

When enabled, WNF uses low value `3`, when disabled, it uses low value `1`. The high value stays `0xFFFFFFFF` in both cases. The GameMode profile has one processor override `Minimum processor state` = `100%` for AC/DC (note that you won't see the changes via powercfg, as these are profile values not a scheme).

You can use [`gm_effects`](https://www.noverse.dev/docs/win-config/system/game-mode#gm_effects) to see what value is set.

[`BroadcastDVRComponent::IsUsingPowerProfile`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/twinui-pcshell/-IsUsingPowerProfile@BroadcastDVRComponent@@AEAA_NAEBU_GUID@@@Z.c) checks whether the active power scheme is `GUID_MIN_POWER_SAVINGS` (High Performance), the request builder uses that result as "already using a performance plan". In the default cases, it asks the service for the GameMode power profile only when the current plan isn't High Performance (`GUID_MIN_POWER_SAVINGS` has `PROCTHROTTLEMIN`/`PROCTHROTTLEMIN1` at `100` by default).

```c
// BroadcastDVRComponent::IsUsingPowerProfile
v2 = PowerGetActiveScheme(0LL, &v6) == 0;
if ( v7 )
  hMem = v6;
if ( v2 )
{
  v3 = *(_QWORD *)&hMem->Data1 - *(_QWORD *)&GUID_MIN_POWER_SAVINGS.Data1;
  if ( *(_QWORD *)&hMem->Data1 == *(_QWORD *)&GUID_MIN_POWER_SAVINGS.Data1 )
    v3 = *(_QWORD *)hMem->Data4 - *(_QWORD *)GUID_MIN_POWER_SAVINGS.Data4;
  v4 = v3 == 0;
}
```

### Expanded Resource Extension Notification

When the optional extension is present, RM notifies it when Game Mode has active policy recipients and when the main Game Mode process enters or leaves expanded resource mode. [`PsmInitializeServiceExtension4`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/PsmInitializeServiceExtension4.c) shows why this is optional, the service only initializes the extension when the extension functions are present.

```c
// PsmInitializeServiceExtension4
if ( (unsigned __int8)IsNotifyGameModeExtensionRecipientsPresentPresent(v4) ) // extension exists
{
  v10[0] = RmGameModeCpuSetManagerCreateClientContext;
  v10[1] = RmGameModeCpuSetManagerAcquireExplicitCpuSets;
  v10[2] = RmGameModeCpuSetManagerRegisterProcessWithAllocation;
  v10[3] = RmGameModeCpuSetManagerReleaseAllocation;
  v10[4] = RmGameModeCpuSetManagerReleaseProcessRegistration;
  InitializeGameModeExtension(v10, v8); // give extension those callbacks + RM service globals
}
```

[`RmpGameModeNotifyExtensionRecipientsPresent`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeNotifyExtensionRecipientsPresent@@YAXPEAU_RM_GAME_MODE_CONTEXT@@E@Z.c) sends the global "Game Mode recipients exist" state, it only calls the extension when that state changes.

```c
// RmpGameModeNotifyExtensionRecipientsPresent
if ( *((_BYTE *)a1 + 140) != a2 ) // cached state differs from new state
{
  v4 = 0;
  *((_DWORD *)a1 + 20) = 0;
  RtlReleaseSRWLockExclusive((char *)a1 + 72);
  if ( (unsigned __int8)IsNotifyGameModeExtensionRecipientsPresentPresent() ) // extension exists
  {
    LOBYTE(v4) = a2 != 0; // convert state to boolean
    NotifyGameModeExtensionRecipientsPresent(v4); // notify whether Game Mode recipients exist
  }
  *((_BYTE *)a1 + 140) = a2; // cache the state after notification
  RtlAcquireSRWLockExclusive((char *)a1 + 72);
  *((_DWORD *)a1 + 20) = GetCurrentThreadId();
}
```

[`RmpGameModeTryApplySystemExtensionPolicy`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeTryApplySystemExtensionPolicy@@YAJPEAU_RM_GAME_MODE_CONTEXT@@PEAU_RM_GAME_MODE_RECIP.c) sends the enabled state for the main Game Mode recipient (related or auxiliary recipients skip this). [`RmpGameModeUnapplySystemExtensionPolicy`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpGameModeUnapplySystemExtensionPolicy@@YAXPEAU_RM_GAME_MODE_CONTEXT@@PEAU_RM_GAME_MODE_RECIPI.c) sends the disabled state when the policy is removed.

```c
// RmpGameModeTryApplySystemExtensionPolicy
if ( *((_DWORD *)a2 + 26) )
  return 255LL; // not the main recipient = skipped
RmpSystemNotifyGameModeExtensionStateChange(*((void **)a2 + 5), 1u); // enabled for this process handle
```

```c
// RmpGameModeUnapplySystemExtensionPolicy
RmpSystemNotifyGameModeExtensionStateChange(a2[5], 0); // disabled for this process handle
```

```c
// RmpSystemNotifyGameModeExtensionStateChange
v4 = IsNotifyGameModeExtensionRecipientsPresentPresent();
v5 = 0LL;
if ( v4 )
{
  LOBYTE(v5) = a2 != 0; // enabled/disabled
  NotifySystemExpandedResourceModeStateChange(a1, v5); // process handle + expanded resource mode state
}
```

The same optional extension can also change how the system allowed CPU set mask is applied, [`RmpSystemSetSystemAllowedCpuSets`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/PsmServiceExtHost/-RmpSystemSetSystemAllowedCpuSets@@YAJPEA_K@Z.c) uses the extension when it's present, otherwise it writes the mask directly through `NtSetSystemInformation`.

```c
// RmpSystemSetSystemAllowedCpuSets
if ( (unsigned __int8)IsNotifyGameModeExtensionRecipientsPresentPresent(SystemInformation) )
  return DelegateSetSystemAllowedCpuSets(SystemInformation, v2); // extension handles system allowed CPU set
else
  return NtSetSystemInformation(SystemPlugPlayBusInformation|0x80, SystemInformation, v2);
```

## Summary (& Opinion)

- WU driver updates/automatic restarts/restart notifications shouldn't be enabled, so that behavior doesn't matter.
- [Process priority class](https://www.noverse.dev/docs/win-config/system/game-mode/#process-priority-class) can prevent a game from setting itself to `REALTIME_PRIORITY_CLASS` as Game Mode would overwrite that with `NORMAL_PRIORITY_CLASS`. If a game doesn't have such issues, the priority classes Game Mode uses are usually similar to what normal games already use.
- Game Mode prevents the FG boost from happening (tested on 23H2), if you don't use `PsPrioritySeparation` FG boost (`1`/`2`), then this doesn't matter (follow [watching-the-boost](https://www.noverse.dev/docs/win-config/system/quantum-priority-separation/#watching-the-boost) but with the game, as said in the section).
- I haven't seen any game yet where Game Mode applied [CPU Sets](https://www.noverse.dev/docs/win-config/system/game-mode/#cpu-sets) through `GetProcessDefaultCpuSets`, if Game Mode chose proper CPU set IDs, this could be useful, but I wouldn't trust Microsoft with that.
- [GPU policy](https://www.noverse.dev/docs/win-config/system/game-mode/#gpu-scheduler--gpu-memory-budget) should only be noticeable if the system has GPU scheduling (`D3DKMTSetYieldPercentage`, means when there's a lot of GPU work in the background, see '[GPU yield percentage](https://www.noverse.dev/docs/win-config/system/game-mode/#gpu-scheduler--gpu-memory-budget)' description?) or GPU memory issues (if VRAM is kind of used while background processes need GPU memory, e.g. high quality captures?).
- [Game Mode power profile](https://www.noverse.dev/docs/win-config/system/game-mode/#game-mode-power-profile-wnf-state) doesn't seem to have any effect when the active scheme is already `GUID_MIN_POWER_SAVINGS` or a modified version of that scheme (must be GUID of `GUID_MIN_POWER_SAVINGS`, so not a copied version of it).

FPS testing isn't a good way to decide whether Game Mode has any benefits for you, rather check whether the game registers with Game Mode at all, whether the game already sets priority class correctly itself, whether CPU sets are applied, and if they are applied, which CPU set IDs are used. Use [gm_effects](https://www.noverse.dev/docs/win-config/system/game-mode#gm_effects)/WPR (see below, I'll add more on it soon to see if it's actually useful, since wevtutil doesn't show events)/SI for it.

```powershell
Provider: Microsoft.Windows.ResourceManager
GUID:     {4180C4F7-E238-5519-338F-EC214F0B49AA}

resourceFileName: %SystemRoot%\system32\PsmServiceExtHost.dll
messageFileName:  %SystemRoot%\system32\PsmServiceExtHost.dll
```

# Kernel Values

Since many people don't yet know which values exist and what default value they have, here's a list. I used [IDA](https://discord.com/channels/836870260715028511/836896618410278952/1492546690413236425), WinDbg, [WinObjEx](https://github.com/hfiref0x/WinObjEx64), [Windows Internals E7 P1](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf) to create it. Many applied values are defaults, some not. See documentation below for details. The applied data is sometimes pure speculation.

## Registry Values

This contains details on several `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\...` keys, not only the `Session Manager\\Kernel` key.

See [session-manager-symbols](https://github.com/nohuto/win-config/tree/main/system/assets/session-manager/session-manager-symbols.txt) for reference ([sym-dump](https://github.com/nohuto/sym-dump)).

- [session-manager/assets | ProcLibGlobalInit.c](https://github.com/nohuto/win-config/tree/main/system/assets/session-manager/ProcLibGlobalInit.c)
- [session-manager/assets | GetRegistryQwordValue.c](https://github.com/nohuto/win-config/tree/main/system/assets/session-manager/GetRegistryQwordValue.c)
- [session-manager/assets | RtlpHpApplySegmentHeapConfigurations.c](https://github.com/nohuto/win-config/tree/main/system/assets/session-manager/RtlpHpApplySegmentHeapConfigurations.c)

The comments of some values with more details are based on pseudocode, if so I added the function name to the end of the comment. Search for the function name in [decompiled-pseudocode/tree/main/11-23H2/ntoskrnl](https://github.com/nohuto/decompiled-pseudocode/tree/main/11-23H2/ntoskrnl).

Everything listed below is based on personal research, mistakes may exist.

```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel";
    "AdjustDpcThreshold" = 20; // KiAdjustDpcThreshold, per CPU countdown value. When it reaches 1, it's reloaded and current DPC queue depth is incremented up to DpcQueueDepth ("number of clock ticks before DpcQueueDepth is incremented if DPCs are not pending") (KeAccumulateTicks, KiInitPrcb)
    "AlwaysTrackIoBoosting" = 0; // PspAlwaysTrackIoBoosting enabling forces IO-boost tracking part in PsBoostThreadIoEx
    "AmdTprLowerInterruptDelayConfig" = 0; // KiAmdTprLowerInterruptDelayConfig
    "BoostingPeriodMultiplier" = 3; // KiNormalPriorityBoostingPeriodMultiplier clamped to 1-20 and used as multiplier in 'NormalPriority AntiStarvation' scheduling paths (KiInitializeNormalPriorityAntiStarvationPolicies, KiPrepareReadyThreadForRescheduling, KiNormalPriorityReadyScan)
    "BugCheckUnexpectedInterrupts" = 0; // KiBugCheckUnexpectedInterrupts
    "CacheAwareScheduling" = 47; // KiCacheAwareScheduling
    "CacheErrataOverride" = 0; // KiTLBCOverride, value 1 and other nonzero values set MSR 0xC0011023 differently (KiInitializeCacheErrataSupport, KiInitMachineDependent, KiDisableCacheErrataSource, KeRestoreProcessorSpecificFeatures)
    "CacheIsoBitmap" = 0; // KiCacheIsoBitmap, if nonzero and "if ( _bittest64(&KeFeatureBits, 0x2Cu) )", value is written to MSR 0xC91 (KeInitializeCatRegisters)
    "DebuggerIsStallOwner" = 0; // KiDebuggerIsStallOwner (KiSetDebuggerOwner)
    "DebugPollInterval" = 2000; // KiDebugPollInterval, debugger enabled (KdDebuggerEnabled) timer path uses 10000 * value (KiGetNextTimerExpirationDueTime)
    "DefaultDynamicHeteroCpuPolicy" = 3; // KiDefaultDynamicHeteroCpuPolicy, behavior of Dynamic hetero policy All (0) (all available) Large (1) LargeOrIdle (2) Small (3) SmallOrIdle (4) Dynamic (5) (use priority and other metrics to decide) BiasedSmall (6) (use priority and other metrics, but prefer small) BiasedLarge (7).
    "DefaultHeteroCpuPolicy" = 5; // KiDefaultHeteroCpuPolicy
    "DeviceOwnerProtectionDowngradeAllowed" = 0; // SeDeviceOwnerProtectionDowngradeAllowed
    "DisableControlFlowGuardExportSuppression" = 0; // PspDisableControlFlowGuardExportSuppression
    "DisableExceptionChainValidation" = 2; // PspSehValidationPolicy
    "DisableLightWeightSuspend" = 0; // KiDisableLightWeightSuspend, nonzero blocks lightweight suspend part in KiSuspendThread and uses the APC path (KiSuspendThread)
    "DisableLowQosTimerResolution" = 1; // KeDisableLowQosTimerResolution, uses ExpUpdateTimerResolution for specific processes etc? (PspSetProcessTimerResolutionPolicy)
    "DisablePointerParameterAlignmentValidation" = 0; // KiDisablePointerParameterAlignmentValidation
    "DisableTsx" = 0; // KiDisableTsx
    "DpcCumulativeSoftTimeout" = 120000; // KeDpcCumulativeSoftTimeoutMs, range 2000-DpcWatchdogPeriod, gets multiplied by KeVerifierDpcScalingFactor (KiInitDpcThresholds, KiApplyDpcVerificationScaleSettings)
    "DpcQueueDepth" = 4; // KiMaximumDpcQueueDepth, "Number of DPCs queued before an interrupt will be sent even for Medium or below DPCs"
    "DpcSoftTimeout" = 20000; // KeDpcSoftTimeoutMs, range 20-DPCTimeout, gets multiplied by KeVerifierDpcScalingFactor (KiInitDpcThresholds, KiApplyDpcVerificationScaleSettings)
    "DPCTimeout" = 20000; // KeDpcTimeoutMs, data 1-19 = 20, "specific DPC execution time limit control" (KiInitDpcThresholds)
    "DpcWatchdogPeriod" = 120000; // KeDpcWatchdogPeriodMs
    "DpcWatchdogProfileBufferSizeBytes" = 266240; // KeDpcWatchdogProfileBufferSizeBytes
    "DpcWatchdogProfileCumulativeDpcThreshold" = 110000; // KeDpcWatchdogProfileCumulativeDpcThresholdMs
    "DpcWatchdogProfileOffset" = 10000; // KeDpcWatchdogProfileOffsetMs
    "DpcWatchdogProfileSingleDpcThreshold" = 18333; // KeDpcWatchdogProfileSingleDpcThresholdMs
    "DriveRemappingMitigation" = 1; // ObpDriveRemappingMitigation
    "DynamicHeteroCpuPolicyExpectedRuntime" = 5200; // KiDynamicHeteroCpuPolicyExpectedRuntime
    "DynamicHeteroCpuPolicyImportant" = 2; // (LargeOrIdle)
    // Policy for a dynamic thread that is deemed important.
    "DynamicHeteroCpuPolicyImportantPriority" = 8; // KiDynamicHeteroCpuPolicyImportantPriority
    // Priority above which threads are considered important if prioritybased dynamic policy is chosen.
    "DynamicHeteroCpuPolicyImportantShort" = 3; // (Small)
    // Policy for dynamic thread that is deemed important but run a short amount of time.
    "DynamicHeteroCpuPolicyMask" = 7; //  (foreground status = 1, priority = 2, expected run time = 4)
    // Determine what is considered in assessing whether a thread is important.
    "EnablePerCpuClockTickScheduling" = 0; // KiEnableClockTimerPerCpuTickScheduling
    "EnableTickAccumulationFromAccountingPeriods" = 0; // KiEnableTickAccumulationFromAccountingPeriods
    "EnableWerUserReporting" = 1; // DbgkEnableWerUserReporting
    "ForceBugcheckForDpcWatchdog" = 0; // KiForceBugcheckForDpcWatchdog
    "ForceForegroundBoostDecay" = 0; // KiSchedulerForegroundBoostDecayPolicy
    "ForceIdleGracePeriod" = 5; // KiForceIdleGracePeriodInSec
    "ForceParkingRequested" = 1; // KiForceParkingConfiguration
    "GlobalTimerResolutionRequests" = 0; // KiGlobalTimerResolutionRequests
    "HeteroFavoredCoreFallback" = 0; // PpmHeteroFavoredCoreFallback
    "HeteroSchedulerOptions" = 0; // KiHeteroSchedulerOptions
    "HeteroSchedulerOptionsMask" = 0; // KiHeteroSchedulerOptionsMask
    "HgsPlusFeedbackUpdateThresholdNetRuntime" = 20; // dword_140FC33C0
    "HgsPlusFeedbackUpdateThresholdRuntime" = 20; // dword_140FC33B4
    "HgsPlusHigherPerfClassFeedbackThreshold" = 1; // dword_140FC33E0
    "HgsPlusInvalidFeedbackDefaultClass" = 0; // dword_140FC33D4
    "HgsPlusInvalidFeedbackDefaultClassSet" = 0; // dword_140FC33D8
    "HgsPlusInvalidFeedbackLimit" = 50; // dword_140FC33D0
    "HgsPlusLowerPerfClassFeedbackThreshold" = 4; // dword_140FC33DC
    "HgsPlusMinimumScoreDifferenceForSwap" = 25; // dword_140FC33E8
    "HgsPlusThreadCreationDefaultClass" = 0; // dword_140FC33E4
    "HotpatchTestMode" = 0; // KeHotpatchTestMode
    "HyperStartDisabled" = 0; // HvlVpStartDisabled
    "IdealDpcRate" = 20; // KiIdealDpcRate
    "IdealNodeRandomized" = 1; // PspIdealNodeRandomized
    "InterruptSteeringFlags" = 0; // KiInterruptSteeringFlags
    "LongDpcQueueThreshold" = 3; // KiLongDpcQueueThreshold
    "LongDpcRuntimeThreshold" = 100; // KiLongDpcRuntimeThreshold
    "MaxDynamicTickDuration" = 8; // KiMaxDynamicTickDurationSize
    "MaximumCooperativeIdleSearchWidth" = 16; // KiMaximumCooperativeIdleSearchWidth
    "MaximumSharedReadyQueueSize" = 260; // KiMaximumSharedReadyQueueSize
    "MinimumDpcRate" = 3; // KiMinimumDpcRate
    "MitigationAuditOptions" = 0; // PspSystemMitigationAuditOptions
    "MitigationOptions" = 0; // PspSystemMitigationOptions
    "ObCaseInsensitive" = 1; // ObpCaseInsensitive
    "ObObjectSecurityInheritance" = 0; // ObpObjectSecurityInheritance
    "ObTracePermanent" = 0; // ObpTracePermanent
    "ObTracePoolTags" = 0; // ObpTracePoolTagsBuffer / ObpTracePoolTagsLength
    "ObTraceProcessName" = 0; // ObpTraceProcessNameBuffer / ObpTraceProcessNameLength
    "ObUnsecureGlobalNames" = 6619246; // ObpUnsecureGlobalNamesBuffer / ObpUnsecureGlobalNamesLength
    "PassiveWatchdogTimeout" = 300; // KiPassiveWatchdogTimeout
    "PerfIsoEnabled" = 0; // KiPerfIsoEnabled
    "PoCleanShutdownFlags" = 0; // PopShutdownCleanly
    "PowerOffFrozenProcessors" = 1; // KiPowerOffFrozenProcessors
    "ReadyTimeTicks" = 6; // KiNormalPriorityBoostReadyTimeTicks
    "RebalanceMinPriority" = 1; // KiRebalanceMinPriority
    "ReservedCpuSets" = 0; // KiReservedCpuSets
    "ScanLatencyTicks" = 7; // KiNormalPriorityBoostScanLatencyTicks
    "SchedulerAssistThreadFlagOverride" = 0; // KiSchedulerAssistThreadFlagOverride
    "SeAllowAllApplicationAceRemoval" = 0; // SepAllowAllApplicationAceRemoval
    "SeAllowSessionImpersonationCapability" = 0; // SepAllowSessionImpersonationCap
    "SeCompatFlags" = 0; // SeCompatFlags
    "SeLpacEnableWatsonReporting" = 0; // SeLpacEnableWatsonReporting
    "SeLpacEnableWatsonThrottling" = 1; // SeLpacEnableWatsonThrottling
    "SerializeTimerExpiration" = 1; // KiSerializeTimerExpiration
    // This behavior is controlled by the kernel variable KiSerializeTimerExpiration, which is initialized based on a registry setting whose value is different between a server and client installation. By modifying or creating the value SerializeTimerExpiration under HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel other than 0 or 1, serialization can be disabled, enabling timers to be distributed among processors. Deleting the value, or keeping it as 0, allows the kernel to make the decision based on Modern Standby availability, and setting it to 1 permanently enables serialization even on non-Modern Standby systems.
    "SeTokenDoesNotTrackSessionObject" = 0; // SeTokenDoesNotTrackSessionObject
    "SeTokenLeakDiag" = 0; // SeTokenLeakTracking
    "SeTokenSingletonAttributesConfig" = 3; // SepTokenSingletonAttributesConfig
    "SplitLargeCaches" = 0; // KiSplitLargeCaches
    "ThreadDpcEnable" = 1; // KeThreadDpcEnable, https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-threaded-dpcs
    "ThreadReadyCount" = 1; // KiNormalPriorityBoostMaximumThreadReadyCount
    "TimerCheckFlags" = 1; // KeTimerCheckFlags
    "VerifierDpcScalingFactor" = 1; // KeVerifierDpcScalingFactor
    "VirtualHeteroHysteresis" = 4294967295; // PpmPerfQosTransitionHysteresisOverride
    "VpThreadSystemWorkPriority" = 30; // KiVpThreadSystemWorkPriority
    "WpsSimulationOverride" = 0; // PpmWpsSimulationOverride / PpmWpsSimulationOverrideSize
    "XStateContextLookasidePerProcMaxDepth" = 0; // KiXStateContextLookasidePerProcMaxDepth

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel\\RNG";
    "RNGAuxiliarySeed" = ; // ExpRNGAuxiliarySeed - REG_DWORD, default of 1807947291? ("HKLM\System\CurrentControlSet\Control\Session Manager\kernel\RNG\RNGAuxiliarySeed","Type: REG_DWORD, Data: 1807947291", procmon boot trace)

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
    "AlpcMessageLog" = 0; // AlpcpMessageLogEnabled 
    "AlpcWakePolicy" = 1; // AlpcpWakePolicyDefault 
    "CriticalSectionTimeout" = 2592000; // dword_140FC3204 dd 278D00
    "CWDIllegalInDLLSearch" = 0; // PspCurDirDevicesSkippedForDlls, can cause "There was a problem starting PolicyAgentProvider.dll The specified module could not be found" if set to 0xFFFFFFFF (https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/client-installation/client-installation-fails-with-policyagentprovider-dll)
    "Debugger Retries" = 20; // KdpContext (0x14) 
    "DisableIFEOCaching" = 0; // RtlpDisableIFEOCaching 
    "GlobalFlag" = 0; // CmNtGlobalFlag <> 0x7061006c ? https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-details
    "GlobalFlag2" = 0; // CmNtGlobalFlag2 <> 0x6c642e30 ?
    "HeapDeCommitFreeBlockThreshold" = 4096; // qword_140FC3210 dq 1000
    "HeapDeCommitTotalFreeThreshold" = 65536; // qword_140FC3218 dq 10000
    "HeapSegmentCommit" = 8192; // qword_140FC3220 dq 2000
    "HeapSegmentReserve" = 1048576; // qword_140FC3228 dq 100000
    "ImageExecutionOptions" = 0; // ViImageExecutionOptions 
    "InitConsoleFlags" = 0; // InitConsoleFlags 
    "MultiUsersInSessionSupported" = 0; // RtlpMultiUsersInSessionSupported 
    "ObjectSecurityMode" = 1; // ObpObjectSecurityMode 
    "PowerPolicySimulate" = 0; // PopSimulate 
    "ProtectionMode" = 1; // ObpProtectionMode , DWORD
    "ResourceCheckFlags" = 3; // ExResourceCheckFlags 
    "ResourceEnforceOwnerTransfer" = 0; // ExpResourceEnforceOwnerTransfer 
    "ResourceTimeoutCount" = 45; // ExResourceTimeoutCount (0x2d) 
    "SkipRegistryInit" = 0; // CmNtSkipRegistryInit 

    // procmon boot trace
    "ObjectDirectories" = \Windows, \RPC Control; // ? - REG_MULTI_SZ
    "BootExecute" = ?; // REG_SZ
    "BootExecuteNoPnpSync" = ?;
    "PlatformExecute" = ?;
    "SetupExecute" = ?;
    "SetupExecuteNoPnpSync" = ?;
    "S0InitialCommand" = ?;
    "NumberOfInitialSessions" = 2; // ? - REG_DWORD
    "PendingFileRenameOperations" = ?;
    "PendingFileRenameOperations2" = ?;
    "AllowProtectedRenames" = ?;
    "ClearTempFiles" = ?;
    "TempFileDirectory" = ?;
    "ExcludeFromKnownDlls" = ?; // REG_MULTI_SZ
    "BackgroundLoadKnownDlls" = ?;
    "DisableWpbtExecution" = ?; // REG_DWORD
    "RaiseExceptionOnPossibleDeadlock" = ?;
    "ResourcePolicies" = ?;
    "SafeDllSearchMode" = ?; // https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#standard-search-order-for-unpackaged-apps
    "SafeProcessSearchMode" = ?;
    "SmtDelayBaseYield" = ?;
    "SmtDelayMaxYield" = ?;
    "SmtDelaySleepLoopWindowSize" = ?;
    "SmtDelaySpinCountThreshold" = ?;
    "SmtFactorYield" = ?;
    "SystemUpdateOnBoot" = ?;

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Quota System";
    "ApplicationBlockedMessageLimit" = 50; // PspJobNoWakeChargeLimit (0x32) 
    "JobTimeLimitsPeriodSeconds" = 7; // PspJobTimeLimitsPeriodSeconds 
    "SystemBlockedMessageLimit" = 200; // PspSystemNoWakeChargeLimit (0xC8) 

    "DfssGenerationLengthMS" = 600; // PsDfssGenerationLengthMS dd 258
    "DfssLongTermFraction1024" = 512; // sDfssLongTermFraction1024 dd 200
    "DfssLongTermSharingMS" = 15; // PsDfssLongTermSharingMS dd 0F
    "DfssResolutionMS" = 4294967295; // PsDfssDesiredTimerResolutionMs dd 0FFFFFFFF
    "DfssShortTermSharingMS" = 30; // PsDfssShortTermSharingMS dd 1E
    "EnableCpuQuota" = 0;

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";
    "AllocationPreference" = 0; // dword_140FC3200 dd 0
    "AllowUserHotPatchWithoutVbs" = 0; // dword_140FC3250 dd 0
    "CacheUnmapBehindLengthInMB" = 8388608; // CcUnmapBehindLength (0x00800000) 
    "CustomDTPDenominator" = 8; // CcClientDTPDenominator (0x8) 
    "DeadlockRecursionDepthLimit" = 0; // ViRecursionDepthLimitFromRegistry 
    "DeadlockSearchNodesLimit" = 0; // ViSearchedNodesLimitFromRegistry 
    "DifPluginConfigData" = 635710207; // DifPluginConfigData (0x25e8007f) 
    "DifPluginConfigDataLength" = 1276097421; // DifPluginConfigDataLength (0x4c084b8d) 
    "DisableCacheTelemetry" = 2; // CcDisableTelemetryRegKeyAtInit 
    "DisablePageCombining" = 0; // dword_140FC31E8 dd 0
    "DisablePagingExecutive" = 0; // dword_140FC31E4 dd 0
    "EnableAsyncLazywrite" = 2; // CcEnableAsyncLazywriteOverride 
    "EnableAsyncLazywriteMulti" = 2; // CcEnableAsyncLazywriteMultiOverride 
    "EnableCooling" = 0; // dword_140FC31F8 dd 0
    "EnablePerVolumeLazyWriter" = 2; // CcEnablePerVolumeLazyWriterOverride 
    "ForceValidateIo" = 0; // dword_140FC31F0 dd 0
    "HighMemoryThreshold" = 0; // qword_140FC3238 dq 0
    "KernelPadSectionsOverride" = 0; // dword_140FC3248 dd 0
    "LargeWriteSize" = 0; // CcAzure_LargeWriteSize 
    "LazyWriterPercentageOfNumProcs" = 0; // CcAzure_LazyWriterPercentageOfNumProcs 
    "LowMemoryThreshold" = 0; // qword_140FC3230 dq 0
    "MaxLazyWritePages" = 0; // CcMaxLazyWritePagesOverride 
    "MinimumStackCommitInBytes" = 0; // dword_140FC3208 dd 0
    "Mirroring" = 0; // dword_140FC31F4 dd 0
    "ModifiedWriteMaximum" = ?; // dword_140FC31FC
    "MoveImages" = 1; // MmRegistryState 
    "NonPagedPoolQuota" = 4294967295; // PspDefaultResourceLimits (4294967295) 
    "PagedPoolQuota" = ?; // unk_140FD7DE4
    "PageValidationAction" = 0; // MmPageValidationAction 
    "PageValidationFrequency" = 0; // MmPageValidationFrequency 
    "PagingFileQuota" = ?; // unk_140FD7DE8
    "PhysicalMemoryMapperEnforcementMode" = 0; // dword_140FC324C dd 0
    "PoolForceFullDecommit" = 0; // PoolForceFullDecommit 
    "PoolTag" = 0; // MmSpecialPoolTag, https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-details
    "PoolTagOverruns" = 1; // MmSpecialPoolCatchOverruns 
    "PoolTagSmallTableSize" = 4097; // PoolTrackTableSize (0x1001) 
    "ProtectNonPagedPool" = 0; // MmProtectFreedNonPagedPool 
    "RemoteFileDirtyPageThreshold" = 1310720; // CcRemoteFileDPInlineFlushThreshold (0x00140000), "This value determines the maximum number of dirty pages in the cache (on a per file basis) for a remote write before an inline flush is performed."
    "SimulateCommitSavings" = 0; // dword_140FC3240 dd 0
    "SoftThrottleDelayInMs" = 0; // CcAzure_SoftThrottleDelayInMs 
    "SoftThrottleLargeWriteAtPct" = 0; // CcAzure_SoftThrottleLargeWriteAtPct 
    "SpecialPurposeMemoryPages" = 0; // MmSpecialPurposeMemoryPages 
    "SpecialPurposeMemoryStartPage" = 0; // MmSpecialPurposeMemoryStartPage 
    "SpecialPurposeMemoryStartPageValueSize" = 4294967295; // MmSpecialPurposeMemoryStartPageValueSize (4294967295) 
    "TopBottomDPTEqual" = 0; // CcAzure_TopBottomDPTEqual 
    "TrackLockedPages" = 0; // MmTrackLockedPages 
    "TrackPtes" = 0; // dword_140FC31EC dd 0
    "VerifierDifPoolTags" = 0; // DifpPoolTags 
    "VerifierDifPoolTagsSizeBytes" = 4294967295; // DifpPoolTagsSizeBytes (4294967295) 
    "VerifierFaultApplications" = 0; // VerifierFaultApplicationsBuffer 
    "VerifierFaultApplicationsSize" = 4294967295; // VerifierFaultApplicationsBufferSize (4294967295) 
    "VerifierFaultBootMinutes" = 8; // VfFaultInjectionBootMinutes 
    "VerifierFaultProbability" = 600; // VfFaultInjectionProbability (0x258) 
    "VerifierFaultTags" = 0; // VerifierFaultTagsBuffer 
    "VerifierFaultTagsSize" = 4294967295; // VerifierFaultTagsBufferSize (4294967295) 
    "VerifierHandleTraces" = 16384; // VfHandleTracingEntries (0x4000) 
    "VerifierIrpStackTraces" = 16384; // IovIrpTracesLength (0x4000) 
    "VerifierIrpTimeout" = 0; // VfWdIrpTimeoutMsec 
    "VerifierNewRuleWorkaround" = 0; // VerifierNewRuleWorkaround 
    "VerifierOptions" = 0; // VfOptionFlags 
    "VerifierRandomTargets" = 0; // VfRandomVerifiedDrivers 
    "VerifierSettingState" = 0; // VfRuleClasses 
    "VerifierSettingStateSize" = 4294967295; // VfRuleClassesSize (4294967295) 
    "VerifierTipDisable" = 0; // VerifierTipDisable 
    "VerifierTipLimitDenominator" = 0; // DifiPluginControlDenominator 
    "VerifierTipLimitNumerator" = 0; // DifiPluginControlNumerator 
    "VerifierTipSparseness" = 0; // DifiPluginControlSparseness 
    "VerifierTriageContext" = 0; // VfTriageContext 
    "VerifyBTSBufferSize" = 0; // ViVerifyBTSBufferSize 
    "VerifyDriverLevel" = 4294967295; // MmVerifyDriverLevel (4294967295) 
    "VerifyDrivers" = 3905129288; // MmVerifyDriverBuffer (0xE8C38B48) 
    "VerifyDriversLength" = 1207968387; // MmVerifyDriverBufferLength (0x48002283) 
    "VerifyDriversSuppress" = 276138824; // VfXdvSuppressDriversBuffer (0x10758b48) 
    "VerifyDriversSuppressLength" = 3482011648; // VfXdvSuppressDriversBufferLength (0xCF8B4800) 
    "VerifyMode" = 4; // VfVerifyMode 
    "VerifyTriage" = 4294967295; // ViVerifyTriage (4294967295) 
    "VerifyTriageRules" = 0; // ViVerifyTriageRules 
    "VerifyTriageRulesSize" = 4294967295; // ViVerifyTriageRulesSize (4294967295) 
    "VmPauseOutswapSizeCapMB" = 512; // VmPauseOutswapSizeCapMB (0x200) 
    "WorkingSetPagesQuota" = ?; // unk_140FD7DEC
    "WorkingSetSwapSharedPages" = 0; // PspOutSwapSharedPages 
    "XdvTipTag" = 0; // CarTipTag 
    "XdvVerifierOptions" = 0; // CarXdvOptions 
    "XdvVerifierOptions" = 0; // VfFlightOptions

    // procmon boot trace
    "PagingFiles" = C:\pagefile.sys <int> <int> // REG_MULTI_SZ
    "PagefileOnOsVolume" = ?; // 4,094
    "WaitForPagingFiles" = ?; // 4,094
    "ExistingPageFiles" = \??\C:\pagefile.sys; // REG_MULTI_SZ
    "DisableDedicatedMemoryCaching" = ?;
    "DedicatedMemoryPagefileSizeMB" = ?
    "PagefileHybridPriority" = ?;
    "SwapfileControl" = ?;
    "SwapFile" = ?;
    "TempPageFile" = ?;
    "FeatureSettings" = ? // DWORD

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Executive";
    "AdditionalCriticalWorkerThreads" = 0; // ExpAdditionalCriticalWorkerThreads 
    "AdditionalDelayedWorkerThreads" = 0; // ExpAdditionalDelayedWorkerThreads 
    "ForceEnableMutantAutoboost" = 0; // ExpForceEnableMutantAutoboost 
    "KernelWorkerTestFlags" = 0; // ExpWorkerQueueTestFlags 
    "MaximumKernelWorkerThreads" = 4096; // ExpMaximumKernelWorkerThreads (0x1000) 
    "MaxTimeSeparationBeforeCorrect" = 60; // ExpMaxTimeSeperationBeforeCorrect (0x3C) 
    "WorkerFactoryThreadCreationTimeout" = 10; // ExpWorkerFactoryThreadCreationTimeoutInSeconds (0x0A) 
    "WorkerFactoryThreadIdleTimeout" = 67; // ExpWorkerFactoryThreadIdleTimeoutInSeconds (0x43) 
    "WorkerThreadTimeoutInSeconds" = 600; // ExpWorkerThreadTimeoutInSeconds (0x258)
    "TickcountRolloverDelay" = 0; // ? (InitTickRolloverDelay dd 0) - InitTickRolloverDelay <> 24848b00, InitTickRolloverDelayLength <> 5e4130c4, InitTickRolloverDelayType <> e2894460

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power";
    "FlushPolicy" = 0; // PopFlushPolicy 
    "IdleScanInterval" = 30; // PopIdleScanInterval (0x1E) 
    "SkipTickOverride" = 1; // PopSkipTickPolicy
    "SleepStudyDeviceAccountingLevel" = 4; // PopSleepStudyDeviceAccountingLevel 
    "SleepStudyDisabled" = 0; // PopSleepStudyDisabled 
    "WatchdogResumeTimeout" = 120; // PopWatchdogResumeTimeout (0x78) 
    "WatchdogSleepTimeout" = 300; // PopWatchdogSleepTimeout (0x12C) 
    "Win32CalloutWatchdogBugcheckEnabled" = 0; // PopWin32CalloutWatchdogBugcheckEnabled 

    // PopOpenPowerKey
    "AwayModeEnabled" = 0; // REG_DWORD, range 0-1
    "HiberbootEnabled" = 1; // REG_DWORD, range 0-1
    "KernelResumeIoCpuTime" = 0; // REG_DWORD, milliseconds, range 0-4294967295
    "MaxHuffRatio" = 1; // REG_DWORD, range 1-98
    "MultiPhaseResumeDisabled" = 0; // REG_DWORD, range 0-1
    "SystemPowerPolicy" = "<STRUCT 232 BYTES>"; // REG_BINARY, Size=232

    // HybridBootAnimationTime records the boot animation duration during fast boot, HiberIoCpuTime is CPU time spent on hibernation I/O during resume, ResumeCompleteTimestamp is the system timestamp when resume from hibernation completed. So all of them are just counters and changing their data won't affect the boot.
    "HybridBootAnimationTime" = 1601; // REG_DWORD, milliseconds, range: 0-0xFFFFFFFF
    "HiberIoCpuTime" = 0; // REG_DWORD, milliseconds, range: 0-0xFFFFFFFF
    "ResumeCompleteTimestamp" = 0; // REG_QWORD, range: 0-0xFFFFFFFFFFFFFFFF

    // PpmInitIllegalThrottleLogging
    "ProcessorThrottleLogInterval" = 10000; // REG_DWORD, milliseconds, range 0-10000 (values >10000 are clamped to 10000)

    // procmon boot trace
    "SleepStudyBufferSizeInMB" = ?;
    "SleepStudyHistoryDays" = ?;
    "SleepStudyPerfTrackDripsThresholdPercentage" = ?;
    "SleepStudyTraceDirectory" = ?;

"HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\Throttle";
    "PerfEnablePackageIdle" = 0;

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Segment Heap";
    "Enabled" = 0; // if present with DataLength==4 and nonzero type:
                    //    RtlpLowFragHeapGlobalFlags |= 0x10;  // global segment heap enable
                    //    if (value & 0x2)                      // low byte, bit 1
                    //        RtlpLowFragHeapGlobalFlags |= 0x20; // extra option ?
                    // if the value exists but is stored as REG_NONE (type==0):
                    //    RtlpLowFragHeapGlobalFlags |= 0x8;   // global "disable/override"

// Miscellaneous values

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA";
    "AuditBaseDirectories" = 0; // ObpAuditBaseDirectories 
    "AuditBaseObjects" = 0; // ObpAuditBaseObjects 

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\audit";
    "ProcessAccessesToAudit" = 0; // SepProcessAccessesToAudit 

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation";
    "ActiveTimeBias" = ?; // dword_140FCE974
    "Bias" = 480; // ExpAltTimeZoneBias (0x000001e0) 
    "RealTimeIsUniversal" = 0; // ExpRealTimeIsUniversal 

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\I/O System";
    "DisableDiskCounters" = 0; // PsDisableDiskCounters 
    "IoAllowLoadCrashDumpDriver" = 0; // IopAllowLoadCrashDumpDriver 
    "IoBlockLegacyFsFilters" = 0; // IopBlockLegacyFsFilters 
    "IoCaseInsensitive" = 1; // IopCaseInsensitive 
    "IoEnableSessionZeroAccessCheck" = 0; // IopSessionZeroAccessCheckEnabled 
    "IoFailZeroAccessCreate" = 1; // IopFailZeroAccessCreate 
    "IoIrpCompletionTimeoutInSeconds" = 300; // IopIrpCompletionTimeoutInSeconds (0x12C) 
    "IoKeepAliveTimeMs" = 5000; // IopKeepAliveTimeMs (0x1388) 
    "LargeIrpStackLocations" = 14; // IopLargeIrpStackLocations (0x0E) 
    "MediumIrpStackLocations" = 2; // IopMediumIrpStackLocations 
    "RequireDeviceAccessCheck" = 1; // IopRequireDeviceAccessCheck 

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Configuration Manager";
    "BugcheckRecoveryEnabled" = 0; // CmBugcheckRecoveryEnabled 
    "CallbackMemoryFromPerProcLookaside" = 1; // CmpAllocateCallbackMemoryFromPerProcLookaside 
    "CallbackMemoryFromPool" = 0; // CmpAllocateCallbackMemoryFromPool 
    "DelayCloseSize" = 2048; // CmpDelayedCloseSize (0x800) 
    "Enabled" = 0; // CmpLKGEnabled 
    "EnablePeriodicBackup" = 0; // CmpDoIdleProcessing, https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder#more-information
    "FastBoot" = 1; // CmFastBoot 
    "FreezeThawTimeoutInSeconds" = 60; // CmFreezeThawTimeoutInSeconds (0x3C) 
    "RegistryFlushGlobalFlags" = 0; // CmpGlobalFlushControlFlags 
    "RegistryLazyFlushBootDelay" = 60; // CmpEnableLazyFlushBootDelayInterval (0x3C) 
    "RegistryLazyFlushInterval" = 60; // CmpLazyFlushIntervalInSeconds (0x3C) 
    "RegistryLazyLocalizeInterval" = 60; // CmpLazyLocalizeIntervalInSeconds (0x3C) 
    "RegistryLazyReconcileInterval" = 3600; // CmpLazyReconcileIntervalInSeconds (0x0E10) 
    "RegistryLogFileSizeCap" = 0; // CmpLogFileSizeCap 
    "RegistryReorganizationLimit" = 1048576; // CmpReorganizeLimit (0x00100000) 
    "RegistryReorganizationLimitDays" = 7; // CmpReorganizeDelayDays 
    "SelfHealingEnabled" = 1; // CmSelfHeal 
    "SystemHiveLimitSize" = 1610612736; // CmSystemHiveLimitSize (0x60000000) 
    "VirtualizationEnabled" = 1; // CmVEEnabled 
    "VolatileBoot" = 0; // CmpVolatileBoot 

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\StateSeparation\\Policy";
    "AllHivesVolatile" = 0; // CmStateSeparationAllHivesVolatile 
    "DevelopmentMode" = 0; // CmStateSeparationDevMode 
    "Enabled" = 0; // CmStateSeparationEnabled 

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ValidationRunlevels";
    "Global" = 1210938368; // CmGlobalValidationRunlevel (0x482d7400) 

"HKLM\\System\\CurrentControlSet\\Control\\Processor";
    "AllowGuestPerfStates" = 0;
    "AllowPepPerfStates" = 0;
    "Capabilities" = 4294967288; // Fallback of 0 ?
    "DisableAsserts" = 0;
    "Overrides" = 0;
```

## [Windows Internals](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf)

![](https://github.com/nohuto/win-config/blob/main/system/images/kernel0.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/kernel1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/kernel2.png?raw=true)

## Notes on SerializeTimerExpiration

`0` = depends on `HalpAcpiAoacCapable`, can end up with `0`/`1`. `HalpSetPlatformFlags` checks if bit 21
```c
if ( (*(_DWORD *)(a1 + 112) & 0x200000) != 0 )
  HalpPlatformFlags |= 8u;
```
is set or not, if set it's `1`, if not `0`.
```
LOW_POWER_S0_IDLE_CAPABLE Bit offset 21. Indicates that the platform supports low-power idle states within the ACPI S0 system power state that are more energy efficient than any Sx sleep state. If this flag is set, Windows won't try to sleep and resume, but will instead use platform idle states and connected standby.
```
Means for desktops/servers it's usually `0`, since "S0 Low‑Power Idle/Modern Standby" is more of a laptop/tablet thing.

You can check if the bit is true or false using [iasl & acpidump](https://github.com/acpica/acpica).

`1` = forced on (uses CPU 0 `KiProcessorBlock[0]`)
`>=2` = forced `0`

This isn't complete, it's currently only for the data ranges.

![](https://github.com/nohuto/win-config/blob/main/system/images/kernel-ste.png?raw=true)

Read more about 'Timer expiration' in [Windows Interals E7, P1, P.66f](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf).

## RegistryMachin_* Keys

These are from `ntoskrnl.exe`. Looking at xrefs of these names is sometimes a start point when trying to find values within a binary or to see what keys are somewhere used, therefore I'm adding it (note that `aRegistryMachin_*` are IDA generated names so you won't find them in strings, nor will they be the exact same for you unless you disassemble the same binary build version).

```c
// ntoskrnl.exe
aRegistryMachin = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Restrictions"
aRegistryMachin_0 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Arbiters"
aRegistryMachin_1 = "\\Registry\\Machine\\HARDWARE"
aRegistryMachin_2 = "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\FileSystems\\NTFS"
aRegistryMachin_3 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\StoreParameters\\CacheInfo"
aRegistryMachin_4 = "\\Registry\\Machine\\SAM\\SAM"
aRegistryMachin_5 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache"
aRegistryMachin_6 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Lsa"
aRegistryMachin_7 = "\\Registry\\Machine\\Software\\Microsoft\\SQMClient\\Windows"
aRegistryMachin_8 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Storage"
aRegistryMachin_9 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control"
aRegistryMachin_10 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage"
aRegistryMachin_11 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CommonGlobUserSettings\\"
aRegistryMachin_12 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class"
aRegistryMachin_13 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\WHEA"
aRegistryMachin_14 = "\\Registry\\Machine\\System\\LastKnownGoodRecovery\\LastGood.Tmp"
aRegistryMachin_15 = "\\Registry\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"
aRegistryMachin_16 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
aRegistryMachin_17 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Lsa\\CentralizedAccessPolicies\\CAPs"
aRegistryMachin_18 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\EventLog\\Security"
aRegistryMachin_19 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
aRegistryMachin_20 = "\\Registry\\Machine\\OSBOOT\\System\\CurrentControlSet\\Control\\CrashControl"
aRegistryMachin_21 = "\\REGISTRY\\MACHINE"
aRegistryMachin_22 = "\\REGISTRY\\MACHINE\\HARDWARE\\RESOURCEMAP"
aRegistryMachin_23 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WMI"
aRegistryMachin_24 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control"
aRegistryMachin_25 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices"
aRegistryMachin_26 = "\\Registry\\Machine\\System\\Setup"
aRegistryMachin_27 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\WMI\\ProfileSource"
aRegistryMachin_28 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\FirmwareResources"
aRegistryMachin_29 = "\\Registry\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel\\KGroups"
aRegistryMachin_30 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Compatibility"
aRegistryMachin_31 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SESSION MANAGER\\MEMORY MANAGEMENT"
aRegistryMachin_32 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CrashControl"
aRegistryMachin_33 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\ApiSetSchemaExtensions"
aRegistryMachin_34 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
aRegistryMachin_35 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\DeviceOverrides"
aRegistryMachin_36 = "\\registry\\machine\\system\\currentcontrolset\\control\\hiveredirectionlist"
aRegistryMachin_37 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions"
aRegistryMachin_38 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\Control\\HAL\\OriginalImageFeatures"
aRegistryMachin_39 = "\\Registry\\Machine\\OSBOOT\\System\\CurrentControlSet\\Control\\LiveDump"
aRegistryMachin_40 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\PnP"
aRegistryMachin_41 = "\\Registry\\Machine\\System\\LastKnownGoodRecovery\\LastGood"
aRegistryMachin_42 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\StoreParameters"
aRegistryMachin_43 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Lsa\\CentralizedAccessPolicies\\CAPEs"
aRegistryMachin_44 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\TieredStorage"
aRegistryMachin_45 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control"
aRegistryMachin_46 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\FileSystem"
aRegistryMachin_47 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\\CPU Partitions"
aRegistryMachin_48 = "\\Registry\\MACHINE\\System\\CurrentControlSet\\Control\\CI\\NGEN"
aRegistryMachin_49 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Language"
aRegistryMachin_50 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft"
aRegistryMachin_51 = "\\Registry\\Machine\\Software\\Microsoft\\SecurityManager\\AdminCapabilities"
aRegistryMachin_52 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\Control\\WDI\\Config"
aRegistryMachin_53 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\VolatileNotifications"
aRegistryMachin_54 = "\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM"
aRegistryMachin_55 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\StateSeparation\\RedirectionMap\\Keys"
aRegistryMachin_56 = "\\REGISTRY\\MACHINE\\OSBOOT\\ControlSetOverride\\Session Manager\\Memory Management"
aRegistryMachin_57 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GroupOrderList"
aRegistryMachin_58 = "\\REGISTRY\\MACHINE\\SYSTEM\\CONTROLSET001"
aRegistryMachin_59 = "\\Registry\\Machine\\%ws\\ControlSet%03d"
aRegistryMachin_60 = "\\Registry\\Machine\\System\\Select"
aRegistryMachin_61 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\WMI\\GlobalLogger"
aRegistryMachin_62 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\DedupChange"
aRegistryMachin_63 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Update\\TargetingInfo\\DynamicInstalled"
aRegistryMachin_64 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control"
aRegistryMachin_65 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\.NETFramework"
aRegistryMachin_66 = "\\Registry\\Machine\\SYSTEM"
aRegistryMachin_67 = "\\REGISTRY\\MACHINE"
aRegistryMachin_68 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control"
aRegistryMachin_69 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters"
aRegistryMachin_70 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\Control\\HAL"
aRegistryMachin_71 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management"
aRegistryMachin_72 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\ROOT"
aRegistryMachin_73 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CrashControl\\FullLiveKernelReports"
aRegistryMachin_74 = "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\FileSystems\\NTFS"
aRegistryMachin_75 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CrashControl"
aRegistryMachin_76 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services"
aRegistryMachin_77 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Notifications"
aRegistryMachin_78 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\NLS\\Language"
aRegistryMachin_79 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\BOOTLOG"
aRegistryMachin_80 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\MUI\\UILanguages\\PendingDelete"
aRegistryMachin_81 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CrashControl\\EncryptionCertificates\\Certificate.1"
aRegistryMachin_82 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\WMI"
aRegistryMachin_83 = "\\registry\\machine\\system\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\Defrag"
aRegistryMachin_84 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\MUI\\Settings"
aRegistryMachin_85 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\LsaInformation"
aRegistryMachin_86 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\NLS\\Language"
aRegistryMachin_87 = "\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION"
aRegistryMachin_88 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\WMI\\AutoLogger"
aRegistryMachin_89 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Lsa\\CentralizedAccessPolicies\\CAPs"
aRegistryMachin_90 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\EarlyLaunch"
aRegistryMachin_91 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
aRegistryMachin_92 = "\\Registry\\Machine\\System\\CurrentControlSet\\Policies\\EarlyLaunch"
aRegistryMachin_93 = "\\REGISTRY\\MACHINE\\SOFTWARE"
aRegistryMachin_94 = "\\REGISTRY\\MACHINE"
aRegistryMachin_95 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\LiveDump"
aRegistryMachin_96 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET"
aRegistryMachin_97 = "\\Registry\\Machine\\%wZ\\CurrentControlSet\\Hardware Profiles\\%04d"
aRegistryMachin_98 = "\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES"
aRegistryMachin_99 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Executive"
aRegistryMachin_100 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\FileInfo"
aRegistryMachin_101 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\condrv"
aRegistryMachin_102 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WindowsTrustedRT\\Parameters"
aRegistryMachin_103 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\FileSystem"
aRegistryMachin_104 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\MCUpdate\\PatchConfig"
aRegistryMachin_105 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CrashControl\\LastCrashdump"
aRegistryMachin_106 = "\\registry\\machine\\"
aRegistryMachin_107 = "\\REGISTRY\\MACHINE\\HARDWARE\\UEFI"
aRegistryMachin_108 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\FileSystem\\GroupPolicyKeys"
aRegistryMachin_109 = "\\Registry\\Machine\\HARDWARE\\UEFI"
aRegistryMachin_110 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel"
aRegistryMachin_111 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WDI"
aRegistryMachin_112 = "\\Registry\\Machine\\Hardware\\Description\\System"
aRegistryMachin_113 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Errata\\Dynamic"
aRegistryMachin_114 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET"
aRegistryMachin_115 = "\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\SHUTDOWN"
aRegistryMachin_116 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions"
aRegistryMachin_117 = "\\REGISTRY\\MACHINE\\HARDWARE\\DEVICEMAP"
aRegistryMachin_118 = "\\Registry\\Machine\\SOFTWARE"
aRegistryMachin_119 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\FeatureManagement\\EnterpriseTempControls\\Active"
aRegistryMachin_120 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\Control\\WDI\\Scenarios"
aRegistryMachin_121 = "\\Registry\\Machine\\System\\Setup"
aRegistryMachin_122 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Lsa\\CentralizedAccessPolicies\\CAPEs"
aRegistryMachin_123 = "\\Registry\\Machine\\System\\DriverDatabase\\Policies"
aRegistryMachin_124 = "\\REGISTRY\\MACHINE\\OSDATA"
aRegistryMachin_125 = "\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows\\Appx"
aRegistryMachin_126 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\KernelVelocity"
aRegistryMachin_127 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control"
aRegistryMachin_128 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CAD"
aRegistryMachin_129 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock"
aRegistryMachin_130 = "\\Registry\\Machine\\Hardware\\Description\\System\\CentralProcessor"
aRegistryMachin_131 = "\\Registry\\Machine\\System\\CurrentControlSet\\Policies\\Microsoft\\Compatibility"
aRegistryMachin_132 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB"
aRegistryMachin_133 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\EVENTLOG"
aRegistryMachin_134 = "\\Registry\\Machine\\%wZ\\CurrentControlSet"
aRegistryMachin_135 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CMF\\SqmData"
aRegistryMachin_136 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Windows"
aRegistryMachin_137 = "\\registry\\machine\\SYSTEM\\CurrentControlSet\\Control\\NUMA"
aRegistryMachin_138 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion"
aRegistryMachin_139 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CrashControl"
aRegistryMachin_140 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\FsDepends\\Parameters"
aRegistryMachin_141 = "\\Registry\\Machine\\%wZ\\CurrentControlSet\\Hardware Profiles\\%04d"
aRegistryMachin_142 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Compatibility\\Device"
aRegistryMachin_143 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\DeviceGuard"
aRegistryMachin_144 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceContainerPropertyUpdateEvents"
aRegistryMachin_145 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Syspart"
aRegistryMachin_146 = "\\Registry\\Machine\\%ws"
aRegistryMachin_147 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\HARDWARE PROFILES\\CURRENT"
aRegistryMachin_148 = "\\REGISTRY\\MACHINE\\SOFTWARE\\WowAA32Node"
aRegistryMachin_149 = "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall"
aRegistryMachin_150 = "\\Registry\\Machine\\System\\ControlSet%03d"
aRegistryMachin_151 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Quota System"
aRegistryMachin_152 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\LeapSecondInformation"
aRegistryMachin_153 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
aRegistryMachin_154 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\IPT"
aRegistryMachin_155 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node"
aRegistryMachin_156 = "\\registry\\machine\\system\\currentcontrolset\\control\\hivelist"
aRegistryMachin_157 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\PXE"
aRegistryMachin_158 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\OneCore"
aRegistryMachin_159 = "\\REGISTRY\\MACHINE\\"
aRegistryMachin_160 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Compatibility\\Driver"
aRegistryMachin_161 = "\\Registry\\Machine\\Hardware\\Description\\System"
aRegistryMachin_162 = "\\Registry\\Machine\\Software\\Policies\\Microsoft\\SQMClient\\Windows"
aRegistryMachin_163 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\LicenseInfoSuites"
aRegistryMachin_164 = "\\REGISTRY\\MACHINE\\%s"
aRegistryMachin_165 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\FeatureManagement"
aRegistryMachin_166 = "\\Registry\\Machine"
aRegistryMachin_167 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\WMI\\Security"
aRegistryMachin_168 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SESSION MANAGER\\Configuration Manager"
aRegistryMachin_169 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\WindowsUpdate"
aRegistryMachin_170 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Diagnostics\\Performance"
aRegistryMachin_171 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot"
aRegistryMachin_172 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\AutoAttachVirtualDisks"
aRegistryMachin_173 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\MUI\\UILanguages"
aRegistryMachin_174 = "\\Registry\\Machine\\Hardware\\DeviceMap"
aRegistryMachin_175 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\StateSeparation\\RedirectionMap\\Files"
aRegistryMachin_176 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\FeatureManagement\\EnterpriseTempControls"
aRegistryMachin_177 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\FileSystemVolumes\\{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}"
aRegistryMachin_178 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\HARDWARE PROFILES\\CURRENT"
aRegistryMachin_179 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Normalization"
aRegistryMachin_180 = "\\REGISTRY\\MACHINE\\SYSTEM"
aRegistryMachin_181 = "\\Registry\\Machine\\Security\\SAM"
aRegistryMachin_182 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\NLS\\Language"
aRegistryMachin_183 = "\\REGISTRY\\MACHINE\\HARDWARE\\OWNERMAP"
aRegistryMachin_184 = "\\Registry\\MACHINE\\SYSTEM\\CurrentControlSet\\Control"
aRegistryMachin_185 = "\\Registry\\Machine\\System\\LastKnownGoodRecovery\\LastGood.Tmp"
aRegistryMachin_186 = "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Session Manager\\Quota System"
aRegistryMachin_187 = "\\Registry\\Machine\\ELAM"
aRegistryMachin_188 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Lsa"
aRegistryMachin_189 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control"
aRegistryMachin_190 = "\\Registry\\Machine\\System\\CurrentControlSet\\ServiceState"
aRegistryMachin_191 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SAFEBOOT"
aRegistryMachin_192 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Arbiters"
aRegistryMachin_193 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Restrictions"
aRegistryMachin_194 = "\\Registry\\Machine\\"
aRegistryMachin_195 = "\\Registry\\Machine\\Software\\Policies\\Microsoft\\MUI\\Settings"
aRegistryMachin_196 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\SERVICES"
aRegistryMachin_197 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\BitlockerStatus"
aRegistryMachin_198 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\IDConfigDB"
aRegistryMachin_199 = "\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\PERFLIB"
aRegistryMachin_200 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\MiniNT"
aRegistryMachin_201 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Compatibility"
aRegistryMachin_202 = "\\REGISTRY\\MACHINE\\SYSTEM"
aRegistryMachin_203 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\DeviceOverrides"
aRegistryMachin_204 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CrashControl\\ForceDumpsDisabled"
aRegistryMachin_205 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ACPI\\Parameters"
aRegistryMachin_206 = "\\REGISTRY\\MACHINE\\HARDWARE"
aRegistryMachin_207 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\ENUM"
aRegistryMachin_208 = "\\REGISTRY\\MACHINE\\SOFTWARE"
aRegistryMachin_209 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\WMI"
aRegistryMachin_210 = "\\REGISTRY\\MACHINE\\SYSTEM\\Software\\Microsoft"
aRegistryMachin_211 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\International"
aRegistryMachin_212 = "\\Registry\\Machine\\System\\Setup"
aRegistryMachin_213 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ValidationRunlevels"
aRegistryMachin_214 = "\\REGISTRY\\MACHINE\\"
aRegistryMachin_215 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control"
aRegistryMachin_216 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\StoreParameters"
aRegistryMachin_217 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\kernel"
aRegistryMachin_218 = "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Kernel DMA Protection"
aRegistryMachin_219 = "\\Registry\\Machine\\System\\LastKnownGoodRecovery\\LastGood"
aRegistryMachin_220 = "\\Registry\\Machine"
aRegistryMachin_221 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\FileSystem"
aRegistryMachin_222 = "\\Registry\\Machine\\OSDATA\\System\\CurrentControlSet\\Control\\CrashControl"
aRegistryMachin_223 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control"
aRegistryMachin_224 = "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\CLASS"
aRegistryMachin_225 = "\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION"
aRegistryMachin_226 = "\\Registry\\Machine\\System\\DriverDatabase\\Updates"
aRegistryMachin_227 = "\\Registry\\Machine\\%wZ\\CurrentControlSet\\%wZ"
aRegistryMachin_228 = "\\Registry\\Machine\\OSDATA\\System\\CurrentControlSet\\Control\\LiveDump"
aRegistryMachin_229 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Power"
aRegistryMachin_230 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\"
aRegistryMachin_231 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ServiceGroupOrder"
aRegistryMachin_232 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters"
aRegistryMachin_233 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Lsa\\CentralizedAccessPolicies"
aRegistryMachin_234 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Notifications"
aRegistryMachin_235 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel"
aRegistryMachin_236 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\7503491f-4a39-4f84-b231-8aca3e203b94"
aRegistryMachin_237 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\MUI\\Settings\\LanguageConfiguration"
aRegistryMachin_238 = "\\REGISTRY\\MACHINE\\OSDATA\\Notifications"
aRegistryMachin_239 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Windows"
aRegistryMachin_240 = "\\Registry\\Machine\\System\\Select"
```

# DXG Kernel Values

`dxgkrnl.sys` is Windows DirectX/WDDM graphics kernel driver that mediates between apps and the GPU to schedule work, manage graphics memory, present frames, and handle TDR hang recovery.

Many applied values are defaults, some not. See documentation below for details. The applied data is sometimes pure speculation.

## Registry Values

These are default values I found in `dxgkrnl.sys`, see [assets/dxg-values](https://github.com/nohuto/win-config/tree/main/system/assets/dxg-values) for pseudocode snippets I used / [records/Graphics-Drivers.txt](https://github.com/nohuto/regkit/blob/main/records/Graphics-Drivers.txt) for all values that get read on boot.

The `GraphicsDrivers\Scheduler` / `GraphicsDrivers\MemoryManager` values are from `dxgmms2.sys`, I used the drivers from 23H2/25H2 since they differ at some point. See [dxgmms2](https://github.com/nohuto/win-config/tree/main/system/assets/dxg-values/dxgmms2) for all used files.

Everything listed below is based on personal research, mistakes may exist.

```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers"
    "MiracastForceDisable" = 2;
    "MiracastUseIhvDriver" = 2;

    "ContextNoPatchMode" = 0;
    "CreateGdiPrimaryOnSlaveGpu" = 0;
    "CrtcPhaseFrames" = 2;
    "DeadlockPulse" = 5000;
    "DeadlockPulseTolerance" = 500;
    "DeadlockTimeout" = 30000;
    "DisableBadDriverCheckForHwProtection" = 0; // REG_DWORD
    "DisableBoostedVSyncVirtualization" = 0; // REG_DWORD
    "DisableGdiContextGpuVa" = 0;
    "DisableIndependentVidPnVSync" = 0; // REG_DWORD
    "DisableMonitoredFenceGpuVa" = 0;
    "DisableMultiSourceMPOCheck" = 0;
    "DisableOverlays" = 0;
    "DisablePagingContextGpuVa" = 0;
    "DisableSecondaryIFlipSupport" = 0;
    "DriverManagesResidencyOverride" = 1;
    "DriverStoreCopyMode" = 1;
    "EnableBasicRenderGpuPv" = 0;
    "EnableDecodeMPO" = 1;
    "EnableFbrValidation" = 1;
    "EnableMultiPlaneOverlay3DDIs" = 0;
    "EnableOfferReclaimOnDriver" = 1;
    "EnablePanelFitterSupport" = 0;
    "EnableTimedCalls" = 0;
    "EnableWDDM23Synchronization" = 0;
    "Force32BitFences" = 0;
    "ForceDirectFlip" = 0;
    "ForceEnableDxgMms2" = 0;
    "ForceExplicitResidencyNotification" = 0; // REG_DWORD
    "ForceInitPagingProcessVaSpace" = 0;
    "ForceReplicateGdiContent" = 0;
    "ForceSecondaryIFlipSupport" = 0;
    "ForceSecondaryMPOSupport" = 0;
    "ForceSurpriseRemovalSupport" = 0;
    "ForceVariableRefresh" = 0;
    "GdiPhysicalAdapterIndex" = 0;
    "GpuPriorityChangeMode" = 1;
    "HighPriorityCompletionMode" = 1;
    "InitialPagingQueueFenceValue" = 7000;
    "IoMmuFlags" = 0;
    "KnownProcessBoostMode" = 1;
    "LeanMemoryLimit" = ?; // REG_QWORD
    "NumVirtualFunctions" = 0;
    "SmallQuantumMode" = 1;

    "DefaultActiveIdleThreshold" = 2000;
    "DefaultD3TransitionIdleLongTimeThreshold" = 60000;
    "DefaultD3TransitionIdleShortTimeThreshold" = 10000;
    "DefaultD3TransitionIdleVeryLongTimeThreshold" = 60000;
    "DefaultD3TransitionLatencyActivelyUsed" = 80;
    "DefaultD3TransitionLatencyIdleLongTime" = 140000;
    "DefaultD3TransitionLatencyIdleMonitorOff" = 250000;
    "DefaultD3TransitionLatencyIdleNoContext" = 250000;
    "DefaultD3TransitionLatencyIdleShortTime" = 80000;
    "DefaultD3TransitionLatencyIdleVeryLongTime" = 200000;
    "DefaultExpectedResidency" = 2000;
    "DefaultIdleThresholdIdle0" = 200;
    "DefaultIdleThresholdIdle0MonitorOff" = 100;
    "DefaultLatencyToleranceIdle0" = 80;
    "DefaultLatencyToleranceIdle0MonitorOff" = 2000;
    "DefaultLatencyToleranceIdle1" = 15000;
    "DefaultLatencyToleranceIdle1MonitorOff" = 50000;
    "DefaultLatencyToleranceMemory" = 15000;
    "DefaultLatencyToleranceMemoryNoContext" = 30000;
    "DefaultLatencyToleranceNoContext" = 35000;
    "DefaultLatencyToleranceNoContextMonitorOff" = 100000;
    "DefaultLatencyToleranceOther" = -1;
    "DefaultLatencyToleranceTimerPeriod" = 200;
    "DefaultMemoryRefreshLatencyToleranceActivelyUsed" = 80;
    "DefaultMemoryRefreshLatencyToleranceIdleShortTime" = 15000;
    "DefaultMemoryRefreshLatencyToleranceMonitorOff" = 80000;
    "DefaultMemoryRefreshLatencyToleranceNoContext" = 30000;
    "DefaultPowerNotRequiredTimeout" = 25000;
    "DisableDevicePowerRequired" = 0;
    "DisablePStateManagement" = 0;
    "EnablePODebounce" = 0;
    "EnableRuntimePowerManagement" = 1;
    "lowdebounce" = 3;
    "MonitorLatencyTolerance" = 300000;
    "MonitorRefreshLatencyTolerance" = 17000;
    "uglitch" = 900;
    "uhigh" = 700;
    "uideal" = 500;
    "ulow" = 300;

    "AllowAdvancedEtwLogging" = 0;
    "DiagnosticsBufferExpansionTime" = 300;
    "EnableFuzzing" = 0;
    "EnableHMDTestMode" = 0;
    "EnableIgnoreWin32ProcessStatus" = 0;
    "ExternalDiagnosticsBufferMultiplier" = 1;
    "ExternalDiagnosticsBufferSize" = 16384;
    "ForceUsb4MonitorSupport" = 0;
    "InternalDiagnosticsBufferMultiplier" = 2;
    "InternalDiagnosticsBufferSize" = 65536;
    "InvestigationDebugParameter" = 0;
    "MaximumAdapterCount" = 32;
    "NodeUsageTelemetryTimerInterval" = ?; // REG_DWORD
    "PreserveFirmwareMode" = 0;
    "PreventFullscreenWireFormatChange" = 0;
    "RapidHpdMaxChainInMilliseconds" = 0;
    "RapidHpdTimeoutInMilliseconds" = 0;
    "TerminationListSizeLimit" = 67108864;
    "TreatUsb4MonitorAsNormal" = 0;
    "Usb4MonitorDpcdDP_IN_Adapter_Number" = 0;
    "Usb4MonitorDpcdUSB4_Driver_ID" = 0;
    "Usb4MonitorPowerOnDelayInSeconds" = 0;
    "Usb4MonitorTargetId" = 0;
    "ValidateWDDMCaps" = 0;
    "WDDM2LockManagement" = 1;

    "DisableVaBackedVm" = 0;
    "DisableVersionMismatchCheck" = 0;
    "GpuVirtualizationFlags" = ?; // REG_DWORD
    "LimitNumberOfVfs" = 0;
    "VirtualGpuOnly" = 0;

    "ForceBddFallbackOnly" = ?;
    "HwSchMode" = ?;
    "HwSchOverrideBlockList" = ?;
    "HwSchTreatExperimentalAsStable" = ?;
    "MiracastDefaultRtspPort" = ?;
    "PlatformSupportMiracast" = ?;
    "SupportMultipleIntegratedDisplays" = ?;
    "SuspendAdapterTimerPeriod" = ?;

    "EnableExperimentalRefreshRates" = 0;
    "RapidHPDThresholdCount" = 5;
    "RapidHPDTime" = 1000;

    // https://www.noverse.dev/docs/win-config/security/increase-tdr/
    "TdrDdiDelay" = 5;
    "TdrDebugMode" = 2;
    "TdrDelay" = 2;
    "TdrDodPresentDelay" = 2;
    "TdrDodVSyncDelay" = 2;
    "TdrLevel" = 3;
    "TdrLimitCount" = 5;
    "TdrLimitTime" = 60;

    "DRTTestEnable" = 0; // 1484026436 = Enabled ?
    "EnableAcmSupportDeveloperPreview" = 0;
    "ForceEnableDWMClone" = ?; // REG_DWORD, default is adapter capability flag
    "HybridInternalPanelOverrideEnable" = 0;
    "IsInternalRelease" = 0;
    "MultiMonSupport" = 1;
    "OutputDuplicationSessionApplicationLimit" = 4;
    "TdrTestMode" = 0;
    "UnsupportedMonitorModesAllowed" = ?;

    "PageFaultDebugMode" = 1; // REG_DWORD, missing/invalid or >1 -> 1

    // from procmon boot trace
    "DisableCABC" = ?;
    "ForceAccessedPhysically" = ?;
    "ForceToMapGpuVa" = ?;
    "WarpOverrideWDDMVersion" = ?;
    "WarpSupportHybridDiscrete" = ?;
    "WarpSupportsResourceResidency" = ?;

    // miscellaneous
    "CddBootImageMode" = ?;
    "CddBootScreenMode" = ?;
    "DisableLddmSpriteTearDown" = ?;
    "DisplayBrokerShouldNotBeActive" = ?;
    "DODPreferredPresentMoveRegeionsOverride" = ?;
    "DxgKrnlVersion" = ?;
    "MinDxgKrnlVersion" = ?;

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Scheduler";
    "AdjustWorkerThreadPriority" = 1; // REG_DWORD
    "AudioDgAutoBoostPriority" = 24; // REG_DWORD, found in 25H2 (not in 23H2)
    "AutoSyncToCPUPriority" = 0; // REG_DWORD
    "BackgroundProcessMaximumAllowedPreemptionDelay" = 8; // REG_DWORD
    "CarryOverUsedQuantum" = 0; // REG_DWORD
    "ContextSchedulingPenaltyDelay" = 1000; // REG_DWORD
    "CountFlipTowardHwLimit" = 0; // REG_DWORD
    "CountPresentTowardHwLimit" = 0; // REG_DWORD
    "DdiSuspendMode" = 0; // REG_DWORD, values 0-2, found in 23H2 (not in 25H2)
    "DebugLargeSmoothenedDuration" = 1; // REG_DWORD, found in 25H2 (not in 23H2)
    "EnableContextDelay" = 1; // REG_DWORD, found in 23H2 (not in 25H2)
    "EnableDirectSubmission" = ?; // REG_DWORD, found in 25H2 (not in 23H2), default from adapter cap
    "EnableFlipImmediateSwFlipQueue" = 1; // REG_DWORD, found in 23H2 (not in 25H2)
    "EnablePreemption" = 1; // REG_DWORD
    "FlipDoNotFlipMode" = 0; // REG_DWORD, values 0-2
    "FlipOverrideMode" = 0; // REG_DWORD, 1 or 2 override device mode
    "ForceEnableFlipFenceModel" = 0; // REG_DWORD
    "ForceFlipTrueImmediateMode" = 0; // REG_DWORD, values 0-2
    "ForegroundPriorityBoost" = 1; // REG_DWORD
    "FrameServerAutoBoostPriority" = 17; // REG_DWORD, found in 25H2 (not in 23H2)
    "HistoryLogSize" = 64; // REG_DWORD, clamped 16-0x10000, must be 16, 32, 64, 128, ... (doubling sequence)
    "HwQueuedRenderPacketGroupLimit" = 2; // REG_DWORD
    "HwQueuePacketCap" = ?; // REG_DWORD, default from adapter cap, clamped 1-14
    "HwSchThreadOffloadMode" = 2; // REG_DWORD, found in 25H2 (not in 23H2)
    "InitDriverFenceId" = 0; // REG_DWORD
    "LogDriverVSyncCallback" = 0; // REG_DWORD, found in 23H2 (not in 25H2)
    "MaxFocusGpuQuantumWithoutPresent" = 100; // REG_DWORD, 25H2 default 10 when flag set
    "MaximumAllowedPreemptionDelay" = 900; // REG_DWORD
    "MaxYieldInterval" = 16; // REG_DWORD
    "MinYieldInterval" = 8000; // REG_DWORD, found in 25H2 (not in 23H2)
    "NpuContextSwitchQuantum" = 30000; // REG_DWORD, found in 25H2 (not in 23H2)
    "NpuPreemptionQuantum" = 60000; // REG_DWORD, found in 25H2 (not in 23H2)
    "NumberOfDmaPacketPool" = 20; // REG_DWORD
    "PerSourceCustomDuration" = ?; // REG_DWORD, default 1 when adapter version >= 2000
    "PfnCpuOverride" = 0; // REG_DWORD, values 0-3
    "PreemptionQuantumUnit" = 50000; // REG_DWORD
    "ProfileLevel" = 2; // REG_DWORD
    "QuantumUnit" = 25000; // REG_DWORD
    "QueuedPresentLimit" = 3; // REG_DWORD
    "VSyncIdleTimeout" = 7; // REG_DWORD, becomes 1 when adapter version >= 1300 and flag set, <1300 min 4
    "YieldPercentage" = 10; // REG_DWORD, valid 1-0x53 else default 10

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\MemoryManager";
    // ReadConfiguration
    "BugcheckOnApertureCorruption" = 0; // REG_DWORD
    "CommitProcessHeapOnDemand" = 1; // REG_DWORD
    "DirectFlipMemoryRequirement" = 200; // REG_DWORD
    "DisablePrefetching" = 0; // REG_DWORD
    "DmaBufferBytesLimitAllDevices" = 0x800000; // REG_DWORD, 0x2000000 if system memory > 0x20000000
    "DmaBufferListBytesLimitAllDevices" = 0x400000; // REG_DWORD, 0x1000000 if system memory > 0x20000000
    "EventThrottleThreshold" = 300; // REG_DWORD
    "EvictTemporaryPeriod" = 60; // REG_DWORD
    "EvictUnusedPeriod" = 60; // REG_DWORD
    "ExcessiveMemTransferFlipThreshold" = 15; // REG_DWORD
    "ExcessiveMemTransferPenalty" = 5; // REG_DWORD
    "MaxSegmentSize<0-31>" = 0; // REG_DWORD, if set, aligns to 4K and clamps to 0x800000
    "MemTransferThreshold" = 10; // REG_DWORD
    "NbCddDmaBufferLimitPerDevice" = 4; // REG_DWORD
    "NbDmaBufferLimitCompareWatermark" = 10; // REG_DWORD
    "NbDmaBufferLimitPerDevice" = 256; // REG_DWORD, 1024 if system memory > 0x20000000
    "NbPagingHistoryRecords" = 0; // REG_DWORD, 0x40 if internal release
    "PagesHistory" = 0; // REG_DWORD, max 0x7FFFFFF
    "PinDWMAllocationBackingStore" = 1; // REG_DWORD
    "PinnedApertureMemoryLimit" = 40; // REG_DWORD, >= 0x5A -> default 40
    "PinnedMemoryLimit" = 25; // REG_DWORD, >= 0x5A -> default 25
    "PrivateHeapPackingBlockSize" = 0x800000; // REG_DWORD
    "PrivateHeapPackingThreshold" = 0x100000; // REG_DWORD
    "ProcessPendingOfferPeriod" = 1; // REG_DWORD
    "ProcessSysmemOfferPeriod" = 8; // REG_DWORD
    "QuickApertureCorruptionCheck" = 0; // REG_DWORD
    "RemovePagesFromWorkingSetOnPagingForDwm" = 1; // REG_DWORD
    "SegmentBalancingPolicy" = 2; // REG_DWORD
    "SegmentCleanupCountThreshold" = 6; // REG_DWORD
    "SegmentCleanupSizeThreshold" = 4096; // REG_DWORD
    "SegmentCleanupTime" = 20; // REG_DWORD
    "SelfRefreshVramForceEvictionTimer" = 900; // REG_DWORD
    "UseUnreset" = 1; // REG_DWORD

    // unsure about the decomp defaults here
    "PhysicalHeapHighestAddress" = ?; // REG_QWORD
    "PhysicalHeapLowestAddress" = ?; // REG_QWORD
    "PhysicalHeapSize" = ?; // REG_QWORD

    // ReadCommitLimitInformation
    "MinimumSystemMemoryCommitLimit" = 0; // REG_DWORD, MB (<< 20), min 0x4000000
    "PinnedBackingStoreLimit" = 0; // REG_DWORD, MB (<< 20), 0 -> system memory / 8
    "SecondaryPartitionCommitLimitPercentage" = 80; // REG_DWORD, clamped to 5-100
    "SmallSystemMemorySize" = 0; // REG_DWORD, MB (<< 20)
    "SystemPartitionCommitLimitPercentage" = 50; // REG_DWORD, clamped to 5-100

    // ReadWorkingSetConfiguration
    "WorkingSet.DefaultMaximumPercentile" = 90; // REG_DWORD
    "WorkingSet.DefaultMinimumPercentile" = 65; // REG_DWORD

    // ReadUnusedAllocationConfiguration
    "Unused.EvictApertureOfferHighThreshold" = 30; // REG_DWORD
    "Unused.EvictApertureOfferLowThreshold" = 15; // REG_DWORD
    "Unused.EvictApertureOfferMaximumThreshold" = 30; // REG_DWORD
    "Unused.EvictApertureOfferNormalThreshold" = 15; // REG_DWORD
    "Unused.HighThreshold" = 120; // REG_DWORD
    "Unused.LowThreshold" = 15; // REG_DWORD
    "Unused.MaximumThreshold" = 1000000; // REG_DWORD
    "Unused.MinimumThreshold" = 0; // REG_DWORD
    "Unused.NormalThreshold" = 45; // REG_DWORD
    "Unused.SelfTrimHighThreshold" = 5; // REG_DWORD
    "Unused.SelfTrimLowThreshold" = 1; // REG_DWORD
    "Unused.SelfTrimMaximumThreshold" = 1000000; // REG_DWORD
    "Unused.SelfTrimMinimumThreshold" = 0; // REG_DWORD
    "Unused.SelfTrimNormalThreshold" = 2; // REG_DWORD
    "UnusedTrimmingPeriod" = 1; // REG_DWORD

    // ReadPreparationPeriodConfiguration
    "Period.AlwaysForceMemReset" = 1; // REG_DWORD
    "Period.EvictionThresholdForMemReset" = 32; // REG_DWORD, post query << 20
    "Period.MaximumPolicyHeldPeriod" = 64; // REG_DWORD
    "Period.MinimumPolicyHeldPeriod" = 4; // REG_DWORD
    "Period.NbOfAllocationsThresholdToMRU" = 0x7FFFFFFF; // REG_DWORD
    "PreparationPeriod" = 1; // REG_DWORD, scaled to 100ns

    // ReadHeapConfiguration
    "DebouncedDecommitAge" = 15; // REG_DWORD
    "DebouncedPageManagement" = 1; // REG_DWORD
    "DebouncedUnlockAge" = 15; // REG_DWORD
    "LeanRecycleHeapPackingBlockSize" = 8; // REG_DWORD
    "LeanRecycleHeapPackingThreshold" = 4; // REG_DWORD
    "LeanRecycleHeapPTDBlockSize" = 64; // REG_DWORD
    "MaximumDecommitDebounce" = 256; // REG_DWORD, 64 if system memory <= 0x53333333
    "MaximumUnlockDebounce" = 256; // REG_DWORD, 64 if system memory <= 0x53333333
    "RecycleHeapPackingBlockSize" = 32; // REG_DWORD
    "RecycleHeapPackingThreshold" = 4; // REG_DWORD
    "RecycleHeapPTDBlockSize" = 1024; // REG_DWORD
    "RecycleHistory" = 0; // REG_DWORD
    "RecycleHistorySize" = 64; // REG_DWORD
    "ZeroedRecyclePages" = 1; // REG_DWORD
    "ZeroPageLockThreshold" = 0x200000; // REG_DWORD, found in 25H2 (not in 23H2)

    // ReadPowerConfiguration
    "MemoryComponentActiveThreshold" = 300; // REG_DWORD, MB (<< 20)
    "SelfRefreshMemoryEvictionThreshold" = 300; // REG_DWORD, MB (<< 20)

    // ReadGpuVaConfiguration
    "AllocateGpuVaFromHighAddresses" = 0; // REG_DWORD
    "CompanionContextMaxPendingOperations" = 128; // REG_DWORD, found in 25H2 (not in 23H2)
    "DisableMakeIoMmuAddressValid" = 0; // REG_DWORD
    "DisableUncommitGpuVaInPagingProcess" = 0; // REG_DWORD
    "EnableGpuVaGuardPages" = 0; // REG_DWORD
    "EnableZeroFlagInPde" = 0; // REG_DWORD
    "GpuVaFirstValidAddress" = 0x10000; // REG_DWORD, masked to 4K
    "PagingProcessVaSpaceBitCount" = 30; // REG_DWORD

    // ReadGpuVaPagingHistoryConfiguration
    "GpuVaPagingHistoryMask" = 391174; // REG_DWORD, derived, min 0x1000
    "GpuVaPagingHistorySize" = ?; // REG_DWORD, default 0x40 if system memory > 0x53333333 else 0

    // ReadPagingConfiguration
    "BreakOnPagingFailure" = 0; // REG_DWORD
    "DemotionWithinDeviceEnabled" = 1; // REG_DWORD
    "DeviceResumePeriodMax" = 1000; // REG_DWORD
    "DeviceResumePeriodMin" = 1000; // REG_DWORD
    "DeviceSuspendPeriodMax" = 500; // REG_DWORD
    "DeviceSuspendPeriodMin" = 500; // REG_DWORD
    "EnableAsyncResidency" = 1; // REG_DWORD
    "EnablePromotion" = 1; // REG_DWORD, found in 25H2 (not in 23H2)
    "ForceSynchronousEvict" = 0; // REG_DWORD
    "ForceUncommitGpuVAOnEvict" = 0; // REG_DWORD
    "InitialPromotionInterval" = 48; // REG_DWORD
    "MaximumPromotionInterval" = 5000; // REG_DWORD
    "PagingQueueProcessingPeriodTime" = 50; // REG_DWORD, clamped 16-300
    "PromotionNumberCapPerInterval" = 50; // REG_DWORD
    "PromotionTargetSizePerInterval" = 0x2000000; // REG_QWORD
    "TemporaryResourcePolicy" = 0; // REG_DWORD, found in 25H2 (not in 23H2)
    "TransferFlushThreshold" = 1; // REG_DWORD, MB (<< 20)

    // ReadTestAndStagingConfiguration
    "AlwaysDecommitOnOffer" = 0; // REG_DWORD
    "BudgetThreshold" = 25; // REG_DWORD, clamped to <= 100
    "DecommitRepurposeMode" = 1; // REG_DWORD, values 0-2 else 0, found in 23H2 (not in 25H2)
    "DxgMms2OfferReclaim" = 4294967295; // REG_DWORD, allowed 0/1/2/4294967295, others = 0
    "ExpandTo64KBAllocationSizeThreshold" = 0x400000; // REG_DWORD
    "LargifyUpgradeThresholdBytes" = 0; // REG_DWORD, found in 25H2 (not in 23H2)
    "LargifyUpgradeThresholdPercent" = 0; // REG_DWORD, found in 25H2 (not in 23H2)
    "LazyDecommitChunkSizeMB" = 32; // REG_DWORD, max 512
    "PagingQueueFenceIncrement" = 1; // REG_DWORD, 0 = 1, upper bound 0x51EB851
    "RestrictToPreferredSegment" = 0; // REG_DWORD
    "Use64KPages" = 0; // REG_DWORD

    // ReadVPRConfiguration
    "VPRCapacityRatioDenominator" = 5; // REG_DWORD, if denominator <= numerator or numerator == 0 -> 4/5
    "VPRCapacityRatioNumerator" = 1; // REG_DWORD
    "VPRGrowRatioDenominator" = 5; // REG_DWORD, if denominator <= numerator or numerator == 0 -> 4/5
    "VPRGrowRatioNumerator" = 4; // REG_DWORD

    // ReadBudgetConfiguration
    "CriticalPeriodicTrimThreshold" = 10; // REG_DWORD
    "EnableTrimWnfCallback" = 1; // REG_DWORD
    "ForegroundTrimInterval" = 90000; // REG_DWORD
    "GlobalCommitmentBudget" = 0; // REG_QWORD
    "IdleTrimInterval" = 90000; // REG_DWORD
    "L_LocalMemoryBudgetDWMTarget" = 30; // REG_DWORD
    "L_LocalMemoryBudgetFocusTarget" = 50; // REG_DWORD
    "LNL_LocalMemoryBudgetDWMTarget" = 30; // REG_DWORD
    "LNL_LocalMemoryBudgetFocusTarget" = 50; // REG_DWORD
    "LNL_NonLocalMemoryBudgetDWMTarget" = 30; // REG_DWORD
    "LNL_NonLocalMemoryBudgetFocusTarget" = 50; // REG_DWORD
    "MaximumTrimInterval" = 10000; // REG_DWORD
    "MaxProcessBudgetCapBuffer" = 256; // REG_DWORD
    "MaxVideoMemoryFragmentationBuffer" = 512; // REG_DWORD
    "MinimumTrimInterval" = 2000; // REG_DWORD
    "ProcessBudgetCapBuffer" = 5; // REG_DWORD
    "StartPeriodicTrimThreshold" = 40; // REG_DWORD
    "SystemMemoryFragmentationBuffer" = 5; // REG_DWORD
    "VideoMemoryFragmentationBuffer" = 10; // REG_DWORD

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Power";
    "UseSelfRefreshVRAMInS3" = 1;

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\BasicDisplay";
    "BasicDisplayUserNotified" = 0;

    "DisableBasicDisplayFallback" = ?;
    "EnableBasicDisplayFallback" = ?;
    "ForcePreserveBootDisplay" = ?;

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Smm";
    "DebugMode" = 0;
    "EnablePageTracking" = 0;
    "ForceDmaRemapping" = 0;
    "ForceEnableIommu" = 0;
    "IdentityMappedPassthrough" = 0;
    "LogicalAddressMode" = 0;
    "PreferHighLogicalAddresses" = 0;

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\DMM";
    "AssertOnDdiViolation" = 0;
    "BadMonitorModeDiag" = 2;

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\DMM";
    "EnableVirtualRefreshRateOnExternalMonitor" = 0;
    "HPDFilterLimit" = 20000000;
    "LongLinkTrainingTimeout" = 1000;
    "ModeListCaching" = 1;
    "SetTimingsFlags" = 0;
    "ShortLinkTrainingTimeout" = 200;

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Validation";
    "FailEscapeDDI" = 0;
    "FailRenderDDI" = 0;
    "FailReserveGPUVA" = 0;
    "Level" = 0;
    "ReportVirtualMachine" = 0;

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\MonitorDataStore\\MONITOR-ID"
    "AdvancedColorEnabled" = 0;
    "AutoColorManagementEnabled" = 0;
    "AutoColorManagementSupported" = ?; // REG_DWORD, bool?
    "DockedOrientation" = ?;
    "EnableBoostRefreshRateByDefault" = ?;
    "EnableIntegratedPanelAcmByDefault" = 0;
    "EnableIntegratedPanelHdrByDefault" = 0;
    "HDREnabled" = 0;
    "MicrosoftApprovedAcmSupport" = 0;
    "MonitorOrientation" = ?;
    "OverrideWCGCapabilities" = ?;
    "PreferredScaleFactor" = ?;
    "SDRWhiteLevel" = ?;
    "VMSDisabled" = ?;

// the 3 keys below are based on a testing system monitor, therefore the defaults will be different for you

"HKLM\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration"; // from LGPE
    "DefaultCloneResolutionSetting" = 0; // range 0 (default), 1 (internal), 2 (external), "Set Cloned Monitor Preferred Resolution Source", "Enabling this policy allows to override the default behavior when connecting an additional monitor. It allows control over whether a cloned display prioritizes the internal or external monitor i.e. setting its preferred resolution source. Internal sets the resolution of the main display as the source on both screens. External sets the resolution of the connected (external) display as the source on both screens. Default uses the system's default behavior determined by Windows Settings." This policy is supported on 24H2+

"HKLM\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration\\<CONFIG_ID>";
    "SetId" = ?; // REG_SZ
    "Timestamp" = ?; // REG_QWORD

"HKLM\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration\\<CONFIG_ID>\\00\\00";
    "ActiveSize.cx" = ?; // REG_DWORD, horizontal pixels
    "ActiveSize.cy" = ?; // REG_DWORD, vertical lines
    "BoostRefreshRateMultiplier" = ?; // REG_DWORD
    "ColorBasis" = ?; // REG_DWORD
    "DwmClipBox.bottom" = ?; // REG_DWORD
    "DwmClipBox.left" = ?; // REG_DWORD
    "DwmClipBox.right" = ?; // REG_DWORD
    "DwmClipBox.top" = ?; // REG_DWORD
    "Flags" = ?; // REG_DWORD
    "HSyncFreq.Denominator" = ?; // REG_DWORD
    "HSyncFreq.Numerator" = ?; // REG_DWORD
    "PixelFormat" = ?; // REG_DWORD
    "PixelRate" = ?; // REG_DWORD
    "PrimSurfSize.cx" = ?; // REG_DWORD
    "PrimSurfSize.cy" = ?; // REG_DWORD
    "Rotation" = ?; // REG_DWORD
    "Scaling" = ?; // REG_DWORD
    "ScanlineOrdering" = ?; // REG_DWORD
    "Stride" = ?; // REG_DWORD
    "VideoStandard" = ?; // REG_DWORD
    "VirtualRefreshRate.Denominator" = ?; // REG_DWORD
    "VirtualRefreshRate.Numerator" = ?; // REG_DWORD
    "VSyncFreq.Denominator" = ?; // REG_DWORD
    "VSyncFreq.Numerator" = ?; // REG_DWORD, refresh rate

"HKLM\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration\\<CONFIG_ID>\\00";
    "CcdDbVersion" = ?; // REG_DWORD
    "ColorBasis" = ?; // REG_DWORD
    "PixelFormat" = ?; // REG_DWORD
    "Position.cx" = ?; // REG_DWORD
    "Position.cy" = ?; // REG_DWORD
    "PrimSurfSize.cx" = ?; // REG_DWORD
    "PrimSurfSize.cy" = ?; // REG_DWORD
    "Stride" = ?; // REG_DWORD
```

## RegistryMachin_* Keys

These are from `dxgkrnl.sys`. Looking at xrefs of these names is sometimes a start point when trying to find values within a binary or to see what keys are somewhere used, therefore I'm adding it (note that `aRegistryMachin_*` are IDA generated names so you won't find them in strings, nor will they be the exact same for you unless you disassemble the same binary build version).

```c
// dxgkrnl.sys
aRegistryMachin = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\DWM"
aRegistryMachin_0 = "\\Registry\\Machine\\Software\\Microsoft\\Shell\\Docking"
aRegistryMachin_1 = "\\Registry\\Machine\\System\\Platform\\DeviceTargetingInfo"
aRegistryMachin_2 = "\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
aRegistryMachin_3 = "\\Registry\\Machine\\"
aRegistryMachin_4 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\MultiScreen"
aRegistryMachin_5 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\BlockList\\Runtime"
aRegistryMachin_6 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\BlockList\\Kernel"
aRegistryMachin_7 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class"
aRegistryMachin_8 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Theme"
aRegistryMachin_9 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers"
aRegistryMachin_10 = "\\REGISTRY\\MACHINE\\OSDATA\\Software\\Microsoft\\Durango\\LiveSettings\\HevcOverride"
aRegistryMachin_11 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\Connectivity\\"
aRegistryMachin_12 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration\\"
aRegistryMachin_13 = "\\REGISTRY\\MACHINE\\System\\ControlSet001\\Control\\Terminal Server\\WinStations"
aRegistryMachin_14 = "\\Registry\\Machine\\Software\\Microsoft\\DirectX"
aRegistryMachin_15 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\BreakOnBadEDID"
aRegistryMachin_16 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\MiniNT"
aRegistryMachin_17 = "\\Registry\\Machine\\Software\\Microsoft\\PolicyManager\\current\\Experience"
aRegistryMachin_18 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Video\\"
aRegistryMachin_19 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\MonitorDataStore"
aRegistryMachin_20 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\AdditionalModeLists\\"
aRegistryMachin_21 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\Dwm"
aRegistryMachin_22 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\FeatureSetUsage"
aRegistryMachin_23 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\InternalMonEdid"
aRegistryMachin_24 = "\\Registry\\Machine\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\PackageRepository\\Packages"
aRegistryMachin_25 = "\\Registry\\Machine\\System"
aRegistryMachin_26 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations"
```

# MMCSS Values

Everything below is based on the 11-23H2 mmcss driver pseudocode (see [bin-diff](https://www.noverse.dev/bin-diff.html?left=11-23H2&right=11-25H2&module=mmcss&function=CiConfigInitialize.c&mode=side-by-side) if you want to see changes on newer builds), means that I haven't looked at live behaviours of values yet (excluding MMCSS Boost section) which will be included somewhat soon.

> "*The Multimedia Class Scheduler service (MMCSS) enables multimedia applications to ensure that their time-sensitive processing receives prioritized access to CPU resources. This service enables multimedia applications to utilize as much of the CPU as possible without denying CPU resources to lower-priority applications.*
>
> *MMCSS uses information stored in the registry to identify supported tasks and determine the relative priority of threads performing these tasks. Each thread that is performing work related to a particular task calls the [AvSetMmMaxThreadCharacteristics](https://learn.microsoft.com/en-us/windows/win32/api/avrt/nf-avrt-avsetmmmaxthreadcharacteristicsa) or [AvSetMmThreadCharacteristics](https://learn.microsoft.com/en-us/windows/win32/api/avrt/nf-avrt-avsetmmthreadcharacteristicsa) function to inform MMCSS that it is working on that task.*"
>
> — Microsoft, [Multimedia Class Scheduler Service](https://learn.microsoft.com/en-us/windows/win32/procthread/multimedia-class-scheduler-service)

The MMCSS scheduler thread is set to priority `27`, as it must preempt Pro Audio threads so it can lower them to the exhausted category when their guaranteed period is over.

```c
// CiSchedulerThreadFunction
CurrentThread = KeGetCurrentThread();
CiThreadsMovedUp = 1;
CiSchedulerThread = CurrentThread;
CiSchedulerInLazyMode = 0;
KeSetActualBasePriorityThread(CurrentThread, 27LL); // worker priority
```

![](https://github.com/nohuto/win-config/blob/main/system/images/mmcssprio.png?raw=true)

## Registry Values

All values below are read via [`CiConfigReadDWORD`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/mmcss/CiConfigReadDWORD.c), means the accepted type is `REG_DWORD`.  The values shown below are fallbacks used when the value is missing/not in range/not a `REG_DWORD` (`SystemResponsiveness` = `20`, `NetworkThrottlingIndex` = `10` exist on a new installation, so beside these the data listed below is used).

```c
"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile";
    "SystemResponsiveness" = 100; // clamped to 10-100, 100 disables MMCSS, <10 or >100 = 20
    "NetworkThrottlingIndex" = 10; // 0 = 1, 1-70 stay, 71-0xFFFFFFFE = 70, 0xFFFFFFFF disables NDIS throttle
    "NoLazyMode" = 0; // nonzero skips lazy mode idle detection
    "IdleDetectionCycles" = 2; // range 1-31
    "LazyModeTimeout" = 1000000; // 0 replaced with 1000000, no upper clamp?
    "SchedulerTimerResolution" = 10000; // values above 10000 capped to 10000
    "SchedulerPeriod" = 100000; // range 50000-1000000
    "MaxThreadsPerProcess" = 32; // range 8-128
    "MaxThreadsTotal" = 256; // range 64-65535
```

## SystemResponsiveness

If `SystemResponsiveness == 100`, [`CiConfigInitialize`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/mmcss/CiConfigInitialize.c) returns before the rest of the values and the `Tasks` key are read, it also prevents scheduler initialization later in [`CsInitialize`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/mmcss/CsInitialize.c), means as written above it disables MMCSS.

![](https://github.com/nohuto/win-config/blob/main/system/images/mmcss-10-100.png?raw=true)

For other values than 100, [`CiSchedulerInitialize`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/mmcss/CiSchedulerInitialize.c) splits `SchedulerPeriod` with `CiSystemResponsiveness`, see [`SchedulerPeriod`]() section for more details on that.

> "*Determines the percentage of CPU resources that should be guaranteed to low-priority tasks. For example, if this value is 20, then 20% of CPU resources are reserved for low-priority tasks. Note that values that are not evenly divisible by 10 are rounded down to the nearest multiple of 10. Values below 10 and above 100 are clamped to 20. A value of 100 disables MMCSS (driver returns `STATUS_SERVER_DISABLED`).*"
>
> — Microsoft, [Multimedia Class Scheduler Service](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/ProcThread/multimedia-class-scheduler-service.md#registry-settings)

```c
// CiConfigInitialize
DWORD = CiConfigReadDWORD(KeyHandle, 0x1C0011090LL, 100LL); // SystemResponsiveness, fallback = 100
if ( DWORD - 10 > 0x5A )
  v2 = 20; // <10 or >100
else
  v2 = 10 * (DWORD / 0xA); // round down to multiple of 10
CiSystemResponsiveness = v2;

if ( CiSystemResponsiveness == 100 )
{
  v0 = -1073741696; // STATUS_SERVER_DISABLED
}
else
{
// values and Tasks
}
```

### Calculation

```c
CiSystemResponsiveness = 10 * (value / 10);

< 10 -> 20 // fallback since not in range
10-19 -> 10
20-29 -> 20
30-39 -> 30
40-49 -> 40
50-59 -> 50
60-69 -> 60
70-79 -> 70
80-89 -> 80
90-99 -> 90
== 100 -> 100 // STATUS_SERVER_DISABLED
> 100 -> 20 // fallback since not in range
```

## NetworkThrottlingIndex

> "*MMCSS functionality does not stop at simple priority boosting, however. Because of the nature of network drivers on Windows and the NDIS stack, DPCs are quite common mechanisms for delaying work after an interrupt has been received from the network card. Because DPCs run at an IRQL level higher than user-mode code, long-running network card driver code can still interrupt media playback—for example, during network transfers or when playing a game.*
>
> *MMCSS sends a special command to the network stack, telling it to throttle network packets during the duration of the media playback. This throttling is designed to maximize playback performance at the cost of some small loss in network throughput (which would not be noticeable for network operations usually performed during playback, such as playing an online game).*"
>
> — Windows Internals, [E7, P1: 'Priority boosts for multimedia applications and games'](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

```c
// CiConfigInitialize
v3 = CiConfigReadDWORD(KeyHandle, 0x1C00110A0LL, 10LL); // NetworkThrottlingIndex, fallback = 10
LODWORD(WPP_MAIN_CB.Dpc.DpcData) = v3;
v4 = v3;
if ( v3 )
{
  if ( (unsigned int)(v3 - 71) <= 0xFFFFFFB7 )
  {
    v4 = 70;
    LODWORD(WPP_MAIN_CB.Dpc.DpcData) = 70; // 71-0xFFFFFFFE = 70
  }
}
else
{
  v4 = 1;
  LODWORD(WPP_MAIN_CB.Dpc.DpcData) = 1; // 0 = 1
}
```

Note that [`CsInitialize`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/mmcss/CsInitialize.c) only opens the NDIS part when the value isn't `-1` and MMCSS wasn't disabled by `SystemResponsiveness == 100`.

```c
// CsInitialize
if ( LODWORD(WPP_MAIN_CB.Dpc.DpcData) != -1 && CiSystemResponsiveness != 100 )
{
  CiNdisThrottleWorkItem = IoAllocateWorkItem(CiDeviceObject);
  if ( CiNdisThrottleWorkItem )
    CiNdisOpenDevice();
}
```

## NoLazyMode

MMCSS samples CPU idle/starvation state and increases `CiProcessorIdleHistoryBits`, whenever the history reaches `(1 << IdleDetectionCycles) - 1` it enters lazy mode and uses `LazyModeTimeout` for lazy mode sleeps. Any nonzero value would set `CiSchedulerDisallowLazyMode` which skips that.

```c
// CiConfigInitialize
v5 = (unsigned __int8)CiConfigReadDWORD(KeyHandle, 0x1C0011080LL, 0LL) != 0;
CiSchedulerDisallowLazyMode = v5; // '!= 0' = DisallowLazyMode
```

```c
// CiSchedulerWait
if ( !CiSchedulerDisallowLazyMode )
{
// CPU idle stats, update CiProcessorIdleHistoryBits
}
```

## IdleDetectionCycles

[`CiSchedulerWait`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/mmcss/CiSchedulerWait.c) compares `CiProcessorIdleHistoryBits` against `CiSchedulerIdleCycleBitMask`, which should mean that larger values need more idle histories before lazy mode can be entered.

```c
// CiConfigInitialize
v6 = CiConfigReadDWORD(KeyHandle, 0x1C00110B0LL, 2LL); // fallback = 2
CiSchedulerIdleDetectionCycles = v6;
if ( (unsigned int)(v6 - 1) > 0x1E )
  CiSchedulerIdleDetectionCycles = 2; // range 1-31

CiSchedulerIdleCycleBitMask = (1 << CiSchedulerIdleDetectionCycles) - 1;
```

## LazyModeTimeout

Sleep duration used while MMCSS is in lazy mode.

```c
// CiConfigInitialize
HIDWORD(WPP_MAIN_CB.Dpc.DpcData) =
  CiConfigReadDWORD(KeyHandle, 0x1C00110C0LL, 1000000LL); // LazyModeTimeout, fallback = 1000000

if ( !HIDWORD(WPP_MAIN_CB.Dpc.DpcData) )
  HIDWORD(WPP_MAIN_CB.Dpc.DpcData) = 1000000; // 0 replaced
```

[`CiSchedulerWait`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/mmcss/CiSchedulerWait.c) passes this value to [`CiSchedulerSleep`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/mmcss/CiSchedulerSleep.c) when `CiSchedulerInLazyMode` is true.

```c
// CiSchedulerWait
if ( CiSchedulerInLazyMode )
{
  DpcData_high = HIDWORD(WPP_MAIN_CB.Dpc.DpcData); // LazyModeTimeout
  v4 = 2;
}

CiSchedulerSleep(v4, DpcData_high, v2);
```

## SchedulerTimerResolution

Clamps the requested yield/deadline times so they aren't shorter than this value, with `SchedulerTimerResolution = 10000` (`1 ms`), a request like `0.5 ms` is raised to `1 ms`, so the deadline/yield part won't schedule the thread back to its higher priority sooner than `1 ms` after the yield request ([`CiSchedulerTaskIndexYield`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/mmcss/CiSchedulerTaskIndexYield.c))? That's just a assumption for now.

> "*MMCSS also supports a feature called deadline scheduling. The idea is that an audio-playing program does not always need the highest priority level in its category. If such a program uses buffering (obtaining audio data from disk or network) and then plays the buffer while building the next buffer, deadline scheduling allows a client thread to indicate a time when it must get the high priority level to avoid glitches, but live with a slightly lower priority (within its category) in the meantime. A thread can use the AvTaskIndexYield function to indicate the next time it must be allowed to run, specifying the time it needs to get the highest priority within its category. Until that time arrives, it gets the lowest priority within its category, potentially freeing more CPU time to the system*"
>
> — Windows Internals, [E7, P1: 'Priority boosts for multimedia applications and games'](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

```c
// CiConfigInitialize
WPP_MAIN_CB.ActiveThreadCount =
  CiConfigReadDWORD(KeyHandle, 0x1C00110D0LL, 10000LL); // SchedulerTimerResolution, fallback = 10000

if ( WPP_MAIN_CB.ActiveThreadCount > 0x2710 ) // 0x2710 = 10000
  WPP_MAIN_CB.ActiveThreadCount = 10000; // upper clamp
```

## SchedulerPeriod

As the name says it's the MMCSS scheduler period where registered multimedia threads run at their category priority for a guaranteed part, then get lowered (`1-7`) so other threads can run.

```c
// CiConfigInitialize
v9 = CiConfigReadDWORD(KeyHandle, 0x1C00110E0LL, 100000LL); // SchedulerPeriod, fallback = 100000
*(&WPP_MAIN_CB.ActiveThreadCount + 1) = v9;
if ( (unsigned int)(v9 - 50000) > 0xE7EF0 )
  *(&WPP_MAIN_CB.ActiveThreadCount + 1) = 100000; // range 50000-1000000
```

Used by [`CiSchedulerInitialize`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/mmcss/CiSchedulerInitialize.c), where `SystemResponsiveness` splits the period into two durations:

```c
// CiSchedulerInitialize
HIDWORD(WPP_MAIN_CB.SecurityDescriptor) =
  SchedulerPeriod * CiSystemResponsiveness / 100; // exhausted duration

LODWORD(WPP_MAIN_CB.SecurityDescriptor) =
  SchedulerPeriod - SchedulerPeriod * CiSystemResponsiveness / 100; // boosted duration
```

With `SystemResponsiveness = 20` & `SchedulerPeriod = 100000`, this would mean:

```c
exhausted duration = 100000 * 20 / 100 = 20000
boosted duration = 100000 - (100000 * 20 / 100) = 80000
```

### Calculation Examples

> "*By default, multimedia threads get 80 percent of the CPU time available, while other threads receive 20 percent. (Based on a sample of 10 ms, that would be 8 ms and 2 ms, respectively.)*"
>
> — Windows Internals, [E7, P1: 'Priority boosts for multimedia applications and games'](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

The "*10 ms*" in that quote = `SchedulerPeriod = 100000`.

```c
// SchedulerPeriod = 100000 (default)
SystemResponsiveness = 10
exhausted = 100000 * 10 / 100 = 10000 // 1ms
boosted= 100000 - 10000 = 90000 // 9ms

SystemResponsiveness = 20
exhausted = 100000 * 20 / 100 = 20000 // 2ms
boosted= 100000 - 20000 = 80000 // 8ms

// SchedulerPeriod = 50000 (min)
SystemResponsiveness = 20
exhausted = 50000 * 20 / 100 = 10000 // 1ms
boosted= 50000 - 10000 = 40000 // 4ms

// SchedulerPeriod = 1000000 (max)
SystemResponsiveness = 20
exhausted = 1000000 * 20 / 100 = 200000 // 20ms
boosted= 1000000 - 200000 = 800000 // 80ms
```

## MaxThreadsPerProcess / MaxThreadsTotal

Limits how many MMCSS threads can exist, `MaxThreadsTotal` is checked against `CiTotalThreads` (MMCSS threads of all processes), `MaxThreadsPerProcess` after that against the MMCSS thread count of the current process.

```c
// CiConfigInitialize
v10 = CiConfigReadDWORD(KeyHandle, 0x1C00110F0LL, 32LL); // MaxThreadsPerProcess, fallback = 32
CiMaxThreadsPerProcess = v10;
if ( (unsigned int)(v10 - 8) > 0x78 )
  CiMaxThreadsPerProcess = 32; // range 8-128

v11 = CiConfigReadDWORD(KeyHandle, 0x1C0011100LL, 256LL); // MaxThreadsTotal, fallback = 256
CiMaxThreadsTotal = v11;
if ( (unsigned int)(v11 - 64) > 0xFFBF )
  CiMaxThreadsTotal = 256; // range 64-65535
```

[`CiTryIncrementTotalThreadCount`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/mmcss/CiTryIncrementTotalThreadCount.c) would return an error (`STATUS_TOO_MANY_THREADS`) whenever the count is at or above the maximum.

```c
// CiThreadCreate
v9 = CiTryIncrementTotalThreadCount(&CiTotalThreads, CiMaxThreadsTotal);

v9 = CiTryIncrementTotalThreadCount((volatile signed __int32 *)(v8 + 92), CiMaxThreadsPerProcess);
```

## Tasks

Task keys are read only if `SystemResponsiveness != 100` as already shown above. These are the default tasks:

- `Audio`
- `Capture`
- `Distribution`
- `Games`
- `Playback`
- `Pro Audio`
- `Window Manager`

### [Task Values](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/ProcThread/multimedia-class-scheduler-service.md#registry-settings)

| Value | Format | Possible values |
| --- | --- | --- |
| **Affinity** | `REG_DWORD` | A bitmask that indicates the processor affinity. Both `0x00` and `0xFFFFFFFF` indicate that processor affinity is not used. |
| **Background Only** | `REG_SZ` | Indicates whether this is a background task (no user interface). The threads of a background task do not change because of a change in window focus. This value can be set to `True` or `False`. |
| **BackgroundPriority** | `REG_DWORD` | The background priority. The range of values is `1-8`. |
| **Clock Rate** | `REG_DWORD` | A hint used by MMCSS to determine the granularity of processor resource scheduling. **Windows Server 2008 and Windows Vista:** The maximum guaranteed clock rate the system uses if a thread joins this task, in 100-nanosecond intervals. Starting with Windows 7 and Windows Server 2008 R2, this guarantee was removed to reduce system power consumption.<br/> |
| **GPU Priority** | `REG_DWORD` | The GPU priority. The range of values is `0-31`. This priority is not yet used. |
| **Priority** | `REG_DWORD` | The task priority. The range of values is `1` (low) to `8` (high). For tasks with a **Scheduling Category** of High, this value is always treated as `2`. |
| **Scheduling Category** | `REG_SZ` | The scheduling category. This value can be set to High, Medium, or Low. |
| **SFIO Priority** | `REG_SZ` | The scheduled I/O priority. This value can be set to Idle, Low, Normal, or High. This value is not used. |

Some additional notes:
- `Clock Rate` range `5000-10000`, default of `10000`
- `Latency Sensitive` (`REG_SZ`, can be `True`/`False`) also exists (is visible in logging), but I didn't find any point where this is used
- `Priority When Yielded` (`REG_DWORD`) range `1-19`, default of `16`

### Boosted/Exhausted Priorities

This part `For tasks with a Scheduling Category of High, this value is always treated as 2.` doesn't refer to the exhausted priority, only to the boosted priority. `Priority` gets stored as `prio - 1`, means 2 = 1, 3 = 2 etc., value 1 (which would be 0) gets clamped to 1 when calculating the exhausted priority. This doesn't mean that 1 and 2 are the same (they've the same exhaused priority), but boosted priority still differs.

The boosted priority gets calculated using the `Scheduling Category` and the `Priority` value (after subtraction), so if using category `Medium` + priority of `6` the boosted priority would be `16 + 5 = 21`. If using category `High` and `Priority = 6`, the exhausted priority would be `5`, but the boosted base is forced to `24` (by [`CiConfigTaskPolicy`](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/mmcss/CiConfigTaskPolicy.c)). Relative priority can then move that boosted value within `23-26` (see [relative-priorities]()), means:

```c
// Low/Medium
boosted = categoryBase + (Priority - 1) + relativePriority

// High
boosted = 24 // with relative priority it can be 23-26
```

### [Thread Priorities](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/ProcThread/multimedia-class-scheduler-service.md#thread-priorities)

The MMCSS boosts the priority of threads that are working on high-priority multimedia tasks. MMCSS determines the priority of a thread using the following factors:

- The base priority of the task.
- The *Priority* parameter of the [**AvSetMmThreadPriority**](/windows/desktop/api/Avrt/nf-avrt-avsetmmthreadpriority) function.
- Whether the application is in the foreground.
- How much CPU time is being consumed by the threads in each category.

MMCSS sets the priority of client threads depending on their scheduling category.

| Category | Priority | Description |
| --- | --- | --- |
| High | 23-26 | These threads run at a thread priority that is lower than only certain system-level tasks. This category is designed for Pro Audio tasks. |
| Medium | 16-22 | These threads are part of the application that is in the foreground. |
| Low | 8-15 | This category contains the remainder of the threads. They are guaranteed a minimum percentage of the CPU resources if required. |
| | 1-7 | These threads have used their quota of CPU resource. They can continue to run if no low-priority threads are ready to run. |

## Watching the MMCSS Boost

> "*The main mechanism behind MMCSS boosts the priority of threads inside a registered process to the priority level matching their scheduling category and relative priority within this category for a guaranteed period. It then lowers those threads to the exhausted category so that other, non-multimedia threads on the system can also get a chance to execute.*"
>
> *As discussed, changing the relative thread priorities within a process does not usually make sense, and no tool allows this because only developers understand the importance of the various threads in their programs. On the other hand, because applications must manually register with MMCSS and provide it with information about what kind of thread this is, MMCSS does have the necessary data to change these relative thread priorities—and developers are well aware that this will happen.*
>
> — Windows Internals, [E7, P1: 'Priority boosts for multimedia applications and games'](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

[`mmcss_task`](https://github.com/nohuto/win-config/blob/main/system/assets/mmcss_task) calls [`AvSetMmThreadCharacteristicsW`](https://learn.microsoft.com/en-us/windows/win32/api/avrt/nf-avrt-avsetmmthreadcharacteristicsw) for the used MMCSS task, optionally calls [`AvSetMmThreadPriority`](https://learn.microsoft.com/en-us/windows/win32/api/avrt/nf-avrt-avsetmmthreadpriority), then keeps the thread busy.

This follows the `EXPERIMENT: MMCSS priority boosting` guide of [Windows Internals E7, P1](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf), but uses `mmcss_task` instead of Media Player/CPUSTRES.

1. Download [mmcss_task](https://github.com/nohuto/win-config/blob/main/system/assets/mmcss_task.exe), or build it from [source](https://github.com/nohuto/win-config/blob/main/system/assets/mmcss_task):
2. Run it with the MMCSS task you want to test, e.g.:

```powershell
.\mmcss_task.exe Audio
```

3. Start Performance Monitor & set it's priority class to `Realtime`
4. In Performance Monitor, click `Add Counter` or press `Ctrl+I`
5. Select the `Thread` object, then add `Priority Current`
6. In `Instances`, search for `mmcss_task` and select `mmcss_task/0`
7. Open graph properties and set the maximum vertical scale to `32`
8. Watch `Priority Current`

You can also change the relative priority by adding an argument (the number):

```h
// avrt.h

typedef enum _AVRT_PRIORITY
{
    AVRT_PRIORITY_VERYLOW = -2,
    AVRT_PRIORITY_LOW, // -1
    AVRT_PRIORITY_NORMAL, // 0 or nothing
    AVRT_PRIORITY_HIGH, // 1
    AVRT_PRIORITY_CRITICAL // 2
} AVRT_PRIORITY, *PAVRT_PRIORITY;
```

[MS doc](https://learn.microsoft.com/en-us/windows/win32/api/avrt/nf-avrt-avsetmmthreadpriority) doesn't define `-2`, SDK does and it works so I'll leave it.

```powershell
.\mmcss_task.exe Audio 1
.\mmcss_task.exe Audio 2
```

### Relative Priorities

Example using `Scheduling Category = High` and `Priority = 6` (this would normally always use boosted priority of 24):

| Relative priority | Range |
| --- | --- |
| `-2` | `3-23` |
| `-1` | `4-23` |
| `0` | `5-24` |
| `1` | `6-25` |
| `2` | `7-26` |

`-2` and `-1` have the same boosted priority as *High category* is clamped to `23`.

![](https://github.com/nohuto/win-config/blob/main/system/images/relativeprios.png?raw=true)

### Scheduling Category / Priority

| Color | Scheduling Category | Priority | Range |
| --- | --- | --- | --- |
| Green | `Medium` | `2` | `1-17` |
| Red | `Medium` | `3` | `2-18` |
| Purple | `Medium` | `5` | `4-20` |
| Yellow | `High` | `1` | `1-24` |

![](https://github.com/nohuto/win-config/blob/main/system/images/categories.png?raw=true)

# DWM Values

This option currently includes some speculations and default values. I haven't had time yet to test the behavior of the changed data.

## Registry Values

See [assets/dwm](https://github.com/nohuto/win-config/tree/main/system/assets/dwm) for used snippets (taken from `dwmcore.dll`, `win32full.sys`, `dwm.exe`, `dwminit.dll`, `uDWM.dll`).

Everything listed below is based on personal research, mistakes may exist.

```c
"HKLM\\SOFTWARE\\Microsoft\\Windows\\Dwm";
    "BlackOutAllReadback" = 0;
    "ConfigureInput" = 1;
    "CpuClipAASinkEnableIntermediates" = 1;
    "CpuClipAASinkEnableOcclusion" = 1;
    "CpuClipAASinkEnableRender" = 1;
    "CpuClipAreaThreshold" = 20000;
    "CpuClipWarpPartitionThreshold" = 1024;
    "DisableDrawListCaching" = 0; // REG_DWORD
    "DisableProjectedShadows" = 0;
    "DisplayChangeTimeoutMs" = 1000;
    "EnableBackdropBlurCaching" = 1; // REG_DWORD
    "EnableCommonSuperSets" = 1;
    "EnableCpuClipping" = 1;
    "EnableDDisplayScanoutCaching" = 1;
    "EnableEffectCaching" = 1; // REG_DWORD
    "EnableFrontBufferRenderChecks" = 1;
    "EnableMegaRects" = 1;
    "EnablePrimitiveReordering" = 1;
    "ForceFullDirtyRendering" = 0;
    "GammaBlendPencil" = 1;
    "GammaBlendWithFP16" = 1;
    "InkGPUAccelOverrideVendorWhitelist" = 0;
    "LayerClippingMode" = 2;
    "LogExpressionPerfStats" = 0; // REG_DWORD
    "MajorityScreenTest_MinArea" = 80;
    "MajorityScreenTest_MinLength" = 80;
    "MaxD3DFeatureLevel" = 0;
    "MegaRectSearchCount" = 100;
    "MegaRectSize" = 100000;
    "MousewheelAnimationDurationMs" = 250;
    "MousewheelScrollingMode" = 0; // REG_DWORD
    "OptimizeForDirtyExpressions" = 1; // REG_DWORD
    "OverlayMinFPS" = 15; // If this value is present and set to zero, the Desktop Window Manager disables its minimum frame rate requirement for assigning DirectX swap chains to overlay planes in hardware that supports overlays. This makes it more likely that a low frame rate swap chain will get assigned and stay assigned to an overlay plane, if available. (https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/dwm/registry-values.md)
    "RenderThreadTimeoutMilliseconds" = 5000;
    "SuperWetExtensionTimeMicroseconds" = 1000;
    "TelemetryFramesReportPeriodMilliseconds" = 300000;
    "TelemetryFramesSequenceIdleIntervalMilliseconds" = 1000;
    "TelemetryFramesSequenceMaximumPeriodMilliseconds" = 1000;
    "UniformSpaceDpiMode" = 1;
    "UseFastestMonitorAsPrimary" = 0;
    "vBlankWaitTimeoutMonitorOffMs" = 250;
    "WarpEnableDebugColor" = 0;

    "BackdropBlurCachingThrottleMs" = 25; // 25ms if missing, clamped to <=1000ms when present?
    "CompositorClockPolicy" = 1; // range 0-1
    "CpuClipFlatteningTolerance" = 0; // scaled /1000
    "CustomRefreshRateMode" = 0; // range 0-2
    "DisableAdvancedDirectFlip" = 0; // REG_DWORD
    "DisableIndependentFlip" = 0;
    "DisableProjectedShadowsRendering" = 0;
    "FlattenVirtualSurfaceEffectInput" = 0;
    "ForceEffectMode" = 0; // range 0-2, REG_DWORD
    "FrameCounterPosition" = 0;
    "InteractionOutputPredictionDisabled" = 0;
    "OverlayTestMode" = 0; // 5 = MPO disabled, REG_DWORD
    "ParallelModePolicy" = 1; // >=3 coerced to 1
    "ParallelModeRateThreshold" = 119; // divisor for g_qpcFrequency, missing key defaults to 119 Hz (units: Hz)? 0 disables
    "ResampleInLinearSpace" = 0;
    "ResampleModeOverride" = 0;
    "SDRBoostPercentOverride" = 0; // scaled /100
    "ShowDirtyRegions" = 0;

    "AnimationsShiftKey" = 0;
    "DisableLockingMemory" = 0;
    "ModeChangeCurtainUseDebugColor" = 0;
    "UseDPIScaling" = 1;

    "ChildWindowDpiIsolation" = 1; // range 0-1
    "DisableDeviceBitmaps" = 0; // range 0-1
    "EnableResizeOptimization" = 0; // REG_DWORD (no clamp?)
    "ResizeTimeoutGdi" = 0; // range 0-4294967295 (ms)
    "ResizeTimeoutModern" = 0; // range 0-4294967295 (ms)

    "DefaultColorizationColorState" = 0;
    "DisallowAnimations" = 0;
    "DisallowColorizationColorChanges" = 0;

    "DisableSessionTermination" = 0; // range 0-1
    "ForceBasicDisplayAdapterOnDWMRestart" = 0; // range 0-1
    "OneCoreNoBootDWM" = 0; // REG_DWORD, nonzero = enabled
    "OneCoreNoDWMRawGameController" = ? // didn't look into it yet, but it's probably related to OneCoreNoBootDWM

    "DisableHologramCompositor" = 0;

    // Haven't looked into them yet
    "ForceUDwmSoftwareDevice" = ?;
    "ForceDisableModeChangeAnimation" = ?; // REG_DWORD

    // procmon boot trace
    "AccentColorInactive" = ?;
    "AnimationAttributionEnabled" = 1; // REG_DWORD
    "AnimationAttributionHashingEnabled" = 1; // REG_DWORD
    "ColorPrevalence" = ?;
    "CpuClipAASinkEnableDebugColors" = ?;
    "CpuClipAASinkForceEnable" = ?;
    "DebugFailFast" = ?;
    "DisableDeviceBitmapsForMultiAdapter" = ?;
    "DwmInitSessionActivityId_00000001" = ?; // a ID, REG_SZ
    "EnableDesktopOverlays" = ?;
    "EnableMPCPerfCounter" = ?;
    "EnableRenderPathTestMode" = ?;
    "EnableWindowColorization" = ?;
    "ForceDesktopTreeFullDirty" = ?;
    "MajorityScreenTest_MaxCoverage" = ?;
    "MarshalAllDebugInfo" = ?;
    "MPCInputRouterWaitForDebugger" = ?;
    "ShaderLinkingGPUBlacklist" = ?; // REG_SZ
    "SuperWetEnabled" = ?;
    "UseHWDrawListEntriesOnWARP" = ?;


"HKLM\\SOFTWARE\\Microsoft\\Windows\\Dwm\\Scene";
    "EnableBloom" = 0; // REG_DWORD
    "EnableDrawToBackbuffer" = 1; // REG_DWORD
    "EnableImageProcessing" = 1; // REG_DWORD
    "ImageProcessingResizeGrowth" = 200;
    "MsaaQualityMode" = 2;
    "SceneVisualCutoffCountOfConsecutiveIncidentsAllowed" = 5;
    "SceneVisualCutoffThresholdInMS" = 1000;

    "ForceNonPrimaryDisplayAdapter" = 0; // REG_DWORD
    "ImageProcessingResizeThreshold" = 0; // scaled /100

"HKLM\\SOFTWARE\\Microsoft\\Windows\\Dwm\\GpuAccelInkTiming";
    "ExtensionTimeMicroseconds" = 1000;
    "PeriodicFenceMinDifferenceMicroseconds" = 500;
    "RefreshRatePercentage" = 10;
```

## RegistryMachine_* Keys

### win32kfull

Since some values above are from `win32kfull.sys` I'll add that here. Looking at xrefs of these names is sometimes a start point when trying to find values within a binary, therefore I'm adding it (note that `aRegistryMachin_*` are IDA generated names so you won't find them in strings, nor will they be the exact same for you unless you disassemble the same binary build version).

```c
// win32kfull.sys
aRegistryMachin = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\PnP"
aRegistryMachin_1 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
aRegistryMachin_2 = "\\Registry\\Machine\\software\\microsoft\\Windows NT\\CurrentVersion\\Windows"
aRegistryMachin_3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\EAS\\Policies"
aRegistryMachin_4 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontLink\\SystemLink"
aRegistryMachin_5 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\TabletPC"
aRegistryMachin_6 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Fonts"
aRegistryMachin_7 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\FontDPI"
aRegistryMachin_8 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Type 1 Installer\\Type 1 Fonts"
aRegistryMachin_9 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
aRegistryMachin_10 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Gre_Initialize\\SmallFont"
aRegistryMachin_11 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\DWM"
aRegistryMachin_12 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage"
aRegistryMachin_13 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Gre_Initialize"
aRegistryMachin_14 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\AutoRotation"
aRegistryMachin_15 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontLink\\"
aRegistryMachin_17 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\UIPI\\Clipboard\\ExceptionFormats"
aRegistryMachin_18 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Gre_Initialize\\LargeFont"
aRegistryMachin_19 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\UIPI\\Clipboard\\IntegrityLevelDef"
aRegistryMachin_20 = "\\Registry\\Machine\\System\\CurrentControlSet\\Hardware Profiles"
aRegistryMachin_22 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\TabletPC\\UserLinearityData"
aRegistryMachin_23 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\AutoRotation\\NonPreserve"
aRegistryMachin_24 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\DPI"
aRegistryMachin_25 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Edgy"
aRegistryMachin_26 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\FontMapper\\FamilyDefaults"
aRegistryMachin_27 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\TabletPC\\LinearityData"
```

### win32kbase

Added for documentational purposes and future references.

```c
// win32kbase.sys
aRegistryMachin = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\DefaultPressure"
aRegistryMachin_0 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\PrecisionTouchPad\\LegacyDevices"
aRegistryMachin_1 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Terminal Server\\Video\\"
aRegistryMachin_2 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control"
aRegistryMachin_3 = "\\Registry\\Machine\\SYSTEM\\INPUT"
aRegistryMachin_4 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\PrecisionTouchPad\\LegacyControlled"
aRegistryMachin_5 = "\\Registry\\Machine\\Hardware\\DeviceMap\\Video"
aRegistryMachin_6 = "\\Registry\\Machine\\"
aRegistryMachin_7 = "\\Registry\\Machine\\Software\\Wow6432Node\\Microsoft\\Windows\\Tablet PC"
aRegistryMachin_8 = "\\Registry\\Machine\\OSDATA\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\CIT"
aRegistryMachin_9 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\PrecisionTouchPad\\IgnoredExternalMice"
aRegistryMachin_10 = "\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINDOWS"
aRegistryMachin_11 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Services\\TSDDD\\Device0"
aRegistryMachin_12 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
aRegistryMachin_13 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\DWM"
aRegistryMachin_14 = "\\Registry\\Machine\\System\\Setup"
aRegistryMachin_15 = "\\Registry\\Machine\\Software\\Microsoft\\Wisp\\Pen\\Digimon"
aRegistryMachin_16 = "\\Registry\\Machine\\SYSTEM\\Setup"
aRegistryMachin_17 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Theme"
aRegistryMachin_18 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\CIT"
aRegistryMachin_19 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Language"
aRegistryMachin_20 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers"
aRegistryMachin_21 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Input\\DelayZonePalmRejection"
aRegistryMachin_22 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State"
aRegistryMachin_23 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\Tablet PC"
aRegistryMachin_24 = "\\Registry\\Machine\\Software\\Microsoft\\Wisp\\ExcludedDEvices"
aRegistryMachin_26 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers\\InvalidDisplay"
aRegistryMachin_27 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
aRegistryMachin_28 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\DPI"
aRegistryMachin_29 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Win32kWPP"
aRegistryMachin_30 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager"
aRegistryMachin_31 = "\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop"
aRegistryMachin_32 = "\\Registry\\Machine\\Software\\WowAA32Node\\Microsoft\\Windows\\Tablet PC"
aRegistryMachin_33 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Power"
```

# Disable Scheduled Tasks

This list was created using my small [`ScheduledTasksLists.ps1`](https://github.com/nohuto/win-config/blob/main/system/assets/ScheduledTasksList.ps1) parser which displays name, path, description, principals, settings, triggers, actions if given. See example output of a stock 25H2 installation: [scheduled-tasks.json](https://github.com/nohuto/win-config/blob/main/system/assets/scheduled-tasks.json).

## Scheduled Tasks Table

| Option Name | Task | Description | Action Command |
| --- | --- | --- | --- |
| CEIP | `\Microsoft\Windows\Autochk\Proxy` | This task collects and uploads autochk SQM data if opted-in to the Microsoft Customer Experience Improvement Program. | `%windir%\system32\rundll32.exe /d acproxy.dll,PerformAutochkOperations` |
|  | `\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip` | The USB CEIP (Customer Experience Improvement Program) task collects Universal Serial Bus related statistics and information about your machine and sends it to the Windows Device Connectivity engineering group at Microsoft.  The information received is used to help improve the reliability, stability, and overall functionality of USB in Windows.  If the user has not consented to participate in Windows CEIP, this task does not do anything. | `ClassId:{C27F6B1D-FE0B-45E4-9257-38799FA69BC8}` |
|  | `\Microsoft\Windows\Customer Experience Improvement Program\Consolidator` | If the user has consented to participate in the Windows Customer Experience Improvement Program, this job collects and sends usage data to Microsoft. | `%WINDIR%\System32\wsqmcons.exe` |
|  | `\Microsoft\Windows\Customer Experience Improvement Program\Uploader` | - | - |
|  | `\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant` | - | - |
|  | `\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerRoleUsageCollector` | - | - |
| Error Reporting | `\Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate` | - | - |
|  | `\Microsoft\Windows\Windows Error Reporting\QueueReporting` | Windows Error Reporting task to process queued reports. | `%windir%\system32\wermgr.exe -upload` |
| Offline Files | `\Microsoft\Windows\Offline Files\Background Synchronization` | This task controls periodic background synchronization of Offline Files when the user is working in an offline mode. | `ClassId:{FA3F3DD9-4C1A-456B-A8FA-C76EF3ED83B8}` |
|  | `\Microsoft\Windows\Offline Files\Logon Synchronization` | This task initiates synchronization of Offline Files when a user logs onto the system. | `ClassId:{FA3F3DD9-4C1A-456B-A8FA-C76EF3ED83B8}` |
| Printing | `\Microsoft\Windows\Printing\PrintJobCleanupTask` | - | `ClassId:{8ABCE260-32B6-476C-AE13-B34D0C91292D}` |
|  | `\Microsoft\Windows\Printing\PrinterCleanupTask` | - | `ClassId:{C56F065E-DE49-4E42-BE7C-305C45609D25}` |
|  | `\Microsoft\Windows\Printing\EduPrintProv` | - | `%windir%\system32\eduprintprov.exe` |
| Wi-Fi Service | `\Microsoft\Windows\WCM\WiFiTask` | Background task for performing per user and web interactions | `%WINDIR%\System32\WiFiTask.exe` |
|  | `\Microsoft\Windows\WlanSvc\CDSSync` | - | `ClassId:{B0D2B535-12E1-439F-86B3-BADA289510F0}` |
|  | `\Microsoft\Windows\WwanSvc\NotificationTask` | Background task for performing per user and web interactions | `%WINDIR%\System32\WiFiTask.exe wwan` |
|  | `\Microsoft\Windows\WwanSvc\OobeDiscovery` | - | `ClassId:{C93CF9D5-031B-4AAA-AB0B-EF802347B381}` |
|  | `\Microsoft\Windows\WlanSvc\MoProfileManagement` | - | `ClassId:{085EDA12-CF4A-4944-8222-8ADCADE137CB}` |
| Office Telemetry | `\Microsoft\Office\OfficeTelemetryAgentFallBack` | - | - |
|  | `\Microsoft\Office\OfficeTelemetryAgentFallBack2016` | - | - |
|  | `\Microsoft\Office\OfficeTelemetryAgentLogOn` | - | - |
|  | `\Microsoft\Office\OfficeTelemetryAgentLogOn2016` | - | - |
| NVIDIA Telemetry | `NvTmRep_*` | Sends data at 12:25PM daily | - |
|  | `NvTmRepOnLogon*` | Sends data on logon | - |
|  | `NvTmMon_*` | Sends data on logon, then in a 1H interval | - |
| Feedback | `\Microsoft\Windows\Feedback\Siuf\DmClient` | Update SIUF strings | `%windir%\system32\dmclient.exe` |
|  | `\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload` | Update SIUF strings | `%windir%\system32\dmclient.exe utcwnf` |
| Application Experience | `\Microsoft\Windows\Application Experience\MareBackup` | Gathers Win32 application data for App Backup scenario | `%windir%\system32\compattelrunner.exe -m:aeinv.dll -f:UpdateSoftwareInventoryW invsvc ; %windir%\system32\compattelrunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun ; %windir%\system32\compattelrunner.exe -m:aemarebackup.dll -f:BackupMareData` |
|  | `\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser` | Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program. | `%windir%\system32\sc.exe start InventorySvc` |
|  | `\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp` | Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program. | `%windir%\system32\compattelrunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun express` |
|  | `\Microsoft\Windows\Application Experience\PcaPatchDbTask` | Updates compatibility database | `%windir%\system32\rundll32.exe %windir%\system32\PcaSvc.dll,PcaPatchSdbTask` |
|  | `\Microsoft\Windows\Application Experience\SdbinstMergeDbTask` | Merges shim databases that are pending merge. | `%windir%\system32\sdbinst.exe -mm` |
|  | `\Microsoft\Windows\Application Experience\StartupAppTask` | Scans startup entries and raises notification to the user if there are too many startup entries. | `%windir%\system32\rundll32.exe Startupscan.dll,SusRunTask` |
| Maintenance | `\Microsoft\Windows\ApplicationData\DsSvcCleanup` | Performs maintenance for the Data Sharing Service. | `%windir%\system32\dstokenclean.exe` |
|  | `\Microsoft\Windows\CloudExperienceHost\CreateObjectTask` | - | `ClassId:{E4544ABA-62BF-4C54-AAB2-EC246342626C}` |
|  | `\Microsoft\Windows\Defrag\ScheduledDefrag` | This task optimizes local storage drives. | `%windir%\system32\defrag.exe -c -h -o -$` |
|  | `\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner` | Check for recommended troubleshooting from Microsoft | `ClassId:{AD08DCC2-4E35-4486-9D49-547CBD30942D}` |
|  | `\Microsoft\Windows\Diagnosis\Scheduled` | The Windows Scheduled Maintenance Task performs periodic maintenance of the computer system by fixing problems automatically or reporting them through Security and Maintenance. | `ClassId:{C1F85EF8-BCC2-4606-BB39-70C523715EB3}` |
|  | `\Microsoft\Windows\Diagnosis\UnexpectedCodePath` | - | - |
|  | `\Microsoft\Windows\DiskCleanup\SilentCleanup` | Maintenance task used by the system to launch a silent auto disk cleanup when running low on free disk space. | `%windir%\system32\cleanmgr.exe /autocleanstoragesense /d %systemdrive%` |
|  | `\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector` | The Windows Disk Diagnostic reports general disk and system information to Microsoft for users participating in the Customer Experience Program. | `%windir%\system32\rundll32.exe dfdts.dll,DfdGetDefaultPolicyAndSMART` |
|  | `\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver` | The Microsoft-Windows-DiskDiagnosticResolver warns users about faults reported by hard disks that support the Self Monitoring and Reporting Technology (S.M.A.R.T.) standard. This task is triggered automatically by the Diagnostic Policy Service when a S.M.A.R.T. fault is detected. | `%windir%\system32\DFDWiz.exe` |
|  | `\Microsoft\Windows\DiskFootprint\Diagnostics` | - | `%windir%\system32\disksnapshot.exe -z` |
|  | `\Microsoft\Windows\DiskFootprint\StorageSense` | - | `ClassId:{AB2A519B-03B0-43CE-940A-A73DF850B49A}` |
|  | `\Microsoft\Windows\Speech\SpeechModelDownloadTask` | - | `%windir%\system32\speech_onecore\common\SpeechModelDownload.exe` |
|  | `\Microsoft\Windows\Sysmain\ResPriStaticDbSync` | Reserved Priority static db sync maintenance task | `ClassId:{297EE78C-BA95-4E94-81D3-D6E7F089C7B5}` |
|  | `\Microsoft\Windows\Sysmain\WsSwapAssessmentTask` | Working set swap assessment maintenance task | `%windir%\system32\rundll32.exe sysmain.dll,PfSvWsSwapAssessmentTask` |
|  | `\Microsoft\Windows\UNP\RunUpdateNotificationMgr` | - | - |
|  | `\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask` | Maintains registrations for background tasks for Universal Windows Platform applications. | `ClassId:{E984D939-0E00-4DD9-AC3A-7ACA04745521}` |
|  | `\Microsoft\Windows\capabilityaccessmanager\maintenancetasks` | Capability Access Manager Maintenance Tasks | `%windir%\system32\rundll32.exe %windir%\system32\CapabilityAccessManager.dll,CapabilityAccessManagerDoStoreMaintenance` |
| Census | `\Microsoft\Windows\Device Information\Device User` | - | `%windir%\system32\devicecensus.exe UserCxt` |
|  | `\Microsoft\Windows\Device Information\Device` | - | `%windir%\system32\devicecensus.exe SystemCxt` |
| Update Service | `\Microsoft\Windows\InstallService\ScanForUpdates` | - | `ClassId:{A558C6A5-B42B-4C98-B610-BF9559143139}` |
|  | `\Microsoft\Windows\InstallService\ScanForUpdatesAsUser` | - | `ClassId:{DDAFAEA2-8842-4E96-BADE-D44A8D676FDB}` |
|  | `\Microsoft\Windows\InstallService\SmartRetry` | - | `ClassId:{F3A219C3-2698-4CBF-9C07-037EDB8E72E6}` |
|  | `\Microsoft\Windows\InstallService\WakeUpAndContinueUpdates` | - | `ClassId:{0DC331EE-8438-49D5-A721-E10B937CE459}` |
|  | `\Microsoft\Windows\InstallService\WakeUpAndScanForUpdates` | - | `ClassId:{D5A04D91-6FE6-4FE4-A98A-FEB4500C5AF7}` |
| Localization | `\Microsoft\Windows\International\Synchronize Language Settings` | Synchronize User Language Settings from other devices. | `ClassId:{10D62541-90D0-42FE-848C-0DBC1AC42EDA}` |
|  | `\Microsoft\Windows\LanguageComponentsInstaller\Installation` | Install language components that match the user's language list. | `ClassId:{6F58F65F-EC0E-4ACA-99FE-FC5A1A25E4BE}` |
|  | `\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources` | Install language components that match the user's language list. | `ClassId:{D0582E3B-3126-4CAA-9155-AC37C912A489}` |
|  | `\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation` | Uninstall language components that are not in any user's language list. | `ClassId:{6F58F65F-EC0E-4ACA-99FE-FC5A1A25E4BE}` |
| Maps | `\Microsoft\Windows\Maps\MapsUpdateTask` | This task checks for updates to maps which you have downloaded for offline use. Disabling this task will prevent Windows from notifying you of updated maps. | `ClassId:{B9033E87-33CF-4D77-BC9B-895AFBBA72E4}` |
|  | `\Microsoft\Windows\Maps\MapsToastTask` | This task shows various Map related toasts | `ClassId:{9885AEF2-BD9F-41E0-B15E-B3141395E803}` |
| Sleep Study | `\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem` | This task analyzes the system looking for conditions that may cause high energy use. | `ClassId:{927EA2AF-1C54-43D5-825E-0074CE028EEE}` |
| Time Sync | `\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime` | This task performs time synchronization. | `ClassId:{A31AD6C2-FF4C-43D4-8E90-7101023096F9}` |
|  | `\Microsoft\Windows\Time Synchronization\SynchronizeTime` | Maintains date and time synchronization on all clients and servers in the network. If this service is stopped, date and time synchronization will be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start. | `%windir%\system32\sc.exe start w32time task_started` |
| Miscellaneous | `\Microsoft\Windows\Registry\RegIdleBackup` | Registry Idle Backup Task | `ClassId:{CA767AA8-9157-4604-B64B-40747123D5F2}` |
|  | `\Microsoft\Windows\RetailDemo\CleanupOfflineContent` | Auto cleanup RetailDemo Offline content | `ClassId:{61F77D5E-AFE9-400B-A5E6-E9E80FC8E601}` |
| WU | `\Microsoft\Windows\UpdateOrchestrator\Report policies` | - | `%WINDIR%\system32\usoclient.exe ReportPolicies` |
|  | `\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work` | - | `%WINDIR%\system32\usoclient.exe StartMaintenanceWork` |
|  | `\Microsoft\Windows\UpdateOrchestrator\Schedule Scan` | - | `%WINDIR%\system32\usoclient.exe StartScan` |
|  | `\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task` | This task performs a scheduled Windows Update scan. | `%WINDIR%\system32\usoclient.exe StartScan` |
|  | `\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work` | - | `%WINDIR%\system32\usoclient.exe StartWork` |
|  | `\Microsoft\Windows\UpdateOrchestrator\Schedule Work` | - | `%WINDIR%\system32\usoclient.exe StartWork` |
|  | `\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work` | This task performs a scheduled Windows Update scan. | `%WINDIR%\system32\usoclient.exe StartWork` |
|  | `\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_LicenseAccepted` | This task performs a scheduled Windows Update scan. | `%WINDIR%\system32\usoclient.exe StartOobeAppsScan` |
|  | `\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScanAfterUpdate` | This task performs a scheduled Windows Update scan. | `%WINDIR%\system32\usoclient.exe StartOobeAppsScanAfterUpdate` |
|  | `\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker` | This task triggers a system reboot following update installation. | `%WINDIR%\system32\MusNotification.exe` |
|  | `\Microsoft\Windows\UpdateOrchestrator\UUS Failover Task` | - | `%windir%\System32\MLEngineStub.exe HandleUusFailoverEvaluationSignalFromWnf` |
|  | `\Microsoft\Windows\WindowsUpdate\Scheduled Start` | This task is used to start the Windows Update service when needed to perform scheduled operations such as scans. | `%WINDIR%\System32\sc.exe start wuauserv` |
|  | `\Microsoft\Windows\WindowsUpdate\Refresh Group Policy Cache` | This task is used to refresh group policy cache in Windows Update | `ClassId:{07369A67-07A6-4608-ABEA-379491CB7C46}` |
| BitLocker | `\Microsoft\Windows\BitLocker\BitLocker Encrypt All Drives` | - | `ClassId:{61BCD1B9-340C-40EC-9D41-D7F1C0632F05}` |
|  | `\Microsoft\Windows\BitLocker\BitLocker MDM Policy Refresh` | - | - |
| Microsoft Account | `\Microsoft\Windows\AccountHealth\RecoverabilityToastTask` | AccountHealth Task Handler evaluates the state of a Microsoft Account and takes any necessary repair action | `ClassId:{B7F5B442-EBF8-46CD-9F0B-D8E45ED43492}` |
| Chkdsk | `\Microsoft\Windows\Chkdsk\ProactiveScan` | NTFS Volume Health Scan | `ClassId:{CF4270F5-2E43-4468-83B3-A8C45BB33EA1}` |
|  | `\Microsoft\Windows\Chkdsk\SyspartRepair` | - | `%windir%\system32\bcdboot.exe %windir% /sysrepair` |
| OneSettings | `\Microsoft\Windows\Flighting\OneSettings\RefreshCache` | Task periodically refreshing data for OneSettings clients. | `ClassId:{E07647F7-AED2-48D9-9720-939BC24A8A3C}` |
| Location Notification | `\Microsoft\Windows\Location\WindowsActionDialog` | Location Notification | `%windir%\System32\WindowsActionDialog.exe` |
| Memory Diagnostic | `\Microsoft\Windows\MemoryDiagnostic\AutomaticOfflineMemoryDiagnostic` | Schedules an offline memory diagnostic in response to system events. | `ClassId:{44F6C389-604A-4363-B09A-F38DA08E6079}` |
|  | `\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents` | Schedules a memory diagnostic in response to system events. | `ClassId:{8168E74A-B39F-46D8-ADCD-7BED477B80A3}` |
|  | `\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic` | Detects and mitigates problems in physical memory (RAM). | `ClassId:{8168E74A-B39F-46D8-ADCD-7BED477B80A3}` |
| Remote Assistance | `\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask` | Checks group policy for changes relevant to Remote Assistance | `%windir%\system32\RAServer.exe /offerraupdate` |
| SR | `\Microsoft\Windows\SystemRestore\SR` | This task creates regular system protection points. | `%windir%\system32\srtasks.exe ExecuteScheduledSPPCreation` |
| Windows Defender | `\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance` | Periodic maintenance task. | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25110.6-0\MpCmdRun.exe -IdleTask -TaskName WdCacheMaintenance` |
|  | `\Microsoft\Windows\Windows Defender\Windows Defender Cleanup` | Periodic cleanup task. | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25110.6-0\MpCmdRun.exe -IdleTask -TaskName WdCleanup` |
|  | `\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan` | Periodic scan task. | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25110.6-0\MpCmdRun.exe Scan -ScheduleJob -ScanTrigger 55 -IdleScheduledJob` |
|  | `\Microsoft\Windows\Windows Defender\Windows Defender Verification` | Periodic verification task. | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25110.6-0\MpCmdRun.exe -IdleTask -TaskName WdVerification` |
| AI | `\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration` | - | `ClassId:{709FD5EF-7296-4154-BD3A-E9830FCFA60A}` |
|  | `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` | - | `ClassId:{0BE6820D-B667-4CB6-931B-C153A77DA895}` |
|  | `\Microsoft\Windows\WindowsAI\Settings\InitialConfiguration` | - | `ClassId:{2886E5FB-4F01-4A89-9A0E-5D6A9C8048AC}` |
| Work Folders | `\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization` | This task initiates synchronization of Work Folders partnerships when a user logs onto the system. | `ClassId:{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}` |
|  | `\Microsoft\Windows\Work Folders\Work Folders Maintenance Work` | This task initiates maintenance work required for on-going good performance of data synchronization of Work Folders partnerships. | `ClassId:{63260BCE-A3FB-4A34-AA51-D4D8E877B62B}` |

# Disable Services/Drivers

I personally recommend using only the main option. This includes disabling telemetry/tracking/diagnostics/location/certain drivers/services, etc. It is not necessary to disable more than this, as most other features won't start automatically anyway. You can use the suboptions if you want to disable services/drivers (e.g. *"Autoplay Service, Bluetooth Services, Camera Services, File/Printer Sharing Services, Printer Services, Store Services"*) for a **specific** reason (note that this may cause broken functionalities). Disabling/enabling features via other options (e.g WER, Windows Search, Clipboard) includes changing service/driver `Start` data/setting policies etc, instead of only changing services/drivers state, so again, rather leave the suboptions alone.

## Internals 'Windows services'

![](https://github.com/nohuto/win-config/blob/main/system/images/services1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/services2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/services3.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/services4.png?raw=true)

Read more about it in [Windows Internals E7, P2](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf) 'Windows services (P.426-474) section.

## Service/Driver Table

The suboptions probably overlap the documentation. If so, you can open the [page on my website](https://github.com/nohuto/win-config/blob/main/system/desc.md#disable-servicesdrivers) instead.

See [services](https://github.com/nohuto/win-config/blob/main/system/assets/services.txt)/[drivers](https://github.com/nohuto/win-config/blob/main/system/assets/drivers.txt) for reference, these files were generated on a stock `W11 IoT Enterprise LTSC` installation via [serviwin](https://www.nirsoft.net/utils/serviwin.html).

| Option Name | Service/Driver | Description |
| --- | --- | --- |
| Activity Moderation | `bam` | Controls activity of background applications |
| Autoplay | `ShellHWDetection` | *Disabling causes CmdPal to not start directly after boot for whatever reason.* -Provides notifications for AutoPlay hardware events. |
| Beep | `Beep` | Legacy PC speaker/tone driver. It provides simple beeps for apps that call the Windows Beep API. |
| Biometrics | `WbioSrvc` | The Windows biometric service gives client applications the ability to capture, compare, manipulate, and store biometric data without gaining direct access to any biometric hardware or samples. The service is hosted in a privileged SVCHOST process. |
| Bluetooth | `BTAGService` | Service supporting the audio gateway role of the Bluetooth Handsfree Profile. |
|  | `BluetoothUserService_*` | The Bluetooth user service supports proper functionality of Bluetooth features relevant to each user session. |
|  | `BluetoothUserService` | The Bluetooth user service supports proper functionality of Bluetooth features relevant to each user session. |
|  | `BthA2dp` | Microsoft Bluetooth A2dp driver |
|  | `BthAvctpSvc` | This is Audio Video Control Transport Protocol service |
|  | `BthEnum` | Bluetooth Enumerator Service |
|  | `BthHFEnum` | Microsoft Bluetooth Hands-Free Profile driver |
|  | `BthLEEnum` | Bluetooth Low Energy Driver |
|  | `BthMini` | Bluetooth Radio Driver |
|  | `BTHMODEM` | Bluetooth Modem Communications Driver |
|  | `BTHPORT` | Bluetooth Port Driver |
|  | `bthserv` | The Bluetooth service supports discovery and association of remote Bluetooth devices. Stopping or disabling this service may cause already installed Bluetooth devices to fail to operate properly and prevent new devices from being discovered or associated. |
|  | `BTHUSB` | Bluetooth Radio USB Driver |
|  | `DeviceAssociationBrokerSvc` | Enables apps to pair devices |
|  | `DeviceAssociationService` | Enables pairing between the system and wired or wireless devices. |
|  | `Microsoft_Bluetooth_AvrcpTransport` | Microsoft Bluetooth Avrcp Transport Driver |
|  | `RFCOMM` | Bluetooth Device (RFCOMM Protocol TDI) |
| Broadcasts | `BcastDVRUserService` | This user service is used for Game Recordings and Live Broadcasts |
|  | `CaptureService_*` | Enables optional screen capture functionality for applications that call the Windows.Graphics.Capture API. |
|  | `AJRouter` | Routes AllJoyn messages for the local AllJoyn clients. If this service is stopped the AllJoyn clients that do not have their own bundled routers will be unable to run. |
|  | `CaptureService` | Enables optional screen capture functionality for applications that call the Windows.Graphics.Capture API. |
|  | `CDPSvc` | This service is used for Connected Devices Platform scenarios |
|  | `CDPUserSvc` | This user service is used for Connected Devices Platform scenarios |
|  | `DevicePickerUserSvc` | This user service is used for managing the Miracast, DLNA, and DIAL UI |
|  | `DevicesFlowUserSvc` | Allows ConnectUX and PC Settings to Connect and Pair with WiFi displays and Bluetooth devices. |
|  | `NcbService` | Brokers connections that allow packaged Microsoft Store apps to receive notifications from the internet. |
|  | `NcdAutoSetup` | Network Connected Devices Auto-Setup service monitors and installs qualified devices that connect to a qualified network. Stopping or disabling this service will prevent Windows from discovering and installing qualified network connected devices automatically. Users can still manually add network connected devices to a PC through the user interface. |
|  | `p2pimsvc` | Provides identity services for the Peer Name Resolution Protocol (PNRP) and Peer-to-Peer Grouping services. If disabled, the Peer Name Resolution Protocol (PNRP) and Peer-to-Peer Grouping services may not function, and some applications, such as HomeGroup and Remote Assistance, may not function correctly. |
|  | `p2psvc` | Enables multi-party communication using Peer-to-Peer Grouping. If disabled, some applications, such as HomeGroup, may not function. |
|  | `PNRPAutoReg` | This service publishes a machine name using the Peer Name Resolution Protocol. Configuration is managed via the netsh context `p2p pnrp peer`. |
|  | `PNRPsvc` | Enables serverless peer name resolution over the Internet using the Peer Name Resolution Protocol (PNRP). If disabled, some peer-to-peer and collaborative applications, such as Remote Assistance, may not function. |
| Camera | `FrameServer` | Enables multiple clients to access video frames from camera devices. |
|  | `FrameServerMonitor` | Monitors the health and state for the Windows Camera Frame Server service. |
|  | `StiSvc` | Provides image acquisition services for scanners and cameras |
| CDROM | `cdrom` | CD-ROM Driver |
| Clipboard | `cbdhsvc` | This user service is used for Clipboard scenarios |
| Cloud Filter | `CldFlt` | Cloud Files Mini Filter Driver |
| DHCP | `Dhcp` | Registers and updates IP addresses and DNS records for this computer. If this service is stopped, this computer will not receive dynamic IP addresses and DNS updates. If this service is disabled, any services that explicitly depend on it will fail to start. |
| Diagnostics | `DusmSvc` | Network data usage, data limit, restrict background data, metered networks. |
|  | `DPS` | The Diagnostic Policy Service enables problem detection, troubleshooting and resolution for Windows components. If this service is stopped, diagnostics will no longer function. |
|  | `diagsvc` | Executes diagnostic actions for troubleshooting support |
|  | `WdiServiceHost` | The Diagnostic Service Host is used by the Diagnostic Policy Service to host diagnostics that need to run in a Local Service context. If this service is stopped, any diagnostics that depend on it will no longer function. |
|  | `WdiSystemHost` | The Diagnostic System Host is used by the Diagnostic Policy Service to host diagnostics that need to run in a Local System context. If this service is stopped, any diagnostics that depend on it will no longer function. |
|  | `TroubleshootingSvc` | Enables automatic mitigation for known problems by applying recommended troubleshooting. If stopped, your device will not get recommended troubleshooting for problems on your device. |
| Domain/RPC | `Netlogon` | Maintains a secure channel between this computer and the domain controller for authenticating users and services. If this service is stopped, the computer may not authenticate users and services and the domain controller cannot register DNS records. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `MsRPC` | MsRPC |
|  | `RpcLocator` | In Windows 2003 and earlier versions of Windows, the Remote Procedure Call (RPC) Locator service manages the RPC name service database. In Windows Vista and later versions of Windows, this service does not provide any functionality and is present for application compatibility. |
| Edge | `MicrosoftEdgeElevationService` | Provides elevated privileges for Microsoft Edge. |
|  | `edgeupdate` | Keeps your Microsoft software up to date. If this service is disabled or stopped, your Microsoft software will not be kept up to date, meaning security vulnerabilities that may arise cannot be fixed and features may not work. This service uninstalls itself when there is no Microsoft software using it. |
|  | `edgeupdatem` | Keeps your Microsoft software up to date. If this service is disabled or stopped, your Microsoft software will not be kept up to date, meaning security vulnerabilities that may arise cannot be fixed and features may not work. This service uninstalls itself when there is no Microsoft software using it. |
| File/Printer Sharing | `LanmanServer` | Supports file, print, and named-pipe sharing over the network for this computer. If this service is stopped, these functions will be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `LanmanWorkstation` | Creates and maintains client network connections to remote servers using the SMB protocol. If this service is stopped, these connections will be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `CSC` | Allows network files to be used while the local computer is offline. |
|  | `CscService` | The Offline Files service performs maintenance activities on the Offline Files cache, responds to user logon and logoff events, implements the internals of the public API, and dispatches interesting events to those interested in Offline Files activities and changes in cache state. |
|  | `Dfsc` | Client driver for access to DFS Namespaces |
|  | `MRxDAV` | Network Redirector that provides WebDAV file access for the WebClient service |
|  | `mrxsmb` | Implements the framework for the SMB filesystem redirector |
|  | `mrxsmb20` | Implements the SMB 2.0 protocol, which provides connectivity to network resources on Windows Vista and later servers |
|  | `P9Rdr` | Plan 9 Redirector Driver |
|  | `P9RdrService` | Enables trigger-starting plan9 file servers. |
|  | `rdbss` | Provides the framework for network mini-redirectors |
|  | `TrkWks` | Maintains links between NTFS files within a computer or across computers in a network. |
|  | `WebClient` | Enables Windows-based programs to create, access, and modify Internet-based files. If this service is stopped, these functions will not be available. If this service is disabled, any services that explicitly depend on it will fail to start. |
| GameInput | `GameInputSvc` | Enables keyboards, mice, gamepads, and other input devices to be used with the GameInput API. |
| HyperV | `bttflt` | Microsoft Hyper-V VHDPMEM BTT Filter |
|  | `gencounter` | Microsoft Hyper-V Generation Counter |
|  | `hvcrash` | Hyper-V Crashdump |
|  | `HvHost` | Provides an interface for the Hyper-V hypervisor to provide per-partition performance counters to the host operating system. |
|  | `hvservice` | Microsoft Hypervisor Service Driver |
|  | `hyperkbd` | Microsoft VMBus Synthetic Keyboard Driver |
|  | `HyperVideo` | Microsoft VMBus Video Device Miniport Driver |
|  | `storflt` | Microsoft Hyper-V Storage Accelerator |
|  | `Vid` | Microsoft Hyper-V Virtualization Infrastructure Driver |
|  | `vmbus` | Virtual Machine Bus |
|  | `vmgid` | Microsoft Hyper-V Guest Infrastructure Driver |
|  | `vmicguestinterface` | Provides an interface for the Hyper-V host to interact with specific services running inside the virtual machine. |
|  | `vmicheartbeat` | Monitors the state of this virtual machine by reporting a heartbeat at regular intervals. This service helps you identify running virtual machines that have stopped responding. |
|  | `vmickvpexchange` | Provides a mechanism to exchange data between the virtual machine and the operating system running on the physical computer. |
|  | `vmicrdv` | Provides a platform for communication between the virtual machine and the operating system running on the physical computer. |
|  | `vmicshutdown` | Provides a mechanism to shut down the operating system of this virtual machine from the management interfaces on the physical computer. |
|  | `vmictimesync` | Synchronizes the system time of this virtual machine with the system time of the physical computer. |
|  | `vmicvmsession` | Provides a mechanism to manage virtual machine with PowerShell via VM session without a virtual network. |
|  | `vmicvss` | Coordinates the communications that are required to use Volume Shadow Copy Service to back up applications and data on this virtual machine from the operating system on the physical computer. |
|  | `vpci` | Microsoft Hyper-V Virtual PCI Bus |
| IPv6 | `Tcpip6` | @todo.dll,-100;Microsoft IPv6 Protocol Driver |
|  | `IpxlatCfgSvc` | Configures and enables translation from v4 to v6 and vice versa |
| IP Helper | `iphlpsvc` | Provides tunnel connectivity using IPv6 transition technologies (6to4, ISATAP, Port Proxy, and Teredo), and IP-HTTPS. If this service is stopped, the computer will not have the enhanced connectivity benefits that these technologies offer. |
| Kernel Debug Network | `kdnic` | Microsoft Kernel Debugger Network Miniport |
| Location | `lfsvc` | This service monitors the current location of the system and manages geofences (a geographical location with associated events). If you turn off this service, applications will be unable to use or receive notifications for geolocation or geofences. |
| Maps Manager | `MapsBroker` | Windows service for application access to downloaded maps. This service is started on-demand by application accessing downloaded maps. Disabling this service will prevent apps from accessing maps. |
| Network Discovery | `fdPHost` | The FDPHOST service hosts the Function Discovery (FD) network discovery providers. These FD providers supply network discovery services for the Simple Services Discovery Protocol (SSDP) and Web Services Discovery (WS-D) protocol. Stopping or disabling the FDPHOST service will disable network discovery for these protocols when using FD. When this service is unavailable, network services using FD and relying on these discovery protocols will be unable to find network devices or resources. |
|  | `FDResPub` | Publishes this computer and resources attached to this computer so they can be discovered over the network. If this service is stopped, network resources will no longer be published and they will not be discovered by other computers on the network. |
|  | `SSDPSRV` | Discovers networked devices and services that use the SSDP discovery protocol, such as UPnP devices. Also announces SSDP devices and services running on the local computer. If this service is stopped, SSDP-based devices will not be discovered. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `upnphost` | Allows UPnP devices to be hosted on this computer. If this service is stopped, any hosted UPnP devices will stop functioning and no additional hosted devices can be added. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `MsLldp` | Microsoft Link-Layer Discovery Protocol Driver |
|  | `rspndr` | Link-Layer Topology Discovery Responder |
|  | `lltdio` | Link-Layer Topology Discovery Mapper I/O Driver |
|  | `lltdsvc` | Creates a Network Map, consisting of PC and device topology (connectivity) information, and metadata describing each PC and device. If this service is disabled, the Network Map will not function properly. |
| Office | `ClickToRunSvc` | - |
| Telephony | `PhoneSvc` | Manages the telephony state on the device |
|  | `TapiSrv` | Provides Telephony API (TAPI) support for programs that control telephony devices on the local computer and, through the LAN, on servers that are also running the service. |
| Radio Management | `RmSvc` | Radio Management and Airplane Mode Service. |
| Parental Control | `WpcMonSvc` | Enforces parental controls for child accounts in Windows. If this service is stopped or disabled, parental controls may not be enforced. |
| Printer | `McpManagementService` | Universal Print Management Service |
|  | `PrintDeviceConfigurationService` | The Print Device Configuration Service manages the installation of IPP and UP printers. If this service is stopped, any printer installations that are in-progress may be canceled. |
|  | `PrintNotify` | This service opens custom printer dialog boxes and handles notifications from a remote print server or a printer. If you turn off this service, you wont be able to see printer extensions or notifications. |
|  | `PrintScanBrokerService` | Provides support for secure privileged operations needed by low priv spooler. |
|  | `PrintWorkflowUserSvc` | Provides support for Print Workflow applications. If you turn off this service, you may not be able to print successfully. |
|  | `Spooler` | This service spools print jobs and handles interaction with the printer. If you turn off this service, you won't be able to print or see your printers. |
|  | `usbprint` | Microsoft USB PRINTER Class |
| Recovery / Backup | `CloudBackupRestoreSvc` | Monitors the system for changes in application and setting states and performs cloud backup and restore operations when required. |
|  | `SDRSVC` | Provides Windows Backup and Restore capabilities. |
|  | `swprv` | Manages software-based volume shadow copies taken by the Volume Shadow Copy service. If this service is stopped, software-based volume shadow copies cannot be managed. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `VSS` | Manages and implements Volume Shadow Copies used for backup and other purposes. If this service is stopped, shadow copies will be unavailable for backup and the backup may fail. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `wbengine` | The WBENGINE service is used by Windows Backup to perform backup and recovery operations. If this service is stopped by a user, it may cause the currently running backup or recovery operation to fail. Disabling this service may disable backup and recovery operations using Windows Backup on this computer. |
| Remote Desktop | `SessionEnv` | Remote Desktop Configuration service (RDCS) is responsible for all Remote Desktop Services and Remote Desktop related configuration and session maintenance activities that require SYSTEM context. These include per-session temporary folders, RD themes, and RD certificates. |
|  | `TermService` | Allows users to connect interactively to a remote computer. Remote Desktop and Remote Desktop Session Host Server depend on this service. To prevent remote use of this computer, clear the checkboxes on the Remote tab of the System properties control panel item. |
|  | `UmRdpService` | Allows the redirection of Printers/Drives/Ports for RDP connections |
|  | `rdpbus` | Remote Desktop Device Redirector Bus Driver |
|  | `RDPDR` | Remote Desktop Device Redirector Driver |
|  | `terminpt` | Microsoft Remote Desktop Input Driver |
|  | `TsUsbFlt` | Remote Desktop USB Hub Class Filter Driver |
|  | `TsUsbGD` | Remote Desktop Generic USB Device |
|  | `tsusbhub` | Remote Desktop USB Hub |
| Sensor | `SensorDataService` | Delivers data from a variety of sensors |
|  | `SensrSvc` | Monitors various sensors in order to expose data and adapt to system and user state. If this service is stopped or disabled, the display brightness will not adapt to lighting conditions. Stopping this service may affect other system functionality and features as well. |
|  | `SensorService` | A service for sensors that manages different sensors' functionality. Manages Simple Device Orientation (SDO) and History for sensors. Loads the SDO sensor that reports device orientation changes. If this service is stopped or disabled, the SDO sensor will not be loaded and so auto-rotation will not occur. History collection from Sensors will also be stopped. |
|  | `perceptionsimulation` | Enables spatial perception simulation, virtual camera management and spatial input simulation. |
|  | `spectrum` | Enables spatial perception, spatial input, and holographic rendering. |
|  | `VacSvc` | Hosts spatial analysis for Mixed Reality audio simulation. |
| Sign-In Assistant | `wlidsvc` | Enables user sign-in through Microsoft account identity services. If this service is stopped, users will not be able to logon to the computer with their Microsoft account. |
|  | `NaturalAuthentication` | Signal aggregator service, that evaluates signals based on time, network, geolocation, bluetooth and cdf factors. Supported features are Device Unlock, Dynamic Lock and Dynamo MDM policies |
|  | `NgcCtnrSvc` | Manages local user identity keys used to authenticate user to identity providers as well as TPM virtual smart cards. If this service is disabled, local user identity keys and TPM virtual smart cards will not be accessible. It is recommended that you do not reconfigure this service. |
|  | `NgcSvc` | Provides process isolation for cryptographic keys used to authenticate to a user's associated identity providers. If this service is disabled, all uses and management of these keys will not be available, which includes machine logon and single-sign on for apps and websites. This service starts and stops automatically. It is recommended that you do not reconfigure this service. |
| Smart Card | `SCardSvr` | Manages access to smart cards read by this computer. If this service is stopped, this computer will be unable to read smart cards. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `ScDeviceEnum` | Creates software device nodes for all smart card readers accessible to a given session. If this service is disabled, WinRT APIs will not be able to enumerate smart card readers. |
|  | `SCPolicySvc` | Allows the system to be configured to lock the user desktop upon smart card removal. |
|  | `scfilter` | Smart card reader filter driver enabling smart card PnP. |
| SysMain | `SysMain` | SysMain (Superfetch) records app usage patterns, builds prefetch metadata (layout.ini), and warms the cache by preloading files/pages to cut boot and app startup latency; it also drives prefetcher behavior via EnablePrefetcher settings. ([Windows Internals, E7-P1](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)) |
| Microsoft Store | `AppXSvc` | *Disabling breaks CmdPal and other store applications.* - Provides infrastructure support for deploying Store applications. This service is started on demand and if disabled Store applications will not be deployed to the system, and may not function properly. |
|  | `camsvc` | Provides facilities for managing UWP apps access to app capabilities as well as checking an app's access to specific app capabilities |
|  | `ClipSVC` | Provides infrastructure support for the Microsoft Store. This service is started on demand and if disabled applications bought using the Microsoft Store will not behave correctly. |
|  | `InstallService` | Provides infrastructure support for the Microsoft Store. This service is started on demand and if disabled then installations will not function properly. |
|  | `LicenseManager` | Provides infrastructure support for the Microsoft Store. This service is started on demand and if disabled then content acquired through the Microsoft Store will not function properly. |
|  | `PushToInstall` | Provides infrastructure support for the Microsoft Store. This service is started automatically and if disabled then remote installations will not function properly. |
| TCP/IP NetBIOS Helper | `lmhosts` | Provides support for the NetBIOS over TCP/IP (NetBT) service and NetBIOS name resolution for clients on the network, therefore enabling users to share files, print, and log on to the network. If this service is stopped, these functions might be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start. |
| Telemetry | `DiagTrack` | The Connected User Experiences and Telemetry service enables features that support in-application and connected user experiences. Additionally, this service manages the event driven collection and transmission of diagnostic and usage information (used to improve the experience and quality of the Windows Platform) when the diagnostics and usage privacy option settings are enabled under Feedback and Diagnostics. |
|  | `dmwappushservice` | Routes Wireless Application Protocol (WAP) Push messages received by the device and synchronizes Device Management sessions |
|  | `Ndu` | This service provides network data usage monitoring functionality |
|  | `InventorySvc` | This service performs background system inventory, compatibility appraisal, and maintenance used by numerous system components. |
|  | `PcaSvc` | This service provides support for the Program Compatibility Assistant (PCA). PCA monitors programs installed and run by the user and detects known compatibility problems. If this service is stopped, PCA will not function properly. |
|  | `wuqisvc` | A Microsoft service producing summary facts and insights related to usage and quality of experience. Facts are used to automate on-device self-healing and other optional workflows, such as Personalized offers. |
| Themes | `Themes` | Provides user experience theme management. |
| Time | `autotimesvc` | This service sets time based on NITZ messages from a Mobile Network |
|  | `tzautoupdate` | Automatically sets the system time zone. |
| Trusted Runtime | `WindowsTrustedRT` | Windows Trusted Runtime Interface Driver |
|  | `WindowsTrustedRTProxy` | Windows Trusted Runtime Service Proxy Driver |
|  | `PEAUTH` | Protected Environment Authentication and Authorization Export Driver |
| UAC | `luafv` | Virtualizes file write failures to per-user locations. |
| User Data & Sync Platform | `UnistoreSvc` | Handles storage of structured user data, including contact info, calendars, messages, and other content. If you stop or disable this service, apps that use this data might not work correctly. |
|  | `UserDataSvc` | Provides apps access to structured user data, including contact info, calendars, messages, and other content. If you stop or disable this service, apps that use this data might not work correctly. |
|  | `ConsentUxUserSvc` | Allows the system to request user consent to allow apps to access sensitive resources and information such as the device's location |
|  | `MessagingService` | Service supporting text messaging and related functionality. |
|  | `PimIndexMaintenanceSvc` | Indexes contact data for fast contact searching. If you stop or disable this service, contacts might be missing from your search results. |
| Virtual Bus | `CompositeBus` | Multi-Transport Composite Bus Enumerator |
|  | `umbus` | User-Mode Bus Enumerator |
|  | `vdrvroot` | Virtual Drive Root Enumerator |
|  | `NdisVirtualBus` | Microsoft Virtual Network Adapter Enumerator |
| WER | `WerSvc` | Allows errors to be reported when programs stop working or responding and allows existing solutions to be delivered. Also allows logs to be generated for diagnostic and repair services. If this service is stopped, error reporting might not work correctly and results of diagnostic services and repairs might not be displayed. |
|  | `wercplsupport` | This service provides support for viewing, sending and deletion of system-level problem reports for the Problem Reports control panel. |
| Wi-Fi | `WlanSvc` | The WLANSVC service provides the logic required to configure, discover, connect to, and disconnect from a wireless local area network (WLAN) as defined by IEEE 802.11 standards. It also contains the logic to turn your computer into a software access point so that other devices or computers can connect to your computer wirelessly using a WLAN adapter that can support this. Stopping or disabling the WLANSVC service will make all WLAN adapters on your computer inaccessible from the Windows networking UI. It is strongly recommended that you have the WLANSVC service running if your computer has a WLAN adapter. |
|  | `vwififlt` | Virtual WiFi Filter Driver |
|  | `wcncsvc` | WCNCSVC hosts the Windows Connect Now Configuration which is Microsoft's Implementation of Wireless Protected Setup (WPS) protocol. This is used to configure Wireless LAN settings for an Access Point (AP) or a Wireless Device. The service is started programmatically as needed. |
|  | `WFDSConMgrSvc` | Manages connections to wireless services, including wireless display and docking. |
|  | `NativeWifiP` | NativeWiFi Filter |
|  | `Wificx` | Wifi Network Adapter Class Extension |
| Windows Defender | `WinDefend` | Helps protect users from malware and other potentially unwanted software |
|  | `MsSecCore` | Microsoft Security Core Boot Driver |
|  | `wscsvc` | The WSCSVC (Windows Security Center) service monitors and reports security health settings on the computer.  The health settings include firewall (on/off), antivirus (on/off/out of date), antispyware (on/off/out of date), Windows Update (automatically/manually download and install updates), User Account Control (on/off), and Internet settings (recommended/not recommended). The service provides COM APIs for independent software vendors to register and record the state of their products to the Security Center service.  The Security and Maintenance UI uses the service to provide systray alerts and a graphical view of the security health states in the Security and Maintenance control panel.  Network Access Protection (NAP) uses the service to report the security health states of clients to the NAP Network Policy Server to make network quarantine decisions.  The service also has a public API that allows external consumers to programmatically retrieve the aggregated security health state of the system. |
|  | `WdFilter` | Microsoft Defender Antivirus On-Access Malware Protection Mini-Filter Driver |
|  | `WdBoot` | Microsoft Defender Antivirus Boot Driver |
|  | `WdNisSvc` | Helps guard against intrusion attempts targeting known and newly discovered vulnerabilities in network protocols |
|  | `WdNisDrv` | Helps guard against intrusion attempts targeting known and newly discovered vulnerabilities in network protocols |
|  | `SecurityHealthService` | Windows Security Service handles unified device protection and health information |
|  | `Sense` | Windows Defender Advanced Threat Protection service helps protect against advanced threats by monitoring and reporting security events that happen on the computer. |
|  | `MDCoreSvc` | Monitors the availability, health, and performance of various security components |
| Windows Insider | `wisvc` | Provides infrastructure support for the Windows Insider Program. This service must remain enabled for the Windows Insider Program to work. |
| Windows Search | `WSearch` | Provides content indexing, property caching, and search results for files, e-mail, and other content. |
| Windows Update | `WaaSMedicSvc` | Repairs damaged Windows Update components so that the computer can keep getting updates. |
|  | `UsoSvc` | Manages Windows Updates. If stopped, your devices will not be able to download and install the latest updates. |
|  | `wuauserv` | Enables the detection, download, and installation of updates for Windows and other programs. If this service is disabled, users of this computer will not be able to use Windows Update or its automatic updating feature, and programs will not be able to use the Windows Update Agent (WUA) API. |
| Xbox | `XboxGipSvc` | This service manages connected Xbox Accessories. |
|  | `xboxgip` | Xbox Game Input Protocol Driver |
|  | `XblAuthManager` | Provides authentication and authorization services for interacting with Xbox Live. If this service is stopped, some applications may not operate correctly. |
|  | `XblGameSave` | This service syncs save data for Xbox Live save enabled games. If this service is stopped, game save data will not upload to or download from Xbox Live. |
|  | `XboxNetApiSvc` | This service supports the Windows.Networking.XboxLive application programming interface. |
| VBox | `VBoxNetAdp` | VirtualBox NDIS 6.0 Host-Only Network Adapter Driver |
|  | `VBoxNetLwf` | VirtualBox NDIS 6.0 Lightweight Filter Driver  |
|  | `VBoxSup` | VirtualBox Support Driver |
|  | `VBoxUSBMon` | VirtualBox USB Monitor Driver |
|  | `VBoxSDS` | Used as a COM server for VirtualBox API. VirtualBox Global Interface. |
| VPN/RAS Services | `RemoteAccess` | Offers routing services to businesses in local area and wide area network environments. |
|  | `wanarp` | Remote Access IP ARP Driver |
|  | `wanarpv6` | Remote Access IPv6 ARP Driver |
|  | `RasMan` | Manages dial-up and virtual private network (VPN) connections from this computer to the Internet or other remote networks. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `RasAuto` | Creates a connection to a remote network whenever a program references a remote DNS or NetBIOS name or address. |
|  | `PptpMiniport` | WAN Miniport (PPTP) |
|  | `RasAgileVpn` | WAN Miniport (IKEv2) |
|  | `Rasl2tp` | WAN Miniport (L2TP) |
|  | `RasSstp` | WAN Miniport (SSTP) |
|  | `SstpSvc` | Provides support for the Secure Socket Tunneling Protocol (SSTP) to connect to remote computers using VPN. If this service is disabled, users will not be able to use SSTP to access remote servers. |
|  | `RasAcd` | Remote Access Auto Connection Driver |
| Media Sharing / Portable Devices | `WMPNetworkSvc` | Shares Windows Media Player libraries to other networked players and media devices using Universal Plug and Play |
|  | `WPDBusEnum` | Enforces group policy for removable mass-storage devices. Enables applications such as Windows Media Player and Image Import Wizard to transfer and synchronize content using removable mass-storage devices. |
| BranchCache | `PeerDistSvc` | This service caches network content from peers on the local subnet. |
| QoS/AV Streaming (qWave) | `QWAVE` | Quality Windows Audio Video Experience (qWave) is a networking platform for Audio Video (AV) streaming applications on IP home networks. qWave enhances AV streaming performance and reliability by ensuring network quality-of-service (QoS) for AV applications. It provides mechanisms for admission control, run time monitoring and enforcement, application feedback, and traffic prioritization. |
|  | `QWAVEdrv` | Quality Windows Audio/Video Experience component driver |
| NFC/Payments | `SEMgrSvc` | Manages payments and Near Field Communication (NFC) based secure elements. |
| Optimize Drives | `defragsvc` | Helps the computer run more efficiently by optimizing files on storage drives. |
| Mobile Hotspot / ICS Service | `icssvc` | Provides the ability to share a cellular data connection with another device. |
|  | `ALG` | Provides support for 3rd party protocol plug-ins for Internet Connection Sharing |
|  | `SharedAccess` | Provides network address translation, addressing, name resolution and/or intrusion prevention services for a home or small office network. |
| Network Capture Driver | `NdisCap` | Microsoft NDIS Capture |
| Container File System Drivers | `CimFS` | - |
|  | `wcifs` | Provides a virtual filesystem view for processes running within Windows Containers |
| Consumer IR Driver | `circlass` | Consumer IR Class Driver for eHome |
| iSCSI Driver | `msisadrv` | Disabling breaks laptop keyboards. |
| NetBIOS Driver | `NetBIOS` | NetBIOS Interface |
|  | `NetBT` | This service implements NetBios over TCP/IP. |
| Epic Games | `EpicGamesUpdater` | - |
|  | `EpicOnlineServices` | - |
| Logitech | `LGHUBUpdaterService` | LGHUB Updater Service |
|  | `logi_joy_bus_enum` | Logitech G HUB Virtual Bus Enumerator Driver |
|  | `logi_joy_vir_hid` | Logitech G HUB Virtual HID Device Driver |
|  | `logi_lamparray_service` | Provides HID LampArray Lighting support to Logitech devices. |
| SteelSeries | `SteelSeries_Sonar_VAD` | SteelSeries Sonar Driver |
|  | `SteelSeriesGGUpdateServiceProxy` | Launches the SteelSeries Update Service. |
|  | `ssdevfactory` | SteelSeries Device Factory Service |
| NVIDIA Container | `NVDisplay.ContainerLocalSystem` | Container service for NVIDIA root features, required for NVCPL to work. |
| Everything | `Everything (1.5a)` | Provides NTFS indexing, ReFS indexing and USN Journal services to the Everything search client. |
|  | `Everything` | ^ |
| App Deployment | `AppMgmt` | Processes installation, removal, and enumeration requests for software deployed through Group Policy. If the service is disabled, users will be unable to install, remove, or enumerate software deployed through Group Policy. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `AxInstSV` | Provides User Account Control validation for the installation of ActiveX controls from the Internet and enables management of ActiveX control installation based on Group Policy settings. This service is started on demand and if disabled the installation of ActiveX controls will behave according to default browser settings. |
|  | `BITS` | Transfers files in the background using idle network bandwidth. If the service is disabled, then any applications that depend on BITS, such as Windows Update or MSN Explorer, will be unable to automatically download programs and other information. |
|  | `EntAppSvc` | Enables enterprise application management. |
| Network Authentication | `dot3svc` | The Wired AutoConfig (DOT3SVC) service is responsible for performing IEEE 802.1X authentication on Ethernet interfaces. If your current wired network deployment enforces 802.1X authentication, the DOT3SVC service should be configured to run for establishing Layer 2 connectivity and/or providing access to network resources. Wired networks that do not enforce 802.1X authentication are unaffected by the DOT3SVC service. |
|  | `EapHost` | The Extensible Authentication Protocol (EAP) service provides network authentication in such scenarios as 802.1x wired and wireless, VPN, and Network Access Protection (NAP). EAP also provides application programming interfaces (APIs) that are used by network access clients, including wireless and VPN clients, during the authentication process. If you disable this service, this computer is prevented from accessing networks that require EAP authentication. |
| Network Profile & Connectivity UX | `NcaSvc` | Provides DirectAccess status notification for UI components |
|  | `NlaSvc` | Collects and stores configuration information for the network and notifies programs when this information is modified. If this service is stopped, configuration information might be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `Wcmsvc` | Makes automatic connect and disconnect decisions based on the network connectivity options currently available to the PC and enables management of network connectivity based on Group Policy settings. |
| Enterprise Transaction & Storage | `MSDTC` | Coordinates transactions that span multiple resource managers, such as databases, message queues, and file systems. If this service is stopped, these transactions will fail. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `MSiSCSI` | Manages Internet SCSI (iSCSI) sessions from this computer to remote iSCSI target devices. If this service is stopped, this computer will not be able to login or access iSCSI targets. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `smphost` | Host service for the Microsoft Storage Spaces management provider. If this service is stopped or disabled, Storage Spaces cannot be managed. |
| Management / Encryption Broker | `SNMPTRAP` | Receives trap messages generated by local or remote Simple Network Management Protocol (SNMP) agents and forwards the messages to SNMP management programs running on this computer. If this service is stopped, SNMP-based programs on this computer will not receive SNMP trap messages. If this service is disabled, any services that explicitly depend on it will fail to start. |
|  | `WEPHOSTSVC` | Windows Encryption Provider Host Service brokers encryption related functionalities from 3rd Party Encryption Providers to processes that need to evaluate and apply EAS policies. Stopping this will compromise EAS compliancy checks that have been established by the connected Mail Accounts |
| Demo / Shared Device | `RetailDemo` | The Retail Demo service controls device activity while the device is in retail demo mode. |
|  | `shpamsvc` | Manages profiles and accounts on a SharedPC configured device |
| Graphics Compatibility | `WarpJITSvc` | Enables JIT compilation support in d3d10warp.dll for processes in which code generation is disabled. |
| Mobile Broadband | `wlpasvc` | This service provides profile management for subscriber identity modules |
|  | `WwanSvc` | This service manages mobile broadband (GSM & CDMA) data card/embedded module adapters and connections by auto-configuring the networks. It is strongly recommended that this service be kept running for best user experience of mobile broadband devices. |
| Miscellaneous | `WalletService` | Hosts objects used by clients of the wallet |
|  | `PenService` | Part of Windows Ink Services Platform Tablet Input Subsystem and is used to implement Microsoft Tablet PC functionality.  |
|  | `buttonconverter` | Service for Portable Device Control devices |
|  | `SmsRouter` | Routes messages based on rules to appropriate clients. |

Disabling `fvevol` (BitLocker Drive Encryption Filter Driver) / `rdyboost` (ReadyBoost) (rdyboost.sys) = `INACCESSIBLE_BOOT_DEVICE` BSoD.

# BCD Edits

BCDEdit is the CL editor for the Boot Configuration Database (BCD), a registry hive under `HKLM\BCD00000000` backed by a hidden BCD file (UEFI: `\EFI\Microsoft\Boot\BCD`). The BCD replaced `boot.ini` (before Windows Vista) and stores per installation boot configuration. Each entry is a BCD object (GUID) under `Objects`, and each object has `Elements` subkeys with numeric element IDs. The `Element` value is the data that maps to a readable BCDEdit option or boot parameter. BCDEdit exposes symbolic names for objects/elements and can edit online or offline stores (`/store`), and the same data can be modified by loading the BCD hive (including remote hives).

BCDEdit is primarily used for boot troubleshooting, recovery, debugging, and security/boot behavior changes (Safe Mode, driver loading, hypervisor settings). Some may not be used on latest Windows versions anymore (e.g. HalpTscSyncPolicy, see pseudocode below).

BitLocker validates a subset of BCD settings at boot to detect security sensitive changes. The validated set can be extended or reduced via policy, and the hex value of a triggering setting is logged (event ID 523). Friendly names can be listed with `bcdedit /enum all`, but some settings have no friendly name and must be configured by hex. BCD settings are also scoped to specific boot applications (for example, `winload`, `winresume`, `bootmgr`), policy entries can be prefixed with the target application (for example, `winload:nx` or `all:locale`). When secure boot is used for integrity validation, the enhanced BCD validation profile policy is ignored, and secure boot enforces its own BCD rules.

## Registry Values

### Key & Value Structure

As kind of everything else, BCD edits are also stored in the registry:
```c
HKLM\BCD00000000\Objects

// Structure
HKLM\BCD00000000\Objects\{GUID} // {GUID} depends on the object, e.g. {bootmgr}, {current}, {globalsettings}
HKLM\BCD00000000\Objects\{GUID}\Elements\XXXXXXXX // XXXXXXXX is a specific setting for the object (8 digit)
HKLM\BCD00000000\Objects\{GUID}\Elements\XXXXXXXX : Element // (REG_BINARY/REG_MULTI_SZ/REG_SZ - depends on the setting) this value includes the state of the setting
```

See all object identifiers via `bcdedit /enum all /v` (`identifier`). Note that the list below uses `{bootmgr}`, `{current}` etc. which must be replaced by the actual GUID (see block above).

### Value/Data List

Here are elements which I tracked via Procmon (taken from default store and the MS documentation - [bcd-settings-and-bitlocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bcd-settings-and-bitlocker), [bcd-enumerations](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bcd/bcd-enumerations)).

Note that this doesn't show default states, instead it shows several options and their possible states. And obviously the descriptions are most likely parsed, means that even "useless" descriptions will be included whenever the mentioned MS docs above include them.

```c
"HKLM\\BCD00000000\\Objects\\{current}\\Elements";
    "\\26000141"; "Element" = 01; // REG_BINARY, event = true, false = 00
    "\\26000116"; "Element" = 01; // REG_BINARY, hypervisorusevapic = true, false = 00
    "\\260000F8"; "Element" = 01; // REG_BINARY, hypervisordisableslat = true, false = 00
    "\\260000FC"; "Element" = 01; // REG_BINARY, hypervisoruselargevtlb = true, false = 00 - Increases virtual Translation Lookaside Buffer (TLB) size.
    "\\260000F2"; "Element" = 01; // REG_BINARY, hypervisordebug = true, false = 00 - Controls whether the hypervisor debugger is enabled.
    "\\260000E1"; "Element" = 00; // REG_BINARY, disableelamdrivers = false, true = 01 - The OS loader removes this entry for security reasons. This option can only be triggered by using the F8 menu.
    "\\260000C3"; "Element" = 01; // REG_BINARY, onetimeadvancedoptions = true, false = 00 - Controls whether the system boots to the legacy menu (F8 menu) on the next boot.
    "\\260000C4"; "Element" = 01; // REG_BINARY, onetimeoptionsedit = true, false = 00
    "\\260000B0"; "Element" = 01; // REG_BINARY, ems = true, false = 00 - Indicates whether EMS should be enabled in the kernel.
    "\\260000A5"; "Element" = 01; // REG_BINARY, disabledynamictick = true, false = 00
    "\\260000A4"; "Element" = 01; // REG_BINARY, useplatformtick = true (forces platform clock source, often HPET), false = 00
    "\\260000A3"; "Element" = 01; // REG_BINARY, forcelegacyplatform = true, false = 00 - Forces the OS to assume the presence of legacy PC devices like CMOS and keyboard controllers.
    "\\260000A2"; "Element" = 01; // REG_BINARY, useplatformclock = true (forces the use of the platform clock as the system's performance counter), false = 00
    "\\260000A1"; "Element" = 01; // REG_BINARY, halbreakpoint = true, false = 00 - Indicates whether the HAL should call DbgBreakPoint at the start of HalInitSystem for phase 0 initialization of the kernel.
    "\\260000A0"; "Element" = 01; // REG_BINARY, debug = true, false = 00 - Indicates whether the kernel debugger should be enabled using the settings in the inherited debugger object.
    "\\26000091"; "Element" = 01; // REG_BINARY, sos = true, false = 00 - Indicates whether the system should display verbose information.
    "\\26000090"; "Element" = 01; // REG_BINARY, bootlog = true, false = 00 - Indicates whether the system should write logging information to %SystemRoot%\Ntbtlog.txt during initialization.
    "\\25000080"; "Element" = 0000000000000000; // REG_BINARY, safeboot = 0 (Minimal, SafeBoot\\Minimal), Network = 0100000000000000 (SafeBoot\\Network), DsRepair = 0200000000000000 (Directory Services Restore), Unset = not present
    "\\26000081"; "Element" = 01; // REG_BINARY, safebootalternateshell = true, false = 00 - Indicates whether the system should use the shell specified under the following registry key instead of the default shell: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell.
    "\\26000070"; "Element" = 01; // REG_BINARY, usefirmwarepcisettings = true, false = 00 - Indicates whether the system should use I/O and IRQ resources created by the system firmware instead of using dynamically configured resources.
    "\\26000065"; "Element" = 01; // REG_BINARY, groupaware = true, false = 00 - This setting makes drivers group aware and can be used to determine improper group usage.
    "\\26000064"; "Element" = 01; // REG_BINARY, maxgroup = true, false = 00 - Maximizes the number of groups created when assigning nodes to processor groups.
    "\\26000062"; "Element" = 01; // REG_BINARY, maxproc = true, false = 00 - Indicates whether the system should use the maximum number of processors.
    "\\26000060"; "Element" = 01; // REG_BINARY, onecpu = true, false = 00 - Indicates whether the operating system should initialize or start non-boot processors.
    "\\26000054"; "Element" = 01; // REG_BINARY, uselegacyapicmode = true (forces X2APICPOLICY=DISABLE), false = 00 (no-op) - Used to force legacy APIC mode, even if the processors and chipset support extended APIC mode.
    "\\26000051"; "Element" = 01; // REG_BINARY, usephysicaldestination = true, false = 00 - Indicates whether to enable physical-destination mode for all APIC messages.
    "\\26000043"; "Element" = 01; // REG_BINARY, novga = true, false = 00 - Disables the use of VGA modes in the OS.
    "\\26000042"; "Element" = 01; // REG_BINARY, novesa = true, false = 00 - Indicates whether the VGA driver should avoid VESA BIOS calls.
    "\\26000041"; "Element" = 01; // REG_BINARY, quietboot = true, false = 00 - Indicates whether the system should initialize the VGA driver responsible for displaying simple graphics during the boot process. If not, there is no display is presented during the boot process.
    "\\26000040"; "Element" = 01; // REG_BINARY, vga = true, false = 00 - Indicates whether the system should use the standard VGA display driver instead of a high-performance display driver.
    "\\26000030"; "Element" = 01; // REG_BINARY, nolowmem = true, false = 00 - Indicates whether the system should utilize the first 4GB of physical memory. This option requires 5GB of physical memory, and on x86 systems it requires PAE to be enabled.
    "\\26000027"; "Element" = 01; // REG_BINARY, allowprereleasesignatures = true, false = 00 - Indicates whether the test code signing certificate is supported.
    "\\26000025"; "Element" = 01; // REG_BINARY, lastknowngood = true, false = 00 - Indicates that the system should use the last-known good settings.
    "\\26000024"; "Element" = 01; // REG_BINARY, nocrashautoreboot = true, false = 00 - Indicates that the system should not automatically reboot when it crashes.
    "\\26000010"; "Element" = 01; // REG_BINARY, detectkernelandhal = true, false = 00 - Indicates whether the operating system loader should determine the kernel and HAL to load based on the platform features.
    "\\26000004"; "Element" = 01; // REG_BINARY, stampdisks = true, false = 00
    "\\25000142"; "Element" = 0100000000000000; // REG_BINARY, vsmlaunchtype = 1 (auto), Off = 0000000000000000
    "\\25000130"; "Element" = 0000000000000000; // REG_BINARY, claimedtpmcounter = 0
    "\\2500012B"; "Element" = 0100000000000000; // REG_BINARY, xsavedisable = 1, 0 = 0000000000000000 - When set to a value other than zero (0), disables XSAVE functionality in the kernel.
    "\\2500012A"; "Element" = 0000000000000000; // REG_BINARY, xsaveprocessorsmask = 0
    "\\25000129"; "Element" = 0000000000000000; // REG_BINARY, xsaveremovefeature = 0
    "\\25000128"; "Element" = 0000000000000000; // REG_BINARY, xsaveaddfeature7 = 0
    "\\25000127"; "Element" = 0000000000000000; // REG_BINARY, xsaveaddfeature6 = 0
    "\\25000126"; "Element" = 0000000000000000; // REG_BINARY, xsaveaddfeature5 = 0
    "\\25000125"; "Element" = 0000000000000000; // REG_BINARY, xsaveaddfeature4 = 0
    "\\25000124"; "Element" = 0000000000000000; // REG_BINARY, xsaveaddfeature3 = 0
    "\\25000123"; "Element" = 0000000000000000; // REG_BINARY, xsaveaddfeature2 = 0
    "\\25000122"; "Element" = 0000000000000000; // REG_BINARY, xsaveaddfeature1 = 0
    "\\25000121"; "Element" = 0000000000000000; // REG_BINARY, xsaveaddfeature0 = 0
    "\\25000120"; "Element" = 0000000000000000; // REG_BINARY, xsavepolicy = 0
    "\\25000115"; "Element" = 0100000000000000; // REG_BINARY, hypervisoriommupolicy = 1 (enable), Default = 0000000000000000, Disable = 0200000000000000 - Controls whether the hypervisor uses an Input Output Memory Management Unit (IOMMU).
    "\\25000113"; "Element" = 0200000000000000; // REG_BINARY, hypervisorrootproc = 2
    "\\25000100"; "Element" = 0200000000000000; // REG_BINARY, tpmbootentropy = 2 (forceenable), Default = 0000000000000000, ForceDisable = 0100000000000000 - Determines whether entropy is gathered from the trusted platform module (TPM) to help seed the random number generator in the OS.
    "\\250000FB"; "Element" = 0100000000000000; // REG_BINARY, hypervisorrootprocpernode = 1 - Specifies the total number of virtual processors in the root partition that can be started within a pre-split Non-Uniform Memory Architecture (NUMA) node.
    "\\250000FA"; "Element" = 0200000000000000; // REG_BINARY, hypervisornumproc = 2 - Specifies the total number of logical processors that can be started in the hypervisor.
    "\\250000F7"; "Element" = 0000000000000000; // REG_BINARY, bootuxpolicy = 0 (Disabled), Basic = 0100000000000000, Standard = 0200000000000000 (defunct) - Values are Disabled (0), Basic (1), and Standard (2).
    "\\250000F0"; "Element" = 0000000000000000; // REG_BINARY, hypervisorlaunchtype = 0 (Off), Auto = 0100000000000000 - Controls the hypervisor launch type. Options are HyperVisorLaunchOff (0) and HypervisorLaunchAuto (1).
    "\\250000E0"; "Element" = 0000000000000000; // REG_BINARY, bootstatuspolicy = 0 (displayallfailures), IgnoreAllFailures = 0100000000000000, IgnoreBootFailures = 0300000000000000, IgnoreCheckpointFailures = 0400000000000000, IgnoreShutdownFailures = 0200000000000000, DisplayBootFailures = 0600000000000000, DisplayCheckpointFailures = 0700000000000000, DisplayShutdownFailures = 0500000000000000
    "\\250000C2"; "Element" = 0000000000000000; // REG_BINARY, bootmenupolicy = 0 (Legacy), Standard = 0100000000000000 - Defines the type of boot menu the system will use. For Windows 10/11, Windows 8.1, Windows 8 and Windows RT the default is Standard. For Windows Server 2012 R2, Windows Server 2012, the default is Legacy. When Legacy is selected, the Advanced options menu (F8) is available. When Standard is selected, the boot menu appears but only under certain conditions: for example, if there is a startup failure, if you are booting up from a repair disk or installation media, if you have configured multiple boot entries, or if you manually configured the computer to use Advanced startup. When Standard is selected, the F8 key is ignored during boot. - Defines the type of boot menus the system will use. Possible values include menupolicylegacy (0) or menupolicystandard (1).
    "\\250000C1"; "Element" = 0000000000000000; // REG_BINARY, driverloadfailurepolicy = 0 (fatal), UseErrorControl = 0100000000000000 - Indicates the driver load failure policy. Zero (0) indicates that a failed driver load is fatal and the boot will not continue, one (1) indicates that the standard error control is used.
    "\\250000A6"; "Element" = 0100000000000000; // REG_BINARY, tscsyncpolicy = 1 (legacy), Default = 0000000000000000, Enhanced = 0200000000000000 (HalpTscSyncPolicy symbol not present means this doesn't do anything), this should exist on older Windows versions and controls the TSC synchronization policy
    "\\25000072"; "Element" = 0100000000000000; // REG_BINARY, pciexpress = 1 (forcedisable), Default = 0000000000000000
    "\\25000071"; "Element" = 0100000000000000; // REG_BINARY, msi = 1 (forcedisable), Default = 0000000000000000, ForceEnable only via loadoptions FORCEMSI - The PCI Message Signaled Interrupt (MSI) policy. Zero (0) indicates default, and one (1) indicates that MSI interrupts are disabled.
    "\\25000066"; "Element" = 4000000000000000; // REG_BINARY, groupsize = 64 - Specifies the size of all processor groups. Must be set to a power of 2 (max of 64, see pseudocode below).
    "\\25000063"; "Element" = 0100000000000000; // REG_BINARY, configflags = 1 - Indicates whether processor specific configuration flags are to be used.
    "\\25000061"; "Element" = 0200000000000000; // REG_BINARY, numproc = 2 - The maximum number of processors that can be utilized by the system, all other processors are ignored.
    "\\25000055"; "Element" = 0200000000000000; // REG_BINARY, x2apicpolicy = 2 (enable), Default = 0000000000000000, Disable = 0100000000000000 - Enables the use of extended APIC mode, if supported. Zero (0) indicates default behavior, one (1) indicates that extended APIC mode is disabled, and two (2) indicates that extended APIC mode is enabled. The system defaults to using extended APIC mode if available.
    "\\25000050"; "Element" = 0100000000000000; // REG_BINARY, clustermodeaddressing = 1 - Indicates that cluster-mode APIC addressing should be utilized, and the value is the maximum number of processors per cluster.
    "\\25000052"; "Element" = 0000000000000000; // REG_BINARY, restrictapicluster = 0 - The maximum number of APIC clusters that should be used by cluster-mode addressing.
    "\\25000032"; "Element" = 0004000000000000; // REG_BINARY, increaseuserva = 1024 - Increasing this value from the default 2GB decreases the amount of virtual address space available to the system and device drivers. The amount of memory that should be utilized by the process address space, in bytes. This value should be between 2GB and 3GB.
    "\\25000033"; "Element" = 0000000000000000; // REG_BINARY, perfmem = 0 - BcdOSLoaderInteger_PerformaceDataMemory (integer)
    "\\25000031"; "Element" = 8000000000000000; // REG_BINARY, removememory = 128 - The amount of memory the system should ignore.
    "\\25000021"; "Element" = 0100000000000000; // REG_BINARY, pae = 1 (forceenable), Default = 0000000000000000, ForceDisable = 0200000000000000 - If this value is not specified, the default is PaePolicyDefault which follows the rule "enable PAE if hot-pluggable memory is above 4GB"
    "\\25000020"; "Element" = 0000000000000000; // REG_BINARY, nx = 0 (OptIn, NX off by default), OptOut = 0100000000000000 (NX on by default), AlwaysOff = 0200000000000000, AlwaysOn = 0300000000000000 - If this value is not specified, the default is NxPolicyAlwaysOff.
    "\\23000003"; "Element" = {resume}; // REG_SZ, resumeobject = {resume} - The default boot environment application to load if the user does not select one.
    "\\22000053"; "Element" = \EFI\Microsoft\Boot\EVStore.dat; // REG_SZ, evstore = \EFI\Microsoft\Boot\EVStore.dat
    "\\22000041"; "Element" = recovery message; // REG_SZ, fverecoverymessage = recovery message
    "\\22000040"; "Element" = https://example.com/recovery; // REG_SZ, fverecoveryurl = https://example.com/recovery
    "\\22000013"; "Element" = kdcom.dll; // REG_SZ, dbgtransport = kdcom.dll - The transport DLL to be loaded by the operating system loader. This value overrides the default Kdcom.dll.
    "\\22000012"; "Element" = hal.dll; // REG_SZ, hal = hal.dll - The HAL to be loaded by the operating system loader. This value overrides the default HAL.
    "\\22000011"; "Element" = ntoskrnl.exe; // REG_SZ, kernel = ntoskrnl.exe - The kernel to be loaded by the operating system loader. This value overrides the default kernel.
    "\\22000002"; "Element" = \Windows; // REG_SZ, systemroot = \Windows - This value is reserved.
    "\\21000001"; "Element" = partition=C:; // REG_BINARY, filedevice = partition=C: - This value is reserved.
    "\\17000077"; "Element" = 7500001500000000; // REG_BINARY, allowedinmemorysettings = 0x15000075 - Indicates whether or not an in-memory BCD setting passed between boot apps will trigger BitLocker recovery. This value should not be modified as it could trigger a BitLocker recovery action.
    "\\1600007B"; "Element" = 01; // REG_BINARY, forcefipscrypto = true, false = 00 (BitLocker validation profile)
    "\\16000079"; "Element" = 01; // REG_BINARY, forcefipscrypto = true, false = 00 (BCD library enum, the one above is probably the used one) - Force the use of FIPS cryptography checks on boot applications.
    "\\16000074"; "Element" = 01; // REG_BINARY, bootshutdowndisabled = true, false = 00 - Disables the 1-minute timer that triggers shutdown on boot error screens, and the F8 menu, on UEFI systems.
    "\\16000072"; "Element" = 01; // REG_BINARY, nokeyboard = true, false = 00
    "\\1600006C"; "Element" = 01; // REG_BINARY, bootuxdisabled = true, false = 00 - This setting disables the progress bar and default Windows logo. If a custom text string has been defined, it is also disabled by this setting.
    "\\16000069"; "Element" = 01; // REG_BINARY, custom:16000069 = true, false = 00 - disables the loading circle while booting (see image at the bottom)
    "\\16000067"; "Element" = 01; // REG_BINARY, custom:16000067 = true, false = 00 - disables the Windows logo while booting (see image at the bottom)
    "\\16000060"; "Element" = 01; // REG_BINARY, isolatedcontext = true, false = 00 - Do not modify this setting. If this setting is removed from a Windows 8 installation, it will not boot. If this setting is added to a Windows 7 installation, it will not boot. - This setting is used to differentiate between the Windows 7 and Windows 8 implementations of UEFI.
    "\\16000054"; "Element" = 01; // REG_BINARY, highestmode = true, false = 00 - Forces highest available graphics resolution at boot. This value can only be used on UEFI systems.
    "\\16000053"; "Element" = 01; // REG_BINARY, restartonfailure = true, false = 00 - If enabled, specifies that boot error screens are not shown when OS launch errors occur, and the system is reset rather than exiting directly back to the firmware.
    "\\16000050"; "Element" = 01; // REG_BINARY, consoleextendedinput = true, false = 00 - Specifies that legacy BIOS systems should use INT 16h Function 10h for console input instead of INT 16h Function 0h.
    "\\16000049"; "Element" = 01; // REG_BINARY, testsigning = true, false = 00 - Indicates whether the test code signing certificate is supported.
    "\\16000048"; "Element" = 01; // REG_BINARY, nointegritychecks = true, false = 00 - This value is ignored by Windows 7 and Windows 8. - Disables integrity checks. Cannot be set when secure boot is enabled.
    "\\16000046"; "Element" = 01; // REG_BINARY, graphicsmodedisabled = true, false = 00 - Indicates whether graphics mode is disabled and boot applications must use text mode display.
    "\\16000041"; "Element" = 01; // REG_BINARY, optionsedit = true, false = 00 - Indicates whether the boot options editor is enabled.
    "\\16000040"; "Element" = 01; // REG_BINARY, advancedoptions = true, false = 00 - Indicates whether the advanced options boot menu (F8) is displayed.
    "\\1600001E"; "Element" = 01; // REG_BINARY, vm = true, false = 00
    "\\1600000F"; "Element" = 01; // REG_BINARY, traditionalkseg = true, false = 00
    "\\16000009"; "Element" = 01; // REG_BINARY, recoveryenabled = true, false = 00 - Indicates whether the recovery sequence executes automatically if the boot application fails. Otherwise, the recovery sequence only runs on demand.
    "\\15000081"; "Element" = 0000000000000000; // REG_BINARY, logcontrol = 0
    "\\15000088"; "Element" = 0000000000000000; // REG_BINARY, linearaddress57 = 0 (Default), OptOut = 0100000000000000, OptIn = 0200000000000000
    "\\15000066"; "Element" = 0300000000000000; // REG_BINARY, displaymessageoverride = 3 (Recovery), Resume = 0100000000000000
    "\\15000052"; "Element" = 0000000000000000; // REG_BINARY, graphicsresolution = 0 (1024x768), 800x600 = 0100000000000000, 1024x600 = 0200000000000000 - Forces a specific graphics resolution at boot. Possible values include GraphicsResolution1024x768 (0), GraphicsResolution800x600 (1), and GraphicsResolution1024x600 (2).
    "\\15000051"; "Element" = 0000000000000000; // REG_BINARY, initialconsoleinput = 0
    "\\1500004C"; "Element" = 0000000000000000; // REG_BINARY, volumebandid = 0 (fvebandid) - This value (if present) should not be modified.
    "\\1500004B"; "Element" = 0000000000000000; // REG_BINARY, integrityservices = 0 (Default, Enabled - Kernel Mode Code Signing), Enable = 0100000000000000, Disable = 0200000000000000
    "\\15000047"; "Element" = 0000000000000000; // REG_BINARY, configaccesspolicy = 0 (Default, allow MMCONFIG), DisallowMmConfig = 0100000000000000 (use CF8/CFC instead) - Indicates the access policy for PCI configuration space.
    "\\15000042"; "Element" = 0000000000000000; // REG_BINARY, keyringaddress = 0
    "\\1500000E"; "Element" = 0000000000000000; // REG_BINARY, avoidlowphysicalmemory = 0 - Specifies a minimum physical address to use in the boot environment.
    "\\1500000D"; "Element" = 0000000000000000; // REG_BINARY, relocatephysicalmemory = 0 - This value is not used in Windows 8 or Windows Server 2012. - Relocates physical memory on certain AMD processors.
    "\\1500000C"; "Element" = 0000000000000000; // REG_BINARY, firstmegabytepolicy = 0 (UseNone, use none of first MB), UseAll = 0100000000000000 (use all of first MB), UsePrivate = 0200000000000000 (reserved) - Indicates how the first megabyte of memory is to be used.
    "\\15000007"; "Element" = 0000008000000000; // REG_BINARY, truncatememory = 2147483648 - Maximum physical address a boot environment application should recognize. All memory above this address is ignored.
    "\\14000008"; "Element" = {winre}; // REG_MULTI_SZ, recoverysequence = {winre} - List of boot environment applications to be executed if the associated application fails. The applications are executed in the order they appear in this list.
    "\\14000006"; "Element" = {bootloadersettings}; // REG_MULTI_SZ, inherit = {bootloadersettings} - List of BCD objects from which the current object should inherit elements.
    "\\1200004A"; "Element" = \Windows\Fonts; // REG_SZ, fontpath = \Windows\Fonts - Use caution when modifying this setting. Boot screens will not work if the correct fonts are not present. - Overrides the default location of the boot fonts.
    "\\12000044"; "Element" = \Boot\BCD-Log; // REG_SZ, bsdlogpath = \Boot\BCD-Log - Allows a path override for the bootstat.dat log file in the boot manager and winload.exe.
    "\\12000030"; "Element" = NOCRASHONCTRL; // REG_SZ, loadoptions = NOCRASHONCTRL - String that is appended to the load options string passed to the kernel to be consumed by kernel-mode components. This is useful for communicating with kernel-mode components that are not BCD-aware.
    "\\12000005"; "Element" = en-US; // REG_SZ, locale = en-US - Preferred locale, in RFC 3066 format.
    "\\12000004"; "Element" = Windows 11; // REG_SZ, description = Windows 11 - Display name of the boot environment application.
    "\\12000002"; "Element" = \Windows\system32\winload.efi; // REG_SZ, path = \Windows\system32\winload.efi - Path to a boot environment application.
    "\\11000043"; "Element" = partition=C:; // REG_BINARY, bsdlogdevice = partition=C: - Allows a device override for the bootstat.dat log in the boot manager and winload.exe.
    "\\11000001"; "Element" = partition=C:; // REG_BINARY, device = partition=C: - Device on which a boot environment application resides.
"HKLM\\BCD00000000\\Objects\\{resume}\\Elements";
    "\\26000006"; "Element" = 00; // REG_BINARY, debugoptionenabled = false, true = 01 - Enables kernel debugging on resume from hibernate.
    "\\26000004"; "Element" = 01; // REG_BINARY, pae = true, false = 00
    "\\26000003"; "Element" = 01; // REG_BINARY, usecustomsettings = true, false = 00 - Allows the resume loader BCD object to use custom settings. If this setting is not specified or is not enabled, default settings are applied by the OS before resume.
    "\\25000008"; "Element" = 0100000000000000; // REG_BINARY, bootmenupolicy = 1 (Standard), Legacy = 0000000000000000 - Defines the type of boot menus the system will use. Possible values are menupolicylegacy (0) or menupolicystandard (1). The default setting is menupolicylegacy (0).
    "\\25000007"; "Element" = 0000000000000000; // REG_BINARY, bootux = 0 (Disabled), Basic = 0100000000000000, Standard = 0200000000000000 (defunct)
    "\\22000002"; "Element" = \hiberfil.sys; // REG_SZ, filepath = \hiberfil.sys - This value is reserved.
    "\\21000026"; "Element" = partition=C:; // REG_BINARY, custom:21000026 = partition=C:
    "\\21000005"; "Element" = partition=C:; // REG_BINARY, associatedosdevice = partition=C: - Specifies the name of the OS device associated with the hibernated OS. This is only used if the hibernation file is not stored on the OS device.
    "\\21000001"; "Element" = partition=C:; // REG_BINARY, filedevice = partition=C: - This value is reserved.
    "\\17000077"; "Element" = 7500001500000000; // REG_BINARY, allowedinmemorysettings = 0x15000075 - Indicates whether or not an in-memory BCD setting passed between boot apps will trigger BitLocker recovery. This value should not be modified as it could trigger a BitLocker recovery action.
    "\\16000060"; "Element" = 01; // REG_BINARY, isolatedcontext = true, false = 00 - Do not modify this setting. If this setting is removed from a Windows 8 installation, it will not boot. If this setting is added to a Windows 7 installation, it will not boot. - This setting is used to differentiate between the Windows 7 and Windows 8 implementations of UEFI.
    "\\16000009"; "Element" = 01; // REG_BINARY, recoveryenabled = true, false = 00 - Indicates whether the recovery sequence executes automatically if the boot application fails. Otherwise, the recovery sequence only runs on demand.
    "\\14000008"; "Element" = {winre}; // REG_MULTI_SZ, recoverysequence = {winre} - List of boot environment applications to be executed if the associated application fails. The applications are executed in the order they appear in this list.
    "\\14000006"; "Element" = {resumeloadersettings}; // REG_MULTI_SZ, inherit = {resumeloadersettings} - List of BCD objects from which the current object should inherit elements.
    "\\12000005"; "Element" = en-US; // REG_SZ, locale = en-US - Preferred locale, in RFC 3066 format.
    "\\12000004"; "Element" = Windows Resume Application; // REG_SZ, description = Windows Resume Application - Display name of the boot environment application.
    "\\12000002"; "Element" = \Windows\system32\winresume.efi; // REG_SZ, path = \Windows\system32\winresume.efi - Path to a boot environment application.
    "\\11000001"; "Element" = partition=C:; // REG_BINARY, device = partition=C: - Device on which a boot environment application resides.
"HKLM\\BCD00000000\\Objects\\{bootmgr}\\Elements";
    "\\27000030"; "Element" = 0000000000000000; // REG_BINARY, customactionslist = <integer list> - For more information see Custom Bootstrap Actions in Windows Vista.
    "\\26000031"; "Element" = 01; // REG_BINARY, persistbootsequence = true, false = 00 - Controls whether a boot sequence persists across multiple boots.
    "\\26000028"; "Element" = 01; // REG_BINARY, processcustomactionsfirst = true, false = 00 - Controls whether custom actions are processed before a boot sequence.
    "\\26000021"; "Element" = 01; // REG_BINARY, noerrordisplay = true, false = 00 - Indicates whether the display of errors should be suppressed. If this setting is enabled, the boot manager exits to the multi-OS menu on OS launch error.
    "\\26000020"; "Element" = 01; // REG_BINARY, displaybootmenu = true, false = 00 - Forces the display of the legacy boot menu, regardless of the number of OS entries in the BCD store and their BcdOSLoaderInteger_BootMenuPolicy.
    "\\26000005"; "Element" = 01; // REG_BINARY, attemptresume = true, false = 00 - Indicates that a resume operation should be attempted during a system restart.
    "\\25000004"; "Element" = 0300000000000000; // REG_BINARY, timeout = 3 - The boot menu time-out determines how long the boot menu is displayed before the default boot entry is loaded. It is calibrated in seconds. If you want extra time to choose the operating system that loads on your computer, you can extend the time-out value. Or, you can shorten the time-out value so that the default operating system starts faster. - If this value is not specified, the boot manager waits for the user to make a selection. - The maximum number of seconds a boot selection menu is to be displayed to the user. The menu is displayed until the user selects an option or the time-out expires.
    "\\24000010"; "Element" = {memdiag}; // REG_MULTI_SZ, toolsdisplayorder = {memdiag} - The boot manager tools display order list.
    "\\24000002"; "Element" = {current}; // REG_MULTI_SZ, bootsequence = {current} - If the firmware boot manager does not support loading multiple applications, this list cannot contain more than one entry. - List of boot environment applications the boot manager should execute. The applications are executed in the order they appear in this list.
    "\\24000001"; "Element" = {current}; // REG_MULTI_SZ, displayorder = {current} - The order in which BCD objects should be displayed. Objects are displayed using the string specified by the BcdLibraryString_Description element.
    "\\23000006"; "Element" = {resume}; // REG_SZ, resumeobject = {resume} - The resume application object.
    "\\23000003"; "Element" = {current}; // REG_SZ, default = {current} - The default boot environment application to load if the user does not select one.
    "\\22000023"; "Element" = \EFI\Microsoft\Boot\BCD; // REG_SZ, bcdfilepath = \EFI\Microsoft\Boot\BCD - The boot application.
    "\\21000022"; "Element" = partition=\Device\HarddiskVolume1; // REG_BINARY, bcddevice = partition=\Device\HarddiskVolume1 - The device on which the boot application resides.
    "\\14000006"; "Element" = {globalsettings}; // REG_MULTI_SZ, inherit = {globalsettings} - List of BCD objects from which the current object should inherit elements.
    "\\12000005"; "Element" = en-US; // REG_SZ, locale = en-US - Preferred locale, in RFC 3066 format.
    "\\12000004"; "Element" = Windows Boot Manager; // REG_SZ, description = Windows Boot Manager - Display name of the boot environment application.
    "\\12000002"; "Element" = \EFI\MICROSOFT\BOOT\BOOTMGFW.EFI; // REG_SZ, path = \EFI\MICROSOFT\BOOT\BOOTMGFW.EFI - Path to a boot environment application.
    "\\11000001"; "Element" = partition=\Device\HarddiskVolume1; // REG_BINARY, device = partition=\Device\HarddiskVolume1 - Device on which a boot environment application resides.
"HKLM\\BCD00000000\\Objects\\{memdiag}\\Elements";
    "\\26000004"; "Element" = 01; // REG_BINARY, failuresenabled = true, false = 00
    "\\25000009"; "Element" = 0000000000000000; // REG_BINARY, chckrfailcount = 0
    "\\25000007"; "Element" = 0000000000000000; // REG_BINARY, matsfailcount = 0
    "\\25000006"; "Element" = 0000000000000000; // REG_BINARY, invcfailcount = 0
    "\\25000005"; "Element" = 0000000000000000; // REG_BINARY, stridefailcount = 0
    "\\25000003"; "Element" = 0000000000000000; // REG_BINARY, failurecount = 0 - The number of pages that contain errors. This is useful for simulating error flows in the absence of bad physical memory.
    "\\25000002"; "Element" = 0000000000000000; // REG_BINARY, testmix = 0
    "\\25000001"; "Element" = 0000000000000000; // REG_BINARY, passcount = 0 - If this value is not specified, the default is to run memory diagnostic tests until the computer is powered off or the user logs off. - The number of passes for the current test mix.
    "\\1600000B"; "Element" = 01; // REG_BINARY, badmemoryaccess = true, false = 00 - If TRUE, indicates that a boot application can use memory listed in the BcdLibraryIntegerList_BadMemoryList.
    "\\14000006"; "Element" = {globalsettings}; // REG_MULTI_SZ, inherit = {globalsettings} - List of BCD objects from which the current object should inherit elements.
    "\\12000005"; "Element" = en-US; // REG_SZ, locale = en-US - Preferred locale, in RFC 3066 format.
    "\\12000004"; "Element" = Windows Memory Diagnostic; // REG_SZ, description = Windows Memory Diagnostic - Display name of the boot environment application.
    "\\12000002"; "Element" = \EFI\Microsoft\Boot\memtest.efi; // REG_SZ, path = \EFI\Microsoft\Boot\memtest.efi - Path to a boot environment application.
    "\\11000001"; "Element" = partition=\Device\HarddiskVolume1; // REG_BINARY, device = partition=\Device\HarddiskVolume1 - Device on which a boot environment application resides.
"HKLM\\BCD00000000\\Objects\\{badmemory}\\Elements";
    "\\1700000A"; "Element" = 0000000000000000; // REG_BINARY, badmemorylist = <integer list> - List of page frame numbers describing faulty memory in the system.
"HKLM\\BCD00000000\\Objects\\{winre}\\Elements";
    "\\46000010"; "Element" = 01; // REG_BINARY, custom:46000010 = true, false = 00
    "\\26000022"; "Element" = 01; // REG_BINARY, winpe = true, false = 00 - Indicates that the system should be started in Windows Preinstallation Environment (Windows PE) mode.
    "\\250000C2"; "Element" = 0100000000000000; // REG_BINARY, bootmenupolicy = 1 (Standard), Legacy = 0000000000000000 - Defines the type of boot menus the system will use. Possible values include menupolicylegacy (0) or menupolicystandard (1). The default value is menupolicylegacy (0).
    "\\25000020"; "Element" = 0000000000000000; // REG_BINARY, nx = 0 (OptIn), OptOut = 0100000000000000, AlwaysOff = 0200000000000000, AlwaysOn = 0300000000000000 - If this value is not specified, the default is NxPolicyAlwaysOff. - The no-execute page protection policy.
    "\\22000002"; "Element" = \windows; // REG_SZ, systemroot = \windows - This value is reserved.
    "\\21000001"; "Element" = ramdisk=[C:]\Recovery\WindowsRE\Winre.wim,{ramdiskoptions}; // REG_BINARY, osdevice = ramdisk=[C:]\Recovery\WindowsRE\Winre.wim,{ramdiskoptions} - This value is reserved.
    "\\15000065"; "Element" = 0300000000000000; // REG_BINARY, displaymessage = 3 (Recovery), Resume = 0100000000000000
    "\\14000006"; "Element" = {bootloadersettings}; // REG_MULTI_SZ, inherit = {bootloadersettings} - List of BCD objects from which the current object should inherit elements.
    "\\12000005"; "Element" = en-us; // REG_SZ, locale = en-us - Preferred locale, in RFC 3066 format.
    "\\12000004"; "Element" = Windows Recovery Environment; // REG_SZ, description = Windows Recovery Environment - Display name of the boot environment application.
    "\\12000002"; "Element" = \windows\system32\winload.efi; // REG_SZ, path = \windows\system32\winload.efi - Path to a boot environment application.
    "\\11000001"; "Element" = ramdisk=[C:]\Recovery\WindowsRE\Winre.wim,{ramdiskoptions}; // REG_BINARY, device = ramdisk=[C:]\Recovery\WindowsRE\Winre.wim,{ramdiskoptions} - Device on which a boot environment application resides.
"HKLM\\BCD00000000\\Objects\\{ramdiskoptions}\\Elements";
    "\\3600000B"; "Element" = 01; // REG_BINARY, ramdisktftpvarwindow = true, false = 00 - Enables or disables the TFTP variable window size extension.
    "\\3600000A"; "Element" = 01; // REG_BINARY, ramdiskmulticasttftpfallback = true, false = 00 (ramdiskmctftpfallback) - Enables fallback to TFTP if multicast fails.
    "\\36000009"; "Element" = 01; // REG_BINARY, ramdiskmulticastenabled = true, false = 00 (ramdiskmcenabled) - Enables or disables multicast for the RAM disk WIM file.
    "\\36000008"; "Element" = 0000000000000000; // REG_BINARY, ramdisktftpwindowsize = 0 - Defines the TFTP window size for the RAM disk WIM file.
    "\\36000007"; "Element" = 0000000000000000; // REG_BINARY, ramdisktftpblocksize = 0 - Defines the TFTP block size for the RAM disk Windows Imaging (WIM) file.
    "\\36000006"; "Element" = 01; // REG_BINARY, ramdiskexportascd = true, false = 00 - Enables exporting the RAM disk as a CD.
    "\\35000008"; "Element" = 0000000000000000; // REG_BINARY, ramdisktftpwindowsize = 0 (BitLocker list uses 0x35000008)
    "\\35000007"; "Element" = 0000000000000000; // REG_BINARY, ramdisktftpblocksize = 0 (BitLocker list uses 0x35000007)
    "\\35000005"; "Element" = 0000000000000000; // REG_BINARY, ramdiskimagelength = 0 - The length of the image for the RAM disk.
    "\\35000002"; "Element" = 0000000000000000; // REG_BINARY, tftpclientport = 0 - If this value is not specified, the default TFTP protocol port is used. - The IP port number to be used for Trivial File Transfer Protocol (TFTP) reads.
    "\\35000001"; "Element" = 0000000000000000; // REG_BINARY, ramdiskimageoffset = 0 - The RAM disk image offset.
    "\\32000004"; "Element" = \Recovery\WindowsRE\boot.sdi; // REG_SZ, ramdisksdipath = \Recovery\WindowsRE\boot.sdi - The path from the root of the SDI device to the RAM disk file.
    "\\31000003"; "Element" = partition=C:; // REG_BINARY, ramdisksdidevice = partition=C: - The device that contains the SDI object.
    "\\12000004"; "Element" = Windows Recovery; // REG_SZ, description = Windows Recovery - Display name of the boot environment application.
"HKLM\\BCD00000000\\Objects\\{globalsettings}\\Elements";
    "\\16000069"; "Element" = 01; // REG_BINARY, custom:16000069 = true, false = 00
    "\\16000067"; "Element" = 01; // REG_BINARY, custom:16000067 = true, false = 00
    "\\14000006"; "Element" = {dbgsettings};{emssettings};{badmemory}; // REG_MULTI_SZ, inherit = {dbgsettings}, {emssettings}, {badmemory} - List of BCD objects from which the current object should inherit elements.
"HKLM\\BCD00000000\\Objects\\{resumeloadersettings}\\Elements";
    "\\14000006"; "Element" = {globalsettings}; // REG_MULTI_SZ, inherit = {globalsettings} - List of BCD objects from which the current object should inherit elements.
"HKLM\\BCD00000000\\Objects\\{bootloadersettings}\\Elements";
    "\\14000006"; "Element" = {globalsettings};{hypervisorsettings}; // REG_MULTI_SZ, inherit = {globalsettings}, {hypervisorsettings} - List of BCD objects from which the current object should inherit elements.
"HKLM\\BCD00000000\\Objects\\{dbgsettings}\\Elements";
    "\\1600001C"; "Element" = 01; // REG_BINARY, debuggernetdhcp = true, false = 00 - Controls the use of DHCP by the network debugger. Setting this to false causes the OS to only use link-local addresses.
    "\\16000017"; "Element" = 01; // REG_BINARY, debuggerignoreusermodeexceptions = true, false = 00 - If TRUE, the debugger will ignore user mode exceptions and only stop for kernel mode exceptions.
    "\\16000010"; "Element" = 01; // REG_BINARY, debuggerenabled = true, false = 00 - Indicates whether the boot debugger should be enabled.
    "\\1500001B"; "Element" = 0000000000000000; // REG_BINARY, debuggernetport = 0 - Defines the network port for the network debugger.
    "\\1500001A"; "Element" = 0000000000000000; // REG_BINARY, debuggernethostip = 0 - Defines the host IP address for the network debugger.
    "\\15000018"; "Element" = 0000000000000000; // REG_BINARY, debuggerstartpolicy = 0 - Indicates the debugger start policy.
    "\\15000015"; "Element" = 0000000000000000; // REG_BINARY, debugger1394channel = 0 - Channel number for 1394 debugging.
    "\\15000014"; "Element" = 00c2010000000000; // REG_BINARY, debuggerserialbaudrate = 115200 - If this value is not specified, the default is specified by the DBGP ACPI table settings. - Baud rate for serial debugging.
    "\\15000013"; "Element" = 0100000000000000; // REG_BINARY, debuggerserialport = 1 - If this value is not specified, the default is specified by the DBGP ACPI table settings. - Serial port number for serial debugging.
    "\\15000012"; "Element" = 0000000000000000; // REG_BINARY, debuggerserialportaddress = 0 - I/O port address for the serial debugger.
    "\\15000011"; "Element" = 0400000000000000; // REG_BINARY, debugtype = 4 (Local - undocumented), Serial = 0000000000000000, 1394 = 0100000000000000, USB = 0200000000000000, NET = 0300000000000000 - Debugger type.
    "\\1200001D"; "Element" = testkey; // REG_SZ, debuggernetkey = testkey - Holds the key used to encrypt the network debug connection.
    "\\12000019"; "Element" = 0.25.0; // REG_SZ, debuggerbusparams = 0.25.0 - Defines the PCI bus, device, and function numbers of the debugging device. For example, 1.5.0 describes the debugging device on bus 1, device 5, function 0.
    "\\12000016"; "Element" = usbtarget; // REG_SZ, debuggerusbtargetname = usbtarget - The target name for the USB debugger. The target name is arbitrary but must match between the debugger and the debug target.
"HKLM\\BCD00000000\\Objects\\{emssettings}\\Elements";
    "\\16000020"; "Element" = 00; // REG_BINARY, bootems = false, true = 01 - Indicates whether EMS redirection should be enabled.
    "\\15000023"; "Element" = 00c2010000000000; // REG_BINARY, emsbaudrate = 115200 - Baud rate for EMS redirection.
    "\\15000022"; "Element" = 0100000000000000; // REG_BINARY, emsport = 1 - If this value is not specified, the default is specified by the SPCR ACPI table settings. - COM port number for EMS redirection.
"HKLM\\BCD00000000\\Objects\\{fwbootmgr}\\Elements";
    "\\25000004"; "Element" = 0100000000000000; // REG_BINARY, timeout = 1 - If this value is not specified, the boot manager waits for the user to make a selection. - The maximum number of seconds a boot selection menu is to be displayed to the user. The menu is displayed until the user selects an option or the time-out expires.
    "\\24000001"; "Element" = {bootmgr}; // REG_MULTI_SZ, displayorder = {bootmgr} - The order in which BCD objects should be displayed. Objects are displayed using the string specified by the BcdLibraryString_Description element.
"HKLM\\BCD00000000\\Objects\\{hypervisorsettings}\\Elements";
    "\\26000114"; "Element" = 00; // REG_BINARY, hypervisordhcp = false, true = 01 - Controls use of DHCP by the network debugger used with the hypervisor. Setting this to false forces local link only address.
    "\\250000FE"; "Element" = 50c3000000000000; // REG_BINARY, hypervisorhostport = 50000 - Defines the network UDP port for the network debugger.
    "\\250000FD"; "Element" = 0201a8c000000000; // REG_BINARY, hypervisorhostip = 3232235778 (192.168.1.2) - Defines the host IPv4 address for the network debugger.
    "\\250000F6"; "Element" = 0000000000000000; // REG_BINARY, hypervisorchannel = 0 - Specifies the channel number for 1394 debugging.
    "\\250000F5"; "Element" = 00c2010000000000; // REG_BINARY, hypervisorbaudrate = 115200 - If this value is not specified, the default is specified by the DBGP ACPI table settings. - Specifies the baud rate for serial debugging.
    "\\250000F4"; "Element" = 0100000000000000; // REG_BINARY, hypervisordebugport = 1 - If this value is not specified, the default is specified by the DBGP ACPI table settings. - Specifies the serial port number for serial debugging.
    "\\250000F3"; "Element" = 0000000000000000; // REG_BINARY, hypervisordebugtype = 0 (Serial), 1394 = 0100000000000000, NET = 0300000000000000 - Controls the hypervisor debugger type. Can be set to SERIAL (0), 1394 (1), or NET (2).
    "\\22000110"; "Element" = testkey; // REG_SZ, hypervisorusekey = testkey - Holds the key used to encrypt the network debug connection used with the hypervisor.
    "\\220000F9"; "Element" = 0.25.0; // REG_SZ, hypervisorbusparams = 0.25.0 - Defines the PCI bus, device, and function numbers of the debugging device used with the hypervisor. For example, 1.5.0 describes the debugging device on bus 1, device 5, function 0.
```

`{bootmgr}` - Windows Boot Manager  
`{fwbootmgr}` - Firmware Boot Manager  
`{current}` - Windows Boot Loader (current OS entry)  
`{resume}` - Windows Resume Application (resumeobject)  
`{winre}` - Windows Recovery Environment loader (recoverysequence)  
`{memdiag}` - Windows Memory Diagnostic  
`{ramdiskoptions}` - Device options for ramdisk (boot.sdi)  
`{globalsettings}` - Global settings  
`{bootloadersettings}` - Boot loader settings  
`{resumeloadersettings}` - Resume loader settings  
`{dbgsettings}` - Debugger settings  
`{emssettings}` - EMS settings  
`{badmemory}` - RAM defects  
`{hypervisorsettings}` - Hypervisor settings

## [Windows Internals](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf)

![](https://github.com/nohuto/win-config/blob/main/system/images/bcdedit1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/bcdedit2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/bcdedit3.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/bcdedit4.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/bcdedit5.png?raw=true)

## Pseudocode Notes

Personal notes on several features in relation of [HalpMiscGetParameters](https://github.com/nohuto/win-config/blob/main/system/assets/bcdedit-HalpMiscGetParameters.c).

```c
lkd> db HalpInterruptX2ApicPolicy l1
fffff807`8d20a5dc  01

if ( strstr(v3, "X2APICPOLICY=ENABLE") )
    HalpInterruptX2ApicPolicy = 1;

if ( strstr(v3, "X2APICPOLICY=DISABLE") )
    HalpInterruptX2ApicPolicy = 0;

if ( strstr(v3, "USELEGACYAPICMODE") )
    HalpInterruptX2ApicPolicy = 0; // force disable
```
```c
lkd> db HalpTscSyncPolicy l1
Couldnt resolve error at HalpTscSyncPolicy // doesn't exist

HalpTscSyncPolicy = 1; // TSCSYNCPOLICY=LEGACY
HalpTscSyncPolicy = 2; // TSCSYNCPOLICY=ENHANCED
```

`bcdedit /set loadoptions SYSTEMWATCHDOGPOLICY=DISABLED`
```c
if ( strstr(v3, "SYSTEMWATCHDOGPOLICY=DISABLED") )
{
    HalpTimerWatchdogDisable = 1;
}
else if ( strstr(v3, "SYSTEMWATCHDOGPOLICY=PHYSICALONLY") )
{
    HalpTimerWatchdogPhysicalOnly = 1;
}

lkd> db HalpTimerWatchdogDisable l1
fffff803`d21c0712  00 // default
```
```c
lkd> db HalpTimerPlatformSourceForced l1
fffff803`d21c25d0  00
lkd> db HalpTimerPlatformClockSourceForced l1
fffff803`d21c2678  00

if ( strstr(v3, "USEPLATFORMCLOCK") )
    HalpTimerPlatformSourceForced = 1;

if ( strstr(v3, "USEPLATFORMTICK") )
    HalpTimerPlatformClockSourceForced = 1;
```
```c
v17 = strstr(v3, "GROUPSIZE");
if ( v17 )
{
    while ( 1 )
    {
        v18 = *v17;
        if ( !*v17 || v18 == 32 || (unsigned __int8)(v18 - 48) <= 9u )
            break;
        ++v17;
    }
    HalpMaximumGroupSize = atoi(v17);
    if ( (unsigned int)(HalpMaximumGroupSize - 1) > 0x3F )
        HalpMaximumGroupSize = 64; // clamp to 1..64
}

strstr(v3, "HALTPROFILINGPOLICY=BLOCKED");
strstr(v3, "HALTPROFILINGPOLICY=RELAXED");
return strstr(v3, "HALTPROFILINGPOLICY=RESTRICTED"); // only returns pointer if present
```
```c
lkd> db HalpMiscDiscardLowMemory l1
fffff803`d21bff79  01 // USENONE / USEPRIVATE?
lkd> db HalpHvCpuManager l1
fffff804`c27c0490  00

if ( (unsigned int)HalpInterruptModel() == 1 )
    HalpMiscDiscardLowMemory = 1; // default if HalpInterruptModel() == 1

if ( HalpHvCpuManager )
{
    v19[0] = 0;
    if ( (unsigned __int8)HalpGetCpuInfo(0LL, 0LL, 0LL, v19) )
    {
        if ( v19[0] == 2 && (__readmsr(0xFEu) & 0x8000) != 0 )
        HalpMiscDiscardLowMemory = 1; // 1 if HV CPU manager + CPU type 2 + MSR 0xFE bit 15 set
    }
}
if (strstr(BootOptions, "FIRSTMEGABYTEPOLICY=USEALL") || // one of them have to be true to get 0
    (HalpIsMicrosoftCompatibleHvLoaded() && !HalpHvCpuManager)) // system running under hypervisor & not HalpHvCpuManager
{
    HalpMiscDiscardLowMemory = 0; // forced 0 if above is true
}
```
```c
v3 = *(const char **)(a1 + 216);
if ( v3 )
{
    strstr(*(const char **)(a1 + 216), "SAFEBOOT:"); // does nothing here

    if ( strstr(v3, "ONECPU") )
        HalpInterruptProcessorCap = 1;

    if ( strstr(v3, "USEPHYSICALAPIC") )
        HalpInterruptPhysicalModeOnly = 1;

    if ( strstr(v3, "BREAK") )
        HalpMiscDebugBreakRequested = 1;
}
```
```c
v4 = strstr(v3, "MAXPROCSPERCLUSTER");
if ( v4 )
{
    while ( 1 )
    {
        v5 = *v4;
        if ( !*v4 || v5 == 32 || (unsigned __int8)(v5 - 48) <= 9u )
            break;
        ++v4;
    }
    v6 = atoi(v4);
    HalpInterruptForceClusterMode(v6);
}

v7 = strstr(v3, "MAXAPICCLUSTER");
if ( v7 )
{
    while ( 1 )
    {
        v8 = *v7;
        if ( !*v7 || v8 == 32 || (unsigned __int8)(v8 - 48) <= 9u )
            break;
        ++v7;
    }
    v9 = atoi(v7);
    if ( v9 )
        LODWORD(HalpInterruptMaxCluster) = v9;
}
```
```c
if ( strstr(v3, "CONFIGACCESSPOLICY=DISALLOWMMCONFIG") )
    HalpAvoidMmConfigAccessMethod = 1; // force avoid
```
```c
if ( strstr(v3, "MSIPOLICY=FORCEDISABLE") ) // HalpInterruptSetMsiOverride(0)
{
    v10 = 0LL;
}
else
{
    if ( !strstr(v3, "FORCEMSI") ) // HalpInterruptSetMsiOverride(1)
        goto LABEL_46;
    LOBYTE(v10) = 1;
}
HalpInterruptSetMsiOverride(v10);
```

## Custom Edits

`custom:16000067 true` disables the Windows logo while booting:

![](https://github.com/nohuto/win-config/blob/main/system/images/logo.png?raw=true)

`custom:16000069 true` disables the loading circle while booting:

![](https://github.com/nohuto/win-config/blob/main/system/images/load.png?raw=true)

## Default Entries

Default entries (25H2, Build 26200.6584) including WinRE:
```powershell
Windows Boot Manager
--------------------
identifier              {9dea862c-5cdd-4e70-acc1-f32b344d4795}
device                  partition=\Device\HarddiskVolume1
description             Windows Boot Manager
locale                  en-US
inherit                 {7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}
default                 {0fd8694a-e7fe-11f0-91cd-eabb9ab44a94}
resumeobject            {0fd86949-e7fe-11f0-91cd-eabb9ab44a94}
displayorder            {0fd8694a-e7fe-11f0-91cd-eabb9ab44a94}
toolsdisplayorder       {b2721d73-1db4-4c62-bf78-c548a880142d}
timeout                 30

Windows Boot Loader
-------------------
identifier              {0fd8694a-e7fe-11f0-91cd-eabb9ab44a94}
device                  partition=C:
path                    \WINDOWS\system32\winload.exe
description             Windows 11
locale                  en-US
inherit                 {6efb52bf-1766-41db-a6b3-0ee5eff72bd7}
recoverysequence        {0fd8694b-e7fe-11f0-91cd-eabb9ab44a94}
displaymessageoverride  Recovery
recoveryenabled         Yes
allowedinmemorysettings 0x15000075
osdevice                partition=C:
systemroot              \WINDOWS
resumeobject            {0fd86949-e7fe-11f0-91cd-eabb9ab44a94}
nx                      OptIn
bootmenupolicy          Standard

Windows Boot Loader
-------------------
identifier              {0fd8694b-e7fe-11f0-91cd-eabb9ab44a94}
device                  ramdisk=[\Device\HarddiskVolume3]\Recovery\WindowsRE\Winre.wim,{0fd8694c-e7fe-11f0-91cd-eabb9ab44a94}
path                    \windows\system32\winload.exe
description             Windows Recovery Environment
locale                  en-US
inherit                 {6efb52bf-1766-41db-a6b3-0ee5eff72bd7}
displaymessage          Recovery
osdevice                ramdisk=[\Device\HarddiskVolume3]\Recovery\WindowsRE\Winre.wim,{0fd8694c-e7fe-11f0-91cd-eabb9ab44a94}
systemroot              \windows
nx                      OptIn
bootmenupolicy          Standard
winpe                   Yes
custom:46000010         Yes

Resume from Hibernate
---------------------
identifier              {0fd86949-e7fe-11f0-91cd-eabb9ab44a94}
device                  partition=C:
path                    \WINDOWS\system32\winresume.exe
description             Windows Resume Application
locale                  en-US
inherit                 {1afa9c49-16ab-4a5c-901b-212802da9460}
recoverysequence        {0fd8694b-e7fe-11f0-91cd-eabb9ab44a94}
recoveryenabled         Yes
allowedinmemorysettings 0x15000075
filedevice              partition=C:
custom:21000026         partition=C:
filepath                \hiberfil.sys
bootmenupolicy          Standard
debugoptionenabled      No

Windows Memory Tester
---------------------
identifier              {b2721d73-1db4-4c62-bf78-c548a880142d}
device                  partition=\Device\HarddiskVolume1
path                    \boot\memtest.exe
description             Windows Memory Diagnostic
locale                  en-US
inherit                 {7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}
badmemoryaccess         Yes

EMS Settings
------------
identifier              {0ce4991b-e6b3-4b16-b23c-5e0d9250e5d9}
bootems                 No

Debugger Settings
-----------------
identifier              {4636856e-540f-4170-a130-a84776f4c654}
debugtype               Local

RAM Defects
-----------
identifier              {5189b25c-5558-4bf2-bca4-289b11bd29e2}

Global Settings
---------------
identifier              {7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}
inherit                 {4636856e-540f-4170-a130-a84776f4c654}
                        {0ce4991b-e6b3-4b16-b23c-5e0d9250e5d9}
                        {5189b25c-5558-4bf2-bca4-289b11bd29e2}

Boot Loader Settings
--------------------
identifier              {6efb52bf-1766-41db-a6b3-0ee5eff72bd7}
inherit                 {7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}
                        {7ff607e0-4395-11db-b0de-0800200c9a66}

Hypervisor Settings
-------------------
identifier              {7ff607e0-4395-11db-b0de-0800200c9a66}
hypervisordebugtype     Serial
hypervisordebugport     1
hypervisorbaudrate      115200

Resume Loader Settings
----------------------
identifier              {1afa9c49-16ab-4a5c-901b-212802da9460}
inherit                 {7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}

Device options
--------------
identifier              {0fd8694c-e7fe-11f0-91cd-eabb9ab44a94}
description             Windows Recovery
ramdisksdidevice        partition=\Device\HarddiskVolume3
ramdisksdipath          \Recovery\WindowsRE\boot.sdi
```

# Page File

Several notes I took while reading through [`Windows Internals Part 1, Edition 7`](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf), everything written below is based on it.

**You should calculate it while daily workload, or your peak value won't be accurate.**

Paging files are configured via `System > Advanced system settings > Performance > Advanced > Virtual memory`, but they are only one component of virtual memory. Even with no paging file, every process still uses virtual address space managed by the memory manager. Private pages must always live somewhere. RAM holds them while they are in use, and paging files act as disk backed storage so the memory manager can reclaim physical pages when demand grows.

Windows tracks private committed memory as the "commit charge" and enforces a "commit limit" equal to available RAM plus the total size of all paging files. This ensures Windows never promises more pageable storage than it can keep either in memory or in paging files. When commit charge climbs toward the limit, the modified page writer (`MiModifiedPageWriter`) flushes dirty pages to paging files so their physical frames can be reused. If the limit is reached and paging files can't grow, further private allocations fail until memory is freed. Task manager's performance tab/process explorer's system information window/system informers system information display current commit, the commit limit, and the peak value so you can see how much paging file space recent workloads required.

Size calculation if leaving it system managed and RAM as base would be if RAM <= 1 GB, then size = 1 GB. If RAM > 1 GB, then add 1/8 GB for every extra gigabyte of RAM, up to a maximum of 32 GB.

## How the option calculates it

If peak commit is below physical memory, no paging file would have been necessary (the option won't set it to 0, if you do there's literally nowhere to place additional committed pages, so allocations fail and you can even hit a bugcheck). If it exceeds RAM, the difference is the minimum disk backed capacity needed so the commit limit (RAM + paging files) stays above demand. Reads `\Process(_Total)\Page File Bytes Peak`, computes the Smss RAM baseline (`1 GB + 1/8 GB per extra GB of RAM`, capped at 32 GB), and checks whether `peak – RAM` is positive. If the workload never exceeded RAM, it keeps the Smss baseline. Otherwise, it uses the excess value (and currently a safety buffer of 10%, clamped to 1GB if RAM is >= 10 GB).

## Clearing Page File on Shutdown

Paging files can contain fragments of process or kernel data. Enabling the option mitigates offline data exposure at the cost of longer shutdowns.

Local Security Policy: 
> *This security setting determines whether the virtual memory pagefile is cleared when the system is shut down.*
>
> *Virtual memory support uses a system pagefile to swap pages of memory to disk when they are not used. On a running system, this pagefile is opened exclusively by the operating system, and it is well protected. However, systems that are configured to allow booting to other operating systems might have to make sure that the system pagefile is wiped clean when this system shuts down. This ensures that sensitive information from process memory that might go into the pagefile is not available to an unauthorized user who manages to directly access the pagefile.*
>
> *When this policy is enabled, it causes the system pagefile to be cleared upon clean shutdown. If you enable this security option, the hibernation file (hiberfil.sys) is also zeroed out when hibernation is disabled.*

# Enable Segment Heap

"With the introduction of Windows 10, Segment Heap, a new native heap implementation was also introduced. It is currently the native heap implementation used in Windows apps (formerly called Modern/Metro apps) and in certain system processes, while the older native heap implementation (NT Heap) is still the default for traditional applications." Allows modern apps to use a more efficient memory allocator. [Windows Internals (E7-P1, Segment heap)](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf): UWP apps default to segment heaps, while desktop apps keep the NT heap for compatibility. Segment heaps separate metadata from user data and can reduce overhead, but they are not compatible with all heap patterns.

It's recommended to read '[W10 Segment Heap Internals](https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals-wp.pdf)' whenever you want to know more about the differences between NT/Segment Heap.

## Per Executable / Globally

For a specific executeable:
```c
"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<executable>"
  "FrontEndHeapDebugOptions"; // REG_DWORD, bit 2 (0x4) = disable segment heap, bit 3 (0x8) = enable segment heap
```

Globally:
```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Segment Heap"
  "Enabled"; // REG_DWORD, 0 = disable segment heap, nonzero = enable segment heap
```

Enabling segment heap globally forces the system to use the newer segmented allocation model, which can end up with errors (`The exception unknown software exception (0xc000000d) occurred in the application at location 0x00007FFF1E13FF03`). It's not recommended to enable it globally.

## Validating Changes

You can see whenever a program uses 'Segment Heap' or 'NT Heap' via for example [SI](https://github.com/winsiderss/systeminformer/) (Right Click > Miscellaneous > Heaps).

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mullvadbrowser.exe`, `FrontEndHeapDebugOptions` = `0x4`:

![](https://github.com/nohuto/win-config/blob/main/system/images/ntheap.png?raw=true)

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mullvadbrowser.exe`, `FrontEndHeapDebugOptions` = `0x8`:

![](https://github.com/nohuto/win-config/blob/main/system/images/segmentheap.png?raw=true)

## Default Values

```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
    "HeapDeCommitFreeBlockThreshold" = 4096; // qword_140FC3210 dq 1000
    "HeapDeCommitTotalFreeThreshold" = 65536; // qword_140FC3218 dq 10000
    "HeapSegmentCommit" = 8192; // qword_140FC3220 dq 2000
    "HeapSegmentReserve" = 1048576; // qword_140FC3228 dq 100000

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Segment Heap";
    "Enabled" = 0; // if present with DataLength==4 and nonzero type:
                    //    RtlpLowFragHeapGlobalFlags |= 0x10;  // global segment heap enable
                    //    if (value & 0x2)                      // low byte, bit 1
                    //        RtlpLowFragHeapGlobalFlags |= 0x20; // extra option ?
                    // if the value exists but is stored as REG_NONE (type==0):
                    //    RtlpLowFragHeapGlobalFlags |= 0x8;   // global disable/override
```

- [system/assets | segment-RtlpHpApplySegmentHeapConfigurations.c](https://github.com/nohuto/win-config/blob/main/system/assets/segment-RtlpHpApplySegmentHeapConfigurations.c)

## [Windows Internals](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

![](https://github.com/nohuto/win-config/blob/main/system/images/segment1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/segment2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/segment3.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/segment4.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/segment5.png?raw=true)

# Disable Notifications

## Option/Suboptions

| Option | Description |
| ---- | ---- |
| Main | Disables all kind of notifications completely. |
| Disable Low Disk Space Checks | Disables the `Low Disk Space` notification. ![](https://github.com/nohuto/win-config/blob/main/system/images/lowdiskspace.jpg?raw=true) |
| Hide all Windows Security notifications | Disables all notifications via the `DisableNotifications`  policy (this probably overrides all other security notifications below). |
| Hide non-critical Windows Security notifications | Disables non-critical/enhanced notifications via the Windows Security and Microsoft Defender Antivirus `DisableEnhancedNotifications` policies. |
| Disable Enhanced Phishing Protection warnings | Disables the Enhanced Phishing Protection warning prompts for malicious sites, password reuse, and unsafe apps. |
| Disable Virus & threat protection notifications | Disables all in `Windows Security > Settings > Manage notifications: Virus & threat protection notifications` |
| Disable Account protection notifications | Disables all in `Windows Security > Settings > Manage notifications: Account protection notifications` |
| Disable Firewall & network protection notifications | Disables all in `Windows Security > Settings > Manage notifications: Firewall & network protection notifications` |
| Disable Security & Maintenance Notifications | Disables it via `SystemSettings > System > Notifications: Security and Maintenance` |
| Disable Sync Provider Notifications | Disables it via `Explorer > View > Options > View: Show sync provider notifications` |
| Disable account-related notifications | Disables it via `SystemSettings > Personalization > Start: Show account related notifications occasionally in Start` |
| Disable Clock Change notifications | Disables it via `Control Panel > Clock and Region > Date and Time: Notify me when the clock chanes` |
| Hide Notification Center | Works via `NoAutoTrayNotify`/`DisableNotificationCenter` policies and `SystemSettings > System > Notifications: Show notification bell icon` |
| Disable Notification Sound | Disables it via `SystemSettings > System > Notifications > Allow notifications to play sound` |
| Disable Lockscreen Notifications | Works via `DisableLockScreenAppNotifications` policy and `SystemSettings > System > Notifications: Show notifications on the lock screen + Show reminders and incoming VoIP calls on the lock screen` |
| Turn off access to the Store | `NoUseStoreOpenWith` policy - "*This policy setting specifies whether to use the Store service for finding an application to open a file with an unhandled file type or protocol association. When a user opens a file type or protocol that is not associated with any applications on the computer, the user is given the choice to select a local application or use the Store service to find an application. If you enable this policy setting, the "Look for an app in the Store" item in the Open With dialog is removed. If you disable or do not configure this policy setting, the user is allowed to use the Store service and the Store item is available in the Open With dialog.*" |
| Hide Time in Notification Center | Works via `SystemSettings > Time & language > Date & time: Show time and date in the System tray` |

## Miscellaneous Notes

### WnsEndpoint

"`WnsEndpoint` (`REG_SZ`) determines which Windows Notification Service (WNS) endpoint will be used to connect for Windows push notifications. If you disable or don't configure this setting, the push notifications will connect to the default endpoint of `client.wns.windows.com`. " Located in `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications`. Block `client.wns.windows.com` via the hosts file.

### Registry Values

All `NOC_GLOBAL_SETTING_*` I found in `NotificationController.dll`:
```c
"HKLM\\SOFTWARE\\Microsoft\\WINDOWS\\CurrentVersion\\Notifications\\Settings"
  'NOC_GLOBAL_SETTING_SUPRESS_TOASTS_WHILE_DUPLICATING'; // Hide notifications when I'm duplicating my screen
  'NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK'; // Show notifications on the lock screen
  'NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK'; // Show reminders and incoming VoIP calls on the lock screen
  'NOC_GLOBAL_SETTING_CORTANA_MANAGED_NOTIFICATIONS';
  'NOC_GLOBAL_SETTING_ALLOW_ACTION_CENTER_ABOVE_LOCK';
  'NOC_GLOBAL_SETTING_HIDE_NOTIFICATION_CONTENT';
  'NOC_GLOBAL_SETTING_TOASTS_ENABLED';
  'NOC_GLOBAL_SETTING_BADGE_ENABLED'; // Don't show number of notifications
  'NOC_GLOBAL_SETTING_GLEAM_ENABLED'; // App icons (Action Center)
  'NOC_GLOBAL_SETTING_ALLOW_HMD_NOTIFICATIONS'; // Show notifications on my head mounted display
  'NOC_GLOBAL_SETTING_ALLOW_CONTROL_CENTER_ABOVE_LOCK';
  'NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND'; // Allow notification to play sounds
```
The options I've commented on are included in the options under `System > Notifications`/right click menu of notification center.

Since `BackupReminderToastCount` isn't a well known value, I've done quick research where it exists and if it does exist. While doing so I found different values:
```c
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy";
    "StoragePoliciesNotified" = 0; // REG_DWORD, default 0 if missing, range: 0-1
    "StoragePoliciesChanged" = 0; // REG_DWORD, default 0 if missing, range: 0-1
    "OptinToastFired" = 0; // REG_DWORD, default 0 if missing, range: 0-1
    "FirstLaunchToastFired" = 0; // REG_DWORD, default 0 if missing, range: 0-1
    "CloudfilePolicyConsent" = 0; // REG_DWORD, default 0 if missing, range: 0-1
    "CloudConsentToastCount" = 0; // REG_DWORD, default 0 if missing, range: 0-3
    "OptOutButtonClicked" = 0; // REG_DWORD, default 0 if missing, range: 0-1

"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DiskSpaceChecking";
    "LastInstallTimeLowStorageNotify" = 0; // REG_QWORD FILETIME, range: FILETIME, ComparedTo: OneDay
    "NumWinOldLowStorageNotify" = 0; // REG_DWORD, default 0 if missing, range: 0-3

"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion";
    "InstallTime" = 0; // REG_QWORD FILETIME, range: FILETIME, ComparedTo: TwoHours

"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\BackupReminder";
    "TestBackupReminderToast" = 0; // REG_DWORD, default 0 if missing, range: 0-2?

"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\BackupReminder";
    "FirstProfileSeenTime" = 0; // REG_QWORD FILETIME, default set to current system time if missing, range: FILETIME, ComparedTo: FourMinutes
    "BackupReminderToastCount" = 0; // REG_DWORD, default 0 if missing, range: 0-3
    "LastTimeBackupReminderNotify" = 0; // REG_QWORD FILETIME, range: FILETIME, ComparedTo: TwoMinutes

// FILETIME THRESHOLDS
"OneDay" = 0xC92A69C000; // Seconds: 86400, 1 day, LastInstallTimeLowStorageNotify
"TwoHours" = 0x10C388D000; // Seconds: 7200, 2 hours, InstallTime
"FourMinutes" = 0x8F0D1800; // Seconds: 240, 4 minutes, FirstProfileSeenTime
"TwoMinutes" = 0x47868C00; // Seconds: 120, 2 minutes, LastTimeBackupReminderNotify
```

See [system/assets | noti-CLowDiskSpaceUI_CanShowStorageSenseToast.c](https://github.com/nohuto/win-config/blob/main/system/assets/noti-CLowDiskSpaceUI_CanShowStorageSenseToast.c) for used pseudocode. Note that I added my chosen values to the `Disable Low Disk Space Checks` suboption for safety reasons.

```c
"HKCU\\Control Panel\\Accessibility";
  // Dismiss notifications after this amount of time
  "MessageDuration" = 5; // REG_DWORD, range 5-300(s) - According to pseudocode, it has a range from `0` to `0xFFFFFFFF`. Fallback of `5`, SystemSettings supports ranges from `5` (5 seconds) to `300` (5 minutes). Anything above/below will likely be limited (haven't tested it yet).

"HKCU\\Software\\Microsoft\\Windows\\MiracastDiscovery"
  "DisableNotification" = 0; // read on boot - "HKCU\Software\Microsoft\Windows\MiracastDiscovery\DisableNotification","Type: REG_DWORD, Length: 4, Data: 0"
  "NotificationCount" = 0; // read on boot - "HKCU\Software\Microsoft\Windows\MiracastDiscovery\NotificationCount","Type: REG_DWORD, Length: 4, Data: 0"

// miscellaneous procmon boot trace values
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\IsDebugEnabled","Length: 16"
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\SmartOptOut\\InitialTimerCooldown","Length: 20"
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\SmartOptOut\\PeriodicTimerCooldown","Length: 20"
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\SmartOptOut\\SmartOptOutRevision","Type: REG_QWORD, Length: 8, Data: "
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\TimestampWhenSeen","Length: 20"
```

## SystemSettings Captures

```c
// System > Notifications

// Get notifications from apps and other senders
// On = 1 or value missing
// Off = 0
HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\ToastEnabled // Type: REG_DWORD

// Allow notifications to play sounds
// On = delete
// Off = 0
HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND // Type: REG_DWORD

// Show notifications on the lock screen
// On = NOC value deleted, LockScreenToastEnabled = 1
// Off = NOC value 0, LockScreenToastEnabled = 0
HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK // Type: REG_DWORD
HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\LockScreenToastEnabled // Type: REG_DWORD

// Show reminders and incoming VoIP calls on the lock screen
// On = delete
// Off = 0
HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK // Type: REG_DWORD

// Show notification bell icon
// On = 1
// Off = 0
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowNotificationIcon // Type: REG_DWORD

// Notifications from apps and other senders (examples since this depends on the installed apps)
// On = delete
// Off = 0
HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.ActionCenter.SmartOptOut\Enabled // Notification Suggestions
HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.Windows.Explorer\Enabled // File Explorer
HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance\Enabled // Security and Maintenance
HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.PinConsent\Enabled // Apps
HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel\Enabled // Settings
HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.StartupApp\Enabled // Startup App Notification
```

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Turn off account notifications in Start](https://www.noverse.dev/policies.html?p=AccountNotifications*DisableAccountNotifications) | `HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AccountNotifications` | `DisableAccountNotifications` |
| [Turn off access to the Store](https://www.noverse.dev/policies.html?p=ICM*ShellNoUseStoreOpenWith_2) | `HKLM\Software\Policies\Microsoft\Windows\Explorer` | `NoUseStoreOpenWith` |
| [Turn off app notifications on the lock screen](https://www.noverse.dev/policies.html?p=Logon*DisableLockScreenAppNotifications) | `HKLM\Software\Policies\Microsoft\Windows\System` | `DisableLockScreenAppNotifications` |
| [Remove Notifications and Action Center](https://www.noverse.dev/policies.html?p=Taskbar*DisableNotificationCenter) | `HKLM\Software\Policies\Microsoft\Windows\Explorer`<br>`HKCU\Software\Policies\Microsoft\Windows\Explorer` | `DisableNotificationCenter` |
| [Notify Malicious](https://www.noverse.dev/policies.html?p=WebThreatDefense*NotifyMalicious) | `HKLM\Software\Policies\Microsoft\Windows\WTDS\Components` | `NotifyMalicious` |
| [Notify Password Reuse](https://www.noverse.dev/policies.html?p=WebThreatDefense*NotifyPasswordReuse) | `HKLM\Software\Policies\Microsoft\Windows\WTDS\Components` | `NotifyPasswordReuse` |
| [Notify Unsafe App](https://www.noverse.dev/policies.html?p=WebThreatDefense*NotifyUnsafeApp) | `HKLM\Software\Policies\Microsoft\Windows\WTDS\Components` | `NotifyUnsafeApp` |
| [Turn off enhanced notifications](https://www.noverse.dev/policies.html?p=WindowsDefender*Reporting_DisableEnhancedNotifications) | `HKLM\Software\Policies\Microsoft\Windows Defender\Reporting` | `DisableEnhancedNotifications` |
| [Hide all notifications](https://www.noverse.dev/policies.html?p=WindowsDefenderSecurityCenter*Notifications_DisableNotifications) | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications` | `DisableNotifications` |
| [Hide non-critical notifications](https://www.noverse.dev/policies.html?p=WindowsDefenderSecurityCenter*Notifications_DisableEnhancedNotifications) | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications` | `DisableEnhancedNotifications` |
| [Turn off tile notifications](https://www.noverse.dev/policies.html?p=WPN*NoTileNotification) | `HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications` | `NoTileApplicationNotification` |
| [Turn off toast notifications](https://www.noverse.dev/policies.html?p=WPN*NoToastNotification) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications`<br>`HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications` | `NoToastApplicationNotification` |
| [Turn off toast notifications on the lock screen](https://www.noverse.dev/policies.html?p=WPN*NoLockScreenToastNotification) | `HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications` | `NoToastApplicationNotificationOnLockScreen` |
| [Turn off notifications network usage](https://www.noverse.dev/policies.html?p=WPN*NoCloudNotification) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications` | `NoCloudApplicationNotification` |
| [Turn off notification mirroring](https://www.noverse.dev/policies.html?p=WPN*NoNotificationMirroring) | `HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications` | `DisallowNotificationMirroring` |
| [Show notification bell icon](https://www.noverse.dev/policies.html?p=Taskbar*AlwaysShowNotificationIcon) | `HKCU\Software\Policies\Microsoft\Windows\Explorer` | `AlwaysShowNotificationIcon` |
| [Turn off all balloon notifications](https://www.noverse.dev/policies.html?p=Taskbar*TaskbarNoNotification) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `TaskbarNoNotification` |
| [Turn off feature advertisement balloon notifications](https://www.noverse.dev/policies.html?p=Taskbar*NoBalloonFeatureAdvertisements) | `HKCU\Software\Policies\Microsoft\Windows\Explorer` | `NoBalloonFeatureAdvertisements` |

# Optimize File System

Small documentation on several values the option applies, see links below for more details.

### [Registry Values](https://github.com/nohuto/regkit/blob/main/records/FileSystem.txt)

This list isn't complete yet, see [FileSystem](https://github.com/nohuto/regkit/blob/main/records/FileSystem.txt) boot trace for more.

| Value | Description |
| ----- | ------------ |
| `DisableDeleteNotification` | 0 = TRIM/UNMAP enabled, 1 = disabled. Controls whether delete operations send trim/unmap notifications to the underlying storage. |
| `DontVerifyRandomDrivers` | 0 = Driver Verifier may pick random drivers, 1 = random selection suppressed, so only explicitly chosen drivers are verified. |
| [`LongPathsEnabled`](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry) | 0 = legacy `MAX_PATH` limit, 1 = Win32 long paths enabled (paths up to ~32k characters for apps and policies that opt in). |
| `NtfsAllowExtendedCharacter8dot3Rename` | 0 = 8.3 short names restricted to basic ASCII, 1 = extended characters (including diacritics). |
| `NtfsBugcheckOnCorrupt` | 0 = NTFS attempts self healing without forcing a bugcheck, 1 = triggers a bugcheck when corruption is detected on an NTFS volume, avoiding "silent" data loss with self healing NTFS. |
| `NtfsDisable8dot3NameCreation` | Disables the creation of 8.3 character-length file names on FAT- and NTFS-formatted volumes.<br>0: Enables 8dot3 name creation for all volumes on the system.<br>1: Disables 8dot3 name creation for all volumes on the system.<br>2: Sets 8dot3 name creation on a per volume basis.<br>3: Disables 8dot3 name creation for all volumes except the system volume. |
| `NtfsDisableCompression` | 0 = NTFS compression allowed, 1 = new compressed files/folders cannot be created (existing compressed data remains readable). |
| `NtfsDisableCompressionLimit` | 0 = when a compressed file gets highly fragmented, NTFS stops compressing new extents so the file can grow larger uncompressed, 1 = disables this behavior and enforces the internal compression limit. |
| `NtfsDisableEncryption` | 0 = NTFS EFS file/folder encryption available, 1 = EFS disabled on NTFS volumes. |
| `NTFSDisableLastAccessUpdate` | Controls Last Access Time updates on NTFS files/directories. |
| `NtfsDisableSpotCorruptionHandling` | 0 = NTFS spot corruption handling active, 1 = disabled, so NTFS relies on manual tools. Also allows running CHKDSK to analyze a volume online without taking it offline. |
| `NtfsEncryptPagingFile` | 0 = pagefile.sys stored unencrypted, 1 = paging file encrypted. |
| `NtfsMemoryUsage` | Configures the internal cache levels of NTFS paged-pool memory and NTFS nonpaged-pool memory. |
| `NtfsMftZoneReservation` | Sets reserved NTFS MFT zone size as 200 MB x value: 1 = 200 MB (default), up to 4 = 800 MB. Larger values reduce MFT fragmentation on volumes with many small files. |
| `RefsDisableLastAccessUpdate` | Related to NTFSDisableLastAccessUpdate (both get set via disablelastaccess). |
| `SymlinkXToXEvaluation` | 0 = x->x symlinks not followed, 1 = resolved (X = Local/Remote). Symlinksare shortcuts or references that point to a file or folder in another location, like a portal. They're not duplicates, just pointers. File at: `C:\Projects\Game\assets\logo.png`, Symlink: `C:\Users\YourName\Desktop\logo.png`. |
| `Win31FileSystem` | 0 = standard modern FAT behavior (long filenames, richer timestamps), 1 = legacy Windows 3.1–compatible mode with stricter 8.3 naming and older timestamp semantics. |

- [system/assets | filesystem-NtfsUpdateDynamicRegistrySettings.c](https://github.com/nohuto/win-config/blob/main/system/assets/filesystem-NtfsUpdateDynamicRegistrySettings.c)

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Enable Win32 long paths](https://www.noverse.dev/policies.html?p=FileSys*LongPathsEnabled) | `HKLM\System\CurrentControlSet\Control\FileSystem` | `LongPathsEnabled` |

# Disable Hyper-V

> "*The Hyper-V hypervisor (also known as Windows hypervisor) is a type-1 (native or bare-metal) hypervisor: a mini operating system that runs directly on the host’s hardware to manage a single root and one or more guest operating systems. Unlike type-2 (or hosted) hypervisors, which run on the base of a conventional OS like normal applications, the Windows hypervisor abstracts the root OS, which knows about the existence of the hypervisor and communicates with it to allow the execution of one or more guest virtual machines.*"
>
> — Windows Internals E7 P2, [The Windows hypervisor](https://github.com/nohuto/windows-books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf)

> "*Many third-party virtualization applications don't work together with Hyper-V. Affected applications include VMware Workstation and VirtualBox. These applications might not start virtual machines, or they may fall back to a slower, emulated mode. Many virtualization applications depend on hardware virtualization extensions that are available on most modern processors. It includes Intel VT-x and AMD-V. Only one software component can use this hardware at a time. The hardware cannot be shared between virtualization applications.*"
>
> — Microsoft, [Virtualization applications don't work together with Hyper-V](https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/virtualization-apps-not-work-with-hyper-v)

## Service/Driver Table

| Option Name | Service/Driver | Description |
| --- | --- | --- |
| HyperV | `bttflt` | Microsoft Hyper-V VHDPMEM BTT Filter |
|  | `gencounter` | Microsoft Hyper-V Generation Counter |
|  | `hvcrash` | Hyper-V Crashdump |
|  | `HvHost` | Provides an interface for the Hyper-V hypervisor to provide per-partition performance counters to the host operating system. |
|  | `hvservice` | Microsoft Hypervisor Service Driver |
|  | `hyperkbd` | Microsoft VMBus Synthetic Keyboard Driver |
|  | `HyperVideo` | Microsoft VMBus Video Device Miniport Driver |
|  | `storflt` | Microsoft Hyper-V Storage Accelerator |
|  | `Vid` | Microsoft Hyper-V Virtualization Infrastructure Driver |
|  | `vmbus` | Virtual Machine Bus |
|  | `vmgid` | Microsoft Hyper-V Guest Infrastructure Driver |
|  | `vmicguestinterface` | Provides an interface for the Hyper-V host to interact with specific services running inside the virtual machine. |
|  | `vmicheartbeat` | Monitors the state of this virtual machine by reporting a heartbeat at regular intervals. This service helps you identify running virtual machines that have stopped responding. |
|  | `vmickvpexchange` | Provides a mechanism to exchange data between the virtual machine and the operating system running on the physical computer. |
|  | `vmicrdv` | Provides a platform for communication between the virtual machine and the operating system running on the physical computer. |
|  | `vmicshutdown` | Provides a mechanism to shut down the operating system of this virtual machine from the management interfaces on the physical computer. |
|  | `vmictimesync` | Synchronizes the system time of this virtual machine with the system time of the physical computer. |
|  | `vmicvmsession` | Provides a mechanism to manage virtual machine with PowerShell via VM session without a virtual network. |
|  | `vmicvss` | Coordinates the communications that are required to use Volume Shadow Copy Service to back up applications and data on this virtual machine from the operating system on the physical computer. |
|  | `vpci` | Microsoft Hyper-V Virtual PCI Bus |

# Disable Service Splitting

Prevents services running under `svchost.exe` from being split into separate processes, keeping all grouped services within the same instance. This simplifies process management but increases the risk of system instability and reduces service isolation.

[`Windows Internals 7th Edition, Part 2`](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf) (page `467`f.) handpicked snippets (shortened):
If system physical memory, obtained via [`GlobalMemoryStatusEx`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex), exceeds the SvcHostSplitThresholdInKB registry value (default is `3.5 GB` on client systems and `3.7 GB` on server systems), Svchost service splitting is enabled.

Service splitting is allowed only if:  
- Splitting is globally enabled
- The service is not marked as critical (i.e., it doesn't reboot the machine on failure)
- The service is hosted in `svchost.exe`
- `SvcHostSplitDisable` is not set to `1` in the service registry key

Setting `SvcHostSplitDisable` to `0` for a critical service forces it to be split, but this can lead to issues.

Get the current amount of `svchost` process instances with:
```cmd
(get-process -Name "svchost" | measure).Count
```
```
\Registry\Machine\SYSTEM\ControlSet001\Control : SvcHostDebug
\Registry\Machine\SYSTEM\ControlSet001\Control : SvcHostSplitThresholdInKB
```
`SvcHostDebug` is set to `0` by default:
```c
v1 = 0;
if ( !RegistryValueWithFallbackW && Type == 4 )
    LOBYTE(v1) = Data != 0;
return v1;
```

- [system/assets | servicesplitting-ScReadSCMConfiguration.c](https://github.com/nohuto/win-config/blob/main/system/assets/servicesplitting-ScReadSCMConfiguration.c)

![](https://github.com/nohuto/win-config/blob/main/system/images/servicesplitting1.png?raw=true)

## [Windows Internals](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf)

![](https://github.com/nohuto/win-config/blob/main/system/images/servicesplitting2.png?raw=true)

# Disable Storage Sense

Storage Sense deletes temporary/user files automatically, see [windows policies](https://www.noverse.dev/docs/win-config/system/disable-storage-sense/#windows-policies) for more & [disable-notifications/#registry-values](https://www.noverse.dev/docs/win-config/system/disable-notifications/#registry-values) for storage sense related notification values.

Head over to the `Policies` tab, then `StorageSense` to configure other related policies.

## SystemSettings Captures

The main storage sense toggle in `System > Storage` does the same as the `Automatic User content cleanup` in `System > Storage > Storage Sense`.

```c
// System > Storage > Storage Sense

// Keep WIndows running smoothly by automatically cleaning up temorary system and app files
// 1 = On
// 0 = Off
HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\04 // Type: REG_DWORD

// Automatic User content cleanup
// 1 = On
// 0 = Off
HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\01 // Type: REG_DWORD

// Run Storage Sense
// During low free disk space (default) = 0
// Every month = 30
// Every week = 7
// Every day = 1
HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\2048	// Type: REG_DWORD

// Delete files in my recycle bin if they have been there for over
// 30 days (default): 08 = 1, 25 = 30
// 60 days: 08 = 1, 256 = 60
// 14 days: 08 = 1, 256 = 14
// 1 day: 08 = 1, 256 = 1
// Never: 08 = 0, 256 = 0
HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\08 // Type: REG_DWORD
HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\256 // Type: REG_DWORD

// Delete files in my Downloads folder if they haven't been opened for more than
// Never (default): 32 = 0, 512 = 0
// 1 day: 32 = 1, 512 = 1
// 14 days: 32 = 1, 512 = 14
// 30 days: 32 = 1, 512 = 30
// 60 days: 32 = 1, 512 = 60
HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\32 // Type: REG_DWORD
HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\512 // Type: REG_DWORD
```

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Allow Storage Sense](https://www.noverse.dev/policies.html?p=StorageSense*SS_AllowStorageSenseGlobal) | `HKLM\Software\Policies\Microsoft\Windows\StorageSense` | `AllowStorageSenseGlobal` |
| [Allow Storage Sense Temporary Files cleanup](https://www.noverse.dev/policies.html?p=StorageSense*SS_AllowStorageSenseTemporaryFilesCleanup) | `HKLM\Software\Policies\Microsoft\Windows\StorageSense` | `AllowStorageSenseTemporaryFilesCleanup` |
| [Configure Storage Sense Recycle Bin cleanup threshold](https://www.noverse.dev/policies.html?p=StorageSense*SS_ConfigStorageSenseRecycleBinCleanupThreshold) | `HKLM\Software\Policies\Microsoft\Windows\StorageSense` | `ConfigStorageSenseRecycleBinCleanupThreshold` |
| [Configure Storage Storage Downloads cleanup threshold](https://www.noverse.dev/policies.html?p=StorageSense*SS_ConfigStorageSenseDownloadsCleanupThreshold) | `HKLM\Software\Policies\Microsoft\Windows\StorageSense` | `ConfigStorageSenseDownloadsCleanupThreshold` |

# Disable Accessibility Features

Disables all kind of accessibility features such as `Voice Access`, `Live Captions`, `Narrator`, `Magnifier`, `OSK` etc. (`SystemSettings > Accessibility`/`Control Panel > All Control Panel Items > Ease of Access Center`). Specific features can be enabled via the suboptions.

## Suboptions

| Suboption | Description |
| --- | --- |
| Audio Description | Hear descriptions of what's happening in videos (when available). |
| Dynamic Scrollbars | "Always show scrollbars", `On` dynamically hide them. |
| [Voice Access](https://support.microsoft.com/en-us/topic/use-voice-access-to-control-your-pc-author-text-with-your-voice-4dcd23ee-f1b9-4fd1-bacc-862ab611f55d) | Modern voice command feature to help you interact with your PC and dictate text. |
| Live Captions | Audio and video will be captioned live on your screen. |
| Notification Box Visbility Time | Time how long the Windows notification boxes should stay opened. |
| Narrator | Narrator reads aloud any text on the screen. You will need speakers. |
| Sound Sentry | Visual notifications for sounds (this option chooses 'None' as visual warning). |
| Color Filters | "Use a color filter to make colors on your screen easier to see and differentiate." |
| Mono Audio | Combine left and right audio channels into one. |
| Magnifier | Magnifier zooms in anywhere on the screen, and makes everything in that area larger. You can move Magnifier around, lock it in one place, or resize it. |
| On-Screen Keyboard | Tyoe using the mouse or another pointing device such as a joystick by selecting keys from a picture of a keyboard. |
| [Accessibility Insights Telemetry](https://github.com/microsoft/accessibility-insights-windows/blob/main/docs/TelemetryOverview.md#control-of-telemery) | "Accessibility Insights for Windows uses telemetry to better understand what features are most helpful to users, as well as to help identify potential issues that users are experiencing." |

# Disable Windows Search

## Suboptions

| **Suboption** | **Description** |
| ---- | ---- |
| Disable SafeSearch | Disables the SafeSearch filter for web search, preventing strict filtering of search results. |
| Prevent Index on Battery | Prevents Windows from indexing content while running on battery power, saving system resources. |
| Disable Index Usage for System File Search | Disables the use of the index when searching system files, requiring a full scan each time. |
| Find Partial Matches | Allows partial matches to be found when searching for files, enabling more flexible search results. |
| Exclude System Directories | Excludes system directories from search results, narrowing down the search to user files and folders. |
| Exclude Archived Files | Prevents archived files from being included in search results. |
| Disable Natural Language Search | Disables the use of natural language search, which allows more conversational queries for search results. |
| Search Only in Indexed Locations | Restricts searches in non-indexed locations to only file names, rather than searching both names and contents. |
| Exclude System Directories | Excludes system directories (e.g., Windows folders) in search results when searching non-indexed locations. |
| Exclude Compressed Files | Excludes compressed files (e.g., ZIP, CAB) in search results when searching non-indexed locations. |
| Search Only in Indexed Locations | Disables: "Ensures that file names and contents are always searched in non-indexed locations, which may take more time." |
| [Disallow Indexing of Encrypted Items](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search#allowindexingencryptedstoresoritems) | This policy setting allows encrypted items to be indexed. |
| [Disable Language Detection](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search#alwaysuseautolangdetection) | This policy setting determines when Windows uses automatic language detection results, and when it relies on indexing history. |
| [Prevent Querying Index Remotely](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search#preventremotequeries) | If enabled, clients will be unable to query this computer's index remotely. Thus, when they're browsing network shares that are stored on this computer, they won't search them using the index. If disabled, client search requests will use this computer's index. |
| [Disable Web Results in Search](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search#donotusewebresults) | This policy setting allows you to control whether or not Search can perform queries on the web, and if the web results are displayed in Search. |
| Disable Search Highlights | If enabled: "See content suggestions in the search boxi and in search home". |
| Disable Web Search | If disabled: "removes the option of searching the Web from Windows Desktop Search". |

## Search Indexing

[Search indexing](https://learn.microsoft.com/en-us/windows/win32/search/-search-indexing-process-overview) builds a database of file names, properties, and contents to speed up searches, runs as `SearchIndexer.exe`, updates automatically. Disabling it slows down searches, but as shows below you should use everything anyway. Additionally you can disable content and property indexing per drive, by right clicking on the drive, then unticking the box as shown in the picture.

![](https://github.com/nohuto/win-config/blob/main/system/images/searchindex.png?raw=true)

Instead of using the explorer to search for a file or folder, use [`Everything`](https://www.voidtools.com/downloads/), it's a lot faster.

The `WSearch` service is needed for CmdPals `File Search` extension to work.

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Prevent clients from querying the index remotely](https://www.noverse.dev/policies.html?p=Search*PreventRemoteQueries) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | `PreventRemoteQueries` |
| [Prevent indexing when running on battery power to conserve energy](https://www.noverse.dev/policies.html?p=Search*PreventIndexOnBattery) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | `PreventIndexOnBattery` |
| [Always use automatic language detection when indexing content and properties](https://www.noverse.dev/policies.html?p=Search*AlwaysUseAutoLangDetection) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | `AlwaysUseAutoLangDetection` |
| [Don't search the web or display web results in Search](https://www.noverse.dev/policies.html?p=Search*DoNotUseWebResults) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | `ConnectedSearchUseWeb` |
| [Don't search the web or display web results in Search over metered connections](https://www.noverse.dev/policies.html?p=Search*DoNotUseWebResultsOnMeteredConnections) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | `ConnectedSearchUseWebOverMeteredConnections` |
| [Do not allow web search](https://www.noverse.dev/policies.html?p=Search*DisableWebSearch) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | `DisableWebSearch` |

## Miscellaneous Notes

Exists in [Search Policies](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search), but isn't present anymore on 24H2 and probably versions above.

```c
// Disabling this setting turns off search highlights in the start menu search box and in search home. Enabling or not configuring this setting turns on search highlights in the start menu search box and in search home.
"Disable Search Highlights": {
  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search": {
    "EnableDynamicContentInWSB": { "Type": "REG_DWORD", "Data": 0 }
  }
}
```

It probably got replaced by:
```c
// Privacy & security > Search - Show search highlights
SystemSettings.exe	RegSetValue	HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings\IsDynamicSearchBoxEnabled	Type: REG_DWORD, Length: 4, Data: 0
```

# HAGS

[HAGS](https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/) feature is introduced specifically for the WDDM. If disabled the CPU manages the GPU scheduling via a high-priority kernel thread, GPU context switches and task scheduling are handled by the CPU (CPU offloads graphics intensive tasks to the GPU for rendering). If enabled the GPU handles its own scheduling using a built in scheduler processor, context switching between GPU tasks is done directly on the GPU. It is especially beneficial, if you've a slow CPU, or if the CPU is heavily loaded with other tasks.

"It depends on your hardware, if you want [HAGS](https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/) to be enabled or not. E.g if using a old GPU, it may not fully support the new scheduler."

[HAGS](https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/) should be enabled.

## SystemSettings Records

```c
// Enabled
HKLM\System\CurrentControlSet\Control\GraphicsDrivers\HwSchMode	Type: REG_DWORD, Length: 4, Data: 2
```
```c
// Disabled
HKLM\System\CurrentControlSet\Control\GraphicsDrivers\HwSchMode	Type: REG_DWORD, Length: 4, Data: 1
```

# Enable FSO

This isn't accurate nor complete yet, it's preferable to disable FSO per application via the compability section if doing so. Disabling this option won't revert the changes like all other ones do, it'll disable FSO.

See [demystifying-full-screen-optimizations](https://devblogs.microsoft.com/directx/demystifying-full-screen-optimizations/)/[SwapChain](https://wiki.special-k.info/en/SwapChain)/[PresentationModel](https://wiki.special-k.info/Presentation_Model) for some details.

## ResourcePolicyServer

All values I found that are `GameDVR` related in `ResourcePolicyServer.dll`:
```c
GameDVR_DXGIHonorFSEWindowsCompatible
GameDVR_EFSEFeatureFlags
GameDVR_FSEBehavior
GameDVR_FSEBehaviorMode
GameDVR_HonorUserFSEBehaviorMode
```

`GameDVR_DSEBehavior` doesn't exist on my current system.

## Compability Captures

Disable/enable FSO for a specific application via `Properties > Compatibility > Change settings for all users` - `Disable fullscreen optimizations` or do it per user one step before.

```c
// User
HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers\C:\Program Files (x86)\Steam\steamapps\common\Battlefield 6\bf6.exe	Type: REG_SZ, Length: 66, Data: ~ DISABLEDXMAXIMIZEDWINDOWEDMODE

// Machine
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers\C:\Program Files (x86)\Steam\steamapps\common\Battlefield 6\bf6.exe	Type: REG_SZ, Length: 66, Data: ~ DISABLEDXMAXIMIZEDWINDOWEDMODE
```

# Disable Memory Compression

Memory compression compresses rarely used or less frequently accessed data in RAM so it takes up less space. Windows does this to keep more data in physical memory and avoid writing to the pagefile, which reduces disk I/O. When the data is needed again, it's decompressed. It's faster than paging to disk, but it costs CPU.

Compressed pages are stored in a dedicated "Memory Compression" process managed by the Store Manager. The memory manager compresses modified list pages into that store and later decompresses them on demand, this is enabled by default on client SKUs.

Example:  
1. System looks for cold/rarely used data in RAM
2. It compresses that data, e.g. 24 MB -> 7 MB
3. The 17 MB saved is used for active apps
4. When the data is needed again, it's decompressed back to 24 MB

See the current memory compression state on your system via ([cmdlet](https://learn.microsoft.com/en-us/powershell/module/mmagent/disable-mmagent?view=windowsserver2025-ps)):
```powershell
Get-MMAgent
```
```powershell
ApplicationLaunchPrefetching : True
ApplicationPreLaunch         : True
MaxOperationAPIFiles         : 512
MemoryCompression            : True # Enabled
OperationAPI                 : True
PageCombining                : True
PSComputerName               :
```

## [Windows Internals](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

![](https://github.com/nohuto/win-config/blob/main/system/images/memcompress1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/memcompress2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/memcompress3.png?raw=true)

# Disable Page Combining

Page combining spots identical RAM pages across processes and merges them into a single shared page. Instead of keeping 50 copies of the same DLL/data page, the memory manager keeps one, maps it to everyone, and marks it `copy-on-write`. As long as nobody changes it, everyone shares the same physical page and RAM usage drops. If a process writes to it, Windows gives that process its own private copy and leaves the shared one intact. It's a background RAM deduplicator, basically.

The memory manager can be instructed to combine identical pages across the system, and Superfetch can trigger combining when the system is idle.

> "*Page combining can be disabled by setting a DWORD value named `DisablePageCombining` to `1` in the `HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management` registry key.*"
>
> — Windows Internals, [E7, P1: 'Memory combining'](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

`Disable-MMAgent -PageCombining` toggles the state shown in `Get-MMAgent` but does not write the `DisablePageCombining` registry value on recent builds, so it's most likely deprecated.

```c
INIT:0000000140B9C340                 dq offset aSessionManager_7 ; "Session Manager\\Memory Management"
INIT:0000000140B9C348                 dq offset aDisablepagecom ; "DisablePageCombining"
INIT:0000000140B9C350                 dq offset dword_140D1D1C8

ALMOSTRO:0000000140D1D1C8 dword_140D1D1C8 dd 0                    ; DATA XREF: MiCombineIdenticalPages:loc_1407F7E3A↑r
```

See the current page combining state on your system via ([cmdlet](https://learn.microsoft.com/en-us/powershell/module/mmagent/disable-mmagent?view=windowsserver2025-ps)):
```powershell
Get-MMAgent
```
```powershell
ApplicationLaunchPrefetching : True
ApplicationPreLaunch         : True
MaxOperationAPIFiles         : 512
MemoryCompression            : True
OperationAPI                 : True
PageCombining                : True # Enabled
PSComputerName               :
```

## [Windows Internals](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

![](https://github.com/nohuto/win-config/blob/main/system/images/pagecomb1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/pagecomb2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/pagecomb3.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/pagecomb4.png?raw=true)

# SCM Autostart Delay

Windows marks some services as delayed autostart to reduce boot contention. The Service Control Manager (SCM) waits before starting those services, the default delay is 120 seconds as shown below.

[Windows Internals (E7, P2)](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf) puts this in the middle of the SCM boot sequence, so the delay only applies after normal autostart processing finishes.

1. SCM loops through service groups and starts autostart services, relooping groups until dependencies (DependOnService) are satisfied
2. It ignores Tag values for Windows services (Tag ordering is used by the I/O manager for boot/system-start drivers)
3. Once all groups listed in ServiceGroupOrder\\List are processed, it runs groups not listed there, then services without a group
4. After that, SCM calls ScInitDelayStart to queue a delayed work item for services marked DelayedAutostart

The delayed work item runs on a worker thread after the delay expires and performs the same actions as a normal autostart service start. The delay is a single global value 120000 ms, but it can be overridden.

Autostart services were originally meant for early boot dependencies (for example RPC), but many services are autostart only to run unattended after boot (for example update services). Marking these as delayed autostart lets critical services start faster and makes the desktop responsive sooner right after logon. Delayed autostart services are also started in background mode, which lowers their thread, I/O, and memory priority.

If a non delayed autostart service depends on a delayed autostart service, the delayed flag is ignored and the service is started immediately to satisfy the dependency.

When SCM finishes starting autostart services/drivers and schedules the delayed autostart work item, it signals \\BaseNamedObjects\\SC_AutoStartComplete.

```c
__int64 __fastcall CDelayStartContext::GetAutostartDelay(CDelayStartContext *this, __int64 a2, unsigned int a3)
{
  unsigned int v3; // ebx
  unsigned int v4; // eax
  int v7; // [rsp+40h] [rbp+8h] BYREF
  unsigned int v9; // [rsp+48h] [rbp+10h] BYREF
  unsigned int v10; // [rsp+50h] [rbp+18h] BYREF
  HANDLE Handle; // [rsp+58h] [rbp+20h] BYREF

  Handle = 0LL;
  v3 = 120000;
  v7 = 120000;
  v9 = 4;
  v4 = ScRegOpenKeyExW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control", a3, 0x20019u, (HKEY *)&Handle);
  if ( v4 )
  {
    //...
  }
  else
  {
    if ( !ScRegQueryValueExW((HKEY)Handle, L"AutostartDelay", 0LL, &v10, (unsigned __int8 *)&v7, &v9) && v10 == 4 )
      v3 = v7;
  }
  return v3;
}
```

## EnableAutostartEvents Notes

Note on a different option which I didn't implement (this information is based on [Windows Internals E7 P2](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf), P448-449):

By default the SCM logs events for services that start automatically at boot, which can flood the System event log. Setting this value to 0 suppresses autostart event logging while still keeping normal service start/stop/pause events. Read by SCM at startup = requires reboot to take effect.

"Note that the Service Control Manager by default logs all the events generated by services started automatically at system startup. This can generate an undesired number of events flooding the System event log. To mitigate the problem, you can disable SCM autostart events by creating a registry value named EnableAutostartEvents in the HKLM\System\CurrentControlSet\ Control key and set it to 0 (the default implicit value is 1 in both client and server SKUs). As a result, this will log only events generated by service applications when starting, pausing, or stopping a target service."

I didn't see any differences in the Event Viewer between setting them to `0`/`1` on my current system and on a 25H2 VM. The value exists and gets read:

```
\Registry\Machine\SYSTEM\ControlSet001\Control : EnableAutostartEvents
```
```c
void __fastcall ScCheckAutostartEventsEnabled(__int64 a1, __int64 a2, unsigned int a3)
{
  unsigned int v3; // eax
  unsigned int *v4; // r8
  int v6; // [rsp+40h] [rbp+8h] BYREF
  unsigned int v7; // [rsp+48h] [rbp+10h] BYREF
  unsigned int v8; // [rsp+50h] [rbp+18h] BYREF
  HANDLE Handle; // [rsp+58h] [rbp+20h] BYREF

  v6 = 0;
  Handle = 0LL;
  v7 = 4;
  v3 = ScRegOpenKeyExW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control", a3, 0x20019u, (HKEY *)&Handle);
  if ( v3 )
  {
    //...
  }
  else if ( !ScRegQueryValueExW((HKEY)Handle, L"EnableAutostartEvents", v4, &v8, (unsigned __int8 *)&v6, &v7) && v8 == 4 )
  {
    g_fEnableAutostartEvents = v6 != 0;
  }
}
```
```json
"Disable Autostart Events": {
  "apply": {
    "HKLM\\SYSTEM\\CurrentControlSet\\Control": {
      "EnableAutostartEvents": { "Type": "REG_DWORD", "Data": 0 }
    }
  },
  "revert": {
    "HKLM\\SYSTEM\\CurrentControlSet\\Control": {
      "EnableAutostartEvents": { "Action": "deletevalue" }
    }
  }
},
```

# Time Zone

| ID                              | Display Name                                                  | ID                              | Display Name                                              |
| ------------------------------- | ------------------------------------------------------------- | ------------------------------- | --------------------------------------------------------- |
| Afghanistan Standard Time       | (UTC+04:30) Kabul                                             | Alaskan Standard Time           | (UTC-09:00) Alaska                                        |
| Aleutian Standard Time          | (UTC-10:00) Aleutian Islands                                  | Altai Standard Time             | (UTC+07:00) Barnaul, Gorno-Altaysk                        |
| Arab Standard Time              | (UTC+03:00) Kuwait, Riyadh                                    | Arabian Standard Time           | (UTC+04:00) Abu Dhabi, Muscat                             |
| Arabic Standard Time            | (UTC+03:00) Baghdad                                           | Argentina Standard Time         | (UTC-03:00) City of Buenos Aires                          |
| Astrakhan Standard Time         | (UTC+04:00) Astrakhan, Ulyanovsk                              | Atlantic Standard Time          | (UTC-04:00) Atlantic Time (Canada)                        |
| AUS Central Standard Time       | (UTC+09:30) Darwin                                            | Aus Central W. Standard Time    | (UTC+08:45) Eucla                                         |
| AUS Eastern Standard Time       | (UTC+10:00) Canberra, Melbourne, Sydney                       | Azerbaijan Standard Time        | (UTC+04:00) Baku                                          |
| Azores Standard Time            | (UTC-01:00) Azores                                            | Bahia Standard Time             | (UTC-03:00) Salvador                                      |
| Bangladesh Standard Time        | (UTC+06:00) Dhaka                                             | Belarus Standard Time           | (UTC+03:00) Minsk                                         |
| Bougainville Standard Time      | (UTC+11:00) Bougainville Island                               | Canada Central Standard Time    | (UTC-06:00) Saskatchewan                                  |
| Cape Verde Standard Time        | (UTC-01:00) Cabo Verde Is.                                    | Caucasus Standard Time          | (UTC+04:00) Yerevan                                       |
| Cen. Australia Standard Time    | (UTC+09:30) Adelaide                                          | Central America Standard Time   | (UTC-06:00) Central America                               |
| Central Asia Standard Time      | (UTC+06:00) Nur-Sultan                                        | Central Brazilian Standard Time | (UTC-04:00) Cuiaba                                        |
| Central Europe Standard Time    | (UTC+01:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague | Central European Standard Time  | (UTC+01:00) Sarajevo, Skopje, Warsaw, Zagreb              |
| Central Pacific Standard Time   | (UTC+11:00) Solomon Is., New Caledonia                        | Central Standard Time           | (UTC-06:00) Central Time (US & Canada)                    |
| Central Standard Time (Mexico)  | (UTC-06:00) Guadalajara, Mexico City, Monterrey               | Chatham Islands Standard Time   | (UTC+12:45) Chatham Islands                               |
| China Standard Time             | (UTC+08:00) Beijing, Chongqing, Hong Kong, Urumqi             | Cuba Standard Time              | (UTC-05:00) Havana                                        |
| Dateline Standard Time          | (UTC-12:00) International Date Line West                      | E. Africa Standard Time         | (UTC+03:00) Nairobi                                       |
| E. Australia Standard Time      | (UTC+10:00) Brisbane                                          | E. Europe Standard Time         | (UTC+02:00) Chisinau                                      |
| E. South America Standard Time  | (UTC-03:00) Brasilia                                          | Easter Island Standard Time     | (UTC-06:00) Easter Island                                 |
| Eastern Standard Time           | (UTC-05:00) Eastern Time (US & Canada)                        | Eastern Standard Time (Mexico)  | (UTC-05:00) Chetumal                                      |
| Egypt Standard Time             | (UTC+02:00) Cairo                                             | Ekaterinburg Standard Time      | (UTC+05:00) Ekaterinburg                                  |
| Fiji Standard Time              | (UTC+12:00) Fiji                                              | FLE Standard Time               | (UTC+02:00) Helsinki, Kyiv, Riga, Sofia, Tallinn, Vilnius |
| Georgian Standard Time          | (UTC+04:00) Tbilisi                                           | GMT Standard Time               | (UTC+00:00) Dublin, Edinburgh, Lisbon, London             |
| Greenland Standard Time         | (UTC-02:00) Greenland                                         | Greenwich Standard Time         | (UTC+00:00) Monrovia, Reykjavik                           |
| GTB Standard Time               | (UTC+02:00) Athens, Bucharest                                 | Haiti Standard Time             | (UTC-05:00) Haiti                                         |
| Hawaiian Standard Time          | (UTC-10:00) Hawaii                                            | India Standard Time             | (UTC+05:30) Chennai, Kolkata, Mumbai, New Delhi           |
| Iran Standard Time              | (UTC+03:30) Tehran                                            | Israel Standard Time            | (UTC+02:00) Jerusalem                                     |
| Jordan Standard Time            | (UTC+03:00) Amman                                             | Kaliningrad Standard Time       | (UTC+02:00) Kaliningrad                                   |
| Kamchatka Standard Time         | (UTC+12:00) Petropavlovsk-Kamchatsky - Old                    | Korea Standard Time             | (UTC+09:00) Seoul                                         |
| Libya Standard Time             | (UTC+02:00) Tripoli                                           | Line Islands Standard Time      | (UTC+14:00) Kiritimati Island                             |
| Lord Howe Standard Time         | (UTC+10:30) Lord Howe Island                                  | Magadan Standard Time           | (UTC+11:00) Magadan                                       |
| Magallanes Standard Time        | (UTC-03:00) Punta Arenas                                      | Marquesas Standard Time         | (UTC-09:30) Marquesas Islands                             |
| Mauritius Standard Time         | (UTC+04:00) Port Louis                                        | Mid-Atlantic Standard Time      | (UTC-02:00) Mid-Atlantic - Old                            |
| Middle East Standard Time       | (UTC+02:00) Beirut                                            | Montevideo Standard Time        | (UTC-03:00) Montevideo                                    |
| Morocco Standard Time           | (UTC+01:00) Casablanca                                        | Mountain Standard Time          | (UTC-07:00) Mountain Time (US & Canada)                   |
| Mountain Standard Time (Mexico) | (UTC-07:00) La Paz, Mazatlan                                  | Myanmar Standard Time           | (UTC+06:30) Yangon (Rangoon)                              |
| N. Central Asia Standard Time   | (UTC+07:00) Novosibirsk                                       | Namibia Standard Time           | (UTC+02:00) Windhoek                                      |
| Nepal Standard Time             | (UTC+05:45) Kathmandu                                         | New Zealand Standard Time       | (UTC+12:00) Auckland, Wellington                          |
| Newfoundland Standard Time      | (UTC-03:30) Newfoundland                                      | Norfolk Standard Time           | (UTC+11:00) Norfolk Island                                |
| North Asia East Standard Time   | (UTC+08:00) Irkutsk                                           | North Asia Standard Time        | (UTC+07:00) Krasnoyarsk                                   |
| North Korea Standard Time       | (UTC+09:00) Pyongyang                                         | Omsk Standard Time              | (UTC+06:00) Omsk                                          |
| Pacific SA Standard Time        | (UTC-04:00) Santiago                                          | Pacific Standard Time           | (UTC-08:00) Pacific Time (US & Canada)                    |
| Pacific Standard Time (Mexico)  | (UTC-08:00) Baja California                                   | Pakistan Standard Time          | (UTC+05:00) Islamabad, Karachi                            |
| Paraguay Standard Time          | (UTC-04:00) Asuncion                                          | Qyzylorda Standard Time         | (UTC+05:00) Qyzylorda                                     |
| Romance Standard Time           | (UTC+01:00) Brussels, Copenhagen, Madrid, Paris               | Russia Time Zone 10             | (UTC+11:00) Chokurdakh                                    |
| Russia Time Zone 11             | (UTC+12:00) Anadyr, Petropavlovsk-Kamchatsky                  | Russia Time Zone 3              | (UTC+04:00) Izhevsk, Samara                               |
| Russian Standard Time           | (UTC+03:00) Moscow, St. Petersburg                            | SA Eastern Standard Time        | (UTC-03:00) Cayenne, Fortaleza                            |
| SA Pacific Standard Time        | (UTC-05:00) Bogota, Lima, Quito, Rio Branco                   | SA Western Standard Time        | (UTC-04:00) Georgetown, La Paz, Manaus, San Juan          |
| Sakhalin Standard Time          | (UTC+11:00) Sakhalin                                          | Saint Pierre Standard Time      | (UTC-03:00) Saint Pierre and Miquelon                     |
| Samoa Standard Time             | (UTC+13:00) Samoa                                             | Sao Tome Standard Time          | (UTC+00:00) Sao Tome                                      |
| Saratov Standard Time           | (UTC+04:00) Saratov                                           | SE Asia Standard Time           | (UTC+07:00) Bangkok, Hanoi, Jakarta                       |
| Singapore Standard Time         | (UTC+08:00) Kuala Lumpur, Singapore                           | South Africa Standard Time      | (UTC+02:00) Harare, Pretoria                              |
| South Sudan Standard Time       | (UTC+02:00) Juba                                              | Sri Lanka Standard Time         | (UTC+05:30) Sri Jayawardenepura                           |
| Sudan Standard Time             | (UTC+02:00) Khartoum                                          | Syria Standard Time             | (UTC+03:00) Damascus                                      |
| Taipei Standard Time            | (UTC+08:00) Taipei                                            | Tasmania Standard Time          | (UTC+10:00) Hobart                                        |
| Tocantins Standard Time         | (UTC-03:00) Araguaina                                         | Tokyo Standard Time             | (UTC+09:00) Osaka, Sapporo, Tokyo                         |
| Tomsk Standard Time             | (UTC+07:00) Tomsk                                             | Tonga Standard Time             | (UTC+13:00) Nuku'alofa                                    |
| Transbaikal Standard Time       | (UTC+09:00) Chita                                             | Turkey Standard Time            | (UTC+03:00) Istanbul                                      |
| Turks And Caicos Standard Time  | (UTC-05:00) Turks and Caicos                                  | Ulaanbaatar Standard Time       | (UTC+08:00) Ulaanbaatar                                   |
| US Eastern Standard Time        | (UTC-05:00) Indiana (East)                                    | US Mountain Standard Time       | (UTC-07:00) Arizona                                       |
| UTC                             | (UTC) Coordinated Universal Time                              | UTC+12                          | (UTC+12:00) Coordinated Universal Time+12                 |
| UTC+13                          | (UTC+13:00) Coordinated Universal Time+13                     | UTC-02                          | (UTC-02:00) Coordinated Universal Time-02                 |
| UTC-08                          | (UTC-08:00) Coordinated Universal Time-08                     | UTC-09                          | (UTC-09:00) Coordinated Universal Time-09                 |
| UTC-11                          | (UTC-11:00) Coordinated Universal Time-11                     | Venezuela Standard Time         | (UTC-04:00) Caracas                                       |
| Vladivostok Standard Time       | (UTC+10:00) Vladivostok                                       | Volgograd Standard Time         | (UTC+03:00) Volgograd                                     |
| W. Australia Standard Time      | (UTC+08:00) Perth                                             | W. Central Africa Standard Time | (UTC+01:00) West Central Africa                           |
| W. Europe Standard Time         | (UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna  | W. Mongolia Standard Time       | (UTC+07:00) Hovd                                          |
| West Asia Standard Time         | (UTC+05:00) Ashgabat, Tashkent                                | West Bank Standard Time         | (UTC+02:00) Gaza, Hebron                                  |
| West Pacific Standard Time      | (UTC+10:00) Guam, Port Moresby                                | Yakutsk Standard Time           | (UTC+09:00) Yakutsk                                       |
| Yukon Standard Time             | (UTC-07:00) Yukon                                             |                                 |                                                           |

Get a list of available timezones with more detail via:
```powershell
Get-TimeZone -ListAvailable
```

# Display Scaling

Changes the size of text, apps, and other items. Note that on laptops the default display scaling might not be `100%`. You can set a custom scaling size via `System > Display > Custom scaling`:

![](https://github.com/nohuto/win-config/blob/main/system/images/displayscaling.png?raw=true)

## SystemSettings Captures

```c
// 100%
SystemSettings.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\ScaleFactors\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 0
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\PerMonitorSettings\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 0

// 125%
SystemSettings.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\ScaleFactors\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 1
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\PerMonitorSettings\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 1

// 150%
SystemSettings.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\ScaleFactors\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 2
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\PerMonitorSettings\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 2

// 175%
SystemSettings.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\ScaleFactors\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 3
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\PerMonitorSettings\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 3

// 200%
SystemSettings.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\ScaleFactors\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 4
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\PerMonitorSettings\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 4

// 225%
SystemSettings.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\GraphicsDrivers\ScaleFactors\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 5
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\PerMonitorSettings\MONITORID\DpiValue	Type: REG_DWORD, Length: 4, Data: 5
```

## Suboption

`Prevent Window Minimization on Monitor Disconnection` disables `Minimize windows then a monitor is diconnected` (`System > Display`).

```c
// Enabled
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\MonitorRemovalRecalcBehavior	Type: REG_DWORD, Length: 4, Data: 0

// Disabled
SystemSettings.exe	RegSetValue	HKCU\Control Panel\Desktop\MonitorRemovalRecalcBehavior	Type: REG_DWORD, Length: 4, Data: 1
```

# Reduce Shutdown Time

Forces hung apps and services to terminate faster, see 'Windows Internals' section for details.

```
\Registry\Machine\SYSTEM\ControlSet001\Control : WaitToKillServiceTimeout
\Registry\User\S-ID\Control Panel\Desktop : WaitToKillTimeout
\Registry\User\S-ID\Control Panel\Desktop : HungAppTimeout
\Registry\User\S-ID\Control Panel\Desktop : AutoEndTasks
```
`HungAppTimeout`-> `1500` (`1.5` sec; default is `5` sec)
`WaitToKillTimeout`-> `2500` (`2.5` sec)
`WaitToKillServiceTimeout`-> `2500` (`2.5` sec; default is `5` sec)
`WaitToKillAppTimeout` seems to not be used anymore (would have a default of `20000` (`20` sec))

More timeout related values located in `HKCU\Control Panel\Desktop`: `CriticalAppShutdownCleanupTimeout`, `CriticalAppShutdownTimeout`, `QuickResolverTimeout`, `ActiveWndTrkTimeout`, `CaretTimeout`, `ForegroundLockTimeout`, `LowLevelHooksTimeout`. I may add information about some of them soon.

## [Windows Internals](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P2.pdf)

![](https://github.com/nohuto/win-config/blob/main/system/images/shutdown1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/shutdown2.png?raw=true)

# Detailed Verbose Messages

Enables detailed messages at restart, shut down, sign out, and sign in, which can be helpful.

> "*If verbose logging isn't enabled, you'll still receive normal status messages such as "Applying your personal settings..." or "Applying computer settings..." when you start up, shut down, log on, or log off from the computer. However, if verbose logging is enabled, you'll receive additional information, such as "RPCSS is starting" or "Waiting for machine group policies to finish....".*"
>
> — Microsoft, [Verbose startup, shutdown, logon, and logoff status messages](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/enable-verbose-startup-shutdown-logon-logoff-status-messages)

> "*This policy setting directs the system to display highly detailed status messages.This policy setting is designed for advanced users who require this information.If you enable this policy setting, the system displays status messages that reflect each step in the process of starting, shutting down, logging on, or logging off the system. If you disable or do not configure this policy setting, only the default status messages are displayed to the user during these processes. Note: This policy setting is ignored if the \"Remove Boot/Shutdown/Logon/Logoff status messages" policy setting is enabled.*"
>
> — Windows Security Encyclopedia, [Display highly detailed status messages](https://www.windows-security.org/b74176eebf20a72c6e9cf193ddcedeb7/display-highly-detailed-status-messages)

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Display highly detailed status messages](https://www.noverse.dev/policies.html?p=Logon*VerboseStatus) | `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System` | `VerboseStatus` |

# Disable JPEG Reduction

Windows reduces the quality of JPEG images you set as the desktop background to `85%` by default, you can set it to `100%` via the option switch.

### [TranscodeImage](https://github.com/nohuto/win-config/blob/main/system/assets/jpeg-TranscodeImage.c)

```c
if ( JPEGImportQuality not present or error )
    v54 = 85.0f;
else
    v54 = max(JPEGImportQuality, 60.0f);
    if (v54 > 100.0f)
        v54 = 100.0f;
```
Default value is `85` -> `85%` (gets used if value isn't present), clamp range is `60-100`, if set above `100` it gets clamped to `100`, if set below `60`, it gets clamped to `60`.

# Disable Prefetch & Superfetch

Disables prefetcher (includes disabling [`ApplicationLaunchPrefetching` & `ApplicationPreLaunch`](https://learn.microsoft.com/en-us/powershell/module/mmagent/disable-mmagent?view=windowsserver2025-ps)) features, used to speed up the boot process and application startup by preloading data - **shouldn't be disabled**, leaving it for documentation reasons. Read through the pictures for more detailed information.

The prefetcher traces roughly the first 10 seconds of app startup and writes trace files to `%SystemRoot%\\Prefetch`. The Superfetch service consumes those traces and issues clustered reads on subsequent starts. `EnablePrefetcher` controls the boot/app prefetch modes.

## Value Meanings

- [`EnablePrefetcher`](https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ff794235(v=winembedded.60)?redirectedfrom=MSDN) is a setting in the File-Based Write Filter (FBWF) and Enhanced Write Filter with HORM (EWF) packages. It specifies how to run Prefetch, a tool that can load application data into memory before it is demanded.
- [`EnableSuperfetch`](https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ff794183(v=winembedded.60)?redirectedfrom=MSDN) is a setting in the File-Based Write Filter (FBWF) and Enhanced Write Filter with HORM (EWF) packages. It specifies how to run SuperFetch, a tool that can load application data into memory before it is demanded. SuperFetch improves on Prefetch by monitoring which applications that you use the most and preloading those into system memory.
- `SfTracingState` belongs to `sftracing.exe`. This file most often belongs to product Office Server Search. This file most often has  description Office Server Search.
- `EnableBoottrace` is used to trace the startup, `1`= enabled, `0` = disabled.

```
0 - Disables Prefetch
1 - Enables Prefetch when the application starts
2 - Enables Prefetch when the device starts up
3 - Enables Prefetch when the application or device starts up
```
The same applies to superfetch.

## [Windows Internals](https://github.com/nohuto/Windows-Books/releases/download/7th-Edition/Windows-Internals-E7-P1.pdf)

![](https://github.com/nohuto/win-config/blob/main/system/images/prefetch1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/prefetch2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/prefetch3.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/system/images/prefetch4.png?raw=true)

# Disable Clipboard

If you copy or cut something it gets stored to your clipboard.

Miscellaneous notes:
```c 
"HKLM\SOFTWARE\Microsoft\Clipboard\ClipboardSvcDebugWaitInSec","Length: 16"
"HKLM\SOFTWARE\Microsoft\Clipboard\IsClipboardSignalProducingFeatureAvailable","Type: REG_DWORD, Length: 4, Data: 1"
"HKLM\SOFTWARE\Microsoft\Clipboard\IsCloudAndHistoryFeatureAvailable","Type: REG_DWORD, Length: 4, Data: 1"

"HKCU\Software\Microsoft\Clipboard\ClipboardTipRequired","Length: 16"
"HKCU\Software\Microsoft\Clipboard\CloudClipRDPOverride","Length: 16"
"HKCU\Software\Microsoft\Clipboard\CloudClipboardAutomaticUpload","Length: 16"
"HKCU\Software\Microsoft\Clipboard\CloudContentRemoteOverrideValueWindowInSec","Length: 16"
"HKCU\Software\Microsoft\Clipboard\CloudContentValueWindowInSec","Length: 16"
"HKCU\Software\Microsoft\Clipboard\DoubleCopyGestureEnabled","Length: 16"
"HKCU\Software\Microsoft\Clipboard\EnableClipboardHistory","Length: 16"
"HKCU\Software\Microsoft\Clipboard\PastedFromClipboardUI","Length: 16"
"HKCU\Software\Microsoft\Clipboard\ShellHotKeyUsed","Length: 16"
```

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Allow Clipboard synchronization across devices](https://www.noverse.dev/policies.html?p=OSPolicy*AllowCrossDeviceClipboard) | `HKLM\Software\Policies\Microsoft\Windows\System` | `AllowCrossDeviceClipboard` |
| [Allow Clipboard History](https://www.noverse.dev/policies.html?p=OSPolicy*AllowClipboardHistory) | `HKLM\Software\Policies\Microsoft\Windows\System` | `AllowClipboardHistory` |
| [Do not allow Clipboard redirection](https://www.noverse.dev/policies.html?p=TerminalServer*TS_CLIENT_CLIPBOARD) | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` | `fDisableClip` |
| [Allow clipboard sharing with Windows Sandbox](https://www.noverse.dev/policies.html?p=WindowsSandbox*AllowClipboardRedirection) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Sandbox` | `AllowClipboardRedirection` |

# Enable Detailed BSoD

| Aspect                    | New BSoD (Windows 8/10/11)                      | Old BSoD (Windows 7/classic)                                                      |
| ------------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------- |
| Main look                 | Big blue screen, sad face, simple text, QR code | Plain blue text screen, no icons                                                  |
| Stop code shown           | e.g. CRITICAL_PROCESS_DIED                      | e.g. STOP 0x0000007E                                                              |
| Hex parameters            | Hidden                                          | Shown: (0x00000000, 0x00000000...)                                                |
| Faulty driver/module name | Hidden                                          | Often shown (e.g. nvlddmkm.sys)                                                   |
| Extra help                | QR code + link                                  | Text-only advice                                                                  |
| Purpose                   | Less scary, easier to tell support the code     | See the actual debug information                                                  |

Enabling the options includes setting [`AutoReboot`](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/configure-system-failure-and-recovery-options) to `0` ("The option specifies that Windows automatically restarts your computer").

# Disable Autoruns

The `Open` buttons downloads & executes [`Autoruns`](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns). It's recommended to disable all kind of autoruns in the `Logon` section that you don't need, examples:
```c
OneDrive
Spotify
Discord
Steam
WingetUI
Lghub
SecurityHealth

Microsoft Edge // preferable remove edge from the mounted image, otherwise it'll create keys/values in many different places
```

Try to minimize the amount of applications that run automatically on system startup. You can go through the other sections, but this option was created for the `Logon` section, see `Disable Scheduled Tasks`/`Disable Services`.

See your current autoruns of installed apps:
```powershell
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```
```powershell
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

# Export Explorer/Taskbar Pins

Can be useful when creating your own image and trying to automate the installation and configuration part.

### Quick Access Pins

Quick access pins are saved in a file named `f01b4d95cf55d32a.automaticDestinations-ms`, located at:
```bat
%appdata%\Microsoft\Windows\Recent\AutomaticDestinations
```
You can either terminate `explorer` while copying it to the path, or just restart it afterwards.
```bat
copy /y ".\f01b4d95cf55d32a.automaticDestinations-ms" "%appdata%\Microsoft\Windows\Recent\AutomaticDestinations"
```

### Taskbar Pins

Taskbar pins are saved in a folder and a key, the folder includes the shortcuts:
```bat
%appdata%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar
```
```powershell
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband # Only "Favorites" is needed
```

Post install example (copy the `TaskBar` folder to any folder):
```powershell
del "$env:appdata\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" -Recurse -Force
xcopy ".\TaskBar" "%appdata%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" /e /i /y
```

The option gets current values of `Favorites` (taskbar pins) & `UIOrderList` (system tray icons) and copies all necessary files to `$home\Desktop` (edit `$dest` & `$bat` to whatever you want).

# Disable Aero Shake

Prevents windows from being minimized or restored when the active window is shaken back and forth with the mouse.

`SystemSettings > System > Multitasking: Title bar window shake`.

![](https://www.techjunkie.com/wp-content/uploads/2018/10/windows-aero-shake-example.gif)

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Turn off Aero Shake window minimizing mouse gesture](https://www.noverse.dev/policies.html?p=Desktop*NoWindowMinimizingShortcuts) | `HKCU\Software\Policies\Microsoft\Windows\Explorer` | `NoWindowMinimizingShortcuts` |

# App Archive

"Automatically archive your infrequently used apps to save storage and internet bandwidth. Your files and data will still be saved, and the app's full version will be restored on your next use if it's still available."

If enabled, the system will periodically check for such infrequently used apps. By default app archiving is turned on.

## SystemSettings Records

Toggling the option via `Apps > Advanced app settings`:
```c
// On
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\Stubification\S-{ID}\EnableAppOffloading    Type: REG_DWORD, Length: 4, Data: 1

// Off
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\Stubification\S-{ID}\EnableAppOffloading    Type: REG_DWORD, Length: 4, Data: 0
```

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Archive infrequently used apps](https://www.noverse.dev/policies.html?p=AppxPackageManager*AllowAutomaticAppArchiving) | `HKLM\Software\Policies\Microsoft\Windows\Appx` | `AllowAutomaticAppArchiving` |

# Disable Mobility Center

Note that this is a laptop only feature. The "Mobility Center" is a feature that includes controls for screen brightness, power options, volume, battery status, wireless network status, external display settings, and more.

![](https://github.com/nohuto/win-config/blob/main/system/images/mobility-center.png?raw=true)

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Turn off Windows Mobility Center](https://www.noverse.dev/policies.html?p=MobilePCMobilityCenter*MobilityCenterEnable_2) | `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\MobilityCenter` | `NoMobilityCenter` |
