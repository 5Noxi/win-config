# xHCI IMOD

| Flag | Description |
| --- | --- |
| `--rw-path PATH` | Override the default `%LOCALAPPDATA%\Noverse\IMOD\RwPortable\Win64\Portable\Rw.exe` location |
| `--bdf BB:DD.F` | Use a specific controller by Bus:Device.Function (hex). Mutually exclusive with `--xhci-index`/`--all` |
| `--xhci-index N` | Use the Nth xHCI controller reported by `FPciClass` (defaults to 0 when `--bdf/--all` absent) |
| `--all` | Iterate through every xHCI controller and apply the same IMOD changes to each |
| `--interrupter ID` / `-i ID` | Restrict the operation to specific interrupter IDs, repeat the flag for multiple IDs (defaults to all) |
| `--interval VALUE` | Set a custom IMOD interval (0–0xFFFF, in 250 ns ticks). Use for example `0xC800` (~48 Hz) to see if chaning the interval works |
| `--no-write` | Only read and print IMOD registers (skip the write for information only) |
| `--startup` | Copy the script or exe to `%LOCALAPPDATA%\Noverse\IMOD\` and creates a scheduled task that runs the command at each logon |
| `--delete` | Delete the scheduled task created by `--startup` |
| `--no-exit` | Keep the console open after completion |
| `--verbose` | Output all `rw.exe` commands/results |

```c
--all --no-write --no-exit // information only
--all --no-write --verbose --no-exit // rw commands/output
--all // 0 for all controllers
--all --interval 0xC800 // testing (~48hz)
--all --startup // 0 for all controllers, creates scheduled task
--delete // removes the task
```

You can download the executeable from my repository, I packed it into one package since some may not have python installed on their system.
> https://github.com/nohuto/win-config/blob/main/power/assets/NV-IMOD.exe

## xHCI Interrupt Moderation Notes

Interrupt Moderation (IMOD) is the pacing logic inside an xHCI controller that decides how quickly hardware interrupts are sent up to the CPU. Every time the host controller has new events to report, it can either raise an interrupt immediately or wait for a programmable delay. IMOD is that programmable timer, you choose an interval value, the controller loads a counter, and no second interrupt is allowed until the counter has expired and the Event Handler is ready again.

Note that everything written below is based on the [`eXtensible Host Controller Interfact for Universal Serial Bus`](https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/extensible-host-controler-interface-usb-xhci.pdf) document. See pages `289f.`, `295`, `383`, `388`, `425`, `426`.

`HCSPARAMS1` (Base + 0x04) reports the number of interrupters (`MaxIntrs`). Each *Interrupter Register Set* has its own moderation and the range is 0x1-0x400, so the field must be non zero for a usable controller. The *Runtime Register Base* address equals the *Operational Base* plus the *Runtime Register Space Offset* (`RTSOFF`). `RTSOFF` is at Base + 0x18 and bits [31:5] provide the aligned offset (bits [4:0] are reserved). Every *Interrupter Register Set* has 32 bytes starting at Runtime Base + 0x20. `IMAN` is at `Runtime Base + 0x20 + 32*n`, `IMOD` at `+0x24 + 32*n`, followed by the *Event Ring* registers (`ERSTSZ`, `ERSTBA`, `ERDP`).

When a TRB event triggers the Interrupt Pending (`IP`) flag, host notification is throttled according to the Interrupter's Moderation (`IMOD`) register. `IMOD` combines the Interrupt Moderation Interval (`IMODI`) and the Interrupt Moderation Counter (`IMODC`). Software programs `IMODI` in 250 ns units, the hardware copies it into `IMODC`, counts down, and only raises the interrupt once the counter reaches zero and the *Event Handler Busy* (`EHB`) flag has been cleared. `interrupts/sec = 1 / (250 ns * IMODI)` and `inter-interrupt interval = 250 ns * (interrupts/sec)^-1`. "Recommended tuning values" are 0x28B-0x15CC with a default of 0x4000 (~1ms). For example, `IMODI = 512` guarantees at least 128 us between interrupts, so the maximum rate stays under 8kHz. Writing `IMODI = 0` disables throttling and interrupts are delivered immediately once `EHB` is clear and the *Event Ring* is non empty. Blocking Event handling ensures `IPE` (an internal flag) and `EHB` cooperate with `IMODC`. A new interrupt is prevented until `IMODC` reaches zero, `IPE` is asserted, and `EHB` is cleared, when those conditions hold, the counter reloads from `IMODI` so the pacing cycle repeats.

## Bit Descriptions (taken from document)

**Interrupter Moderation Register (IMOD):**

| Bit   | Description|
| :---: | --- |
| 15:0 | **Interrupt Moderation Interval (IMODI) – RW.** Default = '4000' (~1ms). Minimum inter-interrupt interval. The interval is specified in 250ns increments. A value of '0' disables interrupt throttling logic and interrupts shall be generated immediately if IP = '0', EHB = '0', and the *Event Ring* is not empty. |
| 31:16 | **Interrupt Moderation Counter (IMODC) – RW.** Default = undefined. Down counter. Loaded with the IMODI value whenever IP is cleared to '0', counts down to '0', and stops. The associated interrupt shall be signaled whenever this counter is '0', the *Event Ring* is not empty, the IE and IP flags = '1', and EHB = '0'. This counter may be directly written by software at any time to alter the interrupt rate. |

---

**Host Controller Structural Parameters 2 (HCSPARAMS2):**

| Bit  | Description |
| :---: | --- |
| 0:3 | **Isochronous Scheduling Threshold (IST).** Default = implementation dependent. The value in this field indicates to system software the minimum distance (in time) that it is required to stay ahead of the host controller while adding TRBs, in order to have the host controller process them at the correct time. The value shall be specified in terms of number of frames/microframes.<br><br>If bit [3] of IST is cleared to '0', software can add a TRB no later than IST[2:0] Microframes before that TRB is scheduled to be executed.<br><br>If bit [3] of IST is set to '1', software can add a TRB no later than IST[2:0] Frames before that TRB is scheduled to be executed.<br><br>Refer to Section 4.14.2 for details on how software uses this information for scheduling isochronous transfers. |
| 7:4 | ***Event Ring* Segment Table Max (ERST Max).** Default = implementation dependent. Valid values are 0 – 15. This field determines the maximum value supported the **Event Ring* Segment Table Base Size* registers (5.5.2.3.1), where:<br><br>  The maximum number of *Event Ring* Segment Table entries = 2 ERST Max.<br><br>e.g. if the ERST Max = 7, then the xHC **Event Ring* Segment Table(s)* supports up to 128 entries, 15 then 32K entries, etc. |
| 20:8 | Reserved. |

![](https://github.com/nohuto/win-config/blob/main/power/images/HCSPARAMS2-structure.png?raw=true)

---

**Runtime Register Space Offset Register (RTSOFF):**

| Bit  | Description |
| :---: | --- |
| 0 | **Interrupt Pending (IP) – RW1C.** Default = '0'. This flag represents the current state of the Interrupter. If IP = '1', an interrupt is pending for this Interrupter. A '0' value indicates that no interrupt is pending for the Interrupter. Refer to section 4.17.3 for the conditions that modify the state of this flag.                                    |
| 1 | **Interrupt Enable (IE) – RW.** Default = '0'. This flag specifies whether the Interrupter is capable of generating an interrupt. When this bit and the IP bit are set ('1'), the Interrupter shall generate an interrupt when the Interrupter Moderation Counter reaches '0'. If this bit is '0', then the Interrupter is prohibited from generating interrupts. |
| 31:2 | Reserved and Preserved. |

![](https://github.com/nohuto/win-config/blob/main/power/images/RTSOFF-structure.png?raw=true)

---

**Interrupter Management Register Bit Definitions (IMAN):**

| Bit  | Description |
| :---: | --- |
| 0 | **Interrupt Pending (IP) – RW1C.** Default = '0'. This flag represents the current state of the Interrupter. If IP = '1', an interrupt is pending for this Interrupter. A '0' value indicates that no interrupt is pending for the Interrupter. Refer to section 4.17.3 for the conditions that modify the state of this flag. |
| 1 | **Interrupt Enable (IE) – RW.** Default = '0'. This flag specifies whether the Interrupter is capable of generating an interrupt. When this bit and the IP bit are set ('1'), the Interrupter shall generate an interrupt when the Interrupter Moderation Counter reaches '0'. If this bit is '0', then the Interrupter is prohibited from generating interrupts. |
| 31:2 | Reserved and Preserved. |

# Power Plan

### Noverse Performance

It's a clone of `SCHEME_MIN` including ~60 changes related to disabling parking/selective suspend/(deep) sleep/battery features/ display dimming/hard disk power savings/slide show/PAPB features, several changes to the processor power management (keeps processor idle enabled, which shouldn't be changed). This can be used by desktop users.

### Noverse Balanced

This power plan should be used by laptop users, it's a clone of `SCHEME_BALANCED` including several specific changes, e.g. pausing slide shows, changing time check intervals while keeping power savings (to prevent overheating) and subgroup settings of `Battery`, `Presence Aware Power Behaviour`, `Display`, `Sleep` etc. unchanged.

## Power Settings Documentation

Most markdown files below are from [windows-hardware/customize/power-settings](https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/configure-power-settings), but since this isn't available on GitHub I decided back them up.

Structure is heading level 3 = subgroup name, linked text = setting name, the brackets include `PowerCfg` naming & setting GUID.

### Settings belonging to no subgroup

- [Require a password on wakeup](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/no-subgroup-settings-prompt-for-password-on-resume.md) (`CONSOLELOCK`, `0e796bdb-100d-47d6-a2d5-f7d2daa51f51`)
- [Power plan type](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/no-subgroup-settings.md) (`PERSONALITY`, `245d8541-3943-4422-b025-13a784f679b7`)
- [Device idle policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/no-subgroup-settings-device-idle-policy.md) (`DEVICEIDLE`, `4faab71a-92e5-4726-b531-224559672d19`)
- [Disconnected Standby Mode](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/no-subgroup-settings.md) (`DISCONNECTEDSTANDBYMODE`, `68afb2d9-ee95-47a8-8f50-4115088073b1`)
- [Networking connectivity in Standby](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/no-subgroup-settings-allow-networking-during-standby.md) (`CONNECTIVITYINSTANDBY`, `f15576e8-98b7-4186-b944-eafa664402d9`)

### Hard disk

- [AHCI Link Power Management - HIPM/DIPM](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/disk-settings-link-power-management-mode---hipm-dipm.md) (`0b2d69d7-a2a1-449c-9680-f91c70521c60`)
- [Maximum Power Level](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/disk-settings.md) (`DISKMAXPOWER`, `51dea550-bb38-4bc4-991b-eacf37be5ec8`)
- [Turn off hard disk after](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/disk-settings-disk-idle-timeout.md) (`DISKIDLE`, `6738e2c4-e8a5-4a42-b16a-e040e769756e`)
- [Hard disk burst ignore time](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/disk-settings-disk-burst-ignore-time.md) (`DISKBURSTIGNORE`, `80e3c60e-bb94-4ad8-bbe0-0d3195efc663`)
- [Secondary NVMe Idle Timeout](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/disk-settings.md) (`d3d55efd-c1ff-424e-9dc3-441be7833010`)
- [Primary NVMe Idle Timeout](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/disk-settings.md) (`NVMEPRIMARYIDLETIMEOUT`, `d639518a-e56d-4345-8af2-b9f32fb26109`)
- [AHCI Link Power Management - Adaptive](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/disk-settings-link-power-management-mode---adaptive.md) (`dab60367-53fe-4fbc-825e-521d069d2456`)
- [Secondary NVMe Power State Transition Latency Tolerance](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/disk-settings.md) (`dbc9e238-6de9-49e3-92cd-8c2b4946b472`)
- [NVMe NOPPME](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/disk-settings.md) (`DISKNVMENOPPME`, `fc7372b6-ab2d-43ee-8797-15e9841f2cca`)
- [Primary NVMe Power State Transition Latency Tolerance](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/disk-settings.md) (`fc95af4d-40e7-4b6d-835a-56d131dbc80e`)

### Desktop background settings

- [Slide show](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`309dce9b-bef4-4119-9921-a851fb12f0f4`)

### Wireless Adapter Settings

- [Power Saving Mode](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`12bbebe6-58d6-4636-95bb-3217ef867c1a`)

### Sleep

- [Legacy RTC mitigations](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/sleep-settings.md) (`LEGACYRTCMITIGATION`, `1a34bdc3-7e6b-442e-a9d0-64b6ef378e84`)
- [Allow Away Mode Policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/sleep-settings-allow-away-mode.md) (`AWAYMODE`, `25dfa149-5dd1-4736-b5ab-e8a37b5b8187`)
- [Sleep after](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/sleep-settings-sleep-idle-timeout.md) (`STANDBYIDLE`, `29f6c1db-86da-48c5-9fdb-f2b67b1f44da`)
- [System unattended sleep timeout](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/sleep-settings-sleep-unattended-idle-timeout.md) (`UNATTENDSLEEP`, `7bc4a2f9-d8fc-4469-b07b-33eb785aaca0`)
- [Allow hybrid sleep](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/sleep-settings-hybrid-sleep.md) (`HYBRIDSLEEP`, `94ac6d29-73ce-41a6-809f-6363ba21b47e`)
- [Hibernate after](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/sleep-settings-hibernate-idle-timeout.md) (`HIBERNATEIDLE`, `9d7815a6-7ee4-497e-8888-515a05f02364`)
- [Allow system required policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/sleep-settings-allow-system-required-requests.md) (`SYSTEMREQUIRED`, `a4b195f5-8225-47d8-8012-9d41369786e2`)
- [Allow Standby States](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/sleep-settings-allow-sleep-states.md) (`ALLOWSTANDBY`, `abfc2519-3608-4c2a-94ea-171b0ed546ab`)
- [Allow wake timers](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/sleep-settings-automatically-wake-for-tasks.md) (`RTCWAKE`, `bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d`)
- [Allow sleep with remote opens](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/sleep-settings-allow-sleep-with-open-remote-files.md) (`REMOTEFILESLEEP`, `d4c1d4c8-d5cc-43d3-b83e-fc51215cb04d`)

### USB settings

- [Hub Selective Suspend Timeout](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`0853a681-27c8-4100-a2fd-82013e970683`)
- [USB selective suspend setting](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`48e6b7a6-50f5-4782-a5d4-53bb8f07e226`)
- [Setting IOC on all TDs](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`498c044a-201b-4631-a522-5c744ed4e678`)
- [USB 3 Link Power Mangement](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`d4e98f31-5ffe-4ce1-be31-1b38b384c009`)

### Idle Resiliency

- [Execution Required power request timeout](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`EXECTIME`, `3166bc41-7e98-4e03-b34e-ec0f5f2b218e`)
- [IO coalescing timeout](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`COALTIME`, `c36f0eb4-2988-4a70-8eee-0884fc2c2433`)
- [Processor Idle Resiliency Timer Resolution](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`PROCIR`, `c42b79aa-aa3a-484b-a98f-2cf32aa90a28`)
- [Deep Sleep Enabled/Disabled](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`DEEPSLEEP`, `d502f7ee-1dc7-4efd-a55d-f04b6f5c0545`)

### Interrupt Steering Settings

- [Interrupt Steering Mode](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`MODE`, `2bfc24f9-5ea2-4801-8213-3dbae01aa39d`)
- [Target Load](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`PERPROCLOAD`, `73cde64d-d720-4bb2-a860-c755afe77ef2`)
- [Unparked time trigger](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`UNPARKTIME`, `d6ba4903-386f-4c2c-8adb-5c21b3328d25`)

### Power buttons and lid

- [Lid close action](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/power-button-and-lid-settings-lid-switch-close-action.md) (`LIDACTION`, `5ca83367-6e45-459f-a27b-476b1d01c936`)
- [Power button action](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/power-button-and-lid-settings-power-button-action.md) (`PBUTTONACTION`, `7648efa3-dd9c-4e3e-b566-50f929386280`)
- [Enable forced button/lid shutdown](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/power-button-and-lid-settings-power-button-forced-shutdown.md) (`SHUTDOWN`, `833a6b62-dfa4-46d1-82f8-e09e34d029d6`)
- [Sleep button action](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/power-button-and-lid-settings-sleep-button-action.md) (`SBUTTONACTION`, `96996bc0-ad50-47ec-923b-6f41874dd9eb`)
- [Lid open action](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/lid-open-wake-action.md) (`LIDOPENWAKE`, `99ff10e7-23b1-4c07-a9d1-5c3206d741b4`)
- [Start menu power button](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/power-button-and-lid-settings.md) (`UIBUTTON_ACTION`, `a7066653-8d6c-40a8-910e-a1f54b84c7e5`)

### PCI Express

- [Link State Power Management](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/pci-express-settings-link-state-power-management.md) (`ASPM`, `ee12f906-d277-404b-b6da-e5fa1a576df5`)

### Processor power management

- [Processor performance increase threshold](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfincreasethreshold.md) (`PERFINCTHRESHOLD`, `06cadf0e-64ed-448a-8927-ce7bf90eb35d`)
- [Processor performance increase threshold for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfincreasethreshold.md) (`PERFINCTHRESHOLD1`, `06cadf0e-64ed-448a-8927-ce7bf90eb35e`)
- [Processor performance core parking min cores](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-core-parking-cpmincores.md) (`CPMINCORES`, `0cc5b647-c1df-4637-891a-dec35c318583`)
- [Processor performance core parking min cores for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-core-parking-cpmincores.md) (`CPMINCORES1`, `0cc5b647-c1df-4637-891a-dec35c318584`)
- [Processor performance decrease threshold](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfdecreasethreshold.md) (`PERFDECTHRESHOLD`, `12a0ab44-fe28-4fa9-b3bd-4b64f44960a6`)
- [Processor performance decrease threshold for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfdecreasethreshold.md) (`PERFDECTHRESHOLD1`, `12a0ab44-fe28-4fa9-b3bd-4b64f44960a7`)
- [Initial performance for Processor Power Efficiency Class 1 when unparked](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configuration-for-hetero-power-scheduling-heteroclass1initialperf.md) (`HETEROCLASS1INITIALPERF`, `1facfc65-a930-4bc5-9f38-504ec097bbc0`)
- [Processor performance core parking concurrency threshold](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-core-parking-cpconcurrency.md) (`CPCONCURRENCY`, `2430ab6f-a520-44a2-9601-f7f23b5134b1`)
- [Processor performance core parking increase time](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-core-parking-cpincreasetime.md) (`CPINCREASETIME`, `2ddd5a84-5a71-437e-912a-db0b8c788732`)
- [Processor energy performance preference policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfenergypreference.md) (`PERFEPP`, `36687f9e-e3a5-4dbf-b1dc-15eb381c6863`)
- [Processor energy performance preference policy for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfenergypreference.md) (`PERFEPP1`, `36687f9e-e3a5-4dbf-b1dc-15eb381c6864`)
- [Allow Throttle States](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`THROTTLING`, `3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb`)
- [Processor performance increase time for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`HETEROINCREASETIME`, `4009efa7-e72d-4cba-9edf-91084ea8cbc3`)
- [Processor performance decrease policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfdecreasepolicy.md) (`PERFDECPOL`, `40fbefc7-2e9d-4d25-a185-0cfd8574bac6`)
- [Processor performance decrease policy for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfdecreasepolicy.md) (`PERFDECPOL1`, `40fbefc7-2e9d-4d25-a185-0cfd8574bac7`)
- [Long running threads' processor architecture lower limit](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`LONGTHREADARCHCLASSLOWERTHRESHOLD`, `43f278bc-0f8a-46d0-8b31-9a23e615d713`)
- [Processor performance core parking parked performance state](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`CPPERF`, `447235c7-6a8d-4cc0-8e24-9eaf70b96e2b`)
- [Processor performance core parking parked performance state for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`CPPERF1`, `447235c7-6a8d-4cc0-8e24-9eaf70b96e2c`)
- [Processor performance boost policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/legacy-config-options-perfboostpol.md) (`PERFBOOSTPOL`, `45bcc044-d885-43e2-8605-ee0ec6e96b59`)
- [Processor performance increase policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfincreasepolicy.md) (`PERFINCPOL`, `465e1f50-b610-473a-ab58-00d1077dc418`)
- [Processor performance increase policy for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfincreasepolicy.md) (`PERFINCPOL1`, `465e1f50-b610-473a-ab58-00d1077dc419`)
- [Latency sensitivity hint processor energy performance preference](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-latencyhintepp.md) (`LATENCYHINTEPP`, `4b70f900-cdd9-4e66-aa26-ae8417f98173`)
- [Latency sensitivity hint processor energy performance preference for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-latencyhintepp.md) (`LATENCYHINTEPP1`, `4b70f900-cdd9-4e66-aa26-ae8417f98174`)
- [Processor idle demote threshold](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`IDLEDEMOTE`, `4b92d758-5a24-4851-a470-815d78aee119`)
- [Processor performance core parking distribution threshold](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-core-parking-cpdistribution.md) (`CPDISTRIBUTION`, `4bdaf4e9-d103-46d7-a5f0-6280121616ef`)
- [Processor performance time check interval](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`PERFCHECK`, `4d2b0152-7d5c-498b-88e2-34345392a2c5`)
- [Processor duty cycling](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-dutycycling.md) (`PERFDUTYCYCLING`, `4e4450b3-6179-4e91-b8f1-5bb9938f81a1`)
- [Short running threads' processor architecture lower limit](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`SHORTTHREADARCHCLASSLOWERTHRESHOLD`, `53824d46-87bd-4739-aa1b-aa793fac36d6`)
- [Processor idle disable](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`IDLEDISABLE`, `5d76a2ca-e8c0-402f-a133-2158492d58ad`)
- [Latency sensitivity hint min unparked cores/packages](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`LATENCYHINTUNPARK`, `616cdaa5-695e-4545-97ad-97dc2d1bdd88`)
- [Latency sensitivity hint min unparked cores/packages for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`LATENCYHINTUNPARK1`, `616cdaa5-695e-4545-97ad-97dc2d1bdd89`)
- [Latency sensitivity hint processor performance](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perflatencyhint.md) (`LATENCYHINTPERF`, `619b7505-003b-4e82-b7a6-4dd29c300971`)
- [Latency sensitivity hint processor performance for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perflatencyhint.md) (`LATENCYHINTPERF1`, `619b7505-003b-4e82-b7a6-4dd29c300972`)
- [Processor idle threshold scaling](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`IDLESCALING`, `6c2993b0-8f48-481f-bcc6-00dd2742aa06`)
- [Processor performance core parking decrease policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`CPDECREASEPOL`, `71021b41-c749-4d21-be74-a00f335d582b`)
- [Maximum processor frequency](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`PROCFREQMAX`, `75b0ae3f-bce0-45a7-8c89-c9611c25e100`)
- [Maximum processor frequency for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`PROCFREQMAX1`, `75b0ae3f-bce0-45a7-8c89-c9611c25e101`)
- [Processor idle promote threshold](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`IDLEPROMOTE`, `7b224883-b3cc-4d79-819f-8374152cbe7c`)
- [Processor performance history count](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`PERFHISTORY`, `7d24baa7-0b84-480f-840c-1b0743c00f5f`)
- [Processor performance history count for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`PERFHISTORY1`, `7d24baa7-0b84-480f-840c-1b0743c00f60`)
- [Processor performance decrease time for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`HETERODECREASETIME`, `7f2492b6-60b1-45e5-ae55-773f8cd5caec`)
- [Heterogeneous policy in effect](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`HETEROPOLICY`, `7f2f5cfa-f10c-4823-b5e1-e93ae85f46b5`)
- [Short running threads' processor architecture upper limit](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`SHORTTHREADARCHCLASSUPPERTHRESHOLD`, `828423eb-8662-4344-90f7-52bf15870f5a`)
- [Minimum processor state](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-minperformance.md) (`PROCTHROTTLEMIN`, `893dee8e-2bef-41e0-89c6-b55d0929964c`)
- [Minimum processor state for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-minperformance.md) (`PROCTHROTTLEMIN1`, `893dee8e-2bef-41e0-89c6-b55d0929964d`)
- [Processor performance autonomous mode](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfautonomousmode.md) (`PERFAUTONOMOUS`, `8baa4a8a-14c6-4451-8e8b-14bdbd197537`)
- [Heterogeneous thread scheduling policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configuration-for-hetero-power-scheduling-schedulingpolicy.md) (`SCHEDPOLICY`, `93b8b6dc-0698-4d1c-9ee4-0644e900c85d`)
- [Processor performance core parking overutilization threshold](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`CPOVERUTIL`, `943c8cb6-6f93-4227-ad87-e9a3feec08d1`)
- [System cooling policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`SYSCOOLPOL`, `94d3a615-a899-4ac5-ae2b-e4d8f634367f`)
- [Processor performance core parking soft park latency](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-core-parking-softparklatency.md) (`SOFTPARKLATENCY`, `97cfac41-2217-47eb-992d-618b1977c907`)
- [Processor performance increase time](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`PERFINCTIME`, `984cf492-3bed-4488-a8f9-4286c97bf5aa`)
- [Processor performance increase time for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`PERFINCTIME1`, `984cf492-3bed-4488-a8f9-4286c97bf5ab`)
- [Processor idle state maximum](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`IDLESTATEMAX`, `9943e905-9a30-4ec1-9b99-44dd3b76f7a2`)
- [Processor performance level increase threshold for Processor Power Efficiency Class 1 processor count increase](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`HETEROINCREASETHRESHOLD`, `b000397d-9b0b-483d-98c9-692a6060cfbf`)
- [Processor performance level increase threshold for Processor Power Efficiency Class 2 processor count increase](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`HETEROINCREASETHRESHOLD1`, `b000397d-9b0b-483d-98c9-692a6060cfc0`)
- [Module unpark policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`MODULEUNPARKPOLICY`, `b0deaf6b-59c0-4523-8a45-ca7f40244114`)
- [Smt threads unpark policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`SMTUNPARKPOLICY`, `b28a6829-c5f7-444e-8f61-10e24e85c532`)
- [Complex unpark policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`COMPLEXUNPARKPOLICY`, `b669a5e9-7b1d-4132-baaa-49190abcfeb6`)
- [Heterogeneous short running thread scheduling policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configuration-for-hetero-power-scheduling-shortschedulingpolicy.md) (`SHORTSCHEDPOLICY`, `bae08b81-2d5e-4688-ad6a-13243356654b`)
- [Maximum processor state](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-maxperformance.md) (`PROCTHROTTLEMAX`, `bc5038f7-23e0-4960-96da-33abaf5935ec`)
- [Maximum processor state for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-maxperformance.md) (`PROCTHROTTLEMAX1`, `bc5038f7-23e0-4960-96da-33abaf5935ed`)
- [Processor performance boost mode](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfboostmode.md) (`PERFBOOSTMODE`, `be337238-0d82-4146-a960-4f3749d470c7`)
- [Long running threads' processor architecture upper limit](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`LONGTHREADARCHCLASSUPPERTHRESHOLD`, `bf903d33-9d24-49d3-a468-e65e0325046a`)
- [Processor idle time check](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`IDLECHECK`, `c4581c31-89ab-4597-8e2b-9c9cab440e6b`)
- [Processor performance core parking increase policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`CPINCREASEPOL`, `c7be0679-2817-4d69-9d02-519a537ed0c6`)
- [Processor autonomous activity window](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-perf-state-engine-perfautonomouswindow.md) (`PERFAUTONOMOUSWINDOW`, `cfeda3d0-7697-4566-a922-a9086cd49dfa`)
- [Processor performance decrease time](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`PERFDECTIME`, `d8edeb9b-95cf-4f95-a73c-b061973693c8`)
- [Processor performance decrease time for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`PERFDECTIME1`, `d8edeb9b-95cf-4f95-a73c-b061973693c9`)
- [Short vs. long running thread threshold](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`SHORTTHREADRUNTIMETHRESHOLD`, `d92998c2-6a48-49ca-85d4-8cceec294570`)
- [Processor performance core parking decrease time](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-core-parking-cpdecreasetime.md) (`CPDECREASETIME`, `dfd10d17-d5eb-45dd-877a-9a34ddd15c82`)
- [Processor performance core parking utility distribution](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`DISTRIBUTEUTIL`, `e0007330-f589-42ed-a401-5ddb10e785d3`)
- [Processor performance core parking max cores](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-core-parking-cpmaxcores.md) (`CPMAXCORES`, `ea062031-0e34-4ff1-9b6d-eb1059334028`)
- [Processor performance core parking max cores for Processor Power Efficiency Class 1](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-core-parking-cpmaxcores.md) (`CPMAXCORES1`, `ea062031-0e34-4ff1-9b6d-eb1059334029`)
- [Processor performance core parking concurrency headroom threshold](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/options-for-core-parking-cpheadroom.md) (`CPHEADROOM`, `f735a673-2066-4f80-a0c5-ddee0cf1bf5d`)
- [Processor performance level decrease threshold for Processor Power Efficiency Class 1 processor count decrease](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`HETERODECREASETHRESHOLD`, `f8861c27-95e7-475c-865b-13c0cb3f9d6b`)
- [Processor performance level decrease threshold for Processor Power Efficiency Class 2 processor count decrease](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-processor-power-management-options.md) (`HETERODECREASETHRESHOLD1`, `f8861c27-95e7-475c-865b-13c0cb3f9d6c`)
- [A floor performance for Processor Power Efficiency Class 0 when there are Processor Power Efficiency Class 1 processors unparked](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configuration-for-hetero-power-scheduling-heteroclass0floorperf.md) (`HETEROCLASS0FLOORPERF`, `fddc842b-8364-4edc-94cf-c17f60de1c80`)

### Graphics settings

- [GPU preference policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`GPUPREFERENCEPOLICY`, `dd848b2a-8a5d-4451-9ae2-39cd41658f6c`)

### Display

- [Dim display after](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/display-settings-dim-annoyance-timeout.md) (`VIDEODIM`, `17aaa29b-8b43-4b94-aafe-35f64daaf1ee`)
- [Turn off display after](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/display-settings-display-idle-timeout.md) (`VIDEOIDLE`, `3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e`)
- [Advanced Color quality bias](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/display-settings-advanced-color-quality-bias.md) (`ADVANCEDCOLORQUALITYBIAS`, `684c3e69-a4f7-4014-8754-d45179a56167`)
- [Console lock display off timeout](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/display-settings.md) (`VIDEOCONLOCK`, `8ec4b3a5-6868-48c2-be75-4f3044be88a7`)
- [Adaptive display](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/display-settings-adaptive-display-idle-timeout.md) (`VIDEOADAPT`, `90959d22-d6a1-49b9-af93-bce885ad335b`)
- [Allow display required policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/display-settings-allow-display-required-policy.md) (`ALLOWDISPLAY`, `a9ceb8da-cd46-44fb-a98b-02af69de4623`)
- [Display brightness](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/display-settings-display-brightness-level.md) (`VIDEONORMALLEVEL`, `aded5e82-b909-4619-9949-f5d71dac0bcb`)
- [Dimmed display brightness](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/display-settings-dim-display-brightness.md) (`f1fbfde2-a960-4165-9f88-50667911ce96`)
- [Enable adaptive brightness](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/display-settings.md) (`ADAPTBRIGHT`, `fbd9aa66-9553-4097-ba44-ed6e9d65eab8`)

### Presence Aware Power Behavior

- [Human Presence Sensor Adaptive Away Display Timeout](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/presence-adaptive-away-display-timeout.md) (`HUPRVIDEOIDLE`, `0a7d6ab6-ac83-4ad1-8282-eca5b58308f3`)
- [Standby Reserve Time](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`STANDBYRESERVETIME`, `468fe7e5-1158-46ec-88bc-5b96c9e44fd0`)
- [Standby Reset Percentage](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`STANDBYRESETPERCENT`, `49cb11a5-56e2-4afb-9d38-3df47872e21b`)
- [Non-sensor Input Presence Timeout](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`NSENINPUTPRETIME`, `5adbbfbc-074e-4da1-ba38-db8b36b2c8f3`)
- [Standby Budget Grace Period](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`STANDBYBUDGETGRACEPERIOD`, `60c07fe1-0556-45cf-9903-d56e32210242`)
- [User Presence Prediction mode](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`USERPRESENCEPREDICTION`, `82011705-fb95-4d46-8d35-4042b1d20def`)
- [Standby Budget Percent](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`STANDBYBUDGETPERCENT`, `9fe527be-1b70-48da-930d-7bcf17b44990`)
- [Human Presence Sensor Adaptive Away Dim Timeout](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/presence-adaptive-away-dim-timeout.md) (`HUPRVIDEODIMAWAY`, `a79c8e0e-f271-482d-8f8a-5db9a18312de`)
- [Standby Reserve Grace Period](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`STANDBYRESERVEGRACEPERIOD`, `c763ee92-71e8-4127-84eb-f6ed043a3e3d`)
- [Human Presence Sensor Adaptive Inattentive Dim Timeout](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/presence-adaptive-inattentive-dim-timeout.md) (`HUPRVIDEODIM`, `cf8c6097-12b8-4279-bbdd-44601ee5209d`)
- [Human Presence Sensor Adaptive Inattentive Display Timeout](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/presence-adaptive-inattentive-display-timeout.md) (`HUPRVIDEOIDLEINATTENTIVE`, `ee16691e-6ab3-4619-bb48-1c77c9357e5a`)

### Video playback quality

- [Video playback quality bias](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`10778347-1370-4ee0-8bbd-33bdacaade49`)
- [When playing video](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/configure-power-settings.md) (`34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4`)

### Energy Saver settings

- [Display brightness weight](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/energy-saver-settings.md) (`ESBRIGHTNESS`, `13d09884-f74e-474a-a852-b6bde8ad03a8`)
- [Energy Saver Policy](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/energy-saver-settings.md) (`ESPOLICY`, `5c5bb349-ad29-4ee2-9d0b-2b25270f7a81`)
- [Charge level](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/energy-saver-settings.md) (`ESBATTTHRESHOLD`, `e69653ca-cf7f-4f05-aa73-cb833fa90ad4`)

### Battery

- [Critical battery notification](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/battery-settings.md) (`BATFLAGSCRIT`, `5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f`)
- [Critical battery action](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/battery-settings-critical-battery-action.md) (`BATACTIONCRIT`, `637ea02f-bbcb-4015-8e2c-a1c7b9c0b546`)
- [Low battery level](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/battery-settings-low-battery-threshold.md) (`BATLEVELLOW`, `8183ba9a-e910-48da-8769-14ae6dc1170a`)
- [Critical battery level](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/battery-settings-critical-battery-threshold.md) (`BATLEVELCRIT`, `9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469`)
- [Low battery notification](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/battery-settings.md) (`BATFLAGSLOW`, `bcded951-187b-4d05-bccc-f7e51960c258`)
- [Low battery action](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/battery-settings-low-battery-action.md) (`BATACTIONLOW`, `d8742dcb-3e6a-4b3c-b3fe-374623cdcf06`)
- [Reserve battery level](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/battery-settings-reserve-battery-level.md) (`f3c5027d-cd16-4930-aa6b-90db844a8f00`)

## Suboptions

I've added some specific settings to toggle some features if wanted, note that this applies to the current active scheme. If you want to change more specific settings rather use a tool such as [PowerSettingsExplorer](https://github.com/nohuto/win-config/blob/main/power/assets/PowerSettingsExplorer.exe).

### Default Schemes

`Delete` = deletes the default schemes (select one of the `Noverse x` schemes before deleting them, otherwise a scheme named `Noverse Temporary Scheme` gets created which is a clone of `SCHEME_BALANCED`):

```c
381b4222-f694-41f0-9685-ff5bb260df2e // SCHEME_BALANCED (Balanced)
8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c // SCHEME_MIN (High Performance)
a1841308-3541-4fab-bc81-f71556f20b4a // SCHEME_MAX (Power saver)
```

`Restore` = restores the default schemes, note that this removes all imported/custom plans

### Context Menu Import

Adds a `Import` option when right clicking on `.pow` files.

![](https://github.com/nohuto/win-config/blob/main/power/images/powcontextmenu.png?raw=true)

# Power Values

This option serves as a general values overview for the `Power` key (similar to `DXG Kernel Values`/`Kernel Values`/`DWM Values`). Several values are applied, some have been changed, others are default values. The applied data is sometimes pure speculation.

No values are applied that apply to other options in this section.

See win-registry repo for a list of `CCS\\Control\\Power\\...` values/defaults/notes:
> https://github.com/nohuto/win-registry#power-values

## PowerThrottlingOff Details

```
Power throttling, introduced in W10 and present in W11, limits CPU usage for background or minimized applications. It reduces the processing power available to these apps while allowing active applications to run normally.
```

When looking into the pseudocode (PopInitializeHeteroProcessors) it shows that if the value is set to nonzero it would:
- force QoS allow variable `v5` to `0` and stores it in `PpmPerfQosSupportedAndAllowed` at the end
- passes `v5` (`0`) value into `KeConfigureHeteroProcessors`
- skips `PpmIdleEnableIdleDurationExpirationTimeout` (`PpmIdleDurationExpirationTimeout = (unsigned int)(10000 * PpmIdleDurationExpirationTimeoutMs);`, `PpmInstallNewIdleStates` can also set `PpmIdleDurationExpirationTimeout`), causing the idle expiration to be off by exiting PoExecuteIdleCheck instantly (otherwise periodic checks would run, see `PoExecuteIdleCheck`)

All of this seems to depend on whenever either
```c
v4 = 0;
if ( (PpmBackgroundProfile || PpmEntryLevelPerfProfile || PpmMultimediaQosProfile || PpmPerfAlwaysComputeQosEnabled)
  && PpmPerfSchedulerDirectedPerfStatesSupported
  && KeQueryActiveProcessorCountEx(0) >= 2 )
{
  v4 = 1;
}
if ( PpmPerfVmQosSupported )
{
  v4 = 1;
  goto LABEL_13;
}
if ( v4 )
{
LABEL_13:
  v5 = 1;
  if ( !PpmPerfQosGroupPolicyDisable ) // if PowerThrottlingOff = 1, then v5 = 0
    goto LABEL_15;
}
v5 = 0; // forced 0 if v4 not true
LABEL_15:
```
or `PpmPerfVmQosSupported` (hypervisor present, HvlIsRootPowerSchedulerQosPresent) are true. If both aren't true, then v5 is already 0 means changing PowerThrottlingOff would have no impact?

On my system both aren't true means that changing the value has no impact as v5 can't be `1` (this is my current interpretation).

Note that this is based on [binary build version 22631 (23H2)](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/ntoskrnl/PopInitializeHeteroProcessors.c) and isn't complete. I might add more/get better structure into whenever I've time.

```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerThrottling";
    "PowerThrottlingOff" = 0; // PpmPerfQosGroupPolicyDisable 
```

# PnP Device Values

This currently applies the values for the `USB` enumerator only, since most values were found in USB related drivers and kind of all of them (which I use in the option) only get read in the USB enumerator.

Disables USB selective suspend, idle states, and related LP features if supported.

See win-registry repo for a list of `CCS\\Enum\\<enumerator>\\<deviceID>\\<instanceID>\\...` values/defaults/notes:
> https://github.com/nohuto/win-registry#pnp-device-values

## MSPower_DeviceEnable

Note that the known `MSPower_DeviceEnable` command does nothing more than recursively setting `IdleInWorkingState` & `SelectiveSuspendOn` to `0`.
```c
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\ROOT_HUB30\5&2c35141&0&0\Device Parameters\WDF\IdleInWorkingState	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\ROOT_HUB30\5&2bce96aa&0&0\Device Parameters\WDF\IdleInWorkingState	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\VID_046D&PID_0ABA&MI_03\7&41505d0&0&0003\Device Parameters\SelectiveSuspendOn	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\VID_05E3&PID_0610\6&3365fbaf&0&11\Device Parameters\WDF\IdleInWorkingState	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\VID_0B05&PID_1939&MI_02\7&40fe908&0&0002\Device Parameters\SelectiveSuspendOn	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\VID_046D&PID_C547&MI_00\7&1fc2034b&0&0000\Device Parameters\SelectiveSuspendOn	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\VID_046D&PID_C547&MI_01\7&1fc2034b&0&0001\Device Parameters\SelectiveSuspendOn	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\VID_046D&PID_C547&MI_02\7&1fc2034b&0&0002\Device Parameters\SelectiveSuspendOn	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\VID_1038&PID_161E&MI_00\7&a6e656e&0&0000\Device Parameters\SelectiveSuspendOn	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\VID_1038&PID_161E&MI_01\7&a6e656e&0&0001\Device Parameters\SelectiveSuspendOn	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\VID_1038&PID_161E&MI_02\7&a6e656e&0&0002\Device Parameters\SelectiveSuspendOn	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\VID_1038&PID_161E&MI_03\7&a6e656e&0&0003\Device Parameters\SelectiveSuspendOn	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\VID_1038&PID_161E&MI_04\7&a6e656e&0&0004\Device Parameters\SelectiveSuspendOn	Type: REG_DWORD, Length: 4, Data: 0
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Enum\USB\VID_0CF2&PID_A102&MI_01\8&7b0cf2a&0&0001\Device Parameters\SelectiveSuspendOn	Type: REG_DWORD, Length: 4, Data: 0
```

On my 25H2 VM it also switched `PnPCapabilities`:
```c
// MSPower_DeviceEnable enabled
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000\PnPCapabilities	Type: REG_DWORD, Length: 4, Data: 16

// MSPower_DeviceEnable disabled
wmiprvse.exe	RegSetValue	HKLM\System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000\PnPCapabilities	Type: REG_DWORD, Length: 4, Data: 24
```

## Storport Idle (`Device Parameters\\StorPort`)

"Storport provides support for idle power management to allow storage devices to enter a low power state when not in use. Storport's idle power management (IPM) support includes handling idle power management for storage devices under its management, in coordination with the Power Manager in Windows.

Storport IPM allows the classpnp and disk class drivers to send the SCSI Stop Unit command to the storage device when it's idle for some period of time. The idle period is configurable by the system administrator. The Storport miniport driver is responsible for how the command is used by the Storport miniport driver to conserve power.

Storport Idle Power Management (IPM) isn't enabled by default. It can be enabled in the registry by setting the "EnableIdlePowerManagement" value in the "StorPort" subkey of the device's hardware key to any nonzero value. To do so, use the device INF file or manually edit the registry using the registry editor."

> https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/registry-entries-for-storport-miniport-drivers  
> https://github.com/nohuto/windows-driver-docs/blob/staging/windows-driver-docs-pr/network/standardized-inf-keywords-for-power-management.md  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/ipm-configuration-and-usage  
> https://github.com/nohuto/win-registry/blob/main/records/pci.txt  
> [power/assets | storport.c](https://github.com/nohuto/win-config/blob/main/power/assets/storport.c)

# Disable Hibernation

Windows uses hibernation to provide a fast startup experience. When available, it's also used on mobile devices to extend the usable battery life of a system by giving a mechanism to save all of the user's state prior to shutting down the system. In a hibernate transition, all the contents of memory are written to a file on the primary system drive, the hibernation file. This preserves the state of the operating system, applications, and devices. In the case where the combined memory footprint consumes all of physical memory, the hibernation file must be large enough to ensure there's space to save all the contents of physical memory. Since data is written to non-volatile storage, DRAM does not need to maintain self-refresh and can be powered off, which means power consumption of hibernation is very low, almost the same as power off.

Windows Internals (E7-P1, Power manager): the system saves a full memory image to `Hiberfil.sys` for S4 and resumes execution from that image on the next boot. The hibernation file is invalidated after a resume to prevent multiple resume attempts from stale data.

During a full shutdown and boot (S5), the entire user session is torn down and restarted on the next boot. In contrast, during a hibernation (S4), the user session is closed and the user state is saved.

## Power State Table

| Power state | ACPI state | Description | 
|-------------|------------|-------------|
| Working | *S0* | The system is fully usable. Hardware components that aren't in use can save power by entering a lower power state. | 
| Sleep (Modern Standby) | *S0* low-power idle | Some SoC systems support a low-power idle state known as [Modern Standby](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/modern-standby). In this state, the system can very quickly switch from a low-power state to high-power state in response to hardware and network events. **Note:** SoC systems that support Modern Standby don't use *S1-S3*. | 
| Sleep | *S1*<br> *S2*<br> *S3* | The system appears to be off. The amount of power consumed in states *S1-S3* is less than *S0* and more than *S4*. *S3* consumes less power than *S2*, and *S2* consumes less power than *S1*. Systems typically support one of these three states, not all three.<br><br> In states *S1-S3*, volatile memory is kept refreshed to maintain the system state. Some components remain powered so the computer can wake from input from the keyboard, LAN, or a USB device.<br><br> *Hybrid sleep*, used on desktops, is where a system uses a hibernation file with *S1-S3*. The hibernation file saves the system state in case the system loses power while in sleep.<br><br> **Note:** SoC systems that support Modern Standby don't use *S1-S3*. | 
| Hibernate | *S4* | The system appears to be off. Power consumption is reduced to the lowest level. The system saves the contents of volatile memory to a hibernation file to preserve system state. Some components remain powered so the computer can wake from input from the keyboard, LAN, or a USB device. The working context can be restored if it's stored on nonvolatile media.<br><br> *Fast startup* is where the user is logged off before the hibernation file is created. This allows for a smaller hibernation file, more appropriate for systems with less storage capabilities. | 
| Soft off | *S5* | The system appears to be off. This state is comprised of a full shutdown and boot cycle. | 
| Mechanical off | *G3* | The system is completely off and consumes no power. The system returns to the working state only after a full reboot. | 

> https://learn.microsoft.com/en-us/windows/win32/power/system-power-states

## Registry Value Defaults

```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power";
    "AllowHibernate" = 4294967295; // PopAllowHibernateReg (0xFFFFFFFF) 
    "EnableMinimalHiberFile" = 0; // PopEnableMinimalHiberFile 
    "ForceMinimalHiberFile" = 0; // PopForceMinimalHiberFile 
    "HiberbootEnabled" = 0; // PopHiberbootEnabledReg 
    "HiberFileSizePercent" = 100; // PopHiberFileSizePercent dd 64h (IDA), but set to 0 by default on LTSC IoT Enterprise 2024 since hibernation is unsupported by default
    "HibernateBootOptimizationEnabled" = 0; // PopHiberBootOptimizationEnabledReg 
    "HibernateChecksummingEnabled" = 1; // PopHiberChecksummingEnabledReg 
    "HibernateEnabledDefault" = 1; // PopHiberEnabledDefaultReg 
    "PromoteHibernateToShutdown" = 0; // PopPromoteHibernateToShutdown 
    "SkipHibernateMemoryMapValidation" = 4294967295; // PopEnableHibernateMemoryMapValidationOverride (0xFFFFFFFF) 

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\ForceHibernateDisabled";
    "GuardedHost" = ?; // unk_140FC5234
    "Policy" = 0; // PopHiberForceDisabledReg 
```

`powercfg /hibernate off` sets:
```c
RegSetValue	HKLM\System\CurrentControlSet\Control\Power\HibernateEnabled	Type: REG_DWORD, Length: 4, Data: 0
```

> https://github.com/nohuto/win-registry#power-values  
> https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/disable-and-re-enable-hibernation  
> https://github.com/nohuto/win-registry/blob/main/records/Power.txt

# Reduced HiberFile

Hibernation files are used for hybrid sleep, fast startup, and [standard hibernation](https://learn.microsoft.com/en-us/windows/win32/power/system-power-states#hibernate-state-s4). There are two types, differentiated by size, a full and reduced size hibernation file. Only fast startup can use a reduced hibernation file.

```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power";
    "HiberFileSizePercent" = 100; // PopHiberFileSizePercent dd 64h (IDA), but set to 0 by default on LTSC IoT Enterprise 2024 since hibernation is unsupported by default

    // DWORD 1 = Reduced, DWORD 2 = Full
    "HiberFileType" = 4294967295; // PopHiberFileTypeReg (0xFFFFFFFF)
    "HiberFileTypeDefault" = 4294967295; // PopHiberFileTypeDefaultReg (0xFFFFFFFF)

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\HiberFileBucket";
    "Percent16GBFull" = ?; // unk_140FC36D0 - 28Hex/40Dec
    "Percent16GBReduced" = ?; // unk_140FC36CC - 14Hex/20Dec
    "Percent1GBFull" = ?; // unk_140FC3670 - 28Hex/40Dec
    "Percent1GBReduced" = ?; // unk_140FC366C - 14Hex/20Dec
    "Percent2GBFull" = ?; // unk_140FC3688 - 28Hex/40Dec
    "Percent2GBReduced" = ?; // unk_140FC3684 - 14Hex/20Dec
    "Percent32GBFull" = ?; // unk_140FC36E8 - 28Hex/40Dec
    "Percent32GBReduced" = ?; // unk_140FC36E4 - 14Hex/20Dec
    "Percent4GBFull" = ?; // unk_140FC36A0 - 28Hex/40Dec
    "Percent4GBReduced" = ?; // unk_140FC369C - 14Hex/20Dec
    "Percent8GBFull" = ?; // unk_140FC36B8 - 28Hex/40Dec
    "Percent8GBReduced" = ?; // unk_140FC36B4 - 14Hex/20Dec
    "PercentUnlimitedFull" = ?; // unk_140FC3700 - 28Hex/40Dec
    "PercentUnlimitedReduced" = ?; // unk_140FC36FC - 14Hex/20Dec
```

## PowerCFG Captures & Commands

`powercfg /h /size 0`:
```c
RegSetValue	HKLM\System\CurrentControlSet\Control\Power\HiberFileSizePercent	SUCCESS	Type: REG_DWORD, Length: 4, Data: 0
```
`powercfg /h /type full`:
```c
RegSetValue	HKLM\System\CurrentControlSet\Control\Power\HiberFileType	SUCCESS	Type: REG_DWORD, Length: 4, Data: 2
```
`powercfg /h /type reduced`:
```c
RegSetValue	HKLM\System\CurrentControlSet\Control\Power\HiberFileType	SUCCESS	Type: REG_DWORD, Length: 4, Data: 1
```

| Hibernation file type | Default size           | Supports                              |
|-----------------------|------------------------|---------------------------------------|
| Full                  | 40% of physical memory | hibernate, hybrid sleep, fast startup |
| Reduced               | 20% of physical memory | fast startup                          |

To verify or change the type of hibernation file used, run the *powercfg.exe* utility. The following examples demonstrate how.

| Example      |Description   |
|--------------|--------------|
| `powercfg /a`                      | **Verify the hibernation file type.** When a full hibernation file is used, the results state that hibernation is an available option. When a reduced hibernation file is used, the results say hibernation is not supported. If the system has no hibernation file at all, the results say hibernation hasn't been enabled. |
| `powercfg /h /type full`           | **Change the hibernation file type to full.** This isn't recommended on systems with less than 32GB of storage.                      |
| `powercfg /h /type reduced`        | **Change the hibernation file type to reduced.** If the command returns "the parameter is incorrect," see the following example.      |
| `powercfg /h /size 0`<br> `powercfg /h /type reduced`  | **Retry changing the hibernation file type to reduced.** If the hibernation file is set to a custom size greater than 40%, you must first set the size of the file to zero. Then retry the reduced configuration.     |

> https://github.com/nohuto/win-registry#power-values  
> https://learn.microsoft.com/en-us/windows/win32/power/system-power-states

# Remove Power Options

Removes the `Hibernate`, `Lock`, `Sleep` power options.

If hiding `Lock` for example via `Control Panel > All Control Panel Items > Power Options > Choose what the power buttons do > Change settings that are currently unavailable`, it sets:
```c
DllHost.exe	RegSetValue	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings\ShowLockOption	Type: REG_DWORD, Length: 4, Data: 1
```

## Windows Policies

LGPE would set the values in `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer`:
```json
{
  "File": "WindowsExplorer.admx",
  "CategoryName": "WindowsExplorer",
  "PolicyName": "ShowLockOption",
  "NameSpace": "Microsoft.Policies.WindowsExplorer",
  "Supported": "Windows8",
  "DisplayName": "Show lock in the user tile menu",
  "ExplainText": "Shows or hides lock from the user tile menu. If you enable this policy setting, the lock option will be shown in the User Tile menu. If you disable this policy setting, the lock option will never be shown in the User Tile menu. If you do not configure this policy setting, users will be able to choose whether they want lock to show through the Power Options Control Panel.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\Explorer"
  ],
  "ValueName": "ShowLockOption",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsExplorer.admx",
  "CategoryName": "WindowsExplorer",
  "PolicyName": "ShowSleepOption",
  "NameSpace": "Microsoft.Policies.WindowsExplorer",
  "Supported": "Windows8",
  "DisplayName": "Show sleep in the power options menu",
  "ExplainText": "Shows or hides sleep from the power options menu. If you enable this policy setting, the sleep option will be shown in the Power Options menu (as long as it is supported by the machine's hardware). If you disable this policy setting, the sleep option will never be shown in the Power Options menu. If you do not configure this policy setting, users will be able to choose whether they want sleep to show through the Power Options Control Panel.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\Explorer"
  ],
  "ValueName": "ShowSleepOption",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "WindowsExplorer.admx",
  "CategoryName": "WindowsExplorer",
  "PolicyName": "ShowHibernateOption",
  "NameSpace": "Microsoft.Policies.WindowsExplorer",
  "Supported": "Windows8",
  "DisplayName": "Show hibernate in the power options menu",
  "ExplainText": "Shows or hides hibernate from the power options menu. If you enable this policy setting, the hibernate option will be shown in the Power Options menu (as long as it is supported by the machine's hardware). If you disable this policy setting, the hibernate option will never be shown in the Power Options menu. If you do not configure this policy setting, users will be able to choose whether they want hibernate to show through the Power Options Control Panel.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\Explorer"
  ],
  "ValueName": "ShowHibernateOption",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```

---

Miscellaneous keys:
```powershell
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HidePowerButton
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HideRestart
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HideShutDown
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HideSignOut
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HideSwitchAccount
```

# Disable Hiberboot

Fast startup is a type of shutdown that uses a hibernation file to speed up the subsequent boot. During this type of shutdown, the user is logged off before the hibernation file is created. Fast startup allows for a smaller hibernation file, more appropriate for systems with less storage capabilities.

Windows Internals (E7-P2, Hybrid shutdown): Fast Startup is implemented as a hybrid shutdown that writes a hibernation image after user sessions are closed; Boot Manager uses the hiberboot/hiberfile BCD elements to resume from that image on the next boot.

When using fast startup, the system appears to the user as though a full shutdown (S5) has occurred, even though the system has actually gone through S4. This includes how the system responds to device wake alarms.

Fast startup logs off user sessions, but the contents of kernel (session 0) are written to hard disk. This enables faster boot.

To programmatically initiate a fast startup-style shutdown, call the [InitiateShutdown](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-initiateshutdowna) function with the `SHUTDOWN_HYBRID` flag or the [ExitWindowsEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-exitwindowsex) function with the `EWX_HYBRID_SHUTDOWN` flag.

In Windows, fast startup is the default transition when a system shutdown is requested. A full shutdown (S5) occurs when a system restart is requested or when an application calls a shutdown API.

## Registry Values Defaults

All three values exist as shown below. `PopReadHiberbootGroupPolicy` (`\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\System`) overrides `PopReadHiberbootPolicy` (`Control\\Session Manager\\Power`).

> https://github.com/nohuto/win-registry#power-values

```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power";
    "HiberbootEnabled" = 0; // PopHiberbootEnabledReg 
    "DisableIdleStatesAtBoot" = 0; // PpmIdleDisableStatesAtBoot 
    "HibernateBootOptimizationEnabled" = 0; // PopHiberBootOptimizationEnabledReg 

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power";
    "HiberbootEnabled" = 0; // REG_DWORD, range: 0-1

    // HybridBootAnimationTime records the boot animation duration during fast boot, HiberIoCpuTime is CPU time spent on hibernation I/O during resume, ResumeCompleteTimestamp is the system timestamp when resume from hibernation completed. So all of them are just counters and chaning their data won't affect the boot.
    "HybridBootAnimationTime" = 1601; // REG_DWORD, milliseconds, range: 0-0xFFFFFFFF
    "HiberIoCpuTime" = 0; // REG_DWORD, milliseconds, range: 0-0xFFFFFFFF
    "ResumeCompleteTimestamp" = 0; // REG_QWORD, range: 0-0xFFFFFFFFFFFFFFFF
```
> https://github.com/nohuto/win-registry?tab=readme-ov-file#power-values  
> https://github.com/marcosd4h/memhunter/blob/f68bca7efe31f49c0dc9ad988fb17bec443a1ca7/libs/boost/interprocess/detail/win32_api.hpp#L2373

```c
// PopOpenPowerKey
{
  return PopOpenKey(a1, L"Control\\Session Manager\\Power");
}

// PopReadHiberbootPolicy
result = PopOpenPowerKey(&KeyHandle);
if ( result >= 0 )
{
  RtlInitUnicodeString(&DestinationString, L"HiberbootEnabled");
  if ( ZwQueryValueKey(
         KeyHandle,
         &DestinationString,
         KeyValuePartialInformation,
         &KeyValueInformation,
         0x14u,
         &ResultLength) >= 0 )
    v1 = BYTE12(KeyValueInformation);
  result = ZwClose(KeyHandle);
}
```

> [power/assets | hiberboot-PopReadHiberbootGroupPolicy.c](https://github.com/nohuto/win-config/blob/main/power/assets/hiberboot-PopReadHiberbootGroupPolicy.c)

## DisableIdleStatesAtBoot Notes

Notes on `Disable Idle States At Boot` SUBOPTION (`DisableIdleStatesAtBoot`):

The data `-1` (`PpmIdleDisableStatesAtBoot dd 0FFFFFFFFh`) gets handled as `0`
```cpp
if ( PpmIdleDisableStatesAtBoot == -1 )
  PpmIdleDisableStatesAtBoot = 0;
```
`0` = skips all PpmInstall*IdleStates disable writes
`1` = would write disable in `PpmInstallCoordinatedIdleStates`/`PpmInstallPlatformIdleStates`
```cpp
if ( PpmIdleDisableStatesAtBoot )
  *(_DWORD *)(v20 + 80) = 0x80000000;
```
`2` = would do the same as `1` including disable write in `PpmInstallNewIdleStates`
```cpp
if ( v20 && PpmIdleDisableStatesAtBoot == 2 )
  *(_DWORD *)(v23 + 32) = 0x80000000;
```

## Windows Policies

```json
{
  "File": "WinInit.admx",
  "CategoryName": "ShutdownOptions",
  "PolicyName": "Hiberboot",
  "NameSpace": "Microsoft.Policies.WindowsInitialization",
  "Supported": "Windows8",
  "DisplayName": "Require use of fast startup",
  "ExplainText": "This policy setting controls the use of fast startup. If you enable this policy setting, the system requires hibernate to be enabled. If you disable or do not configure this policy setting, the local setting is used.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\System"
  ],
  "ValueName": "HiberbootEnabled",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```

# Disable Energy Estimation

Not needed, if you disable energy estimation:
```json
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\EnergyEstimation\\TaggedEnergy": {
  "DisableTaggedEnergyLogging": { "Type": "REG_DWORD", "Data": 1 },
  "TelemetryMaxApplication": { "Type": "REG_DWORD", "Data": 0 },
  "TelemetryMaxTagPerApplication": { "Type": "REG_DWORD", "Data": 0 }
}
```
```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power";
    "UserBatteryDischargeEstimator" = 0; // PopDisableBatteryDischargeEstimator 
    "UserBatteryChargeEstimator" = 0; // PopUserBatteryChargingEstimator 
    "EnergyEstimationEnabled" = 1; // PopEnergyEstimationEnabled
                                    // If following HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\knobs\Power/Controls/EnergyEstimationEnabled, it should have a range of 0-4294967295
```

> https://github.com/nohuto/win-registry#power-values  
> [power/assets | energyesti-PtInitializeTelemetry.c](https://github.com/nohuto/win-config/blob/main/power/assets/energyesti-PtInitializeTelemetry.c)

![](https://github.com/nohuto/win-config/blob/main/power/images/energyesti.png?raw=true)

## Suboption

`Disable Battery Capacity Section` = Disables the battery capacity section on the battery saver page of the system settings app.

# Disable Timer Coalescing

"CoalesecingTimerinterval is a computer system energy-saving technique that reduces CPU power consumption by reducing the precision of software timers to allow the synchronization of process wake-ups, minimizing the number of times the CPU is forced to perform the relatively power-costly operation of entering and exiting idle states"

## TimerCoalescing Data

`TimerCoalescing` is a binary value (`v18 == 3`) with a size of 80 bytes (`v19 == 80`).

```c
"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\TimerCoalescing","Length: 96" // 0x60u
```

```c
if (v18 == 3 && v19 == 80 && !v20[0]) // type REG_BINARY, length 80 bytes, leading dword zero
{
  for (i = 0; i < 3; ++i)
    if (v20[i + 1]) return ZwClose(KeyHandle); // v20[1..3] must be zero

  for (j = 0; j < 4; ++j)
    if (v20[j + 8]) return ZwClose(KeyHandle); // v20[8..11] must be zero

  for (k = 0; k < 4; ++k)
    if (v20[k + 16]) return ZwClose(KeyHandle); // v20[16..19] must be zero

  for (m = 0; (unsigned int)m < 4; ++m)
    if (v20[m + 4] > 0x7FFFFFF5) return ZwClose(KeyHandle); // clamp tolerance index 0 entries

  while (v0 < 4)
  {
    if (v20[v0 + 12] > 0x7FFFFFF5) return ZwClose(KeyHandle); // clamp tolerance index 3 entries
    ++v0;
  }
}
```

As the pseudocode shows eight values have data, all other ones are forced to `0` (four dwords of zeros, four dwords for tolerance index 0, four more zeros, four dwords for tolerance index 3, and zeros).

```json
"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows": {
  "TimerCoalescing": { "Type": "REG_BINARY", "Data": "00000000000000000000000000000000F5FFFF7FF5FFFF7FF5FFFF7FF5FFFF7F00000000000000000000000000000000F5FFFF7FF5FFFF7FF5FFFF7FF5FFFF7F00000000000000000000000000000000" }
}
```
Using the highest clamp as shown above will end up with a BSoD (same goes for `0x7FFFFFF4`/`0` and probably any other data).

## Miscellaneous Values

```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power";
    "CoalescingTimerInterval" = 1500; // PopCoalescingTimerInterval (0x000005DC) - Units: seconds (multiplies value by -10,000,000, one second in 100 ns units, so the default corresponds to a 25min cadence)
    "DeepIoCoalescingEnabled" = 0; // PopDeepIoCoalescingEnabled 
```
> https://github.com/nohuto/win-registry?tab=readme-ov-file#power-values

```c
void InitTimerPowerSaving(void)
{
  UserSessionState = W32GetUserSessionState();
  FastGetProfileDword(0LL, 2LL, L"RITdemonTimerPowerSaveElapse", 43200000LL, UserSessionState + 62692); // 12H?
  v1 = W32GetUserSessionState();
  FastGetProfileDword(0LL, 2LL, L"RITdemonTimerPowerSaveCoalescing", 43200000LL, v1 + 62696); // 12H?
}
```

The `CoalescingTimerInterval` value exist (takes a default of `1500` dec, `DeepIoCoalescingEnabled` one is set to `0` by default - both are located in `ntoskrnl.exe`), but doesn't get read on 24H2, the `RITdemonTimerPowerSave...` & `TimerCoalescing` ones get read.

> [power/assets | coalesc-InitTimerCoalescing.c](https://github.com/nohuto/win-config/blob/main/power/assets/coalesc-InitTimerCoalescing.c)  
> https://github.com/nohuto/win-registry/blob/main/records/Winows-NT.txt

![](https://github.com/nohuto/win-config/blob/main/power/images/coalesc.png?raw=true)

# Disable Audio Idle

| Parameter              | Desc                                                                                    | Default  | Notes                                                                 |
| ---------------------- | --------------------------------------------------------------------------------------- | -------- | --------------------------------------------------------------------- |
| `ConservationIdleTime` | Idle timeout for the device, when the system is on battery power.                       | `0`      | `0` disables the inactivity timer for this mode, value is in seconds. |
| `PerformanceIdleTime`  | Idle timeout for the device, when the system is on AC power.                            | `0`      | `0` disables the inactivity timer for this mode, value is in seconds. |
| `IdlePowerState`       | Specifies the power state that the device will enter, when power is no longer needed.   | `3` (D3) | Valid values `1 - D1`, `2 - D2`, `3 - D3`.                            |

I currently disable it, by setting the timeouts to `ff ff ff ff` (`~4.29e9 s ≈ 136 years`) & `IdlePowerState` to `1` (`D1`).

| Parameter              | Type           | Revert Hex data     | Parsed value                      | Meaning                       |
| ---------------------- | -------------- | ------------------- | --------------------------------- | ----------------------------- |
| `ConservationIdleTime` | REG_BINARY (3) | `1e,00,00,0`        | malformed; if `1e,00,00,00` -> 30s | `10s` on battery              |
| `PerformanceIdleTime`  | REG_BINARY (3) | `00,00,00,00`       | 0 seconds                         | No idle mgmt on AC            |
| `IdlePowerState`       | REG_BINARY (3) | `03,00,00,00`       | 3                                 | Go to `D3` when idle          |

| Category   | Class | Class GUID                           | Description                                                                                       |
| ---------- | ----- | ------------------------------------ | ------------------------------------------------------------------------------------------------- |
| Multimedia | Media | 4d36e96c-e325-11ce-bfc1-08002be10318 | Includes Audio and DVD multimedia devices, joystick ports, and full-motion video capture devices. |

> https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/audio-device-class-inactivity-timer-implementation  
> https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/audio-subsystem-power-management-for-modern-standby-platforms  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/portcls-registry-power-settings  

# Disable Storage Idle States

Disables idle states for NVMe, SSD, SD, HDD. This is currently more of a possible idea. 

If `IdleStatesNumber` is set, the other values are ignored? Let me know if you have a better interpretation.

> The values are located in the `EnergyEstimation` (guesses how much power is used over time), so it's probably related to something else. I'll leave it for documentation reasons (and future extended declaration).

> https://github.com/nohuto/win-registry/blob/main/records/Power.txt  
> [power/assets | storageidle-PmPowerContextInitialization.c](https://github.com/nohuto/win-config/blob/main/power/assets/nvmeperf-ClassUpdateDynamicRegistrySettings.c)

## Suboption

### Disable HDD Parking

`EnableHDDParking` is set to `1` by default, `EnableDIPM`/`EnableHIPM` are set to `0` by default. I haven't looked further into it and therefore can't say if changing `EnableHDDParking` has any affect at all, since it seems to not be read. I might add more details soon.

HIPM (Host Initiated Link Power Management)/DIPM (Device Initiated Link Power Management) are controlled via the [AHCI Link Power Management - HIPM/DIPM](https://github.com/nohuto/win-config/blob/main/power/assets/power-settings/disk-settings-link-power-management-mode---hipm-dipm.md) (power plan), I haven't checked whenever these values interfer with it or not.

```powershell
Power Setting GUID: 0b2d69d7-a2a1-449c-9680-f91c70521c60  (AHCI Link Power Management - HIPM/DIPM)
  Possible Setting Index: 000
  Possible Setting Friendly Name: Active - Neither Host or Device initiated allowed
  Possible Setting Index: 001
  Possible Setting Friendly Name: HIPM - Host initiated allowed only
  Possible Setting Index: 002
  Possible Setting Friendly Name: HIPM+DIPM - Both Host and Device initiated allowed
  Possible Setting Index: 003
  Possible Setting Friendly Name: DIPM - Device initiated allowed only
  Possible Setting Index: 004
  Possible Setting Friendly Name: Lowest - HIPM+DIPM+DEVSLP
```

```c
Dst[37] = L"EnableHIPM";
LODWORD(Dst[11]) = 4;
Dst[38] = &dword_4C134;
Dst[40] = &dword_4C134;
Dst[44] = L"EnableDIPM";
LODWORD(Dst[13]) = 4;
Dst[45] = &dword_5D0C8;
Dst[47] = &dword_5D0C8;
Dst[58] = L"EnableHDDParking";
LODWORD(Dst[18]) = 4;
Dst[59] = &dword_4C13C;
Dst[61] = &dword_4C13C;

dword_5D0CC = 0;
dword_5D0C8 = 0;
dword_4C434 = 0;
dword_4C12C = -1;
dword_4C138 = -1;
dword_4C134 = -1;
dword_4C424 = 16;
dword_4C420 = 3000;
dword_5D510 = 1;
dword_4C13C = 1;
dword_4C130 = 1;
dword_4C140 = -1;
```

> [power/assets | hddpark-amdsbs.c](https://github.com/nohuto/win-config/blob/main/power/assets/hddpark-amdsbs.c)  
> [power/assets | hddpark-DllInitialize.c](https://github.com/nohuto/win-config/blob/main/power/assets/hddpark-DllInitialize.c)  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/device-power-states  
> https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/disk-settings-link-power-management-mode---hipm-dipm

# Disable PM in Standby Mode

This policy setting specifies that power management is disabled when the machine enters connected standby mode.
- If this policy setting is enabled, Windows Connection Manager doesn't manage adapter radios to reduce power consumption when the machine enters connected standby mode.
- If this policy setting isn't configured or is disabled, power management is enabled when the machine enters connected standby mode.

## Suboption

`Disable Modern Standby`:
```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power"; 
    "MSDisabled" = 1; // PopModernStandbyDisabled

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\ModernSleep";
    "EnabledActions" = 0; // PopAggressiveStandbyActionsRegValue 
    "EnableDsNetRefresh" = 0; // PopEnableDsNetRefresh 
```
> https://github.com/nohuto/win-registry?tab=readme-ov-file#power-values

## Windows Policies

```json
{
  "File": "WCM.admx",
  "CategoryName": "WCM_Category",
  "PolicyName": "WCM_DisablePowerManagement",
  "NameSpace": "Microsoft.Policies.WindowsConnectionManager",
  "Supported": "Windows8",
  "DisplayName": "Disable power management in connected standby mode",
  "ExplainText": "This policy setting specifies that power management is disabled when the machine enters connected standby mode. If this policy setting is enabled, Windows Connection Manager does not manage adapter radios to reduce power consumption when the machine enters connected standby mode. If this policy setting is not configured or is disabled, power management is enabled when the machine enters connected standby mode.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy"
  ],
  "ValueName": "fDisablePowerManagement",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
```
```powershell
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\GroupPolicy : fAllowFailoverToCellular
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\GroupPolicy : fBlockNonDomain
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\GroupPolicy : fBlockRoaming
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\GroupPolicy : fDisablePowerManagement
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\GroupPolicy : fMinimizeConnections
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\GroupPolicy : fSoftDisconnectConnections
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\Local : fAllowFailoverToCellular
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\Local : fBlockNonDomain
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\Local : fBlockRoaming
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\Local : fDisablePowerManagement
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\Local : fMinimizeConnections
\Registry\Machine\SOFTWARE\Policies\Microsoft\WINDOWS\Wcmsvc\Local : fSoftDisconnectConnections
```

# Disable NIC Power Savings

You can get a lot of information about data ranges and more from `.inf` files, see examples below.

> https://github.com/nohuto/win-registry/blob/main/records/NIC-Intel.txt  
> https://github.com/nohuto/windows-driver-docs/blob/staging/windows-driver-docs-pr/network/standardized-inf-keywords-for-power-management.md  
> https://github.com/nohuto/windows-driver-docs/blob/staging/windows-driver-docs-pr/network/standardized-inf-keywords-for-ndis-selective-suspend.md

## Registry Value Overview

Everything listed below is based on personal research. Mistakes may exist, but I don't think I've made any.

```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\00XX";
    "*DeviceSleepOnDisconnect" = 0; // range 0-1
    "*EnableDynamicPowerGating" = 1; // range 0-1
    "CheckForHangTime" = 2; // range 0-60
    "DisableIntelRST" = 1; // range 0-1
    "DisableReset" = 0; // range 0-1
    "DMACoalescing" = 0; // range 0-10240
    "EnableAdaptiveQueuing" = 1; // range 0-1
    "EnableDisconnectedStandby" = 0; // range 0-1
    "EnableHWAutonomous" = 0; // range 0-1
    "EnableModernStandby" = 0; // range 0-1
    "EnablePME" = 0; // range 0-1
    "EnablePowerManagement" = 1; // range 0-1
    "ForceHostExitUlp" = 0; // range 0-1
    "ForceLtrValue" = 65535; // range 0-65535
    "I218DisablePLLShut" = 0; // range 0-1
    "I218DisablePLLShutGiga" = 0; // range 0-1
    "I219DisableK1Off" = 0; // range 0-1
    "RegForceRxPathSerialization" = 0; // range 0-1
    "SidebandUngateOverride" = 0; // range 0-1
    "ULPMode" = 1; // range 0-1
```

> https://github.com/nohuto/win-registry#intel-nic-values

| SubkeyName | ParamDesc | Default | Minimum | Maximum |
| --- | --- | --- | --- | --- |
| `*WakeOnPattern` | A value that describes whether the device should be enabled to wake the computer when a network packet matches a specified pattern. | 1 | 0 | 1 |
| `*WakeOnMagicPacket` | A value that describes whether the device should be enabled to wake the computer when the device receives a magic packet. A magic packet is a packet that contains 16 contiguous copies of the receiving network adapter's ethernet address. | 1 | 0 | 1 |
| `*EEE` | A value that describes whether the device should enable IEEE 802.3az energy-efficient ethernet. | 1 | 0 | 1 |
| `*IdleRestriction` | If a network device has both idle power down and wake on packet filter capabilities, this setting allows the user to decide when the device idle power down can happen. `1` = Only idle when user isn't present, `0` = No restriction | 0 | 0 | 1 |
| `*ModernStandbyWoLMagicPacket` | A value that describes whether the device should be enabled to wake the computer when the device receives a magic packet and the system is in the S0ix power state. This doesn't apply when the system is in the S4 power state. | 0 | 0 | 1 |
| `*DeviceSleepOnDisconnect` | A value that describes whether the device should be enabled to put the device into a low-power state (sleep state) when media is disconnected and return to a full-power state (wake state) when media is connected again. | 1 | 0 | 1 |
| `*SelectiveSuspend` | Selective suspend (0 disabled, 1 enabled) | 1 | 0 | 1 |
| `*SSIdleTimeout` | This keyword specifies the idle time-out period in units of seconds. If NDIS does not detect any activity on the network adapter for a period that exceeds the *SSIdleTimeout value, NDIS starts a selective suspend operation by calling the miniport driver's MiniportIdleNotification handler function. | 5 | 1 | 60 |
| `*SSIdleTimeoutScreenOff` | This keyword specifies the idle time-out period in units of seconds and is only applicable when the screen is off. If NDIS does not detect any activity on the network adapter for a period that exceeds the *SSIdleTimeoutScreenOff value after the screen is off, NDIS starts a selective suspend operation by calling the miniport driver's MiniportIdleNotification handler function. | 3 | 1 | 60 |

For more detail on each value, see GitHub links above.

> https://github.com/nohuto/win-registry#intel-nic-values

### Setup Information

```inf
HKR,Ndi\Params\*DeviceSleepOnDisconnect,ParamDesc,    ,%DeviceSleepOnDisconnectDesc%
HKR,Ndi\Params\*DeviceSleepOnDisconnect,type,         ,enum
HKR,Ndi\Params\*DeviceSleepOnDisconnect,default,      ,0
HKR,Ndi\Params\*DeviceSleepOnDisconnect\enum,0,       ,%Disabled%
HKR,Ndi\Params\*DeviceSleepOnDisconnect\enum,1,       ,%Enabled%

HKR, Ndi\Params\*EEE,    	                ParamDesc,      0,       %EEE%
HKR, Ndi\Params\*EEE,    	                Type,           0,       "enum"
HKR, Ndi\Params\*EEE\enum, 	                "1",            0,       %Enabled%
HKR, Ndi\Params\*EEE\enum, 	                "0",            0,       %Disabled%
HKR, Ndi\Params\*EEE,    	                Default,        0,       "0"

HKR,Ndi\params\*SelectiveSuspend,	    ParamDesc,  0, %SelectiveSuspend%
HKR,Ndi\params\*SelectiveSuspend,	    default,    0, "1"
HKR,Ndi\params\*SelectiveSuspend,	    type,       0, "enum"
HKR,Ndi\params\*SelectiveSuspend\enum,   "0",        0, "Disabled"
HKR,Ndi\params\*SelectiveSuspend\enum,   "1",        0, "Enabled"

HKR,Ndi\Params\*SSIdleTimeout,      ParamDesc,  0, "SSIdleTimeout"
HKR,Ndi\Params\*SSIdleTimeout,      Type,       0, "int"
HKR,Ndi\Params\*SSIdleTimeout,      Default,    0, "60"
HKR,Ndi\Params\*SSIdleTimeout,      Min,        0, "1" ; might also be at 5
HKR,Ndi\Params\*SSIdleTimeout,      Max,        0, "60"
HKR,Ndi\Params\*SSIdleTimeout,      Step,       0, "1"
HKR,Ndi\Params\*SSIdleTimeout,      Base,       0, "10"

HKR, Ndi\params\AdvancedEEE,        ParamDesc,  0, %AdvancedEEE%
HKR, Ndi\params\AdvancedEEE,        optional,   0, "1"
HKR, Ndi\params\AdvancedEEE,        Type,       0, "enum"
HKR, Ndi\params\AdvancedEEE,        Default,    0, "0"
HKR, Ndi\params\AdvancedEEE\enum,   "0",        0, %Disabled%
HKR, Ndi\params\AdvancedEEE\enum,   "1",        0, %Enabled%

[DisableAutoPowerSave.reg]
HKR,,				       AutoPowerSaveModeEnabled, 0, "0"

HKR, Ndi\params\EnableGreenEthernet,        ParamDesc,  0, %GreenEthernet%
;HKR, Ndi\params\EnableGreenEthernet,        optional,   0, "1"
HKR, Ndi\params\EnableGreenEthernet,        Type,       0, "enum"
HKR, Ndi\params\EnableGreenEthernet,        Default,    0, "0"
HKR, Ndi\params\EnableGreenEthernet\enum,   "0",        0, %Disabled%
HKR, Ndi\params\EnableGreenEthernet\enum,   "1",        0, %Enabled%

HKR, Ndi\params\GigaLite,        ParamDesc,  0, %GigaLite%
;HKR, Ndi\params\GigaLite,        optional,   0, "1"
HKR, Ndi\params\GigaLite,        Type,       0, "enum"
HKR, Ndi\params\GigaLite,        Default,    0, "1"
HKR, Ndi\params\GigaLite\enum,   "0",        0, %Disabled%
HKR, Ndi\params\GigaLite\enum,   "1",        0, %Enabled%

HKR,Ndi\params\*IdleRestriction,        ParamDesc,  0, %IdleRestriction%
HKR,Ndi\params\*IdleRestriction,        Type,       0, "enum"
HKR,Ndi\params\*IdleRestriction,        Default,    0, "0"
HKR,Ndi\params\*IdleRestriction\enum,   "0",        0, %RestrictionDisable%
HKR,Ndi\params\*IdleRestriction\enum,   "1",        0, %RestrictionEnable%

HKR,Ndi\params\PowerSavingMode,    ParamDesc,  0, %PowerSavingMode%
HKR,Ndi\params\PowerSavingMode,    Type,       0, "enum"
HKR,Ndi\params\PowerSavingMode,    Default,    0, "1"
HKR,Ndi\params\PowerSavingMode\enum,   "0",    0, %Disabled%
HKR,Ndi\params\PowerSavingMode\enum,   "1",    0, %Enabled%

HKR,Ndi\Params\ReduceSpeedOnPowerDown,                  ParamDesc,              0, %ReduceSpeedOnPowerDown%
HKR,Ndi\Params\ReduceSpeedOnPowerDown,                  Type,                   0, "enum"
HKR,Ndi\Params\ReduceSpeedOnPowerDown,                  Default,                0, "1"
HKR,Ndi\Params\ReduceSpeedOnPowerDown\Enum,             "1",                    0, %Enabled%
HKR,Ndi\Params\ReduceSpeedOnPowerDown\Enum,             "0",                    0, %Disabled%

HKR,Ndi\Params\ULPMode,                                 Type,                   0, "enum"
HKR,Ndi\Params\ULPMode,                                 Default,                0, "1"
HKR,Ndi\Params\ULPMode\Enum,                            "1",                    0, %Enabled%
HKR,Ndi\Params\ULPMode\Enum,                            "0",                    0, %Disabled%

; Allow host driver to force exit ULP on ME systems
HKR,,                                                   ForceHostExitUlp,       0, "1"

HKR,Ndi\params\WolShutdownLinkSpeed,           ParamDesc,       0, %WolShutdownLinkSpeed%
;HKR,Ndi\params\WolShutdownLinkSpeed,          optional,        0, "1"
HKR,Ndi\params\WolShutdownLinkSpeed,           Type,            0, "enum"
HKR,Ndi\params\WolShutdownLinkSpeed,           Default,         0, "0"
HKR,Ndi\params\WolShutdownLinkSpeed\enum,      "0",             0, %10MbFirst%
HKR,Ndi\params\WolShutdownLinkSpeed\enum,      "1",             0, %100MbFirst%
HKR,Ndi\params\WolShutdownLinkSpeed\enum,      "2",             0, %NotSpeedDown%
```

Reminder: Each adapter uses it's own default values, means that the `default`/`min`/`max` may be different for you. E.g. `SSIdleTimeout` minimum value was `1` in the first setup information file (`.inf`), but `5` in the second.

### Miscellaneous Values

```c
"DynamicLTR": { "Type": "REG_SZ", "Data": 0 },
"EnableAdvancedDynamicITR": { "Type": "REG_SZ", "Data": 0 },
"S3S4WolPowerSaving": { "Type": "REG_SZ", "Data": 0 },
"AutoLinkDownPcieMacOff": { "Type": "REG_SZ", "Data": 0 }, // "Auto Disable PCIe"
"BatteryModeLinkSpeed": { "Type": "REG_SZ", "Data": 2 },  // Similar to WolShutdownLinkSpeed?
// 10MbFirst                      = "10 Mbps First"
// 100MbFirst                     = "100 Mbps First"
// NotSpeedDown                   = "Not Speed Down"
// AdaptiveLinkSpeed              = "Adaptive Link Speed"
// BatteryModeLinkSpeed           = "Battery Mode Link Speed"
"CLKREQ": { "Type": "REG_SZ", "Data": 0 },
"EnableCoalesce": { "Type": "REG_SZ", "Data": 0 },
"DMACoalescing": { "Type": "REG_SZ", "Data": 0 },
"CoalesceBufferSize": { "Type": "REG_SZ", "Data": 0 },
"*PacketCoalescing": { "Type": "REG_SZ", "Data": 0 },

"SVOFFMode": { "Type": "REG_SZ", "Data": 1 },  // SV: Save?
"SVOFFModeHWM": { "Type": "REG_SZ", "Data": 0 },
"SVOFFModeTimer": { "Type": "REG_SZ", "Data": 0 }

"EnabledDatapathCycleCounters":  { "Type": "REG_SZ", "Data": ? }
"EnabledDatapathEventCounters": { "Type": "REG_SZ", "Data": ? }
```

# Disable Audio Execution Power Requests

There's no official documentation on this value, but it probably controls whether audio activity can trigger power execution requests, reducing the responsiveness of the system to power management events, maybe ending up with less efficient power usage or preventing certain power related actions from being triggered.

```c
// Allowed by default
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power";
    "AllowAudioToEnableExecutionRequiredPowerRequests" = 1; // PopPowerRequestActiveAudioEnablesExecutionRequired 
```

> https://github.com/nohuto/win-registry#power-values

```c
bool PopPowerRequestEvaluateExecutionRequiredStatus()
{
  char v0; // r8

  v0 = 0;
  if ( PopExecutionRequiredTimeout )
    return !byte_140F0D173
        || PopPowerRequestActiveAudioEnablesExecutionRequired && byte_140F0D172
        || byte_140F0D171
        || MEMORY[0xFFFFF78000000008] - qword_140F0D178 < 10000000
                                                        * (unsigned __int64)(unsigned int)PopExecutionRequiredTimeout;
  return v0;
}
```
