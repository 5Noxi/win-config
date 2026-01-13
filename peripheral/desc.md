# USBFlags Values

Value names in `usbflags-HUBREG_QueryUsbflagsValuesForDevice.c` are mostly UNICODE_STRING globals, the names below are resolved from `dq offset ... ; "Name"`. The usbflags device key base path is `HKLM\SYSTEM\CurrentControlSet\Control\usbflags` (from `LRegistryMachineSystemCurrentControlSetControlusbflags` in `HUBREG_OpenCreateUsbflagsDeviceKey`). For entries described as "any nonzero", the code treats the DWORD as a boolean, means any nonzero value is equivalent to `1`. Default data is unknown for most values as the driver code only reads the registry and handles fallbacks, note that this is currently based on USBHUB3.sys only, means it's not complete (USBXHCI.sys was used for DisableHCS0Idle & TestRunEsmInWorkItem, Ucx01000.sys for Allow64KLowOrFullSpeedControlTransfers).

`HUBDSM_QueryingRegistryValuesForDevice` -> `HUBMISC_QueryAndCacheRegistryValuesForDevice` -> `HUBREG_QueryUsbflagsValuesForDevice`

```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\usbflags";
    "IgnoreHWSerNum<vvvvpppp>" = ?; // REG_DWORD, dynamic name, seems to use vvvvpppp (vendor, product) see documentation below
    "Allow64KLowOrFullSpeedControlTransfers"; ? = // REG_DWORD (bool), if 1 sets g_Allow64KLowOrFullSpeedControlTransfersFlag true, other values leave it false, missing/read failure leaves the global unchanged - "When enabled, low/full-speed control endpoints use 64KB max transfer size, otherwise table defaults apply. Query failures are non-fatal."
    "DisableHCS0Idle" = 0; // REG_DWORD (bool), any nonzero disables S0 idle, missing/read failure treated as 0 - probably means "Disable Host Controller S0 Idle" (S = System)
    "GenericCompositeUSBDeviceString" = // haven't looked into it yet
    "SetMultiTTBitDuringConfigureEndpoint" = ? // REG_DWORD, if 1 sets flag 0x2000000000000000 at a1+336? if 0 clears it, missing/read failure leaves flags unchanged
    "TestRunEsmInWorkItem" = 0; // REG_DWORD, if 1 sets bit 0 at a1+876? if 0 clears it, missing/read failure leaves bit cleared

// these are built by HUBREG_OpenCreateUsbflagsDeviceKey
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\usbflags\\<vvvvpppprrrr>";
    "IgnoreHWSerNum" = ?; // REG_DWORD, any nonzero value sets flag 0x1
    "UseWin8DescriptorValidation" = ?; // REG_DWORD, any nonzero value sets flag 0x200000
    "ResetOnResume" = ?; // REG_DWORD, any nonzero value sets flag 0x4
    "DisableOnSoftRemove" = ?; // REG_DWORD, if zero clears flag 0x8, any nonzero leaves it set, many inf files set it to 1 so I guess that the default is 1
    "RequestConfigDescOnReset" = ?; // REG_DWORD, any nonzero value sets flag 0x10. When set, device hack flag causes config descriptor request after reset
    "DisableRecoveryFromPowerDrain" = ?; // REG_DWORD, any nonzero value sets flag 0x800000
    "SkipContainerIdQuery" = ?; // REG_BINARY, any nonzero value sets flag 0x20 (1 means skip container ID query)
    "DisableLPM" = ?; // REG_DWORD (bool), any nonzero value sets flag 0x80 - When set, disables low power link states for the device = the driver skips enabling U2 and forces U1/U2 timeouts to 0 so link power management stays off. Also disabled when a parent hub indicates LPM should be off for all downstream devices. (this is how I understood it while reading through the W10 source code)
                      // "A link enters a low power state (consuming less power than the working state) only when the downstream device enters the suspended state through the selective suspend mechanism", "After remaining idle for a certain period of time, link partners progressively enter U1 (standby with fast exit) and then U2 (standby with slower exit)"
                      // https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-3-0-lpm-mechanism- https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/u1-and-u2-transitions
    "SkipBOSDescriptorQuery" = ?; // REG_DWORD, any nonzero value sets flag 0x8000
    "MsOs20DescriptorSetInfo" = ?; // REG_BINARY/REG_QWORD (8 bytes)??, on success stores QWORD and sets internal flag 0x4 for the descriptor info
    "osvc" = ?; // REG_BINARY, see documentation below (written by HUBMISC_StoreDeviceMSOSVendorCodeInRegsitry)

    "AlternateSettingFilter"; // ?
```

Enabling `DisableLPM` won't get you anywhere since the devices are in D0 (working state) anyway while using them. The same can be said for the whole `Power` section too.

> [peripheral/assets | usbflags-HUBDSM_QueryingRegistryValuesForDevice.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbflags-HUBDSM_QueryingRegistryValuesForDevice.c)  
> [peripheral/assets | usbflags-HUBMISC_QueryAndCacheRegistryValuesForDevice.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbflags-HUBMISC_QueryAndCacheRegistryValuesForDevice.c)  
> [peripheral/assets | usbflags-HUBREG_OpenCreateUsbflagsDeviceKey.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbflags-HUBREG_OpenCreateUsbflagsDeviceKey.c)  
> [peripheral/assets | usbflags-HUBREG_QueryUsbflagsValuesForDevice.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbflags-HUBREG_QueryUsbflagsValuesForDevice.c)  
> [peripheral/assets | usbflags-Controller_IsRegKeySetToDisableS0Idle.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbflags-Controller_IsRegKeySetToDisableS0Idle.c)  
> [peripheral/assets | usbflags-Controller_PopulateRegistryOverrideForSetMultiTTBitFlag.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbflags-Controller_PopulateRegistryOverrideForSetMultiTTBitFlag.c)  
> [peripheral/assets | usbflags-Controller_PopulateTestRegistrySettings.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbflags-Controller_PopulateTestRegistrySettings.c)  
> [peripheral/assets | usbflags-Registry_InitializeAllow64KLowOrFullSpeedControlTransfersFlag.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbflags-Registry_InitializeAllow64KLowOrFullSpeedControlTransfersFlag.c)  

The subkeys in `usbflags` always have a length of 12, build in such a structure `vvvvpppprrrr`:
- **vvvv** is a 4-digit hexadecimal number that identifies the vendor
- **pppp** is a 4-digit hexadecimal number that identifies the product
- **rrrr** is a 4-digit hexadecimal number that contains the revision number of the device

The vendor ID, product ID, and revision number values are obtained from the [USB device descriptor](https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/usbcon/usb-device-descriptors.md). The USB_DEVICE_DESCRIPTOR structure describes a device descriptor.

> https://github.com/nohuto/win-registry/blob/main/records/USB-Flags.txt

---

| Registry entry | Description | Possible values |
|---|---|---|
| **osvc**<br><br>REG_BINARY | Indicates whether the operating system queried the device for [Microsoft-defined USB descriptors](https://github.com/nohuto/windows-driver-docs/blob/staging/windows-driver-docs-pr/usbcon/microsoft-defined-usb-descriptors.md). If the previously attempted OS descriptor query was successful, the value contains the vendor code from the OS string descriptor. | <ul><li>0x0000: The device didn't provide a valid response to the Microsoft OS string descriptor request.</li><li>0x01xx: The device provided a valid response to the Microsoft OS string descriptor request, where xx is the **bVendorCode** contained in the response.</li></ul> |
| **IgnoreHWSerNum**<br><br>REG_BINARY | Indicates whether the USB driver stack must ignore the serial number of the device. | <ul><li>0x00: The setting is disabled.</li><li>0x01: Forces the USB driver stack to ignore the serial number of the device. Therefore, the device instance is tied to the port to which the device is attached.</li></ul> |
| **ResetOnResume**<br><br>REG_BINARY | Indicates whether the USB driver stack must reset the device when the port resumes from a sleep cycle. | <ul><li>0x0000: The setting is disabled.</li><li>0x0001: Forces the USB driver stack to reset a device on port resume.</li></ul> |

```
\Registry\Machine\SYSTEM\ControlSet001\Control\usbflags\<vvvvpppprrrr> : ResetOnResume
\Registry\Machine\SYSTEM\ControlSet001\Control\usbflags\<vvvvpppprrrr> : IgnoreHWSerNum
\Registry\Machine\SYSTEM\ControlSet001\Control\usbflags\<vvvvpppprrrr> : osvc
```

`IgnoreHWSerNum<vvvvpppp>` exists in `\Registry\Machine\SYSTEM\ControlSet001\Control\usbflags` too.

> https://github.com/nohuto/windows-driver-docs/blob/staging/windows-driver-docs-pr/usbcon/usb-device-specific-registry-settings.md

```c
aRegistryMachin_1 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\USBFN";
aRegistryMachin_2 = // doesn't exist
aRegistryMachin_3 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\pnp";
aRegistryMachin_4 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\UsbLtm";
aRegistryMachin_5 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\devices";
aRegistryMachin_6 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\AutomaticSurpriseRemoval";
aRegistryMachin_7 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\HardwareVerifier";
aRegistryMachin_8 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\Usb20HardwareLpm";
aRegistryMachin_9 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usbflags";
aRegistryMachin_10 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBHUB\\hubg";
aRegistryMachin_11 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\USB";
aRegistryMachin_12 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\policy";
aRegistryMachin_13 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb";
```

# USB Values

For entries described as "any nonzero", the code treats the DWORD as a boolean, means any nonzero value is equivalent to `1`. Base path is `HKLM\SYSTEM\CurrentControlSet\Control\usb` (from `LRegistryMachineSYSTEMCurrentControlSetControlUSB`). Default data is unknown for most values as the driver code only reads the registry and handles fallbacks, note that this is currently based on USBHUB3.sys only, means it's not complete.

```c
// HUBREG_QueryGlobalUsb20HardwareLpmSettings
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\Usb20HardwareLpm"; // g_Usb20HardwareLpmKeyName (aRegistryMachin_8)
    "Usb20HardwareLpmOverride" = ?; // REG_DWORD, any nonzero keeps global flag 0x8000 set, zero clears it
    "Usb20HardwareLpmTimeout" = 2; // REG_DWORD, if value == 0xFF, byte a1+72 set to 0xFF, didn't find other handles

// HUBREG_OpenQueryAttemptRecoveryFromUsbPowerDrainValue
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\AutomaticSurpriseRemoval"; // g_UsbAutomaticSurpriseRemovalKeyName (aRegistryMachin_6)
    "AttemptRecoveryFromUsbPowerDrain" = ?; // REG_DWORD, queried directly and via persisted state fallback under Control\usb

// HUBREG_QueryUsbHardwareVerifierValue
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\HardwareVerifier"; // g_HwVerifierKeyName (aRegistryMachin_7)
    "<VID><PID><REV>\\usbUpto20|usb2X|usb30\\device" = ?; // REG_DWORD, subkey chosen from bcdUSB, value name is g_HwVerifierDeviceName
    "<VID><PID>\\usbUpto20|usb2X|usb30\\device" = ?; // REG_DWORD, fallback if VID/PID/REV key missing
    "global\\usbUpto20|usb2X|usb30\\device" = ?; // REG_DWORD, final fallback if no device specific key

// HUBREG_QueryGlobalUsbLtmSettings
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\UsbLtm"; // g_UsbLtmKeyName (aRegistryMachin_4)
    "UsbLtmEnable" = 0; // REG_DWORD, any nonzero value sets global flag 0x40000, zero clears it

// these are taken from the W10 source, they seem to exist on latest builds (they do exist in usbport.sys on 23H2)
"HKLM\\SYSTEM\\CurrentControlSet\\Services\\usb";
    "debuglevel" = 0; // REG_DWORD, default to 1/2 when DEBUG1/DEBUG2 builds. Trace verbosity, higher numbers enable more logs
    "debuglogmask" = 0xFFFFFFFE; // REG_DWORD, Bitmask for log categories
    "debuglogenable" = 1; // REG_DWORD (bool), enables debug log output
    "debugcatc" = 0; // REG_DWORD (bool), enables CATC analyzer trigger
    "DisableSelectiveSuspend" = 0; // REG_DWORD (bool), global disable for selective suspend
    "DisableCcDetect" = 0; // REG_DWORD (bool), global disable for CC detection
    "EnPMDebug" = 0; // REG_DWORD (bool), for debugging power management
    "ForceHcD3NoWakeArm" = 0; // REG_DWORD (bool), prevents wake-arming when forcing HC to D3
    "EnableDCA" = 0 // REG_DWORD (bool), enables direct controller access (HCT diagnostics)
    "ForcePortsHighSpeed" = 0; // REG_DWORD (bool), forces ports to remain under EHCI (HCT compatibility)

// "This class is reserved for USB host controllers and USB hubs", I'll add them here as they're also in usbport.sys and also taken from the W10 source
"HKLM\\System\\CurrentControlSet\\Control\\Class\\{36FC9E60-C465-11CF-8056-444553540000}\\<instance>";
    "HcFlavor" = // REG_DWORD, auto detect. Values are USB_CONTROLLER_FLAVOR enum (definition external)
    "TotalBusBandwidth" = // REG_DWORD, computed from miniport registration (bits/ms). Overrides bus bandwidth accounting
    "HcDisableAllSelectiveSuspend" = 0 (non-IA64), 1 (IA64); // REG_DWORD, non-zero disables selective suspend
    "CommonBuffer2GBLimit" = 0; // REG_DWORD, when non-zero, forces common buffers below 2GB ("Limit common buffer allocations for the miniport to the physical address range below 2GB.  Only bits 0 through 30 of the physical address can be set.  Bit 31 of the physical address cannot be set.")
    "ForceHCResetOnResume" = 0; // REG_DWORD, forces controller reset on resume
    "FastResumeEnable" = 0; // REG_DWORD, enables fast S0 resume
```

> [peripheral/assets | usb-GetPersistedKeyPath.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usb-GetPersistedKeyPath.c)  
> [peripheral/assets | usb-HUBREG_OpenQueryAttemptRecoveryFromUsbPowerDrainValue.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usb-HUBREG_OpenQueryAttemptRecoveryFromUsbPowerDrainValue.c)  
> [peripheral/assets | usb-HUBREG_QueryGlobalUsb20HardwareLpmSettings.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usb-HUBREG_QueryGlobalUsb20HardwareLpmSettings.c)  
> [peripheral/assets | usb-HUBREG_QueryGlobalUsbLtmSettings.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usb-HUBREG_QueryGlobalUsbLtmSettings.c)  
> [peripheral/assets | usb-HUBREG_QueryUsbHardwareVerifierValue.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usb-HUBREG_QueryUsbHardwareVerifierValue.c)  
> [peripheral/assets | usb-ReadManifestAssignedValue.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usb-ReadManifestAssignedValue.c)

`AttemptRecoveryFromUsbPowerDrain` is used to stop USB devices when your screen is off, obviously only for laptop users.

```
Stop USB devices when my screen is off to help battery.
```
`Bluetooth & devices` > `USB` > `USB battery saver`

> [power/assets | usbbattery-OpenQueryAttemptRecoveryFromUsbPowerDrainValue.c](https://github.com/nohuto/win-config/blob/main/power/assets/usbbattery-OpenQueryAttemptRecoveryFromUsbPowerDrainValue.c)

```c
aRegistryMachin_1 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\USBFN";
aRegistryMachin_2 = // doesn't exist
aRegistryMachin_3 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\pnp";
aRegistryMachin_4 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\UsbLtm";
aRegistryMachin_5 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\devices";
aRegistryMachin_6 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\AutomaticSurpriseRemoval";
aRegistryMachin_7 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\HardwareVerifier";
aRegistryMachin_8 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\Usb20HardwareLpm";
aRegistryMachin_9 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usbflags";
aRegistryMachin_10 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBHUB\\hubg";
aRegistryMachin_11 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\USB";
aRegistryMachin_12 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\policy";
aRegistryMachin_13 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb";
```

# USBHUB Values

For entries described as "any nonzero", the code treats the DWORD as a boolean, means any nonzero value is equivalent to `1`. Default data is unknown for most values as the driver code only reads the registry and handles fallbacks, note that this is currently based on USBHUB3.sys only, means it's not complete.

```c
// HUBREG_QueryGlobalHubValues
"HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBHUB\\hubg"; // g_HubGlobalKeyName (aRegistryMachin_10)
    "DisableSelectiveSuspendUI" = ?; // REG_DWORD, any nonzero value sets global flag 0x2
    "MsOsDescriptorMode" = ?; // REG_DWORD, stored to a1+8 when 0..3, out of range values are logged, MsOsDescriptorMode == 1 will force a MS OS descriptor query for all devices, regardless of USB version number. MsOsDescriptorMode == 2 will disable all MS OS descriptor queries. (there may exist a value named "DontSkipMsOsDescriptor" in this key)
    "EnableDiagnosticMode" = ?; // REG_DWORD, any nonzero value sets global flag 0x8
    "DisableOnSoftRemove" = ?; // REG_DWORD, if zero clears global flag 0x80 (default on) any nonzero leaves it set
    "DisableUxdSupport" = ?; // REG_DWORD, any nonzero value sets global flag 0x10
    "EnableExtendedValidation" = ?; // REG_DWORD bitmask, any nonzero value sets global flag 0x20, bit 0x8 sets 0x2000, bit 0x4 sets 0x4000
    "WakeOnConnectUI" = ?; // REG_DWORD, any nonzero value sets global flag 0x40 - This controls the UI check box 'Allow this device to wake the system'.  Essentially this is control for the wake on connect feature.
    "PreventDebounceTimeForSuperSpeedDevices" = ?; // REG_DWORD, any nonzero value sets global flag 0x10000 - Checks if we need to give extra time to SuperSpeed devices before talking to them

// HUBREG_QueryGlobalUxdSettings (the defaults were taken from the W10 source)
"HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\policy"; // g_UxdGlobalSettingsKey (aRegistryMachin_12)
    "UxdGlobalDeleteOnShutdown" = 0; // REG_DWORD (bool), any nonzero value sets global flag 0x100, global delete-on-shutdown policy
    "UxdGlobalDeleteOnReload" = 0; // REG_DWORD (bool), any nonzero value sets global flag 0x200, global policy to delete UXD keys on disable/reload events
    "UxdGlobalDeleteOnDisconnect" = 0; // REG_DWORD (bool), any nonzero value sets global flag 0x400, global policy to delete UXD keys on device disconnect
    "UxdGlobalEnable" = 0; // REG_DWORD (bool), any nonzero value sets global flag 0x800, "main" enable = if 0, UXD settings are ignored

// HUBREG_QueryUxdDeviceKey / HUBREG_DeleteUxdDeviceKey
"HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\devices"; // g_UxdDeviceSettingsKey (aRegistryMachin_5)
    "%04X%04X%04X" = ?; // value name from VID/PID/REV

// HUBREG_GetUxdPnpValue
"HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\pnp"; // g_UxdGuidSettingsKey (aRegistryMachin_3)
    "{GUID}" = ?; // value name from RtlStringFromGUID, data queried via WDF
```

> [peripheral/assets | usbhub-HUBREG_QueryUxdDeviceKey.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbhub-HUBREG_QueryUxdDeviceKey.c)  
> [peripheral/assets | usbhub-HUBREG_DeleteUxdDeviceKey.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbhub-HUBREG_DeleteUxdDeviceKey.c)  
> [peripheral/assets | usbhub-HUBREG_QueryGlobalUxdSettings.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbhub-HUBREG_QueryGlobalUxdSettings.c)  
> [peripheral/assets | usbhub-HUBREG_QueryGlobalHubValues.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbhub-HUBREG_QueryGlobalHubValues.c)  
> [peripheral/assets | usbhub-HUBREG_GetUxdPnpValue.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/usbhub-HUBREG_GetUxdPnpValue.c)

```c
aRegistryMachin_1 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\USBFN";
aRegistryMachin_2 = // doesn't exist
aRegistryMachin_3 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\pnp";
aRegistryMachin_4 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\UsbLtm";
aRegistryMachin_5 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\devices";
aRegistryMachin_6 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\AutomaticSurpriseRemoval";
aRegistryMachin_7 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\HardwareVerifier";
aRegistryMachin_8 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\Usb20HardwareLpm";
aRegistryMachin_9 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usbflags";
aRegistryMachin_10 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBHUB\\hubg";
aRegistryMachin_11 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\USB";
aRegistryMachin_12 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\policy";
aRegistryMachin_13 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb";
```

# Mouse Values

`RawMouseThrottleDuration` controls the throttle interval (in ms) for delivering raw mouse input to background windows. "We set out to reduce the amount of processing time it took to handle input requests by throttling and coalescing background raw mouse listeners and capping their message rate." 

Validate the changes with [MouseTester](https://github.com/valleyofdoom/MouseTester), move `MouseTester.exe` to the background after starting it by opening a different window.
```c
*(_QWORD *)&v13 = 0LL;                      // Forced = 0 (default)
*((_QWORD *)&v11 + 1) = 1LL;                // Enabled = 1 (default) - Forced to 1
*(_QWORD *)&v11 = L"RawMouseThrottleEnabled";
*((_QWORD *)&v12 + 1) = L"RawMouseThrottleForced";
*(_QWORD *)&v14 = L"RawMouseThrottleDuration";
*(_QWORD *)&v12 = 1LL;                      // Enabled = 1 (maximum)
*((_QWORD *)&v13 + 1) = 1LL;                // Forced = 1
*((_QWORD *)&v14 + 1) = 0x100000008LL;      // Duration = 8 (default, 125Hz)
*(_QWORD *)&v15 = 20LL;                     // Duration = 20 (maximum)
*((_QWORD *)&v15 + 1) = L"RawMouseThrottleLeeway";
*(_QWORD *)&v16 = 2LL;                      // Leeway = 2 (default)
*((_QWORD *)&v16 + 1) = 5LL;                // Leeway = 5 (maximum)
```
`GetRawMouseThrottlingThresholds.c` includes more detail and my notes. `RawMouseThrottleDuration` has a minumum of `1` (`1000` Hz).

> https://blogs.windows.com/windowsdeveloper/2023/05/26/delivering-delightful-performance-for-more-than-one-billion-users-worldwide/  
> https://github.com/valleyofdoom/PC-Tuning#1150-background-window-message-rate-permalink  
> [peripheral/assets | mouse-GetRawMouseThrottlingThresholds.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/mouse-GetRawMouseThrottlingThresholds.c)

![](https://github.com/nohuto/win-config/blob/main/peripheral/images/mousevalues.png?raw=true)

---

Enabling/disabling `Enhance pointer precision` sets:
```c
// Enabled
HKCU\Control Panel\Mouse\MouseTrails	Type: REG_SZ, Length: 4, Data: 0
HKCU\Control Panel\Mouse\MouseThreshold1	Type: REG_SZ, Length: 4, Data: 6
HKCU\Control Panel\Mouse\MouseThreshold2	Type: REG_SZ, Length: 6, Data: 10
HKCU\Control Panel\Mouse\MouseSpeed	Type: REG_SZ, Length: 4, Data: 1
HKCU\Control Panel\Mouse\MouseSensitivity	Type: REG_SZ, Length: 6, Data: 10

// Disabled
HKCU\Control Panel\Mouse\MouseTrails	Type: REG_SZ, Length: 4, Data: 0
HKCU\Control Panel\Mouse\MouseThreshold1	Type: REG_SZ, Length: 4, Data: 0
HKCU\Control Panel\Mouse\MouseThreshold2	Type: REG_SZ, Length: 4, Data: 0
HKCU\Control Panel\Mouse\MouseSpeed	Type: REG_SZ, Length: 4, Data: 0
HKCU\Control Panel\Mouse\MouseSensitivity	Type: REG_SZ, Length: 6, Data: 10
```

# Keyboard Values

| **Setting**           | **Description**                                                                                          | **Default** | **Changed To** |
| --------------------- | -------------------------------------------------------------------------------------------------------- | ----------- | -------------- |
| **Repeat Delay**      | Controls how long you need to hold down a key before it starts repeating when typing.                    | 1           | 0              |
| **Repeat Rate**       | Adjusts how quickly a key repeats when held down after the repeat delay.                                 | 31          | 31             |
| **Cursor Blink Rate** | Controls the speed at which the text cursor blinks on the screen. You can set it to be faster or slower. | 530         | 900            |

`Disable Language Switch Hotkey` applies: `Time & language > Typing > Advanced keyboard settings : Input language hot keys`, `Between input languages` to `Not assigned` (`None`):
```powershell
rundll32.exe	RegSetValue	HKCU\Keyboard Layout\Toggle\Language Hotkey	Type: REG_SZ, Length: 4, Data: 3
rundll32.exe	RegSetValue	HKCU\Keyboard Layout\Toggle\Hotkey	Type: REG_SZ, Length: 4, Data: 3
rundll32.exe	RegSetValue	HKCU\Keyboard Layout\Toggle\Layout Hotkey	Type: REG_SZ, Length: 4, Data: 3
```

# Audio Ducking

"Windows audio ducking is a dynamic audio processing technique that enables the **automatic adjustment of audio levels** between different audio sources on a Windows-based computer or operating system."
> https://multimedia.easeus.com/ai-article/windows-audio-ducking.html

Can be disabled manually via `mmsys.cpl > Communications` `Do nothing`.

`Mute all other sounds`:
```powershell
RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\UserDuckingPreference	Type: REG_DWORD, Length: 4, Data: 0
```
`Reduce the volume of other sounds by 80%` (default):
```powershell
RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\UserDuckingPreference	Type: REG_DWORD, Length: 4, Data: 1
```
`Reduce the volume of other sounds by 50%`:
```powershell
RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\UserDuckingPreference	Type: REG_DWORD, Length: 4, Data: 2
```
`Do nothing`:
```powershell
RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\UserDuckingPreference	Type: REG_DWORD, Length: 4, Data: 3
```

![](https://github.com/nohuto/win-config/blob/main/peripheral/images/audioducking.png?raw=true)

# Disable Audio Enhancements

The difference is minor (picture), preferable just disable them. Open `mmsys.cpl`, go into propeties of your used device, click on the `Advanced` tab and disable all enhancements.

```powershell
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render\{4bff9f8d-ead4-4ae3-962e-10358e158daf}\Properties\{b3f8fa53-0004-438e-9003-51a46e139bfc},3","Type: REG_DWORD, Length: 4, Data: 0"
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render\{4bff9f8d-ead4-4ae3-962e-10358e158daf}\Properties\{b3f8fa53-0004-438e-9003-51a46e139bfc},4","Type: REG_DWORD, Length: 4, Data: 0"
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture\{6119fee4-d49c-474d-978c-0e5f9a67acb3}\Properties\{b3f8fa53-0004-438e-9003-51a46e139bfc},3","Type: REG_DWORD, Length: 4, Data: 0"
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture\{6119fee4-d49c-474d-978c-0e5f9a67acb3}\Properties\{b3f8fa53-0004-438e-9003-51a46e139bfc},4","Type: REG_DWORD, Length: 4, Data: 0"
"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture\{6119fee4-d49c-474d-978c-0e5f9a67acb3}\FxProperties\{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},5","Type: REG_DWORD, Length: 4, Data: 1"
```

![](https://github.com/nohuto/win-config/blob/main/peripheral/images/audioenhance.png?raw=true)

# Disable Spatial Audio

Spatial audio positions sounds in 3D space around you, surround sound mainly anchors audio to speaker directions.

> https://github.com/nohuto/win-registry/blob/main/records/Audio.txt  
> https://www.dolby.com/experience/home-entertainment/articles/what-is-spatial-audio/

![](https://github.com/nohuto/win-config/blob/main/peripheral/images/spatial.jpeg?raw=true)

---

Miscellaneous notes:
```json
"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Audio": {
  "DisableSpatialOnLowLatency": { "Type": "REG_DWORD", "Data": 1 }
}
```

# Disable System Sounds

Disables system sounds and removes sound events. I did use the keys, which Windows would disable:
```powershell
"HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Close\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Maximize\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\MenuCommand\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\MenuPopup\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Minimize\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\Open\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\PrintComplete\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\AppGPFault\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\SystemQuestion\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\RestoreDown\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\RestoreUp\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\CCSelect\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\ShowBand\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\ChangeTheme\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\BlockedPopup\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\ActivatingDocument\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\EmptyRecycleBin\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\FeedDiscovered\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\MoveMenuItem\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\SecurityBand\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\Explorer\Navigating\.Current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current\(Default)","Type: REG_SZ, Length: 0"
"HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current\(Default)","Type: REG_SZ, Length: 0"
```

The revert data is based on `W11 LTSC IoT Enterprise 2024` defaults.

`DisableStartupSound` is set to `1` by default (`LogonUI\BootAnimation`).

# Disable AutoPlay/Autorun

AutoRun is a mechanism that uses an `autorun.inf` file on removable media (like CDs or old USB sticks) to specify a program that should start automatically when the media is inserted. Typical use case was auto starting setup programs on software CDs. Because malware abused this behavior, Windows now strongly restricts or disables automatic execution from `autorun.inf` on most removable drives.

AutoPlay is a feature that detects the type of content on newly inserted media or connected devices and then offers actions such as "Open folder, Play media, Import photos". It can read some information from `autorun.inf`, but it doesn't automatically run programs without user confirmation.

Disabling `ShellHWDetection` causes CmdPal to not start directly after boot for whatever reason, which is why I added a suboption to enable the service.

Example `autorun.inf` content:
```inf
[autorun]
open=Launch.exe
icon=Launch.exe
```

| Service | Description |
| --- | --- |
| `ShellHWDetection` | Provides notifications for AutoPlay hardware events. |

```c
// Bluetooth & devices > AutoPlay (same for Control Panel > All Control Panel Items > AutoPlay)
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\DisableAutoplay	Type: REG_DWORD, Length: 4, Data: 1

// Removeable drive
// Configure storage settings (Settings) = MSStorageSense
// Take no action = MSTakeNoAction
// Open folder to view files (File Explorer) = MSOpenFolder
// Ask me every time = MSPromptEachTime
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\StorageOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction

// Memory card
// Import Photos and Videos (Photos) = dsd9eksajf9re3669zh5z2jykhws2jy42gypaqjh1qe66nyek1hg!desktopappxcontent!showshowpicturesonarrival
// Play (Windows Media Player) = MSPlayMediaOnArrival
// Take no action = MSTakeNoAction
// Open folder to view files (File Explorer) = MSOpenFolder
// Ask me every time = MSPromptEachTime
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\CameraAlternate\ShowPicturesOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\CameraAlternate\ShowPicturesOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction

// Changing all available ones to 'Take no action'
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\StorageOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\CameraAlternate\ShowPicturesOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\CameraAlternate\ShowPicturesOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\PlayDVDMovieOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\PlayDVDMovieOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\PlayEnhancedDVDOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\PlayEnhancedDVDOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\HandleDVDBurningOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\HandleDVDBurningOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\PlayDVDAudioOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\PlayDVDAudioOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\PlayBluRayOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\PlayBluRayOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\HandleBDBurningOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\HandleBDBurningOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\PlayCDAudioOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\PlayCDAudioOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\PlayEnhancedCDOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\PlayEnhancedCDOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\HandleCDBurningOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\HandleCDBurningOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\PlayVideoCDMovieOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\PlayVideoCDMovieOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\PlaySuperVideoCDMovieOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\PlaySuperVideoCDMovieOnArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\AutorunINFLegacyArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\AutorunINFLegacyArrival\(Default)	Type: REG_SZ, Length: 30, Data: MSTakeNoAction
```

# Disk Write Cache Policy

Enables write cache & turns off write cache buffer flushing on all connected disks.

```
\Registry\Machine\SYSTEM\ControlSet001\Enum\SCSI\Disk&Ven_NVMe&Prod_Samsung_SSD_990\5&33c33320&0&000000\Device Parameters\disk : CacheIsPowerProtected
\Registry\Machine\SYSTEM\ControlSet001\Enum\SCSI\Disk&Ven_NVMe&Prod_Samsung_SSD_990\5&33c33320&0&000000\Device Parameters\disk : UserWriteCacheSetting
```
> https://learn.microsoft.com/en-us/previous-versions/troubleshoot/windows-server/turn-disk-write-caching-on-off  
> [peripheral/assets | diskwritecache.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/diskwritecache.c)

# Disable Bluetooth

| Service/Driver | Description |
| --- | --- |
| `BluetoothUserService_*` | The Bluetooth user service supports proper functionality of Bluetooth features relevant to each user session. |
| `BTAGService` | Service supporting the audio gateway role of the Bluetooth Handsfree Profile. |
| `BthA2dp` | Microsoft Bluetooth A2dp driver |
| `BthAvctpSvc` | This is Audio Video Control Transport Protocol service |
| `BthEnum` | Bluetooth Enumerator Service |
| `BthHFEnum` | Microsoft Bluetooth Hands-Free Profile driver |
| `BthLEEnum` | Bluetooth Low Energy Driver |
| `BthMini` | Bluetooth Radio Driver |
| `BTHMODEM` | Bluetooth Modem Communications Driver |
| `BTHPORT` | Bluetooth Port Driver |
| `bthserv` | The Bluetooth service supports discovery and association of remote Bluetooth devices. Stopping or disabling this service may cause already installed Bluetooth devices to fail to operate properly and prevent new devices from being discovered or associated. |
| `BTHUSB` | Bluetooth Radio USB Driver |
| `DeviceAssociationBrokerSvc` | Enables apps to pair devices |
| `DeviceAssociationService` | Enables pairing between the system and wired or wireless devices. |
| `Microsoft_Bluetooth_AvrcpTransport` | Microsoft Bluetooth Avrcp Transport Driver |
| `RFCOMM` | Bluetooth Device (RFCOMM Protocol TDI) |

# M/K DQS

The value exists by default and is set to `100` decimal (`64` hex). Reducing it doesn't reduce your latency, leave it default.

"Specifies the number of mouse events to be buffered internally by the driver, in nonpaged pool. The allocated size, in bytes, of the internal buffer is this value times the size of the MOUSE_INPUT_DATA structure (defined in NTDDMOU.H)."

```c
v11 = *((_DWORD *)&WPP_MAIN_CB.Reserved + 2); // MouseDataQueueSize value
if (!v11)
{
    // Set default to 100 if value was 0
    v11 = 100;
}
else if (v11 > 0xAAAAAAA) // ≈ 178956970
{
    v12 = 2400;
}
else
{
    v12 = 24 * v11;
}
*((_DWORD *)&WPP_MAIN_CB.Reserved + 2) = v12;

```
__Scenarios:__
Exists & > 0 -> `v11 = reg value`
Value == 0 -> `v11 = 100`
Value not present -> `v11 = 288` ?
Value > `0xAAAAAAA` ->  Clamped to `2400`
Otherwise `v11 * 24`

> https://www.betaarchive.com/wiki/index.php/Microsoft_KB_Archive/102990  
> [peripheral/assets | mkdata-MouConfiguration.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/mkdata-MouConfiguration.c)  
> [peripheral/assets | mkdata-KbdConfiguration.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/mkdata-KbdConfiguration.c)

# Device Manager

The `Clean` option removes non present devices (`-PresentOnly:$false`/`Status -eq 'Unknown'`) via `/remove-device` ([`pnputil`](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax)).

| Component | Description | Note |
| ---- | ---- | ---- |
| `Microphone` | Audio input device | Disable if unused |
| `Speakers` | Audio output device | Disable if unused |
| `High Definition Audio Controller` | Main audio bus/controller for sound devices | Disable if not in use |
| `Generic Monitor` | Basic display driver for monitors | Disabling may affect resolution/brightness (esp. laptops) |
| `WAN Miniports` | Virtual NICs for VPN, PPPoE, remote access, tunneling protocols | Keep if you use VPN/remote access, else can disable |
| `Microsoft ISATAP Adapter` | Tunnels IPv6 over IPv4 infrastructure | Usually safe to disable |
| `Microsoft iSCSI Initiator` | Connects to iSCSI storage targets over network | Disable if you don't use network storage |
| `Microsoft Virtual Drive Enumerator` | Enumerator for virtual drives | Disabling breaks `diskmgmt.msc` |
| `Microsoft RRAS Root Enumerator` | Helper/legacy driver for initializing certain (virtual/older) devices at boot | Usually safe, but can affect legacy/virtual HW |
| `Microsoft System Management BIOS Driver` | Exposes SMBIOS/system info to OS | Disabling breaks GTA V and some system info tools |
| `System Speaker` | Handles system/PC speaker audio (can include monitor audio routing) | Disabling can break monitor audio |

---

Click on `View` > `Devices by connection`.

- Go into `PCI Bus` / `PCI Express Root Complex`
    - Disable all `PCI-to-PCI Bridge` devices, which are unused (`PCI Express Downstream Switch Port`)

![](https://github.com/nohuto/win-config/blob/main/peripheral/images/devman.png?raw=true)

> https://learn.microsoft.com/en-us/powershell/module/pnpdevice/get-pnpdevice?view=windowsserver2025-ps  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax

# Disable Touch & Tablet

Disable the touch screen feature of your device with:
```powershell
Get-PnpDevice -PresentOnly:$false | ? FriendlyName -eq 'HID-compliant touch screen' | % { pnputil /disable-device "$($_.InstanceId)" }
```

"Tablet mode makes Windows more touch friendly and is helpful on touch capable devices."

> https://support.microsoft.com/en-us/windows/turn-tablet-mode-on-or-off-in-windows-add3fbce-5cb5-bf76-0f9c-8d7b30041f30  
> https://github.com/nohuto/win-registry/blob/main/records/Wisp.txt  
> [peripheral/assets | touch-IsTouchDisabled.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/touch-IsTouchDisabled.c)

---

Everything listed below is based on personal research. Mistakes may exist, some parts are speculations. See links below for reference.

```c
"HKCU\\Software\\Microsoft\\Wisp\\Touch";
    "PanningDisabled" = 0;
    "Inertia" = 1;
    "Bouncing" = 1;
    "Friction" = 50;
    "TouchModeN_DtapDist" = 50;
    "TouchModeN_DtapTime" = 50;
    "TouchGate" = 1;
    "TouchModeN_HoldTime_Animation" = 50;
    "TouchModeN_HoldTime_BeforeAnimation" = 50;
    "TouchMode_hold" = 1;
    "Mobile_Inertia_Enabled" = 0;
    "Minimum_Velocity" = 0;
    "Thumb_Flick_Enabled" = 1;

"HKCU\\Software\\Microsoft\\Wisp\\MultiTouch";
    "MultiTouchEnabled" = 1;

"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PrecisionTouchPad";
    "AAPThreshold" = 2; // range 0–4, touchpad sensitivity
    "CursorSpeed" = 10; // range 1–20, pointer speed
    "FeedbackIntensity" = 50; // range 0–100 (%), haptic feedback strength
    "ClickForceSensitivity" = 50; // range 0–100 (%), relative click-force sensitivity
    "LeaveOnWithMouse" = 1; // 0 = disable touchpad when mouse present, 1 = leave enabled
    "FeedbackEnabled" = 1; // 0 = no haptics, 1 = haptics on
    "TapsEnabled" = 1; // 0/1, single-finger tap-to-click
    "TapAndDrag" = 1; // 0/1, double-tap-and-drag
    "TwoFingerTapEnabled" = 1; // 0/1
    "RightClickZoneEnabled" = 1; // 0/1
    "PanEnabled" = 1; // 0/1, two-finger scrolling
    "ScrollDirection" = 0; // 0 = natural, 1 = reversed
    "ZoomEnabled" = 1;
    "HonorMouseAccelSetting" = 0; // 0 = always apply acceleration, 1 = honor SPI mouse accel?
    "RightClickZoneWidth" = 0;
    "RightClickZoneHeight" = 0;

"HKCU\\Software\\Microsoft\\Wisp\\Pen\\SysEventParameters";
    "Splash" = 50;
    "DblDist" = 50;
    "DblTime" = 300;
    "TapTime" = 100;
    "WaitTime" = 300;
    "HoldTime" = 2300;
    "FlickMode" = 1;
    "FlickTolerance" = 50;
    "Latency" = 8;
    "SampleTime" = 8;
    "UseHWTimeStamp" = 1;
    "SguiMode" = 0;
    "HoldMode" = 1;
    "MouseInputResolutionX" = 0;
    "MouseInputResolutionY" = 0;
    "MouseInputFrequency" = 0;
    "EraseEnable" = 1;
    "RightMaskEnable" = 1;
    "Color" = 0xC0000000C0000000; // ?

"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TabletMode";
    "STCDefaultMigrationCompleted" = 0; // SHRegValueExists

"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ImmersiveShell";
    "TabletMode" = 0; // 0 = desktop mode, 1 = tablet mode?
    "ExitedTabletModeWhileCSMActive" = 0; // set to 1 when a3 == 4, HasConvertibleSlateModeChanged() is true
    "TabletModeActivated" = 0; // set to 1 when SetModeInternal() switches into tablet mode

"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ImmersiveShell";
    "AllowPPITabletModeExit" = 0; // SHRegGetBOOLWithREGSAM, non-zero allows the mode switch

"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ImmersiveShell\\OverrideScaling";
    "SmallScreen" = 83; // ?
    "VerySmallScreen" = 71; // ?
    "TabletSmallScreen" = 83; // ?

"HKCU\\Software\\Microsoft\\Wisp\\Pen\\SysEventParameters\\FlickCommands";
    "Left" = { 0x4846455758C33841, 0x9F7145B888BB26B8 };
    "UpLeft" = { 0x47F38E42CEFA51BC, 0xEBDFECA56A8CB1AC };
    "Up"= { 0x450285124653D974, 0x8090833CF6D41AA0 };
    "UpRight" = { 0x47F38E42CEFA51BC, 0x6A8CB1ACEBDFECA5 };
    "Right" = { 0xC267B8DE4FA8068E, 0x4E301EF93B324FAB };
    "DownRight" = { 0x47F38E42CEFA51BC, 0x6A8CB1ACEBDFECA5 };
    "Down" = { 0x441A7051435776E6, 0xF7C82D37F0853D9B };
    "DownLeft" = { 0x47F38E42CEFA51BC, 0xEBDFECA56A8CB1AC };
```

> [peripheral/assets | touch-twinui.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/touch-twinui.c)  
> [peripheral/assets | touch-InitializeInputSettingsGlobals.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/touch-InitializeInputSettingsGlobals.c)

```
TabletModeActivated
TabletModeCoverWindow
TabletModeInputHandler
```
```c
\Registry\Machine\SOFTWARE\Microsoft\TabletTip\1.7 : EnableDesktopModeAutoInvoke
\Registry\Machine\SOFTWARE\Microsoft\TabletTip\1.7 : EnableDesktopModePenAutoInvoke
\Registry\Machine\SOFTWARE\Microsoft\TabletTip\1.7 : LastTipXPositionOnScreen
\Registry\Machine\SOFTWARE\Microsoft\TabletTip\1.7 : TipbandDesiredVisibility
\Registry\Machine\SOFTWARE\Microsoft\TabletTip\1.7 : TipbandDesiredVisibilityTabletMode
\Registry\Machine\SOFTWARE\Microsoft\TabletTip\1.7 : TipPinnedToMonitor
\Registry\Machine\SOFTWARE\Microsoft\TabletTip\1.7 : TouchKeyboardTapInvoke
```

Windows 7/XP:
```json
"HKLM\\SOFTWARE\\Policies\\Microsoft\\TabletTip\\1.7": {
    "DisablePrediction": { "Type": "REG_DWORD", "Data": 1 },
    "DisableACIntegration": { "Type": "REG_DWORD", "Data": 1 },
    "DisableEdgeTarget": { "Type": "REG_DWORD", "Data": 1 },
    "HideIPTIPTargets": { "Type": "REG_DWORD", "Data": 1 },
    "HideIPTIPTouchTargets": { "Type": "REG_DWORD", "Data": 1 },
    "PasswordSecurityState": { "Type": "REG_DWORD", "Data": 0 },
    "IncludeRareChar": { "Type": "REG_DWORD", "Data": 0 },
    "ScratchOutState": { "Type": "REG_DWORD", "Data": 3 }
},
"HKLM\\SOFTWARE\\Policies\\Microsoft\\TabletPC": {
    "DisableInkball": { "Type": "REG_DWORD", "Data": 1 },
    "DisableJournal": { "Type": "REG_DWORD", "Data": 1 },
    "DisableNoteWriterPrinting": { "Type": "REG_DWORD", "Data": 1 },
    "DisableSnippingTool": { "Type": "REG_DWORD", "Data": 1 },
    "TurnOffPenFeedback": { "Type": "REG_DWORD", "Data": 1 },
    "PreventFlicksLearningMode": { "Type": "REG_DWORD", "Data": 1 },
    "PreventFlicks": { "Type": "REG_DWORD", "Data": 1 }
}
```

# Disable Wake on Input

```bat
powercfg /devicequery wake_programmable
powercfg /devicequery wake_armed
```
`powercfg /devicequery wake_programmable` -> devices that are user-configurable to wake the system from a sleep state
`powercfg /devicequery wake_armed` -> currently configured to wake the system from any sleep state

```bat
powercfg /devicedisablewake device
```
Disables the device (replace '*Device*' with the device name) from waking the system from any sleep state. 

> https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#availablesleepstates-or-a

`WakeOnInputDeviceTypes.bat` probably disables wake on input behavior for all input devices - each bit represents a input device type? Since `\SYSTEM\INPUT` only queries two values I'll add the second on in here.
```
\Registry\Machine\SYSTEM\INPUT : UnDimOnInputDeviceTypes
\Registry\Machine\SYSTEM\INPUT : WakeOnInputDeviceTypes
```
`UnDimOnInputDeviceTypes` probably refers to any dimmed elemets (pure speculation)? Disabling it wouldn't make sense. Values named `ButtonsAsVKeys` & `HardwareButtonsAsVKeys` may exist in `SYSTEM\\INPUT\\BUTTONS`, but I haven't looked further into it.

Default values:
```c
WakeOnInputDeviceTypes = 6
UnDimOnInputDeviceTypes = -1  // 0xFFFFFFFF
```
> https://github.com/nohuto/win-registry/blob/main/records/Input.txt  
> https://github.com/nohuto/win-registry/blob/main/records/Enum-USB.txt  
> [peripheral/assets | wakedev-WakeOnInputDeviceTypes.c](https://github.com/nohuto/win-config/blob/main/peripheral/assets/wakedev-WakeOnInputDeviceTypes.c)

---


All available flags (`powercfg /devicequery query_flag`):

| `query_flag`             | Description                                                                      |
| ------------------------ | -------------------------------------------------------------------------------- |
| `wake_from_S1_supported` | Returns all devices that support waking the system from a light sleep state.     |
| `wake_from_S2_supported` | Returns all devices that support waking the system from a deeper sleep state.    |
| `wake_from_S3_supported` | Returns all devices that support waking the system from the deepest sleep state. |
| `wake_from_any`          | Returns all devices that support waking the system from any sleep state.         |
| `S1_supported`           | Lists devices supporting light sleep.                                            |
| `S2_supported`           | Lists devices supporting deeper sleep.                                           |
| `S3_supported`           | Lists devices supporting deepest sleep.                                          |
| `S4_supported`           | Lists devices supporting hibernation.                                            |
| `wake_programmable`      | Lists devices that are user-configurable to wake the system from a sleep state.  |
| `wake_armed`             | Lists devices currently configured to wake the system from any sleep state.      |
| `all_devices`            | Returns all devices present in the system.                                       |

# Disable Dynamic Lighting

"Dynamic Lighting is a feature that allows you to control LED-powered devices such as keyboards, mice, and other illuminated accessories. This feature enables you to coordinate the colors of LEDs, creating a unified lighting experience both within Windows and across all your devices."

| Value | Type | Values | Ranges | Notes |
| --- | --- | --- | --- | --- |
| `AmbientLightingEnabled` | REG_DWORD | `0 = off`, `1 = on` | `0–1` | Master toggle for Dynamic Lighting. |
| `UseSystemAccentColor` | REG_DWORD | `0 = use custom Color/Color2`, `1 = match Windows accent` | `0–1` | When `1`, `Color` is ignored. |
| `Color` | REG_DWORD | `COLORREF (RGB)` | `0x00000000–0x00FFFFFF`    | Format `0x00BBGGRR`. Used when `UseSystemAccentColor = 0`. |
| `Color2` | REG_DWORD | `COLORREF (RGB)` | `0x00000000–0x00FFFFFF`    | Secondary color for some effects. |
| `EffectType` | REG_DWORD | `0 = Solid`, `1 = Breathing`, `2 = Rainbow`, `4 = Wave`, `5 = Wheel`, `6 = Gradient` | `discrete enum` | Defines animation. |
| `Speed` | REG_DWORD | `integer` | `1–10` | Higher = faster. |
| `EffectMode` | REG_DWORD | Rainbow: `0 = Forward`, `1 = Reverse` · Wave: `0 = Right`, `1 = Left`, `2 = Down`, `3 = Up` · Wheel: `0 = Clockwise`, `1 = Counterclockwise` · Gradient: `0 = Horizontal`, `1 = Vertical`, `2 = Outward` | `discrete enum per effect` | Depends on `EffectType`. |
| `Brightness` | REG_DWORD | `integer (%)` | `0–100` | - |
| `ControlledByForegroundApp` | REG_DWORD | `0 = ignore apps`, `1 = apps can take control` | `0–1` | - |

> https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/dynamic-lighting-devices  
> https://support.microsoft.com/en-us/windows/control-dynamic-lighting-devices-in-windows-8e8f22e3-e820-476c-8f9d-9ffc7b6ffcd2

# Disable Printing

Disables printer related services (`Spooler`, `PrintWorkFlowUserSvc`, `PrintNotify`, `usbprint`, `McpManagementService`, `PrintScanBrokerService`, `PrintDeviceConfigurationService`), and various optional features / scheduled tasks.

Remove the `Print` option from the context menu:
```
Remove-Item "Registry::HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\batfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\cmdfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\contact_wab_auto_file\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\emffile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\fonfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\group_wab_auto_file\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\htmlfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\IE.AssocFile.HTM\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\IE.AssocFile.SVG\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\IE.AssocFile.URL\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\IE.AssocFile.XHT\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\inffile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\inifile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\InternetShortcut\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\JSEFile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\JSFile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\opensearchresult\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\otffile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\PBrush\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\pfmfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\regfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\rlefile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\svgfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.avci\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.avcs\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.avif\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.avifs\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.heic\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.heics\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.heif\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.heifs\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.hif\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.jxl\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\image\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\ttcfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\ttffile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\txtfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\VBEFile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\VBSFile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\wdpfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\wmffile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\WSFFile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\xhtmlfile\shell\print" -Force -Recurse
Remove-Item "Registry::HKEY_CLASSES_ROOT\zapfile\shell\print" -Force -Recurse
```

This list was created on a stock `W11 LTSC IoT Enterprise 2024` installation via:
```powershell
dir Registry::HKEY_CLASSES_ROOT -Recurse -ea SilentlyContinue | ? { $_.Name -like '*\shell\print' } | select -ExpandProperty Name
```

---

List all printer connections:
```powershell
Get-Printer
```
> https://learn.microsoft.com/en-us/powershell/module/printmanagement/get-printer?view=windowsserver2025-ps

Remove a specific printer using it's name:
```powershell
Remove-Printer -Name "Printer Name"
```
> https://learn.microsoft.com/en-us/powershell/module/printmanagement/remove-printer?view=windowsserver2025-ps

# Sample Rate

For your knowledge: The sample rate is the amount of times (in a second) an audio singal is measured. The amount of bits that are used to represent each sample (higher bit range = higher dynamic range and volume potential). The best sample rate and bit depth depends on what you're doing, the most commonly used sample rate for production and similar is `44.1` kHz.

`44.1` kHz = `44,100` times per second

As you may know a bit can be `0` or `1`, means (bit depth * `6` = dB):
`8` bit = `256` values
`16` bit = `65536` values
`24` bit = `16777216` values

`44.1` kHz with a bit depth of `16` is more than enough for general usage.

> https://noirsonance.com/bit-depth-calculator-visualizer/  
> https://de.wikipedia.org/wiki/Nyquist-Shannon-Abtasttheorem

![](https://github.com/nohuto/win-config/blob/main/peripheral/images/samplerate.png?raw=true)

# Mouse DPI

Use `800` or `1600`. Going too low will end in worse results, as shown in the pictures ([1](https://www.youtube.com/watch?v=mwf_F2VboFQ&t=458s), [2](https://www.youtube.com/watch?v=imYBTj2RXFs&t=274s)).

![](https://github.com/nohuto/win-config/blob/main/peripheral/images/dpi1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/peripheral/images/dpi2.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/peripheral/images/dpi3.png?raw=true)

# Polling Rate

Higher sampling rates reduce jitter and latency and ensure more accurate cursor positioning (first image), but may affect performance depending on the hardware (CPU cycles) - [*](https://www.youtube.com/watch?v=jtATbpMqbL4). Using `4 kHz` on a mid-tier PC should not be a problem. Run benchmarks on your system to check whether your PC can handle this rate. It should always be `1 kHz+`. You can use [MouseTester](https://github.com/valleyofdoom/MouseTester/releases) to check if your current polling rate is stable.

![](https://github.com/nohuto/win-config/blob/main/peripheral/images/polling1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/peripheral/images/polling2.png?raw=true)

# Monitor Settings

Before starting the configuration, load your default settings, as many settings are already correctly configured by default.

## **Game Mode** - `User`  
Each profile has preconfigured settings. E.g. 'Read mode' is optimized for viewing documents, it probably decreases the [brightness](https://plano.co/does-screen-brightness-affect-your-eyes/) and increases the color temperature. Choose the profile you're satisfied with, for example the sRGB profile if you're a editor, then configure the other settings.

## **Overdrive/OD/Response Time** - `Test`  
If you experience [ghosting](https://www.testufo.com/ghosting) (most noticeable in fast paced motions, e.g. FPS games), caused by a slow response time, which cannot keep up with the speed of the changing image, you should try to increase the OD option, which will increase the response time of your monitor. Ghosting looks like a image artifact that appears as a trail of pixels behind a moving object (pixels can't change color fast enough when a new image appears, parts of the old image remain visible), which is why it gets called ghosting -> the trace looks like a ghost of the object. Increasing the overdrive setting can end up in overshooting/inverse ghosting, which is the opposite of ghosting and get's caused from a too high OD. Which means that the response time is too fast for your monitor to handle it, resulting in pixels changing their color too fast. Ghosting (normally) ends up in a trace behind the object (like motion blur), inverse ghosting can cause artifacts in front and behind the object. Search for your monitor [here](https://www.rtings.com/), scroll down to the motion section and compare the response times, to see if your monitor even performs the best one the fastest option. And no you won't "see" a difference between them, if you experience inverse ghosting, renounce the lowest response time and decrease it (as ghosting makes the image unclear -> annoying), if you experience ghosting increase and test it.

![](https://github.com/nohuto/win-config/blob/main/peripheral/images/monitor1.png?raw=true)

## **Sharpness** - `0%`  
Personal preference. Increasing it too much will end up in [artificial sharpening](http://www.lagom.nl/lcd-test/sharpness.php) = exaggerated outlines.

## **Dark Boost/Black Boost** - `Off`  
Improved vision in [dark scenes](https://www.testufo.com/blacklevels) when increased, but can end up making black look gray, so don't increase it too much. 

## **FreeSync, G-Sync...** - `Disabled`  
G-Sync matches the monitor's refresh rate to the frame rate. The setting is used to eliminate screen tearing, if you don't experience [screen tearing](https://www.youtube.com/watch?v=5mWMP96UdGU&t=110s), leave it disabled. If you want to use it, set your framerate limit a bit lower (kind of a buffer, `freq-(freq*freq)/3600`) than your refresh rate. Optimally set the limit within the game. Never use pure V-Sync -> G-Sync + V-Sync + Reflex & limit. [Gsync/gsync101-input-lag-tests-and-settings](https://blurbusters.com/gsync/gsync101-input-lag-tests-and-settings/) can still be read. It is old, but most of it is still correct. If information from the text above and from the website text don't match, the channel information is correct.

## **Color Temperature** - `Warm`  
Changing it is one of the best ways to reduce eye stain. Using a warm temperature -> less [blue light](https://eyesurgeryguide.org/debunking-the-blue-light-eye-damage-myth/). (read the text below for more information about [blue light](https://eyesurgeryguide.org/debunking-the-blue-light-eye-damage-myth/)) Default mostly is `6500K`. One thing to add: a higher temperature will make it easier for you to concentrate.

![](https://github.com/nohuto/win-config/blob/main/peripheral/images/monitor2.png?raw=true)

## **Brightness** - `50-70`  
Depends on how much light there is in your room. If there's a lot of light, you'll have to increase the [brightness](https://plano.co/does-screen-brightness-affect-your-eyes/). If you mainly play in the dark, it's recommended to reduce the [brightness](https://plano.co/does-screen-brightness-affect-your-eyes/) to a level that is comfortable for your eyes. Remember: decreasing it *can* lower the [blue light](https://eyesurgeryguide.org/debunking-the-blue-light-eye-damage-myth/) by `50+%` -> known to be phototoxic to your eyes ([retina](https://en.wikipedia.org/wiki/Retina) - light sensitive tissue), therefore lower the [brightness](https://plano.co/does-screen-brightness-affect-your-eyes/) to reduce the intensity of [blue light](https://eyesurgeryguide.org/debunking-the-blue-light-eye-damage-myth/). For your general knowledge, [blue light](https://eyesurgeryguide.org/debunking-the-blue-light-eye-damage-myth/) has a short wavelength (~[`450-500`](https://www.livephysics.com/physical-constants/optics-pc/wavelength-colors/)), which means that it carries more energy -> higher impact. Don't dim it too much, or it may end up in worse focus.

![](https://github.com/nohuto/win-config/blob/main/peripheral/images/monitor3.png?raw=true)

## **Contrast** - `~60`  
It shouldn't be set too high, otherwise you will [not be able to see any details](https://www.testufo.com/whitelevels) and not too low, or it will be too dark. You'll have to test it yourself and find the best value.