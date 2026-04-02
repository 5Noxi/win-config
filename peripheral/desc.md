# USBFlags Values

Value names in `usbflags-HUBREG_QueryUsbflagsValuesForDevice.c` are mostly UNICODE_STRING globals, the names below are resolved from `dq offset ... ; "Name"`. The usbflags device key base path is `HKLM\SYSTEM\CurrentControlSet\Control\usbflags` (from `LRegistryMachineSystemCurrentControlSetControlusbflags` in `HUBREG_OpenCreateUsbflagsDeviceKey`). For entries described as "any nonzero", the code treats the DWORD as a boolean, means any nonzero value is equivalent to `1`. Default data is unknown for most values as the driver code only reads the registry and handles fallbacks, note that this is currently based on USBHUB3.sys only, means it's not complete (USBXHCI.sys was used for DisableHCS0Idle & TestRunEsmInWorkItem, Ucx01000.sys for Allow64KLowOrFullSpeedControlTransfers, usbccgp.sys for GenericCompositeUSBDeviceString).

You can use `!usb3kd.device_info` to get more information on a USB device in the USB 3.0 tree, example:
```c
lkd> !usb3.usb_tree

4) !device_info 0xffffb009127ca1f0, !devstack ffffb009127e1d80
    Current Device State: ConfiguredInD0
    Desc: USB Receiver
    USB\VID_046D&PID_C547&REV_0402 Logitech Inc.
    !ucx_device 0xffffb009127cad00 !xhci_deviceslots 0xffffb0090bc17db0 1 !xhci_info 0xffffb0090bc17db0

lkd> !usb3kd.device_info 0xffffb009127ca1f0

U1Timeout: 0, U2Timeout: 0
DeviceFlags: DeviceIsComposite MsOsDescriptorNotSupported UsbWakeupSupport 
DeviceStateFlags: DeviceAttachSuccessful DeviceIsKnown ConfigurationIsValid ConfigDescIsValid 
                  DeviceStarted InstallMSOSExtEventProcessed IsNative 
DeviceHackFlags: DisableOnSoftRemove DisableLpm
```
The `DisableLpm` DeviceHackFlags exists if the value is set (DisableLPM).

You can see existing `_USB_DEVICE_HACKS` using the dt command:
```c
lkd> .load usb3kd
lkd> dt USBHUB3!_USB_DEVICE_HACKS
   +0x000 AsUlong32        : Uint4B
   +0x000 DisableSerialNumber : Pos 0, 1 Bit
   +0x000 DontSkipMsOsDescriptor : Pos 1, 1 Bit
   +0x000 ResetOnResumeSx  : Pos 2, 1 Bit
   +0x000 DisableOnSoftRemove : Pos 3, 1 Bit
   +0x000 RequestConfigDescOnReset : Pos 4, 1 Bit
   +0x000 SkipContainerIdQuery : Pos 5, 1 Bit
   +0x000 IgnoreBOSDescriptorValidationFailure : Pos 6, 1 Bit
   +0x000 DisableLpm       : Pos 7, 1 Bit
   +0x000 SkipSetSel       : Pos 8, 1 Bit
   +0x000 ResetOnResumeInSuperSpeed : Pos 9, 1 Bit
   +0x000 AllowInvalidPipeHandles : Pos 10, 1 Bit
   +0x000 DisableUASP      : Pos 11, 1 Bit
   +0x000 SkipSetIsochDelay : Pos 12, 1 Bit
   +0x000 ResetOnResumeS0  : Pos 13, 1 Bit
   +0x000 DisableHotReset  : Pos 14, 1 Bit
   +0x000 SkipBOSDescriptorQuery : Pos 15, 1 Bit
   +0x000 NonFunctional    : Pos 16, 1 Bit
   +0x000 DisableUsb20HardwareLpm : Pos 17, 1 Bit
   +0x000 DisableRemoteWakeForUsb20HardwareLpm : Pos 18, 1 Bit
   +0x000 DisableSuperSpeed : Pos 19, 1 Bit
   +0x000 IncompatibleWithWindows : Pos 20, 1 Bit
   +0x000 UseWin8DescriptorValidation : Pos 21, 1 Bit
   +0x000 DisableFastEnumeration : Pos 22, 1 Bit
   +0x000 DisableRecoveryFromPowerDrain : Pos 23, 1 Bit
   +0x000 AddControllerSuffixedCompatIdToAudioDevices : Pos 24, 1 Bit
   +0x000 AddMausbSuffixToHardwareId : Pos 25, 1 Bit
   +0x000 EnablePLDRDuringCyclePort : Pos 26, 1 Bit
   +0x000 ResetOnErrorInD2Resume : Pos 27, 1 Bit
```

> https://github.com/nohuto/windows-driver-docs/blob/staging/windows-driver-docs-pr/debuggercmds/-usb3kd-device-info.md

`HUBDSM_QueryingRegistryValuesForDevice` -> `HUBMISC_QueryAndCacheRegistryValuesForDevice` -> `HUBREG_QueryUsbflagsValuesForDevice`

Note on some usbflag values ("queried as 4-byte boolean"), `USBHUB3` reads a 4-byte and handles any nonzero value as enabled. The value type is not enforced, so both `REG_DWORD` and `REG_BINARY` should work if they're a 4-byte nonzero value (that's my current assumption). I would personally use `REG_BINARY` instead of `REG_DWORD` for now, as for example `osvc`, `IgnoreHWSerNum`, `ResetOnResume` are `REG_BINARY` ([usb-device-specific-registry-settings.md](https://github.com/nohuto/windows-driver-docs/blob/staging/windows-driver-docs-pr/usbcon/usb-device-specific-registry-settings.md)).

```c
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\usbflags";
    "Allow64KLowOrFullSpeedControlTransfers" = ?; // REG_DWORD, only value 1 enables, 0/other values disable
    "DisableHCS0Idle" = 0; // REG_DWORD, nonzero disables S0 idle, missing/read failure behaves as 0
    "GenericCompositeUSBDeviceString" = ?; // REG_SZ
    "SetMultiTTBitDuringConfigureEndpoint" = ?; // REG_DWORD, 1 enables override, 0 disables override
    "TestRunEsmInWorkItem" = 0; // REG_DWORD, 1 enables test mode bit, 0 clears it

// built by HUBREG_OpenCreateUsbflagsDeviceKey

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\usbflags\\<vvvvpppprrrr>";
    "IgnoreHWSerNum" = ?; // REG_BINARY, Indicates whether the USB driver stack must ignore the serial number of the device.
                          // 0x00: The setting is disabled.
                          // 0x01: Forces the USB driver stack to ignore the serial number of the device. Therefore, the device instance is tied to the port to which the device is attached.
    "UseWin8DescriptorValidation" = ?; // queried as 4-byte boolean
    "ResetOnResume" = ?; // REG_BINARY, indicates whether the USB driver stack must reset the device when the port resumes from a sleep cycle.
                         // 0x0000: The setting is disabled.
                         // 0x0001: Forces the USB driver stack to reset a device on port resume.
    "DisableOnSoftRemove" = 1; // queried as 4-byte boolean
    "RequestConfigDescOnReset" = ?; // queried as 4-byte boolean
    "DisableRecoveryFromPowerDrain" = ?; // queried as 4-byte boolean
    "DisableLpm" = ?; // queried as 4-byte boolean. When enabled, link power management is disabled for the device.
                      // "A link enters a low power state (consuming less power than the working state) only when the downstream device enters the suspended state through the selective suspend mechanism", "After remaining idle for a certain period of time, link partners progressively enter U1 (standby with fast exit) and then U2 (standby with slower exit)"
                      // https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-3-0-lpm-mechanism- https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/u1-and-u2-transitions
    "SkipBOSDescriptorQuery" = ?; // queried as 4-byte boolean
    "AlternateSettingFilter" = ?; // REG_BINARY, size must be even and > 0 (data is cached as 16 bit entries "count = byte_size/2")
    "ResetTTOnCancel" = ?; // REG_DWORD
    "NoClearTTBufferOnCancel" = ?; // REG_DWORD, has priority over ResetTTOnCancel
    "PowerUpDelay" = ?; // REG_DWORD?

    "osvc" = ?; // REG_BINARY, "Indicates whether the operating system queried the device for Microsoft-defined USB descriptors. If the previously attempted OS descriptor query was successful, the value contains the vendor code from the OS string descriptor."
                // 0x0000: The device didn't provide a valid response to the Microsoft OS string descriptor request.
                // 0x01xx: The device provided a valid response to the Microsoft OS string descriptor request, where xx is the bVendorCode contained in the response.
    "SkipContainerIdQuery" = ?; // queried as 4-byte boolean
    "MsOs20DescriptorSetInfo" = ?; // queried as 8-byte

    //"DontSkipMsOsDescriptor"
    //"IgnoreBOSDescriptorValidationFailure"
    //"SkipSetSel"
    //"ResetOnResumeInSuperSpeed"
    //"AllowInvalidPipeHandles"
    //"DisableUASP"
    //"SkipSetIsochDelay"
    //"ResetOnResumeS0"
    //"DisableHotReset"
    //"NonFunctional"
    //"DisableUsb20HardwareLpm"
    //"DisableRemoteWakeForUsb20HardwareLpm"
    //"DisableSuperSpeed"
    //"IncompatibleWithWindows"
    //"DisableFastEnumeration"
    //"AddControllerSuffixedCompatIdToAudioDevices"
    //"AddMausbSuffixToHardwareId"
    //"EnablePLDRDuringCyclePort"
    //"ResetOnErrorInD2Resume"
```

Enabling `DisableLPM` won't get you anywhere since the devices are in D0 (working state) anyway while using them. The same can be said for the whole `Power` section too.

> [peripheral/assets | HUBDSM_QueryingRegistryValuesForDevice.c](https://github.com/nohuto/win-registry/blob/main/assets/usbflags/HUBDSM_QueryingRegistryValuesForDevice.c)  
> [peripheral/assets | HUBMISC_QueryAndCacheRegistryValuesForDevice.c](https://github.com/nohuto/win-registry/blob/main/assets/usbflags/HUBMISC_QueryAndCacheRegistryValuesForDevice.c)  
> [peripheral/assets | HUBREG_OpenCreateUsbflagsDeviceKey.c](https://github.com/nohuto/win-registry/blob/main/assets/usbflags/HUBREG_OpenCreateUsbflagsDeviceKey.c)  
> [peripheral/assets | HUBREG_QueryUsbflagsValuesForDevice.c](https://github.com/nohuto/win-registry/blob/main/assets/usbflags/HUBREG_QueryUsbflagsValuesForDevice.c)  
> [peripheral/assets | HUBREG_QueryHubErrataFlags.c](https://github.com/nohuto/win-registry/blob/main/assets/usbflags/HUBREG_QueryHubErrataFlags.c)  
> [peripheral/assets | HUBREG_QueryUsbflagsAlternateSettingFilter.c](https://github.com/nohuto/win-registry/blob/main/assets/usbflags/HUBREG_QueryUsbflagsAlternateSettingFilter.c)  
> [peripheral/assets | RegQueryGenericCompositeUSBDeviceString.c](https://github.com/nohuto/win-registry/blob/main/assets/usbflags/RegQueryGenericCompositeUSBDeviceString.c)  
> [peripheral/assets | GetConfigValue.c](https://github.com/nohuto/win-registry/blob/main/assets/usbflags/GetConfigValue.c)  
> [peripheral/assets | Controller_IsRegKeySetToDisableS0Idle.c](https://github.com/nohuto/win-registry/blob/main/assets/usbflags/Controller_IsRegKeySetToDisableS0Idle.c)  
> [peripheral/assets | Controller_PopulateRegistryOverrideForSetMultiTTBitFlag.c](https://github.com/nohuto/win-registry/blob/main/assets/usbflags/Controller_PopulateRegistryOverrideForSetMultiTTBitFlag.c)  
> [peripheral/assets | Controller_PopulateTestRegistrySettings.c](https://github.com/nohuto/win-registry/blob/main/assets/usbflags/Controller_PopulateTestRegistrySettings.c)  
> [peripheral/assets | Registry_InitializeAllow64KLowOrFullSpeedControlTransfersFlag.c](https://github.com/nohuto/win-registry/blob/main/assets/usbflags/Registry_InitializeAllow64KLowOrFullSpeedControlTransfersFlag.c)

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

For entries described as "any nonzero", the code treats the DWORD as a boolean, means any nonzero value is equivalent to `1`. Default data is unknown for most values as the driver code only reads the registry and handles fallbacks, note that this is currently based on USBHUB3.sys only, means it's not complete (USBXHCI.sys was used for DisableHCS0Idle & TestRunEsmInWorkItem, Ucx01000.sys for Allow64KLowOrFullSpeedControlTransfers, usbccgp.sys for GenericCompositeUSBDeviceString).

```c
// HUBREG_QueryGlobalUsb20HardwareLpmSettings
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\Usb20HardwareLpm"; // g_Usb20HardwareLpmKeyName (aRegistryMachin_8)
    "Usb20HardwareLpmOverride" = 1; // REG_DWORD, default behavior enabled, 0 disables it
    "Usb20HardwareLpmTimeout" = 2; // REG_DWORD, accepted range 0-255

// HUBREG_OpenQueryAttemptRecoveryFromUsbPowerDrainValue
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\AutomaticSurpriseRemoval"; // g_UsbAutomaticSurpriseRemovalKeyName (aRegistryMachin_6)
    "AttemptRecoveryFromUsbPowerDrain" = 0; // REG_DWORD, is used to stop USB devices when your screen is off, obviously only for laptop users

// HUBREG_QueryUsbHardwareVerifierValue
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\HardwareVerifier"; // g_HwVerifierKeyName (aRegistryMachin_7)
    "<VID><PID><REV>\\usbUpto20|usb2X|usb30\\device" = ?; // REG_DWORD, first lookup
    "<VID><PID>\\usbUpto20|usb2X|usb30\\device" = ?; // REG_DWORD, fallback
    "global\\usbUpto20|usb2X|usb30\\device" = ?; // REG_DWORD, last fallback

// HUBREG_QueryGlobalUsbLtmSettings
"HKLM\\SYSTEM\\CurrentControlSet\\Control\\usb\\UsbLtm"; // g_UsbLtmKeyName (aRegistryMachin_4)
    "UsbLtmEnable" = 0; // REG_DWORD, nonzero enables USB LTM

"HKLM\\SYSTEM\\CurrentControlSet\\Control\\USB";
    "DualRoleFeaturesTestOverride" = ?; // REG_DWORD, queried from GetPersistedKeyPath
    "UcmIsPresent" = ?; // REG_DWORD

// these are taken from the W10 source, they seem to exist on latest builds (they do exist in usbport.sys on 23H2)

"HKLM\\SYSTEM\\CurrentControlSet\\Services\\usb";
    "debuglevel" = 0; // REG_DWORD, default to 1/2 when DEBUG1/DEBUG2 builds, higher numbers enable more logs
    "debuglogmask" = 0xFFFFFFFE; // REG_DWORD, bitmask for log categories
    "debuglogenable" = 1; // REG_DWORD (bool), enables debug log output
    "debugcatc" = 0; // REG_DWORD (bool), enables CATC analyzer trigger
    "DisableSelectiveSuspend" = 0; // REG_DWORD (bool), global disable for selective suspend (GlobalUsbhubLegacyValues?)
    "DisableCcDetect" = 0; // REG_DWORD (bool), global disable for CC detection
    "EnPMDebug" = 0; // REG_DWORD (bool), for debugging power management
    "ForceHcD3NoWakeArm" = 0 // REG_DWORD (bool), prevents wake-arming when forcing HC to D3
    "EnableDCA" = 0 // REG_DWORD (bool), enables direct controller access (HCT diagnostics)
    "ForcePortsHighSpeed" = 0; // REG_DWORD (bool), forces ports to remain under EHCI (HCT compatibility)

// "This class is reserved for USB host controllers and USB hubs", I'll add them here as they're also in usbport.sys and also taken from the W10 source

"HKLM\\System\\CurrentControlSet\\Control\\Class\\{36FC9E60-C465-11CF-8056-444553540000}\\<instance>";
    "HcFlavor" = ? // REG_DWORD, auto detect
    "TotalBusBandwidth" = ? // REG_DWORD, calculated from miniport registration (bits/ms), overrides bus bandwidth accounting
    "HcDisableAllSelectiveSuspend" = 0 (non-IA64), 1 (IA64); // REG_DWORD, nonzero disables selective suspend
    "CommonBuffer2GBLimit" = 0; // REG_DWORD, when nonzero, forces common buffers below 2GB ("Limit common buffer allocations for the miniport to the physical address range below 2GB.  Only bits 0 through 30 of the physical address can be set.  Bit 31 of the physical address cannot be set.")
    "ForceHCResetOnResume" = 0; // REG_DWORD, forces controller reset on resume
    "FastResumeEnable" = 0; // REG_DWORD, enables fast S0 resume

    //HcDisableSelectiveSuspend

// miscellaneous note for future reference
"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Usb\\Ceip" // UsbhUpdateRegSurpriseRemovalCount
    "BootPathSurpriseRemovalCount" = ?;
```

> [peripheral/assets | GetPersistedKeyPath.c](https://github.com/nohuto/win-registry/blob/main/assets/usb/GetPersistedKeyPath.c)  
> [peripheral/assets | HUBREG_OpenQueryAttemptRecoveryFromUsbPowerDrainValue.c](https://github.com/nohuto/win-registry/blob/main/assets/usb/HUBREG_OpenQueryAttemptRecoveryFromUsbPowerDrainValue.c)  
> [peripheral/assets | HUBREG_QueryGlobalUsb20HardwareLpmSettings.c](https://github.com/nohuto/win-registry/blob/main/assets/usb/HUBREG_QueryGlobalUsb20HardwareLpmSettings.c)  
> [peripheral/assets | HUBREG_QueryGlobalUsbLtmSettings.c](https://github.com/nohuto/win-registry/blob/main/assets/usb/HUBREG_QueryGlobalUsbLtmSettings.c)  
> [peripheral/assets | HUBREG_QueryUsbHardwareVerifierValue.c](https://github.com/nohuto/win-registry/blob/main/assets/usb/HUBREG_QueryUsbHardwareVerifierValue.c)  
> [peripheral/assets | ReadManifestAssignedValue.c](https://github.com/nohuto/win-registry/blob/main/assets/usb/ReadManifestAssignedValue.c)  
> [peripheral/assets | UsbDualRoleFeaturesQueryLocalMachine.c](https://github.com/nohuto/win-registry/blob/main/assets/usb/UsbDualRoleFeaturesQueryLocalMachine.c)

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
    "DisableSelectiveSuspendUI" = ?; // REG_DWORD
    "MsOsDescriptorMode" = ?; // REG_DWORD, valid values are 0-2
    "EnableDiagnosticMode" = ?; // REG_DWORD, nonzero enables diagnostic mode
    "DisableOnSoftRemove" = 1; // REG_DWORD, default behavior enabled, 0 disables it
    "DisableUxdSupport" = ?; // REG_DWORD, nonzero disables UXD support
    "EnableExtendedValidation" = ?; // REG_DWORD
    "WakeOnConnectUI" = ?; // REG_DWORD, nonzero enables wake on connect UI ("This controls the UI check box 'Allow this device to wake the system'. Essentially this is control for the wake on connect feature.")
    "PreventDebounceTimeForSuperSpeedDevices" = ?; // REG_DWORD, nonzero enables extra debounce handling ("Checks if we need to give extra time to SuperSpeed devices before talking to them")

    // miscellaneous ones from GlobalUsbhubValues
    "UsbDebugModeEnable" = ?;
    "BreakOnHubException" = ?;
    "debuglevel" = ?;
    "DebugLogMask" = ?;
    "DebugLogEnable" = ?;
    "DisableHardReset" = ?;
    "BreakOnReplicant" = ?;
    "BreakOnEnumFailure" = ?;
    "UseIoErrorLog" = ?;
    "ForceResetOnResume" = ?;
    "DisableFastResume" = ?;
    "LogSize" = ?;
    "IdleTimeout" = ?;

// HUBREG_QueryGlobalUxdSettings (the defaults were taken from the W10 source)
"HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\policy"; // g_UxdGlobalSettingsKey (aRegistryMachin_12)
    "UxdGlobalDeleteOnShutdown" = 0; // REG_DWORD, nonzero enables delete on shutdown
    "UxdGlobalDeleteOnReload" = 0; // REG_DWORD, nonzero enables delete on reload
    "UxdGlobalDeleteOnDisconnect" = 0; // REG_DWORD, nonzero enables delete on disconnect
    "UxdGlobalEnable" = 0; // REG_DWORD, nonzero enables UXD globally

// HUBREG_QueryUxdDeviceKey / HUBREG_DeleteUxdDeviceKey
"HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\devices"; // g_UxdDeviceSettingsKey (aRegistryMachin_5)
    "%04X%04X%04X" = ?; // value name from VID/PID/REV

// HUBREG_GetUxdPnpValue
"HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbhub\\uxd_control\\pnp"; // g_UxdGuidSettingsKey (aRegistryMachin_3)
    "{GUID}" = ?; // value name from RtlStringFromGUID
```

> [peripheral/assets | HUBREG_QueryUxdDeviceKey.c](https://github.com/nohuto/win-registry/blob/main/assets/usbhub/HUBREG_QueryUxdDeviceKey.c)  
> [peripheral/assets | HUBREG_DeleteUxdDeviceKey.c](https://github.com/nohuto/win-registry/blob/main/assets/usbhub/HUBREG_DeleteUxdDeviceKey.c)  
> [peripheral/assets | HUBREG_QueryGlobalUxdSettings.c](https://github.com/nohuto/win-registry/blob/main/assets/usbhub/HUBREG_QueryGlobalUxdSettings.c)  
> [peripheral/assets | HUBREG_QueryGlobalHubValues.c](https://github.com/nohuto/win-registry/blob/main/assets/usbhub/HUBREG_QueryGlobalHubValues.c)  
> [peripheral/assets | HUBREG_GetUxdPnpValue.c](https://github.com/nohuto/win-registry/blob/main/assets/usbhub/HUBREG_GetUxdPnpValue.c)

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
//HKCU\Control Panel\Mouse\MouseSensitivity	Type: REG_SZ, Length: 6, Data: 10 // pointer speed, reapplies current active speed

// Disabled
HKCU\Control Panel\Mouse\MouseTrails	Type: REG_SZ, Length: 4, Data: 0
HKCU\Control Panel\Mouse\MouseThreshold1	Type: REG_SZ, Length: 4, Data: 0
HKCU\Control Panel\Mouse\MouseThreshold2	Type: REG_SZ, Length: 4, Data: 0
HKCU\Control Panel\Mouse\MouseSpeed	Type: REG_SZ, Length: 4, Data: 0
//HKCU\Control Panel\Mouse\MouseSensitivity	Type: REG_SZ, Length: 6, Data: 10 // pointer speed, reapplies current active speed
```

The main option doesn't change `MouseSensitivity` (leaves it at `10`).

It's recommended to change the pointer speed via `Bluetooth & devices > Mouse`, instead of `Mouse Properties`. Reason is simply that via `Mouse Properties` is only exposes 1, 2, 4, 6, 8, 10... 20 (step = 2 steps), the system settings exposes every single step (they both do the exact same, apart from the fact that four other values are reapplied via mouse properties, see above).

---

`Ease Cursor Movement between Displays`:  
Controls whether the pointer jumps over the non-overlapping seam between misaligned monitors so that it doesn't get stuck on edges/corners when switching between screens. If this option is disabled, the cursor will stop at these seams instead of crossing them.

---

Miscellaneous notes:
```c
"HKCU\Control Panel\Cursors\CursorBaseSize","Type: REG_DWORD, Length: 4, Data: 32"
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

# StorNVMe Values

This option serves as a general values overview for the `stornvme` key. Several values are applied, some have been changed, others are default values. The applied data is sometimes pure speculation.

See win-registry repo for a list of `CCS\\Services\\stornvme\\Parameters\\...` values/defaults/notes:
> https://github.com/nohuto/win-registry#stornvme-values

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

```json
{
  "File": "AutoPlay.admx",
  "CategoryName": "AutoPlay",
  "PolicyName": "NoAutorun",
  "NameSpace": "Microsoft.Policies.AutoPlay",
  "Supported": "WindowsVista - At least Windows Vista",
  "DisplayName": "Set the default behavior for AutoRun",
  "ExplainText": "This policy setting sets the default behavior for Autorun commands. Autorun commands are generally stored in autorun.inf files. They often launch the installation program or other routines. Prior to Windows Vista, when media containing an autorun command is inserted, the system will automatically execute the program without user intervention. This creates a major security concern as code may be executed without user's knowledge. The default behavior starting with Windows Vista is to prompt the user whether autorun command is to be run. The autorun command is represented as a handler in the Autoplay dialog. If you enable this policy setting, an Administrator can change the default Windows Vista or later behavior for autorun to: a) Completely disable autorun commands, or b) Revert back to pre-Windows Vista behavior of automatically executing the autorun command. If you disable or not configure this policy setting, Windows Vista or later will prompt the user whether autorun command is to be run.",
  "KeyPath": [
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
  ],
  "Elements": [
    { "Type": "Enum", "ValueName": "NoAutorun", "Items": [
        { "DisplayName": "Do not execute any autorun commands", "Data": "1" },
        { "DisplayName": "Automatically execute autorun commands", "Data": "2" }
      ]
    }
  ]
},
{
  "File": "AutoPlay.admx",
  "CategoryName": "AutoPlay",
  "PolicyName": "DontSetAutoplayCheckbox",
  "NameSpace": "Microsoft.Policies.AutoPlay",
  "Supported": "WindowsVista - At least Windows Vista",
  "DisplayName": "Prevent AutoPlay from remembering user choices.",
  "ExplainText": "This policy setting allows you to prevent AutoPlay from remembering user's choice of what to do when a device is connected. If you enable this policy setting, AutoPlay prompts the user to choose what to do when a device is connected. If you disable or do not configure this policy setting, AutoPlay remembers user's choice of what to do when a device is connected.",
  "KeyPath": [
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
  ],
  "ValueName": "DontSetAutoplayCheckbox",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
{
  "File": "AutoPlay.admx",
  "CategoryName": "AutoPlay",
  "PolicyName": "Autorun",
  "NameSpace": "Microsoft.Policies.AutoPlay",
  "Supported": "Win2k - At least Windows 2000",
  "DisplayName": "Turn off Autoplay",
  "ExplainText": "This policy setting allows you to turn off the Autoplay feature. Autoplay begins reading from a drive as soon as you insert media in the drive. As a result, the setup file of programs and the music on audio media start immediately. Prior to Windows XP SP2, Autoplay is disabled by default on removable drives, such as the floppy disk drive (but not the CD-ROM drive), and on network drives. Starting with Windows XP SP2, Autoplay is enabled for removable drives as well, including Zip drives and some USB mass storage devices. If you enable this policy setting, Autoplay is disabled on CD-ROM and removable media drives, or disabled on all drives. This policy setting disables Autoplay on additional types of drives. You cannot use this setting to enable Autoplay on drives on which it is disabled by default. If you disable or do not configure this policy setting, AutoPlay is enabled. Note: This policy setting appears in both the Computer Configuration and User Configuration folders. If the policy settings conflict, the policy setting in Computer Configuration takes precedence over the policy setting in User Configuration.",
  "KeyPath": [
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
  ],
  "Elements": [
    { "Type": "Enum", "ValueName": "NoDriveTypeAutoRun", "Items": [
        { "DisplayName": "CD-ROM and removable media drives", "Data": "181" },
        { "DisplayName": "All drives", "Data": "255" }
      ]
    }
  ]
},
{
  "File": "AutoPlay.admx",
  "CategoryName": "AutoPlay",
  "PolicyName": "NoAutoplayfornonVolume",
  "NameSpace": "Microsoft.Policies.AutoPlay",
  "Supported": "Windows7 - At least Windows Server 2008 R2 or Windows 7",
  "DisplayName": "Disallow Autoplay for non-volume devices",
  "ExplainText": "This policy setting disallows AutoPlay for MTP devices like cameras or phones. If you enable this policy setting, AutoPlay is not allowed for MTP devices like cameras or phones. If you disable or do not configure this policy setting, AutoPlay is enabled for non-volume devices.",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\Explorer",
    "HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer"
  ],
  "ValueName": "NoAutoplayfornonVolume",
  "Elements": [
    { "Type": "EnabledValue", "Data": "1" },
    { "Type": "DisabledValue", "Data": "0" }
  ]
},
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

The value exists by default and is set to `100` decimal (`64` hex). Reducing it doesn't "reduce your latency", leave it default. E.g. setting it to `1` (MouseDataQueueSize) = queue size is 24 bytes (1 mouse packet) = one packet can be buffered, so bursts are much more likely to be dropped = worse. Decreasing it for saving memory is also very minimal, therefore there's no reason I could currently think of for decreasing it below 100.

```inf
; keyboard.inf
[KbdClass.HW]
AddReg = KbdClass_HW_AddReg

[KbdClass_HW_AddReg]
HKR,,"KeyboardDataQueueSize",0x00010003,100

; msmouse.inf
[PS2_Inst.HW]
AddReg = PS2_Inst.HW.AddReg

[PS2_Inst.HW.AddReg]
HKR,,"MouseDataQueueSize",0x00010003,100
```

"Specifies the number of mouse events to be buffered internally by the driver, in nonpaged pool. The allocated size, in bytes, of the internal buffer is this value times the size of the MOUSE_INPUT_DATA structure (defined in NTDDMOU.H)."

## MouseDataQueueSize

- not present = default `100` -> final `2400`
- present and `0` = forced to `100` -> final `2400`
- present and `1-0x0AAAAAAA` -> final `24 * raw`
- present and `> 0x0AAAAAAA` -> final `2400`

```c
*((_DWORD *)&WPP_MAIN_CB.Reserved + 2) = 100; // default

*(_QWORD *)(Pool2 + 16) = L"MouseDataQueueSize";
*(_QWORD *)(Pool2 + 24) = &WPP_MAIN_CB.Reserved + 1;

v10 = *((_DWORD *)&WPP_MAIN_CB.Reserved + 2);
if ( !*((_DWORD *)&WPP_MAIN_CB.Reserved + 2) )
{
  v10 = 100; // data 0 = 100
  goto LABEL_9;
}
if ( *((_DWORD *)&WPP_MAIN_CB.Reserved + 2) <= 0xAAAAAAAu )
{
LABEL_9:
  v11 = 24 * v10; // convert packet count to queue bytes
  goto LABEL_10;
}
v11 = 2400; // clamp
LABEL_10:
*((_DWORD *)&WPP_MAIN_CB.Reserved + 2) = v11;
```

## KeyboardDataQueueSize

- not present = default `100` -> final `1200`
- present and `0` = forced to `100` -> final `1200`
- present and `1-0x15555555` -> final `12 * raw`
- present and `> 0x15555555` -> final `1200`

```c
dword_1C000A234 = 100; // default

*(_QWORD *)(Pool2 + 16) = L"KeyboardDataQueueSize";
*(_QWORD *)(Pool2 + 24) = &dword_1C000A234;

v14 = dword_1C000A234;
if ( dword_1C000A234 )
{
  if ( (unsigned int)dword_1C000A234 > 0x15555555 )
  {
    v15 = 1200; // clamp
    goto LABEL_22;
  }
}
else
{
  v14 = 100; // data 0 = 100
}
v15 = 12 * v14; // convert packet count to queue bytes
LABEL_22:
dword_1C000A234 = v15;
```

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

// ?
"HKCU\Software\Microsoft\Touchpad\TouchpadDesiredVisibility","Length: 16"
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

`WakeOnInputDeviceTypes` probably handles wake on input behavior for all input devices - each bit represents a input device type? Since `\SYSTEM\INPUT` only queries two values I'll add the second on in here.
```
\Registry\Machine\SYSTEM\INPUT : UnDimOnInputDeviceTypes
\Registry\Machine\SYSTEM\INPUT : WakeOnInputDeviceTypes
```
`UnDimOnInputDeviceTypes` probably refers to any dimmed elemets (pure speculation)? Disabling it wouldn't make sense. Values named `ButtonsAsVKeys` & `HardwareButtonsAsVKeys` may exist in `SYSTEM\\INPUT\\BUTTONS`, but I haven't looked further into it.

Default values:
```c
WakeOnInputDeviceTypes = 46
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