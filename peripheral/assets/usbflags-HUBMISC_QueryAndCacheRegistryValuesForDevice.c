__int64 __fastcall HUBMISC_QueryAndCacheRegistryValuesForDevice(__int64 a1)
{
  int v1;  ebx
  int UsbflagsValuesForDevice;  esi
  __int64 v4;  rcx
  __int64 result;  rax
  _BYTE v6[8];  [rsp+40h] [rbp-28h] BYREF
  _BYTE v7[8];  [rsp+48h] [rbp-20h] BYREF
  _BYTE v8[8];  [rsp+50h] [rbp-18h] BYREF

  v1 = a1 + 1988;
  HUBMISC_ConvertUsbDeviceIdsToString(a1 + 1988, v8, v7, v6);
  UsbflagsValuesForDevice = HUBREG_QueryUsbflagsValuesForDevice(
                              (volatile signed __int32 )a1,
                              (int)v8,
                              (int)v7,
                              (int)v6);
  HUBREG_QueryUsbHardwareVerifierValue(
    v1,
    (unsigned int)v8,
    (unsigned int)v7,
    (unsigned int)v6,
    (__int64)&g_HwVerifierDeviceName,
    (_QWORD )((_QWORD )(a1 + 8) + 1432LL),
    a1 + 2436);
  if ( UsbflagsValuesForDevice  0 )
  {
    (_DWORD )(a1 + 2432) = 1073807366;
    if ( SLOBYTE(WPP_MAIN_CB.Queue.Wcb.DmaWaitEntry.Blink)  0 )
      McTemplateK0pq_EtwWriteTransfer(
        v4,
        &USBHUB3_ETW_EVENT_REGISTRY_FAILURE,
        a1 + 1516,
        (_QWORD )(a1 + 24),
        UsbflagsValuesForDevice);
  }
  result = 4065LL;
  if ( UsbflagsValuesForDevice = 0 )
    return 4077LL;
  return result;
}