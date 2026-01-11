__int64 __fastcall HUBREG_OpenQueryAttemptRecoveryFromUsbPowerDrainValue(_DWORD a1)
{
  __int64 v2;  r13
  wchar_t Pool2;  r12
  int v4;  eax
  int v5;  edx
  unsigned int v6;  ebx
  _QWORD v7;  r14
  int v8;  eax
  int v9;  edx
  int v10;  edx
  unsigned int PersistedStateLocation;  eax
  char v12;  al
  int v14;  r9d
  NTSTATUS v15;  eax
  __int64 v16;  [rsp+28h] [rbp-40h]
  __int64 v17;  [rsp+28h] [rbp-40h]
  char v18;  [rsp+28h] [rbp-40h]
  __int64 v19;  [rsp+40h] [rbp-28h] BYREF
  __int64 v20;  [rsp+48h] [rbp-20h] BYREF
  struct _UNICODE_STRING DestinationString;  [rsp+50h] [rbp-18h] BYREF
  char v23;  [rsp+C0h] [rbp+58h]
  unsigned int v24;  [rsp+C8h] [rbp+60h] BYREF

  DestinationString = 0LL;
  v24 = 0;
  v2 = ((__int64 (__fastcall )(PWDF_DRIVER_GLOBALS, WDFDRIVER__ , void ))(WdfFunctions_01015 + 1616))(
         WdfDriverGlobals,
         WdfDriverGlobals-Driver,
         off_1C006A1E8);
  v19 = 0LL;
  v20 = 0LL;
  v23 = 0;
  Pool2 = 0LL;
  v16 = &v19;
  v4 = ((__int64 (__fastcall )(PWDF_DRIVER_GLOBALS, _QWORD, void , __int64))(WdfFunctions_01015 + 1832))(
         WdfDriverGlobals,
         0LL,
         &g_UsbAutomaticSurpriseRemovalKeyName,
         131097LL);
  v6 = v4;
  if ( v4 = 0 )
  {
    v8 = ((__int64 (__fastcall )(PWDF_DRIVER_GLOBALS, __int64, const wchar_t , _DWORD ))(WdfFunctions_01015 + 1920))(
           WdfDriverGlobals,
           v19,
           L@B, // "AttemptRecoveryFromUsbPowerDrain"
           a1);
    v6 = v8;
    if ( v8 = 0 )
    {
      v23 = 1;
    }
    else
    {
      a1 = 0;
      if ( WPP_RECORDER_INITIALIZED != (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
      {
        LOBYTE(v9) = 2;
        WPP_RECORDER_SF_d(
          (_QWORD )(v2 + 64),
          v9,
          2,
          138,
          (__int64)&WPP_7a0afab5c79d3741c23ff4ee70090e0b_Traceguids,
          v8);
      }
    }
    ((void (__fastcall )(PWDF_DRIVER_GLOBALS, __int64))(WdfFunctions_01015 + 1848))(WdfDriverGlobals, v19);
    v19 = 0LL;
    v7 = (_QWORD )(v2 + 64);
  }
  else
  {
    v7 = (_QWORD )(v2 + 64);
    if ( WPP_RECORDER_INITIALIZED != (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
    {
      LOBYTE(v5) = 2;
      WPP_RECORDER_SF_d(v7, v5, 2, 137, (__int64)&WPP_7a0afab5c79d3741c23ff4ee70090e0b_Traceguids, v4);
    }
  }
  if ( (unsigned __int8)RtlIsStateSeparationEnabled() != 1 )
    goto LABEL_13;
  LODWORD(v16) = 0;
  PersistedStateLocation = RtlGetPersistedStateLocation(
                             LUSB, // "USB"
                             0LL,
                             LRegistryMachineSystemCurrentControlSetControlusb,
                             0LL,
                             0LL,
                             v16,
                             &v24);
  v6 = PersistedStateLocation;
  if ( PersistedStateLocation == -2147483643 )
  {
    Pool2 = (wchar_t )ExAllocatePool2(64LL, v24, 1681082453LL);
    if ( Pool2 )
    {
      LODWORD(v17) = v24;
      v15 = RtlGetPersistedStateLocation(
              LUSB, // "USB"
              0LL,
              LRegistryMachineSystemCurrentControlSetControlusb,
              0LL,
              Pool2,
              v17,
              0LL);
      v6 = v15;
      if ( v15 = 0 )
      {
        v15 = RtlUnicodeStringInit(&DestinationString, Pool2);
        v6 = v15;
        if ( v15 = 0 )
        {
          v15 = ((__int64 (__fastcall )(PWDF_DRIVER_GLOBALS, _QWORD, struct _UNICODE_STRING , __int64, _QWORD, __int64 ))(WdfFunctions_01015 + 1832))(
                  WdfDriverGlobals,
                  0LL,
                  &DestinationString,
                  131097LL,
                  0LL,
                  &v20);
          v6 = v15;
          if ( v15 = 0 )
          {
            v15 = ((__int64 (__fastcall )(PWDF_DRIVER_GLOBALS, __int64, const wchar_t , __int64, _QWORD, __int64 ))(WdfFunctions_01015 + 1832))(
                    WdfDriverGlobals,
                    v20,
                    L02, // "AutomaticSurpriseRemoval"
                    131097LL,
                    0LL,
                    &v19);
            v6 = v15;
            if ( v15 = 0 )
            {
              v15 = ((__int64 (__fastcall )(PWDF_DRIVER_GLOBALS, __int64, const wchar_t , _DWORD ))(WdfFunctions_01015 + 1920))(
                      WdfDriverGlobals,
                      v19,
                      L@B, // "AttemptRecoveryFromUsbPowerDrain"
                      a1);
              v6 = v15;
              if ( v15 = 0 )
              {
                v12 = 1;
                goto LABEL_14;
              }
              if ( WPP_RECORDER_INITIALIZED == (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
                goto LABEL_30;
              v14 = 145;
            }
            else
            {
              if ( WPP_RECORDER_INITIALIZED == (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
                goto LABEL_30;
              v14 = 144;
            }
          }
          else
          {
            if ( WPP_RECORDER_INITIALIZED == (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
              goto LABEL_30;
            v14 = 143;
          }
        }
        else
        {
          if ( WPP_RECORDER_INITIALIZED == (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
            goto LABEL_30;
          v14 = 142;
        }
      }
      else
      {
        if ( WPP_RECORDER_INITIALIZED == (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
          goto LABEL_30;
        v14 = 141;
      }
      v18 = v15;
    }
    else
    {
      v6 = -1073741670;
      if ( WPP_RECORDER_INITIALIZED == (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
      {
LABEL_30
        v12 = 0;
        goto LABEL_14;
      }
      v14 = 140;
      v18 = -102;
    }
    LOBYTE(v10) = 2;
    WPP_RECORDER_SF_d(v7, v10, 2, v14, (__int64)&WPP_7a0afab5c79d3741c23ff4ee70090e0b_Traceguids, v18);
    goto LABEL_30;
  }
  if ( WPP_RECORDER_INITIALIZED != (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
  {
    LOBYTE(v10) = 2;
    WPP_RECORDER_SF_d(
      (_QWORD )(v2 + 64),
      v10,
      2,
      139,
      (__int64)&WPP_7a0afab5c79d3741c23ff4ee70090e0b_Traceguids,
      PersistedStateLocation);
  }
LABEL_13
  v12 = 0;
LABEL_14
  if ( v23 && !v12 )
  {
    if ( WPP_RECORDER_INITIALIZED != (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
    {
      LOBYTE(v10) = 3;
      WPP_RECORDER_SF_d(v7, v10, 2, 146, (__int64)&WPP_7a0afab5c79d3741c23ff4ee70090e0b_Traceguids, v6);
    }
    v6 = 0;
  }
  if ( Pool2 )
    ExFreePoolWithTag(Pool2, 0x64334855u);
  if ( v20 )
    ((void (__fastcall )(PWDF_DRIVER_GLOBALS))(WdfFunctions_01015 + 1848))(WdfDriverGlobals);
  if ( v19 )
    ((void (__fastcall )(PWDF_DRIVER_GLOBALS))(WdfFunctions_01015 + 1848))(WdfDriverGlobals);
  return v6;
}
