__int64 __fastcall HUBREG_OpenCreateUsbflagsDeviceKey(
        __int64 a1,
        __int64 a2,
        __int64 a3,
        unsigned int a4,
        _QWORD a5,
        _QWORD a6,
        char a7,
        __int64 a8)
{
  void v8;  rsi
  NTSTATUS PersistedStateLocation;  ebx
  __int64 Pool2;  rax
  const wchar_t v11;  rcx
  __int64 v12;  rdx
  unsigned int v13;  r14d
  int v14;  edx
  int v15;  r9d
  unsigned int v17;  [rsp+50h] [rbp-99h] BYREF
  __int64 v18;  [rsp+58h] [rbp-91h] BYREF
  unsigned int v19;  [rsp+60h] [rbp-89h]
  struct _UNICODE_STRING DestinationString;  [rsp+68h] [rbp-81h] BYREF
  struct _UNICODE_STRING v21;  [rsp+78h] [rbp-71h] BYREF
  __int64 v22;  [rsp+88h] [rbp-61h]
  __int64 v23;  [rsp+90h] [rbp-59h]
  __int64 v24;  [rsp+98h] [rbp-51h]
  _QWORD v25;  [rsp+A0h] [rbp-49h]
  char v26;  [rsp+A8h] [rbp-41h] BYREF

  v22 = a3;
  v24 = a1;
  v19 = a4;
  v23 = a2;
  v25 = a5;
  (_QWORD )&v21.Length = 3407872LL;
  v21.Buffer = (wchar_t )&v26;
  v17 = 0;
  v18 = 0LL;
  DestinationString = 0LL;
  if ( a5 )
    a5 = 0LL;
  a6 = 0LL;
  v8 = 0LL;
  if ( a7 != 1 )
  {
    v11 = LRegistryMachineSystemCurrentControlSetControlusbflags;
    v12 = 0x7FFFLL;
    while ( v11 )
    {
      ++v11;
      if ( !--v12 )
        goto LABEL_17;
    }
    DestinationString.Buffer = LRegistryMachineSystemCurrentControlSetControlusbflags;
    DestinationString.Length = 2  (0x7FFF - v12);
    DestinationString.MaximumLength = DestinationString.Length + 2;
    goto LABEL_17;
  }
  PersistedStateLocation = RtlGetPersistedStateLocation(
                             LUsbFlags,
                             0LL,
                             LRegistryMachineSystemCurrentControlSetControlusbflags,
                             0LL,
                             0LL,
                             0,
                             &v17);
  if ( PersistedStateLocation == -2147483643 )
  {
    Pool2 = ExAllocatePool2(64LL, v17, 1681082453LL);
    v8 = (void )Pool2;
    if ( Pool2 )
    {
      PersistedStateLocation = RtlGetPersistedStateLocation(
                                 LUsbFlags,
                                 0LL,
                                 LRegistryMachineSystemCurrentControlSetControlusbflags,
                                 0LL,
                                 Pool2,
                                 v17,
                                 0LL);
      if ( PersistedStateLocation  0 )
      {
        if ( WPP_RECORDER_INITIALIZED != (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
          WPP_RECORDER_SF_d(
            a8,
            2,
            5,
            10,
            (__int64)&WPP_7a0afab5c79d3741c23ff4ee70090e0b_Traceguids,
            PersistedStateLocation);
LABEL_34
        ExFreePoolWithTag(v8, 0x64334855u);
        goto LABEL_35;
      }
      RtlUnicodeStringInit(&DestinationString, (NTSTRSAFE_PCWSTR)v8);
    }
LABEL_17
    v13 = v19;
    PersistedStateLocation = ((__int64 (__fastcall )(PWDF_DRIVER_GLOBALS, _QWORD, struct _UNICODE_STRING , _QWORD, _QWORD, __int64 ))(WdfFunctions_01015 + 1832))(
                               WdfDriverGlobals,
                               0LL,
                               &DestinationString,
                               v19,
                               0LL,
                               &v18);
    if ( PersistedStateLocation == -1073741772 )
    {
      if ( a7 != 1 )
      {
LABEL_21
        if ( WPP_RECORDER_INITIALIZED == (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
          goto LABEL_33;
        v15 = 12;
        goto LABEL_32;
      }
      PersistedStateLocation = ((__int64 (__fastcall )(PWDF_DRIVER_GLOBALS, _QWORD, struct _UNICODE_STRING , _QWORD, _DWORD, _QWORD, _QWORD, __int64 ))(WdfFunctions_01015 + 1840))(
                                 WdfDriverGlobals,
                                 0LL,
                                 &DestinationString,
                                 v13,
                                 0,
                                 0LL,
                                 0LL,
                                 &v18);
    }
    if ( PersistedStateLocation  0 )
      goto LABEL_21;
    PersistedStateLocation = RtlUnicodeStringPrintf(&v21, L%S%S%S, v24, v23, v22); // "%S%S%S"
    if ( PersistedStateLocation  0 )
    {
      if ( WPP_RECORDER_INITIALIZED == (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
        goto LABEL_33;
      v15 = 13;
      goto LABEL_32;
    }
    PersistedStateLocation = ((__int64 (__fastcall )(PWDF_DRIVER_GLOBALS, __int64, struct _UNICODE_STRING , __int64, _QWORD, _QWORD ))(WdfFunctions_01015 + 1832))(
                               WdfDriverGlobals,
                               v18,
                               &v21,
                               131097LL,
                               0LL,
                               a6);
    if ( PersistedStateLocation == -1073741772 )
    {
      if ( a7 != 1 )
      {
LABEL_30
        if ( WPP_RECORDER_INITIALIZED == (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
          goto LABEL_33;
        v15 = 14;
LABEL_32
        LOBYTE(v14) = 2;
        WPP_RECORDER_SF_d(
          a8,
          v14,
          5,
          v15,
          (__int64)&WPP_7a0afab5c79d3741c23ff4ee70090e0b_Traceguids,
          PersistedStateLocation);
LABEL_33
        if ( !v8 )
          goto LABEL_35;
        goto LABEL_34;
      }
      PersistedStateLocation = ((__int64 (__fastcall )(PWDF_DRIVER_GLOBALS, __int64, struct _UNICODE_STRING , __int64, _DWORD, _QWORD, _QWORD, _QWORD ))(WdfFunctions_01015 + 1840))(
                                 WdfDriverGlobals,
                                 v18,
                                 &v21,
                                 983103LL,
                                 0,
                                 0LL,
                                 0LL,
                                 a6);
    }
    if ( PersistedStateLocation = 0 )
      goto LABEL_33;
    goto LABEL_30;
  }
  if ( WPP_RECORDER_INITIALIZED != (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
    WPP_RECORDER_SF_d(a8, 2, 5, 11, (__int64)&WPP_7a0afab5c79d3741c23ff4ee70090e0b_Traceguids, PersistedStateLocation);
LABEL_35
  if ( PersistedStateLocation = 0 )
  {
    if ( !v25 )
    {
LABEL_42
      ((void (__fastcall )(PWDF_DRIVER_GLOBALS))(WdfFunctions_01015 + 1848))(WdfDriverGlobals);
      return (unsigned int)PersistedStateLocation;
    }
    v25 = v18;
  }
  else
  {
    if ( a6 )
    {
      ((void (__fastcall )(PWDF_DRIVER_GLOBALS))(WdfFunctions_01015 + 1848))(WdfDriverGlobals);
      a6 = 0LL;
    }
    if ( v18 )
      goto LABEL_42;
  }
  return (unsigned int)PersistedStateLocation;
}