bool __fastcall Controller_IsRegKeySetToDisableS0Idle(__int64 a1)
{
  int v2; // eax
  int v3; // edx
  int v4; // eax
  int v5; // ecx
  int v7; // [rsp+58h] [rbp+10h] BYREF
  __int64 v8; // [rsp+60h] [rbp+18h] BYREF

  v8 = 0LL;
  v7 = 0;
  v2 = (*(__int64 (__fastcall **)(PWDF_DRIVER_GLOBALS, _QWORD, const wchar_t *, __int64, _QWORD, __int64 *))(WdfFunctions_01023 + 1832))(
         WdfDriverGlobals,
         0LL,
         L"vx",
         131097LL,
         0LL,
         &v8);
  if ( v2 >= 0 )
  {
    v4 = (*(__int64 (__fastcall **)(PWDF_DRIVER_GLOBALS, __int64, void *, __int64, int *, _QWORD, _QWORD))(WdfFunctions_01023 + 1880))(
           WdfDriverGlobals,
           v8,
           &g_DisableHCS0Idle,
           4LL,
           &v7,
           0LL,
           0LL);
    v5 = v7;
    if ( v4 < 0 )
      v5 = 0;
    v7 = v5;
  }
  else if ( WPP_RECORDER_INITIALIZED != (_UNKNOWN *)&WPP_RECORDER_INITIALIZED )
  {
    LOBYTE(v3) = 3;
    WPP_RECORDER_SF_d(*(_QWORD *)(a1 + 72), v3, 4, 21, (__int64)&WPP_ac07559723993fb37d1c33c002d3118e_Traceguids, v2);
  }
  if ( v8 )
    (*(void (__fastcall **)(PWDF_DRIVER_GLOBALS))(WdfFunctions_01023 + 1848))(WdfDriverGlobals);
  return v7 != 0;
}