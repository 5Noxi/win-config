__int64 __fastcall Controller_PopulateRegistryOverrideForSetMultiTTBitFlag(__int64 a1)
{
  __int64 result; // rax
  int v3; // edx
  unsigned int v4; // [rsp+58h] [rbp+10h] BYREF
  __int64 v5; // [rsp+60h] [rbp+18h] BYREF

  v5 = 0LL;
  v4 = 0;
  result = (*(__int64 (__fastcall **)(PWDF_DRIVER_GLOBALS, _QWORD, const wchar_t *, __int64, _QWORD, __int64 *))(WdfFunctions_01023 + 1832))(
             WdfDriverGlobals,
             0LL,
             L"vx",
             131097LL,
             0LL,
             &v5);
  if ( (int)result < 0 )
  {
    if ( WPP_RECORDER_INITIALIZED != (_UNKNOWN *)&WPP_RECORDER_INITIALIZED )
    {
      LOBYTE(v3) = 3;
      result = WPP_RECORDER_SF_d(
                 *(_QWORD *)(a1 + 72),
                 v3,
                 4,
                 169,
                 (__int64)&WPP_ac07559723993fb37d1c33c002d3118e_Traceguids,
                 result);
    }
  }
  else
  {
    result = (*(__int64 (__fastcall **)(PWDF_DRIVER_GLOBALS, __int64, const wchar_t *, __int64, unsigned int *, _QWORD, _QWORD))(WdfFunctions_01023 + 1880))(
               WdfDriverGlobals,
               v5,
               L"HJ",
               4LL,
               &v4,
               0LL,
               0LL);
    if ( (int)result >= 0 )
    {
      result = v4;
      if ( v4 )
      {
        if ( v4 == 1 )
        {
          result = 0x2000000000000000LL;
          *(_QWORD *)(a1 + 336) |= 0x2000000000000000uLL;
        }
      }
      else
      {
        result = 0xDFFFFFFFFFFFFFFFuLL;
        *(_QWORD *)(a1 + 336) &= ~0x2000000000000000uLL;
      }
    }
  }
  if ( v5 )
    return (*(__int64 (__fastcall **)(PWDF_DRIVER_GLOBALS))(WdfFunctions_01023 + 1848))(WdfDriverGlobals);
  return result;
}