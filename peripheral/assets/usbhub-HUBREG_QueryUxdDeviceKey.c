__int64 __fastcall HUBREG_QueryUxdDeviceKey(__int64 a1, __int64 a2)
{
  NTSTATUS v4;  ebx
  int v5;  edx
  __int64 v7;  [rsp+20h] [rbp-98h]
  __int64 v8;  [rsp+40h] [rbp-78h] BYREF
  struct _UNICODE_STRING DestinationString;  [rsp+48h] [rbp-70h] BYREF
  __int64 v10;  [rsp+58h] [rbp-60h] BYREF

  (_QWORD )&DestinationString.Length = 3407872LL;
  DestinationString.Buffer = (wchar_t )&v10;
  v8 = 0LL;
  v4 = ((__int64 (__fastcall )(PWDF_DRIVER_GLOBALS, _QWORD, void , __int64, _QWORD, __int64 ))(WdfFunctions_01015
                                                                                                  + 1832))(
         WdfDriverGlobals,
         0LL,
         &g_UxdDeviceSettingsKey,
         131097LL,
         0LL,
         &v8);
  if ( v4 = 0 )
  {
    LODWORD(v7) = (unsigned __int16 )(a1 + 2000);
    v4 = RtlUnicodeStringPrintf(
           &DestinationString,
           L%04X%04X%04X, // "%04X%04X%04X"
           (unsigned __int16 )(a1 + 1996),
           (unsigned __int16 )(a1 + 1998),
           v7);
    if ( v4 = 0 )
    {
      v4 = ((__int64 (__fastcall )(PWDF_DRIVER_GLOBALS, __int64, struct _UNICODE_STRING , __int64, __int64, _QWORD, _QWORD))(WdfFunctions_01015 + 1880))(
             WdfDriverGlobals,
             v8,
             &DestinationString,
             68LL,
             a2,
             0LL,
             0LL);
    }
    else if ( WPP_RECORDER_INITIALIZED != (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
    {
      LOBYTE(v5) = 2;
      WPP_RECORDER_SF_d(
        (_QWORD )((_QWORD )(a1 + 8) + 1432LL),
        v5,
        5,
        104,
        (__int64)&WPP_7a0afab5c79d3741c23ff4ee70090e0b_Traceguids,
        v4);
    }
  }
  if ( v8 )
    ((void (__fastcall )(PWDF_DRIVER_GLOBALS))(WdfFunctions_01015 + 1848))(WdfDriverGlobals);
  return (unsigned int)v4;
}