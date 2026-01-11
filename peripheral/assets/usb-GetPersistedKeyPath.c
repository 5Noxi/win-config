__int64 __fastcall GetPersistedKeyPath(_QWORD a1)
{
  int v2;  edx
  int PersistedStateLocation;  ebx
  int v4;  edx
  void Pool2;  rdi
  int v6;  edx
  __int64 v8;  [rsp+28h] [rbp-20h]
  unsigned int v9;  [rsp+58h] [rbp+10h] BYREF

  v9 = 0;
  PersistedStateLocation = RtlGetPersistedStateLocation(
                             LUSB, // "USB"
                             0LL,
                             LRegistryMachineSYSTEMCurrentControlSetControlUSB,
                             0LL,
                             0LL,
                             0,
                             &v9);
  if ( PersistedStateLocation == -2147483643 )
  {
    Pool2 = (void )ExAllocatePool2(64LL, v9, 1430540870LL);
    if ( Pool2 )
    {
      LODWORD(v8) = v9;
      PersistedStateLocation = RtlGetPersistedStateLocation(
                                 LUSB, // "USB"
                                 0LL,
                                 LRegistryMachineSYSTEMCurrentControlSetControlUSB,
                                 0LL,
                                 Pool2,
                                 v8,
                                 0LL);
      if ( PersistedStateLocation = 0 )
      {
        a1 = Pool2;
      }
      else
      {
        if ( WPP_RECORDER_INITIALIZED != (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
        {
          LOBYTE(v6) = 2;
          WPP_RECORDER_SF_d(
            WPP_GLOBAL_Control-DeviceExtension,
            v6,
            1,
            12,
            (__int64)&WPP_5169c4c8089132207a438b4341aed5b6_Traceguids,
            PersistedStateLocation);
        }
        ExFreePoolWithTag(Pool2, 0);
      }
    }
    else
    {
      PersistedStateLocation = -1073741670;
      if ( WPP_RECORDER_INITIALIZED != (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
        WPP_RECORDER_SF_Ld(
          WPP_GLOBAL_Control-DeviceExtension,
          v4,
          1,
          11,
          (__int64)&WPP_5169c4c8089132207a438b4341aed5b6_Traceguids,
          v9,
          154);
    }
  }
  else if ( WPP_RECORDER_INITIALIZED != (_UNKNOWN )&WPP_RECORDER_INITIALIZED )
  {
    LOBYTE(v2) = 2;
    WPP_RECORDER_SF_d(
      WPP_GLOBAL_Control-DeviceExtension,
      v2,
      1,
      10,
      (__int64)&WPP_5169c4c8089132207a438b4341aed5b6_Traceguids,
      PersistedStateLocation);
  }
  return (unsigned int)PersistedStateLocation;
}
