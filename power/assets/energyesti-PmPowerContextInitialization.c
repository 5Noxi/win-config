__int64 __fastcall PmPowerContextInitialization(_WORD *a1, int a2)
{
  NTSTATUS DWORDValueKey; // ebx
  int v4; // edx
  int v5; // edx
  const WCHAR *v6; // rdx
  _DWORD *v7; // rdi
  unsigned int v8; // esi
  const unsigned __int16 **v9; // r14
  __int16 v10; // ax
  __int64 v11; // rdi
  int v12; // esi
  unsigned int v13; // r14d
  HANDLE v14; // rcx
  unsigned int v15; // eax
  unsigned int v17[2]; // [rsp+28h] [rbp-E0h] BYREF
  HANDLE Handle; // [rsp+30h] [rbp-D8h] BYREF
  void *DestinationString; // [rsp+38h] [rbp-D0h] BYREF
  struct _UNICODE_STRING DestinationString_8; // [rsp+40h] [rbp-C8h] BYREF
  struct _OBJECT_ATTRIBUTES ObjectAttributes_8; // [rsp+50h] [rbp-B8h] BYREF
  void *KeyHandle; // [rsp+80h] [rbp-88h] BYREF
  struct _UNICODE_STRING String; // [rsp+88h] [rbp-80h] BYREF
  _QWORD v24[10]; // [rsp+98h] [rbp-70h] BYREF
  char v25; // [rsp+E8h] [rbp-20h] BYREF

  v24[0] = L"SmallRandomReadPowerMw";
  KeyHandle = 0LL;
  v24[1] = L"SmallRandomWritePowerMw";
  v24[2] = L"SmallSequentialReadPowerMw";
  v24[3] = L"SmallSequentialWritePowerMw";
  v24[4] = L"LargeRandomReadPowerMw";
  v24[5] = L"LargeRandomWritePowerMw";
  v24[6] = L"LargeSequentialReadPowerMw";
  v24[7] = L"LargeSequentialWritePowerMw";
  v24[8] = L"FlushPowerMw";
  v17[0] = 0;
  DestinationString = 0LL;
  DWORDValueKey = 0;
  Handle = 0LL;
  DestinationString_8 = 0LL;
  String = 0LL;
  memset(&ObjectAttributes_8, 0, sizeof(ObjectAttributes_8));
  if ( a2 )
  {
    v4 = a2 - 1;
    if ( v4 )
    {
      v5 = v4 - 1;
      if ( v5 )
      {
        if ( v5 != 1 )
          return (unsigned int)DWORDValueKey;
        v6 = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Power\\EnergyEstimation\\Storage\\NVME";
      }
      else
      {
        v6 = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Power\\EnergyEstimation\\Storage\\HDD";
      }
    }
    else
    {
      v6 = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Power\\EnergyEstimation\\Storage\\SSD";
    }
  }
  else
  {
    v6 = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Power\\EnergyEstimation\\Storage\\SD";
  }
  RtlInitUnicodeString(&DestinationString_8, v6);
  ObjectAttributes_8.Length = 48;
  ObjectAttributes_8.ObjectName = &DestinationString_8;
  ObjectAttributes_8.RootDirectory = 0LL;
  ObjectAttributes_8.Attributes = 576;
  *(_OWORD *)&ObjectAttributes_8.SecurityDescriptor = 0LL;
  DWORDValueKey = ZwOpenKey(&DestinationString, 0x20019u, &ObjectAttributes_8);
  if ( DWORDValueKey >= 0 )
  {
    v7 = a1 + 84;
    v8 = 0;
    v9 = (const unsigned __int16 **)v24;
    while ( 1 )
    {
      DWORDValueKey = PmQueryDWORDValueKey(DestinationString, *v9, v17);
      if ( DWORDValueKey < 0 )
        break;
      ++v8;
      *v7 = v17[0];
      ++v9;
      ++v7;
      if ( v8 >= 9 )
      {
        DWORDValueKey = PmQueryDWORDValueKey(DestinationString, L"IdleStatesNumber", v17);
        if ( DWORDValueKey >= 0 )
        {
          v10 = v17[0];
          *a1 = v17[0];
          if ( (unsigned __int16)(v10 - 1) > 4u )
          {
            DWORDValueKey = -1073741811;
          }
          else
          {
            RtlInitUnicodeString(&DestinationString_8, L"IdleState");
            ObjectAttributes_8.RootDirectory = DestinationString;
            ObjectAttributes_8.Attributes = 576;
            ObjectAttributes_8.ObjectName = &DestinationString_8;
            ObjectAttributes_8.Length = 48;
            *(_OWORD *)&ObjectAttributes_8.SecurityDescriptor = 0LL;
            DWORDValueKey = ZwOpenKey(&KeyHandle, 0x20019u, &ObjectAttributes_8);
            if ( DWORDValueKey >= 0 )
            {
              v11 = 0LL;
              v12 = 0;
              String.MaximumLength = 28;
              String.Buffer = (PWSTR)&v25;
              if ( *a1 )
              {
                while ( 1 )
                {
                  v13 = v12 + 1;
                  String.Length = 26;
                  DWORDValueKey = RtlIntegerToUnicodeString(v12 + 1, 0xAu, &String);
                  if ( DWORDValueKey < 0 )
                    break;
                  ObjectAttributes_8.RootDirectory = KeyHandle;
                  ObjectAttributes_8.Length = 48;
                  ObjectAttributes_8.ObjectName = &String;
                  ObjectAttributes_8.Attributes = 576;
                  *(_OWORD *)&ObjectAttributes_8.SecurityDescriptor = 0LL;
                  DWORDValueKey = ZwOpenKey(&Handle, 0x20019u, &ObjectAttributes_8);
                  if ( DWORDValueKey < 0 )
                    break;
                  v11 = (__int64)&a1[16 * v12 + 4];
                  DWORDValueKey = PmQueryDWORDValueKey(Handle, L"IdleExitLatencyMs", v17);
                  if ( DWORDValueKey < 0 )
                    break;
                  *(_QWORD *)v11 = 10000 * v17[0];
                  DWORDValueKey = PmQueryDWORDValueKey(Handle, L"IdleExitEnergyMicroJoules", v17);
                  if ( DWORDValueKey < 0 )
                    break;
                  *(_QWORD *)(v11 + 8) = 10000 * v17[0];
                  DWORDValueKey = PmQueryDWORDValueKey(Handle, L"IdleTimeLengthMs", v17);
                  if ( DWORDValueKey < 0 )
                    break;
                  *(_QWORD *)(v11 + 16) = 10000 * v17[0];
                  DWORDValueKey = PmQueryDWORDValueKey(Handle, L"IdlePowerMw", v17);
                  if ( DWORDValueKey < 0 )
                    break;
                  v14 = Handle;
                  *(_DWORD *)(v11 + 24) = v17[0];
                  ZwClose(v14);
                  v15 = (unsigned __int16)*a1;
                  ++v12;
                  Handle = 0LL;
                  if ( v13 >= v15 )
                    goto LABEL_21;
                }
              }
              else
              {
LABEL_21:
                *(_QWORD *)(v11 + 16) = -1LL;
              }
            }
          }
        }
        break;
      }
    }
  }
  if ( Handle )
    ZwClose(Handle);
  if ( DestinationString )
    ZwClose(DestinationString);
  return (unsigned int)DWORDValueKey;
}