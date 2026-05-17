// (C) 2026 Noverse (nohuto). All Rights Reserved.
// https://github.com/nohuto
// https://discord.gg/E2ybG4j9jU

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h>
#include <wchar.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define ARRAY_COUNT(x) (sizeof(x) / sizeof((x)[0]))

#define RTL_QUERY_PROCESS_HEAP_SUMMARY 0x00000004u
#define RTL_QUERY_PROCESS_HEAP_ENTRIES 0x00000010u
#define RTL_QUERY_PROCESS_NONINVASIVE 0x80000000u
#define HEAP_CLASS_MASK_LOCAL 0x0000f000u
#define RTL_HEAP_SIGNATURE_LOCAL 0xffeeffeeu
#define RTL_HEAP_SEGMENT_SIGNATURE_LOCAL 0xddeeddeeu

typedef struct _RTL_HEAP_ENTRY_LOCAL {
    SIZE_T Size;
    USHORT Flags;
    USHORT AllocatorBackTraceIndex;
    union {
        struct {
            SIZE_T Settable;
            ULONG Tag;
        } s1;
        struct {
            SIZE_T CommittedSize;
            PVOID FirstBlock;
        } s2;
    } u;
} RTL_HEAP_ENTRY_LOCAL;

typedef struct _RTL_HEAP_INFORMATION_V1_LOCAL {
    PVOID BaseAddress;
    ULONG Flags;
    USHORT EntryOverhead;
    USHORT CreatorBackTraceIndex;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    ULONG NumberOfTags;
    ULONG NumberOfEntries;
    ULONG NumberOfPseudoTags;
    ULONG PseudoTagGranularity;
    ULONG Reserved[5];
    PVOID Tags;
    RTL_HEAP_ENTRY_LOCAL* Entries;
} RTL_HEAP_INFORMATION_V1_LOCAL;

typedef struct _RTL_HEAP_INFORMATION_V2_LOCAL {
    PVOID BaseAddress;
    ULONG Flags;
    USHORT EntryOverhead;
    USHORT CreatorBackTraceIndex;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    ULONG NumberOfTags;
    ULONG NumberOfEntries;
    ULONG NumberOfPseudoTags;
    ULONG PseudoTagGranularity;
    ULONG Reserved[5];
    PVOID Tags;
    RTL_HEAP_ENTRY_LOCAL* Entries;
    ULONG64 HeapTag;
} RTL_HEAP_INFORMATION_V2_LOCAL;

typedef struct _RTL_PROCESS_HEAPS_V1_LOCAL {
    ULONG NumberOfHeaps;
    RTL_HEAP_INFORMATION_V1_LOCAL Heaps[1];
} RTL_PROCESS_HEAPS_V1_LOCAL;

typedef struct _RTL_PROCESS_HEAPS_V2_LOCAL {
    ULONG NumberOfHeaps;
    RTL_HEAP_INFORMATION_V2_LOCAL Heaps[1];
} RTL_PROCESS_HEAPS_V2_LOCAL;

typedef struct _RTL_DEBUG_INFORMATION_LOCAL {
    HANDLE SectionHandleClient;
    PVOID ViewBaseClient;
    PVOID ViewBaseTarget;
    ULONG_PTR ViewBaseDelta;
    HANDLE EventPairClient;
    HANDLE EventPairTarget;
    HANDLE TargetProcessId;
    HANDLE TargetThreadHandle;
    ULONG Flags;
    SIZE_T OffsetFree;
    SIZE_T CommitSize;
    SIZE_T ViewSize;
    PVOID Modules;
    PVOID BackTraces;
    PVOID Heaps;
    PVOID Locks;
    PVOID SpecificHeap;
    HANDLE TargetProcessHandle;
    PVOID VerifierOptions;
    PVOID ProcessHeap;
    HANDLE CriticalSectionHandle;
    HANDLE CriticalSectionOwnerThread;
    PVOID Reserved[4];
} RTL_DEBUG_INFORMATION_LOCAL;

typedef RTL_DEBUG_INFORMATION_LOCAL* (NTAPI* RtlCreateQueryDebugBuffer_t)(ULONG, BOOLEAN);
typedef NTSTATUS(NTAPI* RtlDestroyQueryDebugBuffer_t)(RTL_DEBUG_INFORMATION_LOCAL*);
typedef NTSTATUS(NTAPI* RtlQueryProcessDebugInformation_t)(HANDLE, ULONG, RTL_DEBUG_INFORMATION_LOCAL*);
typedef NTSTATUS(NTAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW);

typedef struct _NT_RTL {
    RtlCreateQueryDebugBuffer_t RtlCreateQueryDebugBuffer;
    RtlDestroyQueryDebugBuffer_t RtlDestroyQueryDebugBuffer;
    RtlQueryProcessDebugInformation_t RtlQueryProcessDebugInformation;
    RtlGetVersion_t RtlGetVersion;
} NT_RTL;

typedef struct _COUNTS {
    ULONG NtHeap;
    ULONG NtHeapLfh;
    ULONG NtHeapLookaside;
    ULONG SegmentHeap;
    ULONG SegmentHeapLfh;
    ULONG SegmentHeapLookaside;
    ULONG Unknown;
} COUNTS;

static BOOL EnableDebugPrivilege(void)
{
    HANDLE token = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOL ok = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return FALSE;

    ZeroMemory(&tp, sizeof(tp));
    if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    }

    CloseHandle(token);
    return ok;
}

static ULONG QueryBuildNumber(const NT_RTL* rtl)
{
    RTL_OSVERSIONINFOW version;

    ZeroMemory(&version, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);

    if (rtl->RtlGetVersion && NT_SUCCESS(rtl->RtlGetVersion(&version)))
        return version.dwBuildNumber;

    return 0;
}

static BOOL IsProcessWow64(HANDLE process)
{
    typedef BOOL(WINAPI* IsWow64Process2_t)(HANDLE, USHORT*, USHORT*);
    IsWow64Process2_t pIsWow64Process2;
    BOOL wow64 = FALSE;

    pIsWow64Process2 = (IsWow64Process2_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    if (pIsWow64Process2) {
        USHORT processMachine = 0;
        USHORT nativeMachine = 0;
        if (pIsWow64Process2(process, &processMachine, &nativeMachine))
            return processMachine != IMAGE_FILE_MACHINE_UNKNOWN;
    }

    if (IsWow64Process(process, &wow64))
        return wow64 != FALSE;

    return FALSE;
}

static BOOL ReadHeapSignature(HANDLE process, PVOID heap, BOOL wow64, ULONG* signature)
{
    SIZE_T bytesRead = 0;
    const BYTE* address = (const BYTE*)heap + (wow64 ? 8 : 16);

    return ReadProcessMemory(process, address, signature, sizeof(*signature), &bytesRead) &&
        bytesRead == sizeof(*signature);
}

static BOOL ReadHeapFrontEndType(HANDLE process, PVOID heap, BOOL wow64, UCHAR* frontEnd)
{
    SIZE_T bytesRead = 0;
    const BYTE* address = (const BYTE*)heap + (wow64 ? 234 : 418);

    return ReadProcessMemory(process, address, frontEnd, sizeof(*frontEnd), &bytesRead) &&
        bytesRead == sizeof(*frontEnd);
}

static const WCHAR* HeapClassText(ULONG flags)
{
    switch (flags & HEAP_CLASS_MASK_LOCAL) {
    case 0x00000000: return L"Process";
    case 0x00001000: return L"Private";
    case 0x00002000: return L"Kernel";
    case 0x00003000: return L"GDI";
    case 0x00004000: return L"User";
    case 0x00005000: return L"Console";
    case 0x00006000: return L"Desktop";
    case 0x00007000: return L"CSRSS shared";
    case 0x00008000: return L"CSRSS port";
    default: return L"Unknown";
    }
}

static void BuildHeapFlagsText(ULONG flags, WCHAR* buffer, size_t count)
{
    BOOL any = FALSE;

    flags &= ~HEAP_CLASS_MASK_LOCAL;
    buffer[0] = 0;

#define ADD_FLAG(mask, text) \
    do { \
        if (flags & (mask)) { \
            if (any) wcscat_s(buffer, count, L"|"); \
            wcscat_s(buffer, count, (text)); \
            any = TRUE; \
        } \
    } while (0)

    ADD_FLAG(HEAP_NO_SERIALIZE, L"NoSerialize");
    ADD_FLAG(0x00000002u, L"Growable");
    ADD_FLAG(HEAP_GENERATE_EXCEPTIONS, L"GenerateExceptions");
    ADD_FLAG(HEAP_ZERO_MEMORY, L"ZeroMemory");
    ADD_FLAG(HEAP_REALLOC_IN_PLACE_ONLY, L"ReallocInPlace");
    ADD_FLAG(0x00000020u, L"TailChecking");
    ADD_FLAG(0x00000040u, L"FreeChecking");
    ADD_FLAG(0x00000080u, L"DisableCoalesceOnFree");
    ADD_FLAG(0x00010000u, L"CreateAlign16");
    ADD_FLAG(0x00020000u, L"CreateEnableTracing");
    ADD_FLAG(0x00040000u, L"CreateEnableExecute");
    ADD_FLAG(0x00000100u, L"CreateSegmentHeap");
    ADD_FLAG(0x00000200u, L"CreateHardened");

#undef ADD_FLAG

    if (!any)
        wcscpy_s(buffer, count, L"-");
}

static void HeapTypeText(ULONG signature, UCHAR frontEnd, WCHAR* buffer, size_t count)
{
    if (signature == RTL_HEAP_SIGNATURE_LOCAL)
        wcscpy_s(buffer, count, L"NT Heap");
    else if (signature == RTL_HEAP_SEGMENT_SIGNATURE_LOCAL)
        wcscpy_s(buffer, count, L"Segment Heap");
    else
        wcscpy_s(buffer, count, L"Unknown");

    if (frontEnd == 1)
        wcscat_s(buffer, count, L" (Lookaside)");
    else if (frontEnd == 2)
        wcscat_s(buffer, count, L" (LFH)");
}

static void PrintCsvField(const WCHAR* s)
{
    const WCHAR* p;

    putwchar(L'"');
    for (p = s; *p; ++p) {
        if (*p == L'"')
            putwchar(L'"');
        putwchar(*p);
    }
    putwchar(L'"');
}

static void AddTypeCount(COUNTS* counts, ULONG signature, UCHAR frontEnd)
{
    if (signature == RTL_HEAP_SIGNATURE_LOCAL) {
        if (frontEnd == 2)
            ++counts->NtHeapLfh;
        else if (frontEnd == 1)
            ++counts->NtHeapLookaside;
        else
            ++counts->NtHeap;
    } else if (signature == RTL_HEAP_SEGMENT_SIGNATURE_LOCAL) {
        if (frontEnd == 2)
            ++counts->SegmentHeapLfh;
        else if (frontEnd == 1)
            ++counts->SegmentHeapLookaside;
        else
            ++counts->SegmentHeap;
    } else {
        ++counts->Unknown;
    }
}

static void HandleHeap(
    DWORD pid,
    const WCHAR* processName,
    ULONG index,
    PVOID baseAddress,
    ULONG flags,
    ULONG numberOfEntries,
    SIZE_T bytesCommitted,
    HANDLE processHandle,
    BOOL wow64,
    BOOL showHeaps,
    COUNTS* counts)
{
    ULONG signature = 0xffffffffu;
    UCHAR frontEnd = 0xffu;
    WCHAR typeText[64];
    WCHAR flagsText[512];

    ReadHeapSignature(processHandle, baseAddress, wow64, &signature);
    ReadHeapFrontEndType(processHandle, baseAddress, wow64, &frontEnd);
    AddTypeCount(counts, signature, frontEnd);

    if (!showHeaps)
        return;

    HeapTypeText(signature, frontEnd, typeText, ARRAY_COUNT(typeText));
    BuildHeapFlagsText(flags, flagsText, ARRAY_COUNT(flagsText));

    PrintCsvField(processName);
    wprintf(L",%lu,%lu,0x%p,", pid, index + 1, baseAddress);
    PrintCsvField(typeText);
    putwchar(L',');
    PrintCsvField(HeapClassText(flags));
    putwchar(L',');
    PrintCsvField(flagsText);
    wprintf(L",0x%lx,%lu,%llu\n",
        flags & ~HEAP_CLASS_MASK_LOCAL,
        numberOfEntries,
        (unsigned long long)bytesCommitted);
}

static void QueryOneProcess(
    const NT_RTL* rtl,
    DWORD pid,
    const WCHAR* processName,
    BOOL useV2,
    BOOL showHeaps,
    COUNTS* counts)
{
    RTL_DEBUG_INFORMATION_LOCAL* debugBuffer = NULL;
    NTSTATUS status = 0;
    ULONG size;
    HANDLE processHandle;
    BOOL wow64;

    for (size = 0x400000; ; size *= 2) {
        debugBuffer = rtl->RtlCreateQueryDebugBuffer(size, FALSE);
        if (!debugBuffer)
            return;

        status = rtl->RtlQueryProcessDebugInformation(
            (HANDLE)(ULONG_PTR)pid,
            RTL_QUERY_PROCESS_HEAP_SUMMARY | RTL_QUERY_PROCESS_HEAP_ENTRIES | RTL_QUERY_PROCESS_NONINVASIVE,
            debugBuffer);

        if (NT_SUCCESS(status) || status != (NTSTATUS)0xC0000017L)
            break;

        rtl->RtlDestroyQueryDebugBuffer(debugBuffer);
        debugBuffer = NULL;

        if (size > 0x20000000)
            return;
    }

    if (!NT_SUCCESS(status) || !debugBuffer || !debugBuffer->Heaps) {
        if (debugBuffer)
            rtl->RtlDestroyQueryDebugBuffer(debugBuffer);
        return;
    }

    processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!processHandle) {
        rtl->RtlDestroyQueryDebugBuffer(debugBuffer);
        return;
    }

    wow64 = IsProcessWow64(processHandle);

    if (useV2) {
        RTL_PROCESS_HEAPS_V2_LOCAL* heaps = (RTL_PROCESS_HEAPS_V2_LOCAL*)debugBuffer->Heaps;
        ULONG i;
        for (i = 0; i < heaps->NumberOfHeaps; ++i) {
            HandleHeap(
                pid,
                processName,
                i,
                heaps->Heaps[i].BaseAddress,
                heaps->Heaps[i].Flags,
                heaps->Heaps[i].NumberOfEntries,
                heaps->Heaps[i].BytesCommitted,
                processHandle,
                wow64,
                showHeaps,
                counts);
        }
    } else {
        RTL_PROCESS_HEAPS_V1_LOCAL* heaps = (RTL_PROCESS_HEAPS_V1_LOCAL*)debugBuffer->Heaps;
        ULONG i;
        for (i = 0; i < heaps->NumberOfHeaps; ++i) {
            HandleHeap(
                pid,
                processName,
                i,
                heaps->Heaps[i].BaseAddress,
                heaps->Heaps[i].Flags,
                heaps->Heaps[i].NumberOfEntries,
                heaps->Heaps[i].BytesCommitted,
                processHandle,
                wow64,
                showHeaps,
                counts);
        }
    }

    CloseHandle(processHandle);
    rtl->RtlDestroyQueryDebugBuffer(debugBuffer);
}

static void PrintSummary(const COUNTS* counts)
{
    if (counts->NtHeap)
        wprintf(L"NT Heap: %lu\n", counts->NtHeap);
    if (counts->NtHeapLfh)
        wprintf(L"NT Heap (LFH): %lu\n", counts->NtHeapLfh);
    if (counts->NtHeapLookaside)
        wprintf(L"NT Heap (Lookaside): %lu\n", counts->NtHeapLookaside);
    if (counts->SegmentHeap)
        wprintf(L"Segment Heap: %lu\n", counts->SegmentHeap);
    if (counts->SegmentHeapLfh)
        wprintf(L"Segment Heap (LFH): %lu\n", counts->SegmentHeapLfh);
    if (counts->SegmentHeapLookaside)
        wprintf(L"Segment Heap (Lookaside): %lu\n", counts->SegmentHeapLookaside);
    if (counts->Unknown)
        wprintf(L"Unknown: %lu\n", counts->Unknown);
}

int wmain(int argc, WCHAR** argv)
{
    NT_RTL rtl;
    HMODULE ntdll;
    ULONG build;
    BOOL useV2;
    BOOL showHeaps = FALSE;
    HANDLE snapshot;
    PROCESSENTRY32W pe;
    COUNTS counts;
    int i;

    for (i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--heaps") == 0) {
            showHeaps = TRUE;
        } else {
            fwprintf(stderr, L"Unknown argument: %ls\n", argv[i]);
            return 1;
        }
    }

    ZeroMemory(&rtl, sizeof(rtl));
    ZeroMemory(&counts, sizeof(counts));

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        fwprintf(stderr, L"ntdll.dll not loaded\n");
        return 1;
    }

    rtl.RtlCreateQueryDebugBuffer = (RtlCreateQueryDebugBuffer_t)GetProcAddress(ntdll, "RtlCreateQueryDebugBuffer");
    rtl.RtlDestroyQueryDebugBuffer = (RtlDestroyQueryDebugBuffer_t)GetProcAddress(ntdll, "RtlDestroyQueryDebugBuffer");
    rtl.RtlQueryProcessDebugInformation = (RtlQueryProcessDebugInformation_t)GetProcAddress(ntdll, "RtlQueryProcessDebugInformation");
    rtl.RtlGetVersion = (RtlGetVersion_t)GetProcAddress(ntdll, "RtlGetVersion");

    if (!rtl.RtlCreateQueryDebugBuffer || !rtl.RtlDestroyQueryDebugBuffer || !rtl.RtlQueryProcessDebugInformation) {
        fwprintf(stderr, L"Missing ntdll heap query exports\n");
        return 1;
    }

    EnableDebugPrivilege();

    build = QueryBuildNumber(&rtl);
    useV2 = build > 22000;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return 1;
    }

    if (showHeaps)
        wprintf(L"process,pid,heap_index,heap_base,type,class,flags,flags_hex,entries,committed_bytes\n");

    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapshot, &pe)) {
        do {
            QueryOneProcess(&rtl, pe.th32ProcessID, pe.szExeFile, useV2, showHeaps, &counts);
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);

    if (!showHeaps)
        PrintSummary(&counts);

    return 0;
}
