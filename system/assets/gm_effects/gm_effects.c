// (C) 2026 Noverse (nohuto). All Rights Reserved.
// https://github.com/nohuto
// https://discord.gg/E2ybG4j9jU

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>
#include <stdlib.h>

#define WNF_RM_GAME_MODE_ACTIVE 0x41C6033FA3BC1075ULL
#define WNF_SEB_GAME_MODE       0x41840B3EA3BDD875ULL

typedef LONG (NTAPI *NtQueryWnfStateDataFn)(
    unsigned long long *StateName,
    const void *TypeId,
    const void *ExplicitScope,
    unsigned long *ChangeStamp,
    void *Buffer,
    unsigned long *BufferSize);

static NtQueryWnfStateDataFn NtQueryWnfStateDataPtr;

static int InitNt(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = LoadLibraryW(L"ntdll.dll");
    }
    if (!ntdll) {
        fwprintf(stderr, L"LoadLibraryW(ntdll.dll) failed: %lu\n", GetLastError());
        return 0;
    }

    NtQueryWnfStateDataPtr = (NtQueryWnfStateDataFn)GetProcAddress(ntdll, "NtQueryWnfStateData");
    if (!NtQueryWnfStateDataPtr) {
        fwprintf(stderr, L"GetProcAddress(NtQueryWnfStateData) failed: %lu\n", GetLastError());
        return 0;
    }

    return 1;
}

static int QueryWnf(unsigned long long state, void *buffer, unsigned long *bufferSize, LONG *status)
{
    unsigned long changeStamp = 0;
    unsigned long long stateName = state;

    *status = NtQueryWnfStateDataPtr(&stateName, NULL, NULL, &changeStamp, buffer, bufferSize);
    return *status >= 0;
}

static int QueryWnfU32(unsigned long long state, unsigned long *value, LONG *status)
{
    unsigned char buffer[8] = { 0 };
    unsigned long bufferSize = sizeof(buffer);

    if (!QueryWnf(state, buffer, &bufferSize, status) || bufferSize < sizeof(*value)) {
        *value = 0;
        return 0;
    }

    *value = *(unsigned long *)buffer;
    return 1;
}

static void PrintTimestamp(void)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("Timestamp=%02u:%02u:%02u.%03u\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

static void PrintCpuSets(HANDLE process)
{
    ULONG required = 0;
    ULONG cpuSets[256] = { 0 };

    if (!GetProcessDefaultCpuSets(process, cpuSets, (ULONG)(sizeof(cpuSets) / sizeof(cpuSets[0])), &required)) {
        printf("DefaultCpuSetsQueryError=%lu\n", GetLastError());
        return;
    }

    printf("DefaultCpuSetCount=%lu\n", required);
    if (required == 0) {
        return;
    }

    printf("DefaultCpuSetIDs=");
    ULONG printed = required;
    if (printed > (ULONG)(sizeof(cpuSets) / sizeof(cpuSets[0]))) {
        printed = (ULONG)(sizeof(cpuSets) / sizeof(cpuSets[0]));
    }
    for (ULONG i = 0; i < printed; ++i) {
        printf("%s%lu", i ? "," : "", cpuSets[i]);
    }
    if (required > printed) {
        printf(",...");
    }
    printf("\n");
}

static void PrintProcess(unsigned long pid)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        printf("ProcessOpenError=%lu\n", GetLastError());
        return;
    }

    wchar_t path[MAX_PATH * 4];
    DWORD pathLength = (DWORD)(sizeof(path) / sizeof(path[0]));
    if (QueryFullProcessImageNameW(process, 0, path, &pathLength)) {
        const wchar_t *fileName = wcsrchr(path, L'\\');
        fileName = fileName ? fileName + 1 : path;
        wprintf(L"ProcessImage=%ls\n", fileName);
        wprintf(L"ProcessPath=%ls\n", path);
    } else {
        printf("ProcessPathQueryError=%lu\n", GetLastError());
    }

    PrintCpuSets(process);
    CloseHandle(process);
}

static void PrintForegroundPid(void)
{
    HWND hwnd = GetForegroundWindow();
    DWORD pid = 0;

    if (hwnd) {
        GetWindowThreadProcessId(hwnd, &pid);
    }

    printf("FGPid=%lu\n", pid);
}

static int ParsePid(const wchar_t *text, unsigned long *pid)
{
    wchar_t *end = NULL;
    unsigned long value = wcstoul(text, &end, 10);

    if (!text[0] || (end && *end) || value == 0) {
        return 0;
    }

    *pid = value;
    return 1;
}

static void PrintUsage(const wchar_t *exe)
{
    fwprintf(stderr, L"Usage: %ls [--pid <pid>]\n", exe);
}

static void PrintState(unsigned long targetPid)
{
    LONG status = 0;
    unsigned long pid = 0;
    unsigned long powerLow = 0;

    PrintTimestamp();
    PrintForegroundPid();

    if (QueryWnfU32(WNF_RM_GAME_MODE_ACTIVE, &pid, &status)) {
        printf("GameModeActivePid=%lu\n", pid);
        if (pid) {
            PrintProcess(pid);
        }
    } else {
        printf("GameModeActiveQueryStatus=0x%08lX\n", (unsigned long)status);
    }

    if (QueryWnfU32(WNF_SEB_GAME_MODE, &powerLow, &status)) {
        printf("PowerProfileLowValue=%lu\n", powerLow);
    } else {
        printf("PowerProfileLowValue=0\n");
    }

    if (targetPid) {
        printf("TargetPid=%lu\n", targetPid);
        PrintProcess(targetPid);
    }
}

int wmain(int argc, wchar_t **argv)
{
    unsigned long targetPid = 0;

    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--pid") == 0) {
            if (++i >= argc || !ParsePid(argv[i], &targetPid)) {
                PrintUsage(argv[0]);
                return 2;
            }
        } else if (wcsncmp(argv[i], L"--pid=", 6) == 0) {
            if (!ParsePid(argv[i] + 6, &targetPid)) {
                PrintUsage(argv[0]);
                return 2;
            }
        } else {
            PrintUsage(argv[0]);
            return 2;
        }
    }

    if (!InitNt()) {
        return 1;
    }

    for (;;) {
        PrintState(targetPid);
        printf("\n");
        fflush(stdout);
        Sleep(1000);
    }
}
