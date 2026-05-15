// (C) 2026 Noverse (nohuto). All Rights Reserved.
// https://github.com/nohuto
// https://discord.gg/E2ybG4j9jU

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <avrt.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    DWORD task_index = 0;
    HANDLE avrt_handle;
    wchar_t task_name[128] = L"Audio";
    int set_relative = 0;
    int relative_priority = 0;
    volatile unsigned long long spin = 0;

    if (argc > 3) {
        fprintf(stderr, "Invalid arguments\n");
        return 2;
    }

    if (argc >= 2) {
        int written = MultiByteToWideChar(CP_ACP, 0, argv[1], -1, task_name, (int)(sizeof(task_name) / sizeof(task_name[0])));
        if (written <= 0 || written >= (int)(sizeof(task_name) / sizeof(task_name[0]))) {
            fprintf(stderr, "Invalid task_name\n");
            return 2;
        }
    }

    if (argc == 3) {
        char *end = NULL;
        long parsed = strtol(argv[2], &end, 10);
        if (!end || *end != '\0' || parsed < -2 || parsed > 2) {
            fprintf(stderr, "Invalid relative_priority\n");
            return 2;
        }
        set_relative = 1;
        relative_priority = (int)parsed;
    }

    avrt_handle = AvSetMmThreadCharacteristicsW(task_name, &task_index);
    if (!avrt_handle) {
        fprintf(stderr, "AvSetMmThreadCharacteristicsW failed: %lu\n", GetLastError());
        return 1;
    }

    if (set_relative) {
        if (!AvSetMmThreadPriority(avrt_handle, (AVRT_PRIORITY)relative_priority)) {
            fprintf(stderr, "AvSetMmThreadPriority(%d) failed: %lu\n", relative_priority, GetLastError());
            AvRevertMmThreadCharacteristics(avrt_handle);
            return 1;
        }
    }

    wprintf(L"Task: %ls\n", task_name);
    if (set_relative) {
        printf("Relative priority: %d\n", relative_priority);
    }
    fflush(stdout);

    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);

    for (;;) {
        spin++;
        if ((spin & 0xFFFFFF) == 0) {
            Sleep(0);
        }
    }
}
