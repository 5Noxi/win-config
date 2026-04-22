// (C) 2026 Noverse (nohuto). All Rights Reserved.
// https://github.com/nohuto
// https://discord.gg/E2ybG4j9jU

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static void dump(FILE *f) {
    UINT count = 0;
    if (GetRegisteredRawInputDevices(NULL, &count, sizeof(RAWINPUTDEVICE)) == (UINT)-1) {
        fprintf(f, "error=%lu\n", GetLastError());
        return;
    }

    if (!count) {
        fprintf(f, "none\n");
        return;
    }

    RAWINPUTDEVICE *rid = (RAWINPUTDEVICE *)calloc(count, sizeof(*rid));
    if (!rid) {
        fprintf(f, "error=alloc\n");
        return;
    }

    if (GetRegisteredRawInputDevices(rid, &count, sizeof(*rid)) == (UINT)-1) {
        fprintf(f, "error=%lu\n", GetLastError());
        free(rid);
        return;
    }

    for (UINT i = 0; i < count; ++i) {
        int mouse = rid[i].usUsagePage == 1 && rid[i].usUsage == 2;
        int forced = mouse && (rid[i].dwFlags & 0x8000) != 0;
        if (forced)
            fprintf(f, "forced=yes\n");
        else if (mouse)
            fprintf(f, "mouse=yes\n");
        else
            fprintf(f, "raw_other=yes\n");
    }
    free(rid);
}

__declspec(dllexport) DWORD WINAPI RawInputProbeDump(LPVOID unused) {
    (void)unused;

    char temp[MAX_PATH];
    char path[MAX_PATH];
    if (!GetTempPathA(sizeof(temp), temp))
        return 1;

    snprintf(path, sizeof(path), "%sriflags_%lu.txt", temp, (unsigned long)GetCurrentProcessId());

    FILE *f = NULL;
    if (fopen_s(&f, path, "w") != 0 || !f)
        return 2;
    dump(f);
    fclose(f);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(instance);
    return TRUE;
}
