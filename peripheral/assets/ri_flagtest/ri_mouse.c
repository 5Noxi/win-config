// (C) 2026 Noverse (nohuto). All Rights Reserved.
// https://github.com/nohuto
// https://discord.gg/E2ybG4j9jU

#include <stdio.h>
#include <windows.h>

#ifndef RI_FLAGS
#define RI_FLAGS 0x0100
#endif

#ifndef RI_NAME
#define RI_NAME "ri_mouse"
#endif

static volatile LONG run = 1;
static LARGE_INTEGER freq;
static LARGE_INTEGER last;
static unsigned long long count;

static void print_hz(void) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);

    double sec = (double)(now.QuadPart - last.QuadPart) / (double)freq.QuadPart;
    if (sec < 1.0)
        return;

    printf("hz=%7.1f\n", (double)count / sec);
    fflush(stdout);
    count = 0;
    last = now;
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_INPUT) {
        ++count;
        print_hz();
        return DefWindowProcA(hwnd, msg, wp, lp);
    }

    if (msg == WM_CLOSE) {
        InterlockedExchange(&run, 0);
        DestroyWindow(hwnd);
        return 0;
    }

    if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcA(hwnd, msg, wp, lp);
}

int main(void) {
    HINSTANCE inst = GetModuleHandleA(NULL);

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&last);

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = inst;
    wc.lpszClassName = RI_NAME;
    if (!RegisterClassA(&wc)) {
        printf("RegisterClass failed: %lu\n", GetLastError());
        return 1;
    }

    HWND hwnd = CreateWindowExA(0, RI_NAME, RI_NAME, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 420, 160, NULL, NULL, inst, NULL);
    if (!hwnd) {
        printf("CreateWindow failed: %lu\n", GetLastError());
        return 1;
    }

    RAWINPUTDEVICE rid = {0};
    rid.usUsagePage = 1;
    rid.usUsage = 2;
    rid.dwFlags = RI_FLAGS;
    rid.hwndTarget = hwnd;
    if (!RegisterRawInputDevices(&rid, 1, sizeof(rid))) {
        printf("RegisterRawInputDevices failed: %lu\n", GetLastError());
        return 1;
    }

    ShowWindow(hwnd, SW_SHOW);
    printf("%s pid=%lu hwnd=%p flags=0x%04x\n", RI_NAME, GetCurrentProcessId(), (void *)hwnd, RI_FLAGS);
    fflush(stdout);

    MSG msg;
    while (InterlockedCompareExchange(&run, 1, 1)) {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                InterlockedExchange(&run, 0);
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        MsgWaitForMultipleObjects(0, NULL, FALSE, 50, QS_ALLINPUT);
    }

    return 0;
}
