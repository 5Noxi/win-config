// (C) 2026 Noverse (nohuto). All Rights Reserved.
// https://github.com/nohuto
// https://discord.noverse.dev

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;
typedef UINT D3DKMT_HANDLE;
typedef UINT D3DDDI_VIDEO_PRESENT_SOURCE_ID;

typedef struct {
    HDC hDc;
    D3DKMT_HANDLE hAdapter;
    LUID AdapterLuid;
    D3DDDI_VIDEO_PRESENT_SOURCE_ID VidPnSourceId;
} D3DKMT_OPENADAPTERFROMHDC;

typedef struct {
    D3DKMT_HANDLE hAdapter;
    int Type;
    void *pPrivateDriverData;
    UINT PrivateDriverDataSize;
} D3DKMT_QUERYADAPTERINFO;

typedef struct {
    D3DKMT_HANDLE hAdapter;
} D3DKMT_CLOSEADAPTER;

typedef NTSTATUS (WINAPI *PFN_OPEN)(D3DKMT_OPENADAPTERFROMHDC *);
typedef NTSTATUS (WINAPI *PFN_QUERY)(const D3DKMT_QUERYADAPTERINFO *);
typedef NTSTATUS (WINAPI *PFN_CLOSE)(const D3DKMT_CLOSEADAPTER *);

enum {
    KMTQAITYPE_WDDM_2_9_CAPS = 75,
    KMTQAITYPE_WDDM_3_0_CAPS = 77
};

static void query_hwsch(const wchar_t *name, PFN_OPEN open_adapter, PFN_QUERY query, PFN_CLOSE close_adapter)
{
    HDC hdc = CreateDCW(L"DISPLAY", name, NULL, NULL);
    if (!hdc)
        return;

    D3DKMT_OPENADAPTERFROMHDC open = { 0 };
    open.hDc = hdc;
    if (open_adapter(&open) >= 0) {
        UINT caps29 = 0;
        UINT caps30 = 0;
        D3DKMT_QUERYADAPTERINFO info29 = { open.hAdapter, KMTQAITYPE_WDDM_2_9_CAPS, &caps29, sizeof(caps29) };
        D3DKMT_QUERYADAPTERINFO info30 = { open.hAdapter, KMTQAITYPE_WDDM_3_0_CAPS, &caps30, sizeof(caps30) };
        NTSTATUS st29 = query(&info29);
        NTSTATUS st30 = query(&info30);

        wprintf(L"%ls\n", name ? name : L"(primary)");
        printf("  AdapterLuid=%08lx:%08lx VidPnSourceId=%u hAdapter=%u\n",
            (ULONG)open.AdapterLuid.HighPart, open.AdapterLuid.LowPart, open.VidPnSourceId, open.hAdapter);
        if (st29 >= 0)
            printf("  WDDM_2_9 HWSCH DriverSupportState=%u Enabled=%u\n", caps29 & 3u, (caps29 >> 2) & 1u);
        else
            printf("  WDDM_2_9 status=0x%08lx\n", (ULONG)st29);

        if (st30 >= 0)
            printf("  WDDM_3_0 HWFLIPQUEUE DriverSupportState=%u Enabled=%u DisplayableSupported=%u\n",
                caps30 & 3u, (caps30 >> 2) & 1u, (caps30 >> 3) & 1u);
        else
            printf("  WDDM_3_0 status=0x%08lx\n", (ULONG)st30);

        D3DKMT_CLOSEADAPTER close = { open.hAdapter };
        close_adapter(&close);
    }

    DeleteDC(hdc);
}

int wmain(void)
{
    HMODULE gdi32 = LoadLibraryW(L"gdi32.dll");
    if (!gdi32)
        return 1;

    PFN_OPEN open_adapter = (PFN_OPEN)GetProcAddress(gdi32, "D3DKMTOpenAdapterFromHdc");
    PFN_QUERY query = (PFN_QUERY)GetProcAddress(gdi32, "D3DKMTQueryAdapterInfo");
    PFN_CLOSE close_adapter = (PFN_CLOSE)GetProcAddress(gdi32, "D3DKMTCloseAdapter");
    if (!open_adapter || !query || !close_adapter)
        return 1;

    DISPLAY_DEVICEW dd = { 0 };
    dd.cb = sizeof(dd);
    for (DWORD i = 0; EnumDisplayDevicesW(NULL, i, &dd, 0); i++) {
        if (dd.StateFlags & DISPLAY_DEVICE_ACTIVE)
            query_hwsch(dd.DeviceName, open_adapter, query, close_adapter);
        ZeroMemory(&dd, sizeof(dd));
        dd.cb = sizeof(dd);
    }

    return 0;
}
