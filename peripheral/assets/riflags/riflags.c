// (C) 2026 Noverse (nohuto). All Rights Reserved.
// https://github.com/nohuto
// https://discord.gg/E2ybG4j9jU

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define WORKERS 16
#define TIMEOUT_MS 5000
#define DUMP_MAX 8192

typedef enum State {
    OK,
    DENIED,
    LOAD_FAIL,
    LOAD_TIMEOUT,
    DUMP_FAIL,
    DUMP_TIMEOUT,
    FAIL
} State;

typedef struct Proc {
    DWORD pid;
    DWORD err;
    State state;
    char name[MAX_PATH];
    char result[48];
    char dump[DUMP_MAX];
} Proc;

typedef struct Scan {
    Proc *items;
    LONG count;
    LONG next;
    char dll[MAX_PATH];
    wchar_t dll_name[MAX_PATH];
    char temp[MAX_PATH];
} Scan;

static int has(const char *s, const char *needle) {
    return s && strstr(s, needle) != NULL;
}

static void wait_before_close(void) {
    printf("\nPress Enter to close...");
    fflush(stdout);
    getchar();
}

static int exe_dir(char *out, DWORD out_len) {
    DWORD len = GetModuleFileNameA(NULL, out, out_len);
    if (!len || len >= out_len)
        return 0;
    while (len && out[len - 1] != '\\' && out[len - 1] != '/')
        --len;
    if (!len)
        return 0;
    out[len] = '\0';
    return 1;
}

static int stage_dll(const char *src, char *dst, DWORD dst_len, wchar_t *name, DWORD name_len) {
    char program_data[MAX_PATH];
    if (!GetEnvironmentVariableA("ProgramData", program_data, sizeof(program_data))) {
        strcpy_s(dst, dst_len, src);
        MultiByteToWideChar(CP_UTF8, 0, "riprobe.dll", -1, name, name_len);
        return 1;
    }

    char dir[MAX_PATH];
    snprintf(dir, sizeof(dir), "%s\\riflags", program_data);
    CreateDirectoryA(dir, NULL);
    snprintf(dst, dst_len, "%s\\riprobe_%lu_%lu.dll", dir, (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());

    const char *base = strrchr(dst, '\\');
    base = base ? base + 1 : dst;
    MultiByteToWideChar(CP_UTF8, 0, base, -1, name, name_len);
    return CopyFileA(src, dst, FALSE) != 0;
}

static int read_file(const char *path, char *out, size_t out_len) {
    FILE *f = NULL;
    if (fopen_s(&f, path, "rb") != 0 || !f)
        return 0;
    size_t n = fread(out, 1, out_len - 1, f);
    out[n] = '\0';
    fclose(f);
    return 1;
}

static uintptr_t mod_base(DWORD pid, const wchar_t *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    uintptr_t base = 0;
    MODULEENTRY32W mod;
    ZeroMemory(&mod, sizeof(mod));
    mod.dwSize = sizeof(mod);
    if (Module32FirstW(snap, &mod)) {
        do {
            if (_wcsicmp(mod.szModule, name) == 0) {
                base = (uintptr_t)mod.modBaseAddr;
                break;
            }
        } while (Module32NextW(snap, &mod));
    }
    CloseHandle(snap);
    return base;
}

static int remote_free(HANDLE proc, DWORD pid, uintptr_t remote_mod) {
    uintptr_t local_k32 = (uintptr_t)GetModuleHandleA("kernel32.dll");
    uintptr_t local_free = (uintptr_t)GetProcAddress((HMODULE)local_k32, "FreeLibrary");
    uintptr_t remote_k32 = mod_base(pid, L"kernel32.dll");
    if (!local_k32 || !local_free || !remote_k32)
        return 0;

    HANDLE th = CreateRemoteThread(
        proc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)(remote_k32 + (local_free - local_k32)),
        (void *)remote_mod,
        0,
        NULL);
    if (!th)
        return 0;
    WaitForSingleObject(th, 1000);
    CloseHandle(th);
    return 1;
}

static void set_result(Proc *p) {
    if (p->state != OK) {
        switch (p->state) {
        case DENIED: strcpy_s(p->result, sizeof(p->result), "denied"); break;
        case LOAD_FAIL: strcpy_s(p->result, sizeof(p->result), "load_fail"); break;
        case LOAD_TIMEOUT: strcpy_s(p->result, sizeof(p->result), "load_timeout"); break;
        case DUMP_FAIL: strcpy_s(p->result, sizeof(p->result), "dump_fail"); break;
        case DUMP_TIMEOUT: strcpy_s(p->result, sizeof(p->result), "dump_timeout"); break;
        default: strcpy_s(p->result, sizeof(p->result), "failed"); break;
        }
        return;
    }

    if (has(p->dump, "forced=yes")) {
        strcpy_s(p->result, sizeof(p->result), "forced");
    } else if (has(p->dump, "mouse=yes")) {
        strcpy_s(p->result, sizeof(p->result), "mouse");
    } else if (has(p->dump, "raw_other=yes")) {
        strcpy_s(p->result, sizeof(p->result), "raw_other");
    } else if (has(p->dump, "none")) {
        strcpy_s(p->result, sizeof(p->result), "none");
    } else {
        strcpy_s(p->result, sizeof(p->result), "unknown");
    }
}

static State inspect(Proc *p, const Scan *scan) {
    char out_path[MAX_PATH];
    snprintf(out_path, sizeof(out_path), "%sriflags_%lu.txt", scan->temp, (unsigned long)p->pid);
    DeleteFileA(out_path);

    HMODULE local_dll = LoadLibraryA(scan->dll);
    FARPROC local_dump = local_dll ? GetProcAddress(local_dll, "RawInputProbeDump") : NULL;
    uintptr_t dump_rva = local_dump ? (uintptr_t)local_dump - (uintptr_t)local_dll : 0;
    if (!dump_rva) {
        if (local_dll)
            FreeLibrary(local_dll);
        return FAIL;
    }
    FreeLibrary(local_dll);

    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        p->pid);
    if (!proc) {
        p->err = GetLastError();
        return p->err == ERROR_ACCESS_DENIED ? DENIED : FAIL;
    }

    SIZE_T dll_len = strlen(scan->dll) + 1;
    void *remote_path = VirtualAllocEx(proc, NULL, dll_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_path || !WriteProcessMemory(proc, remote_path, scan->dll, dll_len, NULL)) {
        p->err = GetLastError();
        if (remote_path)
            VirtualFreeEx(proc, remote_path, 0, MEM_RELEASE);
        CloseHandle(proc);
        return FAIL;
    }

    LPTHREAD_START_ROUTINE load_library =
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE load = CreateRemoteThread(proc, NULL, 0, load_library, remote_path, 0, NULL);
    if (!load) {
        p->err = GetLastError();
        VirtualFreeEx(proc, remote_path, 0, MEM_RELEASE);
        CloseHandle(proc);
        return FAIL;
    }

    DWORD wait = WaitForSingleObject(load, TIMEOUT_MS < 3000 ? TIMEOUT_MS : 3000);
    VirtualFreeEx(proc, remote_path, 0, MEM_RELEASE);
    if (wait != WAIT_OBJECT_0) {
        p->err = WAIT_TIMEOUT;
        CloseHandle(load);
        CloseHandle(proc);
        return LOAD_TIMEOUT;
    }

    DWORD exit_code = 0;
    if (!GetExitCodeThread(load, &exit_code) || !exit_code) {
        p->err = GetLastError();
        CloseHandle(load);
        CloseHandle(proc);
        return LOAD_FAIL;
    }
    CloseHandle(load);

    uintptr_t remote_dll = mod_base(p->pid, scan->dll_name);
    if (!remote_dll) {
        CloseHandle(proc);
        return LOAD_FAIL;
    }

    HANDLE dump = CreateRemoteThread(
        proc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)(remote_dll + dump_rva),
        NULL,
        0,
        NULL);
    if (!dump) {
        p->err = GetLastError();
        remote_free(proc, p->pid, remote_dll);
        CloseHandle(proc);
        return DUMP_FAIL;
    }

    DWORD slept = 0;
    while (slept < TIMEOUT_MS) {
        if (GetFileAttributesA(out_path) != INVALID_FILE_ATTRIBUTES) {
            WaitForSingleObject(dump, 1000);
            CloseHandle(dump);
            read_file(out_path, p->dump, sizeof(p->dump));
            remote_free(proc, p->pid, remote_dll);
            CloseHandle(proc);
            return OK;
        }
        Sleep(50);
        slept += 50;
    }

    p->err = WAIT_TIMEOUT;
    CloseHandle(dump);
    remote_free(proc, p->pid, remote_dll);
    CloseHandle(proc);
    return DUMP_TIMEOUT;
}

static DWORD WINAPI worker(void *arg) {
    Scan *scan = (Scan *)arg;
    for (;;) {
        LONG i = InterlockedIncrement(&scan->next) - 1;
        if (i >= scan->count)
            return 0;
        Proc *p = &scan->items[i];
        p->state = inspect(p, scan);
        set_result(p);
    }
}

static int list_procs(Proc **out, LONG *out_count) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    DWORD cap = 256;
    DWORD count = 0;
    Proc *items = (Proc *)calloc(cap, sizeof(*items));
    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (items && Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0)
                continue;
            if (count == cap) {
                cap *= 2;
                Proc *next = (Proc *)realloc(items, cap * sizeof(*items));
                if (!next) {
                    free(items);
                    CloseHandle(snap);
                    return 0;
                }
                items = next;
                ZeroMemory(items + count, (cap - count) * sizeof(*items));
            }
            items[count].pid = pe.th32ProcessID;
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, items[count].name, sizeof(items[count].name), NULL, NULL);
            ++count;
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    *out = items;
    *out_count = (LONG)count;
    return items != NULL;
}

static int cmp_proc(const void *a, const void *b) {
    const Proc *pa = (const Proc *)a;
    const Proc *pb = (const Proc *)b;
    int by_name = _stricmp(pa->name, pb->name);
    if (by_name)
        return by_name;
    return (pa->pid > pb->pid) - (pa->pid < pb->pid);
}

static int prepare(Scan *scan) {
    char dir[MAX_PATH];
    char src[MAX_PATH];
    ZeroMemory(scan, sizeof(*scan));

    if (!exe_dir(dir, sizeof(dir)))
        return 0;
    snprintf(src, sizeof(src), "%sriprobe.dll", dir);
    if (GetFileAttributesA(src) == INVALID_FILE_ATTRIBUTES)
        return 0;
    if (!stage_dll(src, scan->dll, sizeof(scan->dll), scan->dll_name, MAX_PATH))
        return 0;
    if (!GetTempPathA(sizeof(scan->temp), scan->temp))
        return 0;
    return 1;
}

static void print_one(const Proc *p) {
    printf("%-6lu %-28s %s", (unsigned long)p->pid, p->name, p->result);
    if (p->state != OK && p->err)
        printf(" (%lu)", (unsigned long)p->err);
    printf("\n");
}

static int run_scan(void) {
    Scan scan;
    if (!prepare(&scan) || !list_procs(&scan.items, &scan.count)) {
        printf("setup failed\n");
        return 2;
    }

    DWORD threads = WORKERS;
    if (threads < 1)
        threads = 1;
    if (threads > 64)
        threads = 64;
    if (threads > (DWORD)scan.count)
        threads = (DWORD)scan.count;

    HANDLE *pool = (HANDLE *)calloc(threads, sizeof(*pool));
    for (DWORD i = 0; i < threads; ++i)
        pool[i] = CreateThread(NULL, 0, worker, &scan, 0, NULL);
    WaitForMultipleObjects(threads, pool, TRUE, INFINITE);
    for (DWORD i = 0; i < threads; ++i)
        CloseHandle(pool[i]);
    free(pool);

    qsort(scan.items, scan.count, sizeof(scan.items[0]), cmp_proc);

    printf("PID    Process                      Result\n");
    printf("-----  ---------------------------  ------------------------------\n");
    for (LONG i = 0; i < scan.count; ++i) {
        print_one(&scan.items[i]);
    }
    free(scan.items);
    DeleteFileA(scan.dll);
    return 0;
}

int main(void) {
    int rc = run_scan();
    wait_before_close();
    return rc;
}
