// (C) 2026 Noverse (nohuto). All Rights Reserved.
// https://github.com/nohuto
// https://discord.noverse.dev

#include <windows.h>
#include <winioctl.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <shellapi.h>
#include <shlobj.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define XHCI_CLASS_ID L"PCI\\CC_0C0330"
#define XHCI_MAX_INTERRUPTERS 0x400u
#define MAX_CONTROLLERS 64u
#define MAX_RANGES 8u
#define DRIVER_SERVICE L"inpoutx64"
#define DRIVER_DEVICE L"\\\\.\\inpoutx64"
#define DRIVER_FILENAME L"inpoutx64.sys"
#define TASK_NAME L"xHCI IMOD"
#define APP_DIRECTORY L"Noverse\\IMOD"

#define IOCTL_WINIO_MAPPHYSTOLIN ((DWORD)0x9C40201Cu)
#define IOCTL_WINIO_UNMAPPHYSADDR ((DWORD)0x9C402020u)

typedef struct {
    HANDLE physical_memory_handle;
    SIZE_T size;
    void *physical_address;
    void *linear_address;
} PHYSICAL_MEMORY_REQUEST;

typedef struct {
    PHYSICAL_MEMORY_REQUEST request;
    volatile uint8_t *view;
} PHYSICAL_MAPPING;

typedef struct {
    SC_HANDLE manager;
    SC_HANDLE service;
    HANDLE device;
    bool created_service;
    bool started_service;
    bool verbose;
} INPOUT_DRIVER;

typedef struct {
    uint64_t base;
    uint64_t length;
} MEMORY_RANGE;

typedef struct {
    unsigned bus;
    unsigned device;
    unsigned function;
    wchar_t instance_id[MAX_DEVICE_ID_LEN];
    MEMORY_RANGE ranges[MAX_RANGES];
    size_t range_count;
} XHCI_CONTROLLER;

typedef enum {
    SELECT_FIRST,
    SELECT_INDEX,
    SELECT_BDF,
    SELECT_ALL
} CONTROLLER_SELECTION;

typedef struct {
    CONTROLLER_SELECTION selection;
    unsigned index;
    unsigned bus;
    unsigned device;
    unsigned function;
    bool interrupter_selected[XHCI_MAX_INTERRUPTERS];
    bool has_interrupter_selection;
    unsigned interval;
    bool no_write;
    bool verbose;
    bool startup;
    bool delete_task;
    bool no_exit;
    wchar_t driver_path[MAX_PATH];
} OPTIONS;

typedef enum {
    PHYS_NONE,
    PHYS_READ,
    PHYS_WRITE,
    PHYS_READ_BLOCK,
    PHYS_WRITE_BLOCK
} PHYS_COMMAND_KIND;

typedef struct {
    PHYS_COMMAND_KIND kind;
    uint64_t address;
    unsigned width;
    size_t size;
    uint64_t value;
    uint8_t *bytes;
} PHYS_COMMAND;

static void print_last_error(const wchar_t *operation, DWORD error)
{
    wchar_t *message = NULL;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    FormatMessageW(flags, NULL, error, 0, (wchar_t *)&message, 0, NULL);
    if (message != NULL) {
        size_t length = wcslen(message);
        while (length != 0 && (message[length - 1] == L'\r' || message[length - 1] == L'\n')) {
            message[--length] = L'\0';
        }
        fwprintf(stderr, L"[!] %ls failed with error %lu: %ls\n", operation, error, message);
        LocalFree(message);
    } else {
        fwprintf(stderr, L"[!] %ls failed with error %lu\n", operation, error);
    }
}

static bool parse_u64(const wchar_t *text, uint64_t maximum, uint64_t *value)
{
    wchar_t *end = NULL;
    int base = 0;
    errno = 0;
    unsigned long long parsed = wcstoull(text, &end, base);
    if (errno != 0 || end == text || *end != L'\0') {
        errno = 0;
        end = NULL;
        parsed = wcstoull(text, &end, 16);
    }
    if (errno != 0 || end == text || *end != L'\0' || parsed > maximum) {
        return false;
    }
    *value = (uint64_t)parsed;
    return true;
}

static bool parse_bdf(const wchar_t *text, unsigned *bus, unsigned *device, unsigned *function)
{
    unsigned b = 0;
    unsigned d = 0;
    unsigned f = 0;
    wchar_t tail = L'\0';
    if (swscanf_s(text, L"%x:%x.%x%c", &b, &d, &f, &tail, 1u) != 3 || b > 0xff || d > 0x1f || f > 7) {
        return false;
    }
    *bus = b;
    *device = d;
    *function = f;
    return true;
}

static void print_help(void)
{
    fputws(
        L"Usage: xhci_imod.exe [-h] [--driver PATH] [--bdf BDF | --xhci-index N | --all] [--interrupter ID] [--interval VALUE] [--no-write] [--verbose] [--startup] [--delete] [--no-exit]\n"
        L"       xhci_imod.exe read8|read16|read32|read64 ADDRESS\n"
        L"       xhci_imod.exe write8|write16|write32|write64 ADDRESS VALUE\n"
        L"       xhci_imod.exe readblk ADDRESS BYTES\n"
        L"       xhci_imod.exe writeblk ADDRESS BYTE [BYTE ...]\n\n"
        L"Options:\n"
        L"  -h, --help              Show this help message\n"
        L"  --driver PATH           Override the colocated inpoutx64.sys path\n"
        L"  --bdf BB:DD.F           Select an xHCI controller by PCI address\n"
        L"  --xhci-index N          Select the Nth xHCI controller\n"
        L"  --all                   Process every xHCI controller\n"
        L"  -i, --interrupter ID    Process one Interrupter, may be repeated\n"
        L"  --interval VALUE        Set IMODI in 250 ns units, defaults to 0\n"
        L"  --no-write              Read and output without MMIO writes\n"
        L"  --verbose               Show driver and controller details\n"
        L"  --startup               Create a highest privilege logon task\n"
        L"  --delete                Delete the logon task and IMOD folder\n"
        L"  --no-exit               Wait for Enter before closing\n",
        stdout);
}

static bool set_selection(OPTIONS *options, CONTROLLER_SELECTION selection)
{
    if (options->selection != SELECT_FIRST) {
        fputws(L"[!] Use only one of --bdf, --xhci-index, or --all\n", stderr);
        return false;
    }
    options->selection = selection;
    return true;
}

static bool parse_options(int argc, wchar_t **argv, OPTIONS *options)
{
    memset(options, 0, sizeof(*options));
    options->selection = SELECT_FIRST;
    options->interval = 0;

    for (int i = 1; i < argc; ++i) {
        const wchar_t *argument = argv[i];
        uint64_t value = 0;
        if (wcscmp(argument, L"-h") == 0 || wcscmp(argument, L"--help") == 0) {
            print_help();
            return false;
        } else if (wcscmp(argument, L"--driver") == 0) {
            if (++i == argc || wcslen(argv[i]) >= ARRAY_COUNT(options->driver_path)) {
                fputws(L"[!] --driver requires a valid path\n", stderr);
                return false;
            }
            wcscpy_s(options->driver_path, ARRAY_COUNT(options->driver_path), argv[i]);
        } else if (wcscmp(argument, L"--bdf") == 0) {
            if (++i == argc || !set_selection(options, SELECT_BDF) ||
                !parse_bdf(argv[i], &options->bus, &options->device, &options->function)) {
                fputws(L"[!] --bdf requires hexadecimal BB:DD.F\n", stderr);
                return false;
            }
        } else if (wcscmp(argument, L"--xhci-index") == 0) {
            if (++i == argc || !set_selection(options, SELECT_INDEX) || !parse_u64(argv[i], 0xff, &value)) {
                fputws(L"[!] --xhci-index requires a value within 0-255\n", stderr);
                return false;
            }
            options->index = (unsigned)value;
        } else if (wcscmp(argument, L"--all") == 0) {
            if (!set_selection(options, SELECT_ALL)) {
                return false;
            }
        } else if (wcscmp(argument, L"--interrupter") == 0 || wcscmp(argument, L"-i") == 0) {
            if (++i == argc || !parse_u64(argv[i], XHCI_MAX_INTERRUPTERS - 1u, &value)) {
                fputws(L"[!] --interrupter requires a value within 0-1023\n", stderr);
                return false;
            }
            options->interrupter_selected[value] = true;
            options->has_interrupter_selection = true;
        } else if (wcscmp(argument, L"--interval") == 0) {
            if (++i == argc || !parse_u64(argv[i], 0xffff, &value)) {
                fputws(L"[!] --interval requires a value within 0-65535\n", stderr);
                return false;
            }
            options->interval = (unsigned)value;
        } else if (wcscmp(argument, L"--no-write") == 0) {
            options->no_write = true;
        } else if (wcscmp(argument, L"--verbose") == 0) {
            options->verbose = true;
        } else if (wcscmp(argument, L"--startup") == 0) {
            options->startup = true;
        } else if (wcscmp(argument, L"--delete") == 0) {
            options->delete_task = true;
        } else if (wcscmp(argument, L"--no-exit") == 0) {
            options->no_exit = true;
        } else {
            fwprintf(stderr, L"[!] Unknown argument: %ls\n", argument);
            return false;
        }
    }

    if (options->startup && options->delete_task) {
        fputws(L"[!] Use either --startup or --delete\n", stderr);
        return false;
    }
    return true;
}

static bool parse_phys_command(int argc, wchar_t **argv, PHYS_COMMAND *command)
{
    memset(command, 0, sizeof(*command));
    if (argc < 2) {
        return false;
    }

    const wchar_t *name = argv[1];
    if (wcsncmp(name, L"read", 4) == 0 && wcscmp(name, L"readblk") != 0) {
        command->kind = PHYS_READ;
        name += 4;
    } else if (wcsncmp(name, L"write", 5) == 0 && wcscmp(name, L"writeblk") != 0) {
        command->kind = PHYS_WRITE;
        name += 5;
    } else if (wcscmp(name, L"readblk") == 0) {
        command->kind = PHYS_READ_BLOCK;
    } else if (wcscmp(name, L"writeblk") == 0) {
        command->kind = PHYS_WRITE_BLOCK;
    } else {
        return false;
    }

    uint64_t parsed = 0;
    if (command->kind == PHYS_READ || command->kind == PHYS_WRITE) {
        if (!parse_u64(name, 64, &parsed) || (parsed != 8 && parsed != 16 && parsed != 32 && parsed != 64)) {
            fputws(L"[!] Physical access width must be 8, 16, 32, or 64\n", stderr);
            return false;
        }
        command->width = (unsigned)parsed;
        command->size = command->width / 8u;
        int expected = command->kind == PHYS_READ ? 3 : 4;
        if (argc != expected || !parse_u64(argv[2], UINT64_MAX, &command->address)) {
            fputws(L"[!] Invalid physical memory command arguments\n", stderr);
            return false;
        }
        if (command->kind == PHYS_WRITE && !parse_u64(argv[3], UINT64_MAX, &command->value)) {
            fputws(L"[!] Invalid physical memory value\n", stderr);
            return false;
        }
        if (command->width != 64 && command->value >= (UINT64_C(1) << command->width)) {
            fputws(L"[!] Physical memory value does not fit the selected width\n", stderr);
            return false;
        }
    } else if (command->kind == PHYS_READ_BLOCK) {
        if (argc != 4 || !parse_u64(argv[2], UINT64_MAX, &command->address) ||
            !parse_u64(argv[3], 0x100000, &parsed) || parsed == 0) {
            fputws(L"[!] readblk requires ADDRESS and BYTES\n", stderr);
            return false;
        }
        command->size = (size_t)parsed;
    } else {
        if (argc < 4 || !parse_u64(argv[2], UINT64_MAX, &command->address)) {
            fputws(L"[!] writeblk requires ADDRESS and at least one BYTE\n", stderr);
            return false;
        }
        command->size = (size_t)(argc - 3);
        command->bytes = calloc(command->size, 1);
        if (command->bytes == NULL) {
            fputws(L"[!] Memory allocation failed\n", stderr);
            return false;
        }
        for (size_t i = 0; i < command->size; ++i) {
            if (!parse_u64(argv[i + 3], 0xff, &parsed)) {
                fputws(L"[!] writeblk values must be bytes\n", stderr);
                free(command->bytes);
                command->bytes = NULL;
                return false;
            }
            command->bytes[i] = (uint8_t)parsed;
        }
    }
    return true;
}

static bool get_executable_directory(wchar_t *directory, size_t count)
{
    DWORD length = GetModuleFileNameW(NULL, directory, (DWORD)count);
    if (length == 0 || length >= count) {
        return false;
    }
    wchar_t *separator = wcsrchr(directory, L'\\');
    if (separator == NULL) {
        return false;
    }
    *separator = L'\0';
    return true;
}

static bool make_absolute_path(const wchar_t *path, wchar_t *absolute, size_t count)
{
    DWORD length = GetFullPathNameW(path, (DWORD)count, absolute, NULL);
    return length != 0 && length < count;
}

static bool resolve_driver_path(OPTIONS *options)
{
    wchar_t path[MAX_PATH];
    if (options->driver_path[0] != L'\0') {
        if (!make_absolute_path(options->driver_path, path, ARRAY_COUNT(path))) {
            fputws(L"[!] Invalid driver path\n", stderr);
            return false;
        }
    } else {
        if (!get_executable_directory(path, ARRAY_COUNT(path)) ||
            wcscat_s(path, ARRAY_COUNT(path), L"\\" DRIVER_FILENAME) != 0) {
            fputws(L"[!] Failed to resolve the driver path\n", stderr);
            return false;
        }
    }
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"[!] Driver not found: %ls\n", path);
        return false;
    }
    wcscpy_s(options->driver_path, ARRAY_COUNT(options->driver_path), path);
    return true;
}

static bool wait_for_service(SC_HANDLE service, DWORD desired_state)
{
    SERVICE_STATUS_PROCESS status;
    DWORD needed = 0;
    ULONGLONG deadline = GetTickCount64() + 5000;
    do {
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &needed)) {
            return false;
        }
        if (status.dwCurrentState == desired_state) {
            return true;
        }
        Sleep(20);
    } while (GetTickCount64() < deadline);
    SetLastError(ERROR_TIMEOUT);
    return false;
}

static bool driver_open(INPOUT_DRIVER *driver, const wchar_t *driver_path, bool verbose)
{
    memset(driver, 0, sizeof(*driver));
    driver->device = INVALID_HANDLE_VALUE;
    driver->verbose = verbose;
    driver->manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (driver->manager == NULL) {
        print_last_error(L"OpenSCManager", GetLastError());
        return false;
    }

    driver->service = OpenServiceW(driver->manager, DRIVER_SERVICE,
        SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | DELETE);
    if (driver->service == NULL && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
        driver->service = CreateServiceW(driver->manager, DRIVER_SERVICE, DRIVER_SERVICE,
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | DELETE,
            SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            driver_path, NULL, NULL, NULL, NULL, NULL);
        if (driver->service != NULL) {
            driver->created_service = true;
            if (verbose) {
                fwprintf(stdout, L"[driver] Created %ls from %ls\n", DRIVER_SERVICE, driver_path);
            }
        }
    }
    if (driver->service == NULL) {
        print_last_error(L"OpenService/CreateService", GetLastError());
        return false;
    }

    SERVICE_STATUS_PROCESS status;
    DWORD needed = 0;
    if (!QueryServiceStatusEx(driver->service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &needed)) {
        print_last_error(L"QueryServiceStatus", GetLastError());
        return false;
    }
    if (status.dwCurrentState != SERVICE_RUNNING) {
        if (!StartServiceW(driver->service, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            print_last_error(L"StartService", GetLastError());
            return false;
        }
        driver->started_service = true;
        if (!wait_for_service(driver->service, SERVICE_RUNNING)) {
            print_last_error(L"Wait for inpoutx64", GetLastError());
            return false;
        }
        if (verbose) {
            fputws(L"[driver] Started inpoutx64\n", stdout);
        }
    }

    driver->device = CreateFileW(DRIVER_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (driver->device == INVALID_HANDLE_VALUE) {
        print_last_error(L"Open inpoutx64 device", GetLastError());
        return false;
    }
    return true;
}

static void driver_close(INPOUT_DRIVER *driver)
{
    if (driver->device != INVALID_HANDLE_VALUE) {
        CloseHandle(driver->device);
        driver->device = INVALID_HANDLE_VALUE;
    }
    if (driver->service != NULL && driver->started_service) {
        SERVICE_STATUS status;
        ControlService(driver->service, SERVICE_CONTROL_STOP, &status);
        wait_for_service(driver->service, SERVICE_STOPPED);
        if (driver->verbose) {
            fputws(L"[driver] Stopped inpoutx64\n", stdout);
        }
    }
    if (driver->service != NULL && driver->created_service) {
        DeleteService(driver->service);
        if (driver->verbose) {
            fputws(L"[driver] Deleted the temporary service\n", stdout);
        }
    }
    if (driver->service != NULL) {
        CloseServiceHandle(driver->service);
    }
    if (driver->manager != NULL) {
        CloseServiceHandle(driver->manager);
    }
}

static bool physical_map(INPOUT_DRIVER *driver, uint64_t address, size_t size, PHYSICAL_MAPPING *mapping)
{
    if (size == 0 || size > MAXDWORD || address > UINTPTR_MAX || address + size < address) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    memset(mapping, 0, sizeof(*mapping));
    mapping->request.size = size;
    mapping->request.physical_address = (void *)(uintptr_t)address;
    DWORD returned = 0;
    if (!DeviceIoControl(driver->device, IOCTL_WINIO_MAPPHYSTOLIN,
            &mapping->request, sizeof(mapping->request), &mapping->request, sizeof(mapping->request),
            &returned, NULL)) {
        return false;
    }
    uint64_t mapped_base = (uint64_t)(uintptr_t)mapping->request.physical_address;
    if (mapping->request.linear_address == NULL || mapped_base > address) {
        SetLastError(ERROR_INVALID_ADDRESS);
        return false;
    }
    mapping->view = (volatile uint8_t *)mapping->request.linear_address + (size_t)(address - mapped_base);
    return true;
}

static bool physical_unmap(INPOUT_DRIVER *driver, PHYSICAL_MAPPING *mapping)
{
    PHYSICAL_MEMORY_REQUEST request;
    memset(&request, 0, sizeof(request));
    request.physical_memory_handle = mapping->request.physical_memory_handle;
    request.linear_address = (void *)mapping->view;
    DWORD returned = 0;
    bool result = DeviceIoControl(driver->device, IOCTL_WINIO_UNMAPPHYSADDR,
        &request, sizeof(request), NULL, 0, &returned, NULL) != FALSE;
    mapping->view = NULL;
    return result;
}

static uint32_t mmio_read32(const volatile uint8_t *base, size_t offset)
{
    MemoryBarrier();
    uint32_t value = *(const volatile uint32_t *)(base + offset);
    MemoryBarrier();
    return value;
}

static void mmio_write32(volatile uint8_t *base, size_t offset, uint32_t value)
{
    MemoryBarrier();
    *(volatile uint32_t *)(base + offset) = value;
    MemoryBarrier();
}

static bool physical_read32(INPOUT_DRIVER *driver, uint64_t address, uint32_t *value)
{
    PHYSICAL_MAPPING mapping;
    if (!physical_map(driver, address, sizeof(*value), &mapping)) {
        return false;
    }
    *value = mmio_read32(mapping.view, 0);
    return physical_unmap(driver, &mapping);
}

static bool get_device_property(HDEVINFO devices, SP_DEVINFO_DATA *device, DWORD property,
    BYTE **buffer, DWORD *size, DWORD *type)
{
    DWORD required = 0;
    SetupDiGetDeviceRegistryPropertyW(devices, device, property, type, NULL, 0, &required);
    if (required == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return false;
    }
    BYTE *data = malloc(required);
    if (data == NULL) {
        return false;
    }
    if (!SetupDiGetDeviceRegistryPropertyW(devices, device, property, type, data, required, &required)) {
        free(data);
        return false;
    }
    *buffer = data;
    *size = required;
    return true;
}

static bool multi_sz_contains(const wchar_t *values, size_t bytes, const wchar_t *expected)
{
    const wchar_t *end = (const wchar_t *)((const uint8_t *)values + bytes);
    for (const wchar_t *value = values; value < end && *value != L'\0'; value += wcslen(value) + 1) {
        if (_wcsicmp(value, expected) == 0) {
            return true;
        }
    }
    return false;
}

static void add_memory_range(XHCI_CONTROLLER *controller, uint64_t base, uint64_t length)
{
    if (base == 0 || length == 0 || controller->range_count == MAX_RANGES) {
        return;
    }
    for (size_t i = 0; i < controller->range_count; ++i) {
        if (controller->ranges[i].base == base && controller->ranges[i].length == length) {
            return;
        }
    }
    controller->ranges[controller->range_count].base = base;
    controller->ranges[controller->range_count].length = length;
    ++controller->range_count;
}

static void add_allocated_memory_resources(XHCI_CONTROLLER *controller, DEVINST devinst, bool verbose)
{
    LOG_CONF config = 0;
    CONFIGRET result = CM_Get_First_Log_Conf(&config, devinst, ALLOC_LOG_CONF);
    if (result != CR_SUCCESS) {
        if (verbose) fwprintf(stderr, L"[device] CM_Get_First_Log_Conf returned 0x%08X\n", result);
        return;
    }
    RES_DES current = (RES_DES)config;
    for (;;) {
        RES_DES next = 0;
        RESOURCEID found_type = 0;
        result = CM_Get_Next_Res_Des(&next, current, ResType_All, &found_type, 0);
        if (current != (RES_DES)config) {
            CM_Free_Res_Des_Handle(current);
        }
        if (result != CR_SUCCESS) {
            break;
        }
        current = next;
        if (found_type != ResType_Mem && found_type != ResType_MemLarge) {
            continue;
        }
        ULONG size = 0;
        if (CM_Get_Res_Des_Data_Size(&size, current, 0) != CR_SUCCESS || size == 0) {
            continue;
        }
        void *data = malloc(size);
        if (data == NULL) {
            continue;
        }
        if (CM_Get_Res_Des_Data(current, data, size, 0) == CR_SUCCESS) {
            if (found_type == ResType_Mem && size >= sizeof(MEM_DES)) {
                MEM_DES *memory = data;
                if (memory->MD_Alloc_End >= memory->MD_Alloc_Base) {
                    add_memory_range(controller, memory->MD_Alloc_Base,
                        memory->MD_Alloc_End - memory->MD_Alloc_Base + 1);
                }
            } else if (found_type == ResType_MemLarge && size >= sizeof(MEM_LARGE_DES)) {
                MEM_LARGE_DES *memory = data;
                if (memory->MLD_Alloc_End >= memory->MLD_Alloc_Base) {
                    add_memory_range(controller, memory->MLD_Alloc_Base,
                        memory->MLD_Alloc_End - memory->MLD_Alloc_Base + 1);
                }
            }
        }
        free(data);
    }
    CM_Free_Log_Conf_Handle(config);
}

static int compare_controllers(const void *left, const void *right)
{
    const XHCI_CONTROLLER *a = left;
    const XHCI_CONTROLLER *b = right;
    if (a->bus != b->bus) return a->bus < b->bus ? -1 : 1;
    if (a->device != b->device) return a->device < b->device ? -1 : 1;
    if (a->function != b->function) return a->function < b->function ? -1 : 1;
    return 0;
}

static bool enumerate_xhci(XHCI_CONTROLLER *controllers, size_t *controller_count, bool verbose)
{
    *controller_count = 0;
    HDEVINFO devices = SetupDiGetClassDevsW(NULL, L"PCI", NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (devices == INVALID_HANDLE_VALUE) {
        print_last_error(L"SetupDiGetClassDevs", GetLastError());
        return false;
    }

    for (DWORD index = 0; *controller_count < MAX_CONTROLLERS; ++index) {
        SP_DEVINFO_DATA device;
        memset(&device, 0, sizeof(device));
        device.cbSize = sizeof(device);
        if (!SetupDiEnumDeviceInfo(devices, index, &device)) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) {
                print_last_error(L"SetupDiEnumDeviceInfo", GetLastError());
            }
            break;
        }
        BYTE *ids = NULL;
        DWORD ids_size = 0;
        DWORD type = 0;
        if (!get_device_property(devices, &device, SPDRP_COMPATIBLEIDS, &ids, &ids_size, &type) ||
            type != REG_MULTI_SZ || !multi_sz_contains((wchar_t *)ids, ids_size, XHCI_CLASS_ID)) {
            free(ids);
            continue;
        }
        free(ids);

        DWORD bus = 0;
        DWORD address = 0;
        DWORD size = 0;
        if (!SetupDiGetDeviceRegistryPropertyW(devices, &device, SPDRP_BUSNUMBER, &type,
                (BYTE *)&bus, sizeof(bus), &size) ||
            !SetupDiGetDeviceRegistryPropertyW(devices, &device, SPDRP_ADDRESS, &type,
                (BYTE *)&address, sizeof(address), &size)) {
            continue;
        }
        XHCI_CONTROLLER *controller = &controllers[(*controller_count)++];
        memset(controller, 0, sizeof(*controller));
        controller->bus = bus;
        controller->device = (address >> 16) & 0xffff;
        controller->function = address & 0xffff;
        SetupDiGetDeviceInstanceIdW(devices, &device, controller->instance_id,
            ARRAY_COUNT(controller->instance_id), NULL);
        add_allocated_memory_resources(controller, device.DevInst, verbose);
        if (verbose) {
            fwprintf(stdout, L"[device] PCI %02x:%02x.%x %ls\n", controller->bus,
                controller->device, controller->function, controller->instance_id);
            for (size_t range = 0; range < controller->range_count; ++range) {
                fwprintf(stdout, L"[device] Memory 0x%016llX-0x%016llX\n",
                    (unsigned long long)controller->ranges[range].base,
                    (unsigned long long)(controller->ranges[range].base + controller->ranges[range].length - 1));
            }
        }
    }
    SetupDiDestroyDeviceInfoList(devices);
    qsort(controllers, *controller_count, sizeof(*controllers), compare_controllers);
    return true;
}

static bool get_controller_layout(INPOUT_DRIVER *driver, const XHCI_CONTROLLER *controller,
    uint64_t *register_base, uint64_t *register_length, uint32_t *runtime_offset,
    unsigned *maximum, unsigned *version)
{
    for (size_t i = 0; i < controller->range_count; ++i) {
        const MEMORY_RANGE *range = &controller->ranges[i];
        if (range->length < 0x20) {
            continue;
        }
        uint32_t capability = 0;
        uint32_t hcsparams1 = 0;
        uint32_t rtsoff = 0;
        if (!physical_read32(driver, range->base, &capability) ||
            !physical_read32(driver, range->base + 0x04, &hcsparams1) ||
            !physical_read32(driver, range->base + 0x18, &rtsoff)) {
            continue;
        }
        unsigned caplength = capability & 0xff;
        unsigned max_intrs = (hcsparams1 >> 8) & 0x7ff;
        uint32_t runtime = rtsoff & 0xffffffe0u;
        uint64_t required = (uint64_t)runtime + 0x20 + (uint64_t)max_intrs * 0x20;
        if (caplength < 0x20 || max_intrs == 0 || max_intrs > XHCI_MAX_INTERRUPTERS ||
            runtime == 0 || required > range->length || required > MAXDWORD) {
            continue;
        }
        *register_base = range->base;
        *register_length = required;
        *runtime_offset = runtime;
        *maximum = max_intrs;
        *version = (capability >> 16) & 0xffff;
        return true;
    }
    return false;
}

static bool process_controller(INPOUT_DRIVER *driver, const XHCI_CONTROLLER *controller,
    const OPTIONS *options)
{
    fwprintf(stdout, L"[~] xHCI controller at PCI %02x:%02x.%x\n",
        controller->bus, controller->device, controller->function);
    uint64_t register_base = 0;
    uint64_t register_length = 0;
    uint32_t runtime_offset = 0;
    unsigned maximum = 0;
    unsigned version = 0;
    if (!get_controller_layout(driver, controller, &register_base, &register_length,
            &runtime_offset, &maximum, &version)) {
        fputws(L"[!] No valid xHCI MMIO resource was found\n", stderr);
        return false;
    }

    PHYSICAL_MAPPING mapping;
    if (!physical_map(driver, register_base, (size_t)register_length, &mapping)) {
        print_last_error(L"Map xHCI MMIO", GetLastError());
        return false;
    }
    bool active[XHCI_MAX_INTERRUPTERS] = { false };
    unsigned active_count = 0;
    for (unsigned index = 0; index < maximum; ++index) {
        size_t erstsz = runtime_offset + 0x20 + (size_t)index * 0x20 + 0x08;
        active[index] = (mmio_read32(mapping.view, erstsz) & 0xffff) != 0;
        active_count += active[index] ? 1u : 0u;
    }
    if (active_count == 0) {
        physical_unmap(driver, &mapping);
        fputws(L"[!] No initialized xHCI Event Rings were found\n", stderr);
        return false;
    }
    if (options->has_interrupter_selection) {
        for (unsigned index = maximum; index < XHCI_MAX_INTERRUPTERS; ++index) {
            if (options->interrupter_selected[index]) {
                physical_unmap(driver, &mapping);
                fwprintf(stderr, L"[!] Interrupter %u is not implemented by this controller\n", index);
                return false;
            }
        }
    }

    fwprintf(stdout, L"    xHCI %X.%02X, register base 0x%016llX\n",
        version >> 8, version & 0xff, (unsigned long long)register_base);
    fwprintf(stdout, L"    Runtime base 0x%016llX, %u implemented, %u initialized\n",
        (unsigned long long)(register_base + runtime_offset), maximum, active_count);

    bool success = true;
    for (unsigned index = 0; index < maximum; ++index) {
        bool selected = options->has_interrupter_selection ? options->interrupter_selected[index] : active[index];
        if (!selected) {
            continue;
        }
        if (!active[index]) {
            fwprintf(stdout, L"[~] Interrupter %u does not have an initialized Event Ring\n", index);
        }
        size_t imod_offset = runtime_offset + 0x20 + (size_t)index * 0x20 + 0x04;
        uint64_t imod_address = register_base + imod_offset;
        uint32_t current = mmio_read32(mapping.view, imod_offset);
        unsigned interval = current & 0xffff;
        unsigned counter = current >> 16;
        if (options->no_write || interval == options->interval) {
            fwprintf(stdout, L"[-] Interrupter %u: IMODI=%u, IMODC=%u at 0x%016llX\n",
                index, interval, counter, (unsigned long long)imod_address);
            continue;
        }
        fwprintf(stdout, L"[+] Interrupter %u: IMODI=%u, IMODC=%u at 0x%016llX, setting IMODI=%u\n",
            index, interval, counter, (unsigned long long)imod_address, options->interval);
        mmio_write32(mapping.view, imod_offset, options->interval);
        uint32_t readback = mmio_read32(mapping.view, imod_offset);
        if ((readback & 0xffff) != options->interval) {
            fwprintf(stderr, L"[!] Interrupter %u verification failed with 0x%08X\n", index, readback);
            success = false;
        }
    }
    if (!physical_unmap(driver, &mapping)) {
        print_last_error(L"Unmap xHCI MMIO", GetLastError());
        success = false;
    }
    if (success) {
        fputws(L"[+] Done\n", stdout);
    }
    return success;
}

static void hexdump(const uint8_t *bytes, size_t size, uint64_t address)
{
    for (size_t offset = 0; offset < size; offset += 16) {
        size_t line = size - offset < 16 ? size - offset : 16;
        fwprintf(stdout, L"%016llX  ", (unsigned long long)(address + offset));
        for (size_t i = 0; i < 16; ++i) {
            if (i < line) fwprintf(stdout, L"%02X ", bytes[offset + i]);
            else fputws(L"   ", stdout);
        }
        fputws(L" |", stdout);
        for (size_t i = 0; i < line; ++i) {
            uint8_t value = bytes[offset + i];
            fputwc(value >= 0x20 && value <= 0x7e ? value : L'.', stdout);
        }
        fputws(L"|\n", stdout);
    }
}

static int execute_phys_command(INPOUT_DRIVER *driver, const PHYS_COMMAND *command)
{
    PHYSICAL_MAPPING mapping;
    if (!physical_map(driver, command->address, command->size, &mapping)) {
        print_last_error(L"Map physical memory", GetLastError());
        return 1;
    }
    if (command->kind == PHYS_READ) {
        uint64_t value = 0;
        for (size_t i = 0; i < command->size; ++i) {
            value |= (uint64_t)mapping.view[i] << (i * 8);
        }
        fwprintf(stdout, L"0x%016llX 0x%0*llX\n",
            (unsigned long long)command->address, command->width / 4, (unsigned long long)value);
    } else if (command->kind == PHYS_WRITE) {
        for (size_t i = 0; i < command->size; ++i) {
            mapping.view[i] = (uint8_t)(command->value >> (i * 8));
        }
        MemoryBarrier();
        uint64_t readback = 0;
        for (size_t i = 0; i < command->size; ++i) {
            readback |= (uint64_t)mapping.view[i] << (i * 8);
        }
        fwprintf(stdout, L"0x%016llX 0x%0*llX\n",
            (unsigned long long)command->address, command->width / 4, (unsigned long long)readback);
    } else if (command->kind == PHYS_READ_BLOCK) {
        uint8_t *copy = malloc(command->size);
        if (copy == NULL) {
            physical_unmap(driver, &mapping);
            return 1;
        }
        for (size_t i = 0; i < command->size; ++i) copy[i] = mapping.view[i];
        hexdump(copy, command->size, command->address);
        free(copy);
    } else {
        for (size_t i = 0; i < command->size; ++i) mapping.view[i] = command->bytes[i];
        MemoryBarrier();
        uint8_t *copy = malloc(command->size);
        if (copy != NULL) {
            for (size_t i = 0; i < command->size; ++i) copy[i] = mapping.view[i];
            hexdump(copy, command->size, command->address);
            free(copy);
        }
    }
    if (!physical_unmap(driver, &mapping)) {
        print_last_error(L"Unmap physical memory", GetLastError());
        return 1;
    }
    return 0;
}

static bool get_imod_directory(wchar_t *directory, size_t count)
{
    PWSTR local = NULL;
    if (SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &local) != S_OK) {
        return false;
    }
    int written = swprintf_s(directory, count, L"%ls\\%ls", local, APP_DIRECTORY);
    CoTaskMemFree(local);
    return written > 0;
}

static int run_process(const wchar_t *application, wchar_t *command_line, bool hidden)
{
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    startup.cb = sizeof(startup);
    if (hidden) {
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = SW_HIDE;
    }
    if (!CreateProcessW(application, command_line, NULL, NULL, FALSE,
            hidden ? CREATE_NO_WINDOW : 0, NULL, NULL, &startup, &process)) {
        return -1;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return (int)exit_code;
}

static bool append_argument(wchar_t *buffer, size_t count, const wchar_t *format, ...)
{
    size_t used = wcslen(buffer);
    va_list arguments;
    va_start(arguments, format);
    int written = _vsnwprintf_s(buffer + used, count - used, _TRUNCATE, format, arguments);
    va_end(arguments);
    return written >= 0;
}

static bool install_startup_task(const OPTIONS *options)
{
    wchar_t directory[MAX_PATH];
    wchar_t source_exe[MAX_PATH];
    wchar_t target_exe[MAX_PATH];
    wchar_t target_driver[MAX_PATH];
    if (!get_imod_directory(directory, ARRAY_COUNT(directory))) {
        fputws(L"[!] Failed to resolve the startup directory\n", stderr);
        return false;
    }
    int directory_result = SHCreateDirectoryExW(NULL, directory, NULL);
    if ((directory_result != ERROR_SUCCESS && directory_result != ERROR_ALREADY_EXISTS &&
            directory_result != ERROR_FILE_EXISTS) ||
        GetModuleFileNameW(NULL, source_exe, ARRAY_COUNT(source_exe)) == 0 ||
        swprintf_s(target_exe, ARRAY_COUNT(target_exe), L"%ls\\xhci_imod.exe", directory) <= 0 ||
        swprintf_s(target_driver, ARRAY_COUNT(target_driver), L"%ls\\%ls", directory, DRIVER_FILENAME) <= 0) {
        fputws(L"[!] Failed to prepare the startup directory\n", stderr);
        return false;
    }
    if (_wcsicmp(source_exe, target_exe) != 0 && !CopyFileW(source_exe, target_exe, FALSE)) {
        print_last_error(L"Copy xhci_imod.exe", GetLastError());
        return false;
    }
    if (_wcsicmp(options->driver_path, target_driver) != 0 && !CopyFileW(options->driver_path, target_driver, FALSE)) {
        print_last_error(L"Copy inpoutx64.sys", GetLastError());
        return false;
    }

    wchar_t task_arguments[4096] = L"";
    if (options->selection == SELECT_ALL) append_argument(task_arguments, ARRAY_COUNT(task_arguments), L" --all");
    if (options->selection == SELECT_INDEX) append_argument(task_arguments, ARRAY_COUNT(task_arguments), L" --xhci-index %u", options->index);
    if (options->selection == SELECT_BDF) append_argument(task_arguments, ARRAY_COUNT(task_arguments), L" --bdf %02x:%02x.%x", options->bus, options->device, options->function);
    for (unsigned index = 0; index < XHCI_MAX_INTERRUPTERS; ++index) {
        if (options->interrupter_selected[index]) append_argument(task_arguments, ARRAY_COUNT(task_arguments), L" --interrupter %u", index);
    }
    append_argument(task_arguments, ARRAY_COUNT(task_arguments), L" --interval %u", options->interval);
    if (options->no_write) append_argument(task_arguments, ARRAY_COUNT(task_arguments), L" --no-write");
    if (options->verbose) append_argument(task_arguments, ARRAY_COUNT(task_arguments), L" --verbose");

    wchar_t task_action[4600];
    wchar_t command[8192];
    swprintf_s(task_action, ARRAY_COUNT(task_action), L"\\\"%ls\\\"%ls", target_exe, task_arguments);
    swprintf_s(command, ARRAY_COUNT(command),
        L"schtasks.exe /Create /SC ONLOGON /RL HIGHEST /TN \"%ls\" /TR \"%ls\" /F",
        TASK_NAME, task_action);
    int result = run_process(L"C:\\Windows\\System32\\schtasks.exe", command, true);
    if (result != 0) {
        fwprintf(stderr, L"[!] Failed to create scheduled task, exit code %d\n", result);
        return false;
    }
    fwprintf(stdout, L"[+] Scheduled task '%ls' created\n", TASK_NAME);
    return true;
}

static bool path_is_inside(const wchar_t *path, const wchar_t *directory)
{
    size_t length = wcslen(directory);
    return _wcsnicmp(path, directory, length) == 0 && (path[length] == L'\\' || path[length] == L'\0');
}

static bool delete_imod_directory(void)
{
    wchar_t directory[MAX_PATH];
    wchar_t source_exe[MAX_PATH];
    if (!get_imod_directory(directory, ARRAY_COUNT(directory))) {
        return false;
    }
    if (GetFileAttributesW(directory) == INVALID_FILE_ATTRIBUTES) {
        return true;
    }
    if (GetModuleFileNameW(NULL, source_exe, ARRAY_COUNT(source_exe)) == 0) {
        return false;
    }
    if (!path_is_inside(source_exe, directory)) {
        wchar_t from[MAX_PATH + 1];
        memset(from, 0, sizeof(from));
        wcscpy_s(from, ARRAY_COUNT(from), directory);
        SHFILEOPSTRUCTW operation;
        memset(&operation, 0, sizeof(operation));
        operation.wFunc = FO_DELETE;
        operation.pFrom = from;
        operation.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
        if (SHFileOperationW(&operation) == 0 && !operation.fAnyOperationsAborted) {
            fwprintf(stdout, L"[+] Deleted %ls\n", directory);
            return true;
        }
        return false;
    }

    wchar_t escaped[MAX_PATH * 2];
    size_t output = 0;
    for (size_t input = 0; directory[input] != L'\0' && output + 2 < ARRAY_COUNT(escaped); ++input) {
        escaped[output++] = directory[input];
        if (directory[input] == L'\'') escaped[output++] = L'\'';
    }
    escaped[output] = L'\0';
    wchar_t parameters[4096];
    swprintf_s(parameters, ARRAY_COUNT(parameters),
        L"-NoProfile -NonInteractive -WindowStyle Hidden -Command \"$target='%ls'; Wait-Process -Id %lu -ErrorAction SilentlyContinue; for($i=0; $i -lt 50 -and (Test-Path -LiteralPath $target); $i++){ Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue; if(Test-Path -LiteralPath $target){ Start-Sleep -Milliseconds 100 } }\"",
        escaped, GetCurrentProcessId());
    SHELLEXECUTEINFOW execute;
    memset(&execute, 0, sizeof(execute));
    execute.cbSize = sizeof(execute);
    execute.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
    execute.lpFile = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    execute.lpParameters = parameters;
    execute.nShow = SW_HIDE;
    if (!ShellExecuteExW(&execute)) {
        return false;
    }
    CloseHandle(execute.hProcess);
    fwprintf(stdout, L"[+] %ls will be deleted after xHCI IMOD exits\n", directory);
    return true;
}

static int delete_startup_task(void)
{
    wchar_t command[512];
    swprintf_s(command, ARRAY_COUNT(command), L"schtasks.exe /Delete /TN \"%ls\" /F", TASK_NAME);
    int result = run_process(L"C:\\Windows\\System32\\schtasks.exe", command, true);
    if (result == 0) {
        fwprintf(stdout, L"[+] Scheduled task '%ls' deleted\n", TASK_NAME);
    } else {
        fwprintf(stdout, L"[~] Scheduled task '%ls' was not present\n", TASK_NAME);
    }
    if (!delete_imod_directory()) {
        fputws(L"[!] Failed to delete the IMOD folder\n", stderr);
        return 1;
    }
    return 0;
}

static void wait_before_exit(bool enabled)
{
    if (!enabled) return;
    fputws(L"Press Ctrl+C to exit...", stdout);
    fflush(stdout);
    Sleep(INFINITE);
}

int wmain(int argc, wchar_t **argv)
{
    if (argc == 1) {
        print_help();
        return 0;
    }
    if (argc == 2 && (wcscmp(argv[1], L"-h") == 0 || wcscmp(argv[1], L"--help") == 0)) {
        print_help();
        return 0;
    }

    PHYS_COMMAND phys;
    bool physical_mode = parse_phys_command(argc, argv, &phys);
    OPTIONS options = { 0 };
    if (!physical_mode && !parse_options(argc, argv, &options)) {
        return 1;
    }
    if (!physical_mode && options.delete_task) {
        int result = delete_startup_task();
        wait_before_exit(options.no_exit);
        return result;
    }
    if (physical_mode) {
        memset(&options, 0, sizeof(options));
    }
    if (!resolve_driver_path(&options)) {
        free(phys.bytes);
        return 1;
    }

    INPOUT_DRIVER driver;
    if (!driver_open(&driver, options.driver_path, options.verbose)) {
        driver_close(&driver);
        free(phys.bytes);
        return 1;
    }

    int exit_code = 0;
    if (physical_mode) {
        exit_code = execute_phys_command(&driver, &phys);
    } else {
        XHCI_CONTROLLER controllers[MAX_CONTROLLERS];
        size_t controller_count = 0;
        if (!enumerate_xhci(controllers, &controller_count, options.verbose) || controller_count == 0) {
            fputws(L"[!] No PCI xHCI controllers were found\n", stderr);
            exit_code = 1;
        } else {
            bool matched = false;
            for (size_t index = 0; index < controller_count; ++index) {
                bool selected = options.selection == SELECT_ALL ||
                    (options.selection == SELECT_FIRST && index == 0) ||
                    (options.selection == SELECT_INDEX && index == options.index) ||
                    (options.selection == SELECT_BDF && controllers[index].bus == options.bus &&
                        controllers[index].device == options.device && controllers[index].function == options.function);
                if (!selected) continue;
                matched = true;
                if (!process_controller(&driver, &controllers[index], &options)) exit_code = 1;
            }
            if (!matched) {
                fputws(L"[!] The selected xHCI controller was not found\n", stderr);
                exit_code = 1;
            }
        }
    }
    driver_close(&driver);
    free(phys.bytes);

    if (!physical_mode && exit_code == 0 && options.startup && !install_startup_task(&options)) {
        exit_code = 1;
    }
    if (!physical_mode) wait_before_exit(options.no_exit);
    return exit_code;
}
