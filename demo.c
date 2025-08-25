// Build: x86_64-w64-mingw32-gcc -s demo.c -nostdlib -nostartfiles -ffreestanding -fno-ident -Wl,-subsystem,windows -e _start -Os -fPIC -fno-asynchronous-unwind-tables -T linker.ld -o demo.exe
#include <windows.h>

// -------------------- PEB structs --------------------
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PEB_LDR_DATA* Ldr;
} PEB;

// -------------------- Module lookup --------------------
HMODULE customGetModuleHandleA(const char* name) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
        LDR_DATA_TABLE_ENTRY* ent = (LDR_DATA_TABLE_ENTRY*)((BYTE*)cur - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        SIZE_T len = ent->BaseDllName.Length / sizeof(WCHAR);
        SIZE_T i;
        for (i = 0; i < len; ++i) {
            if (((char)(ent->BaseDllName.Buffer[i] | 0x20)) != (char)(name[i] | 0x20))
                break;
        }
        if (i == len && name[i] == 0) return (HMODULE)ent->DllBase;
    }
    return NULL;
}

// -------------------- Function lookup --------------------
FARPROC customGetProcAddress(HMODULE hMod, const char* fnName) {
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ords  = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* nameInExport = (const char*)(base + names[i]);
        const char* targetName = fnName;
        int match = 1;
        while (*nameInExport && *targetName) {
            if ((*nameInExport | 0x20) != (*targetName | 0x20)) {
                match = 0;
                break;
            }
            ++nameInExport;
            ++targetName;
        }
        if (match && *targetName == 0)
            return (FARPROC)(base + (SIZE_T)funcs[ords[i]]);
    }
    return NULL;
}

// -------------------- Strings in .text --------------------
__attribute__((section(".text"))) static char kernel32_dll[] = "kernel32.dll";
__attribute__((section(".text"))) static char loadlibrarya[] = "LoadLibraryA";

__attribute__((section(".text"))) static char user32_dll[]   = "user32.dll";
__attribute__((section(".text"))) static char messageboxa[] = "MessageBoxA";
__attribute__((section(".text"))) static char hello_msg[]   = "Hello from shellcode!";
__attribute__((section(".text"))) static char title_msg[]   = "C Shellcode Demo";

// -------------------- Entry Point --------------------
typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
typedef HMODULE (WINAPI* LoadLibraryA_t)(LPCSTR);

__attribute__((section(".text.start")))
int _start(void) {
    HMODULE hKernel32 = customGetModuleHandleA(kernel32_dll);
    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)customGetProcAddress(hKernel32, loadlibrarya);

    HMODULE hUser32 = pLoadLibraryA(user32_dll);
    MessageBoxA_t pMessageBoxA = (MessageBoxA_t)customGetProcAddress(hUser32, messageboxa);

    pMessageBoxA(NULL, hello_msg, title_msg, MB_OK | MB_ICONINFORMATION);
}

