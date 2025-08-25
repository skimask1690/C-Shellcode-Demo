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

typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
typedef NTSTATUS(NTAPI* LdrLoadDll_t)(
    PWSTR PathToFile,
    ULONG Flags,
    UNICODE_STRING* ModuleFileName,
    PHANDLE ModuleHandle
);

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

// -------------------- Unicode helper --------------------
void customRtlInitUnicodeString(UNICODE_STRING* ustr, const wchar_t* str) {
    SIZE_T len = 0;
    while (str[len]) ++len;
    ustr->Length = (USHORT)(len * sizeof(wchar_t));
    ustr->MaximumLength = (USHORT)((len + 1) * sizeof(wchar_t));
    ustr->Buffer = (PWSTR)str;
}

// -------------------- Strings in .text --------------------
__attribute__((section(".text"))) static char ntdll_dll[]         = "ntdll.dll";
__attribute__((section(".text"))) static char ldrloaddll[]        = "LdrLoadDll";

__attribute__((section(".text"))) static wchar_t user32_dll_w[]  = L"user32.dll"; // LdrLoadDll expects a wide-char DLL name
__attribute__((section(".text"))) static char messageboxa[]      = "MessageBoxA";
__attribute__((section(".text"))) static char hello_msg[]        = "Hello from shellcode!";
__attribute__((section(".text"))) static char title_msg[]        = "C Shellcode Demo";

// -------------------- Entry Point --------------------
__attribute__((section(".text.start")))
int _start(void) {
    HMODULE hNtdll = customGetModuleHandleA(ntdll_dll);
    LdrLoadDll_t pLdrLoadDll = (LdrLoadDll_t)customGetProcAddress(hNtdll, ldrloaddll);

    UNICODE_STRING ustr;
    customRtlInitUnicodeString(&ustr, user32_dll_w);

    HMODULE hUser32 = NULL;
    pLdrLoadDll(NULL, 0, &ustr, (PHANDLE)&hUser32);

    MessageBoxA_t pMessageBoxA = (MessageBoxA_t)customGetProcAddress(hUser32, messageboxa);
    pMessageBoxA(NULL, hello_msg, title_msg, MB_OK | MB_ICONINFORMATION);
}
