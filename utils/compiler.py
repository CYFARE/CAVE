import subprocess
from config import CPP_COMPILER, C_COMPILER, COMPILER_FLAGS

def cross_compile_cpp(source_path, output_path, extra_flags=""):
    """Compiles a C++ source file into a Windows executable using MinGW."""
    # Ensure extra_flags is a string
    extra_flags_str = " ".join(extra_flags) if isinstance(extra_flags, list) else str(extra_flags)
    
    command = f"{CPP_COMPILER} {source_path} -o {output_path} {COMPILER_FLAGS} {extra_flags_str}"
    print(f"[*] Compiling C++ with command: {command}")
    try:
        process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, timeout=120)
        if process.stdout:
            print(f"    Compiler STDOUT: {process.stdout.strip()}")
        # MinGW often outputs warnings to stderr even on success
        if process.stderr:
            print(f"    Compiler STDERR (may include warnings): {process.stderr.strip()}")
        print(f"[+] C++ Compilation successful. Executable saved to {output_path}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] C++ Compilation failed!")
        print(f"    Command: {e.cmd}")
        print(f"    Return code: {e.returncode}")
        if e.stdout:
            print(f"    STDOUT: {e.stdout.strip()}")
        if e.stderr:
            print(f"    STDERR: {e.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired as e:
        print(f"[!] C++ Compilation timed out after {e.timeout} seconds!")
        print(f"    Command: {e.cmd}")
        if e.stdout: # stdout might be bytes if not decoded, but text=True should handle it
            print(f"    STDOUT: {e.stdout.strip() if isinstance(e.stdout, str) else e.stdout.decode(errors='ignore').strip()}")
        if e.stderr:
            print(f"    STDERR: {e.stderr.strip() if isinstance(e.stderr, str) else e.stderr.decode(errors='ignore').strip()}")
        return False
    except Exception as e:
        print(f"[!] An unexpected error occurred during C++ compilation: {e}")
        return False

def cross_compile_c(source_path, output_path, extra_flags=""):
    """Compiles a C source file into a Windows executable using MinGW."""
    # Ensure extra_flags is a string
    extra_flags_str = " ".join(extra_flags) if isinstance(extra_flags, list) else str(extra_flags)

    command = f"{C_COMPILER} {source_path} -o {output_path} {COMPILER_FLAGS} {extra_flags_str}"
    print(f"[*] Compiling C with command: {command}")
    try:
        process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, timeout=120)
        if process.stdout:
            print(f"    Compiler STDOUT: {process.stdout.strip()}")
        if process.stderr:
            print(f"    Compiler STDERR (may include warnings): {process.stderr.strip()}")
        print(f"[+] C Compilation successful. Executable saved to {output_path}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] C Compilation failed!")
        print(f"    Command: {e.cmd}")
        print(f"    Return code: {e.returncode}")
        if e.stdout:
            print(f"    STDOUT: {e.stdout.strip()}")
        if e.stderr:
            print(f"    STDERR: {e.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired as e:
        print(f"[!] C Compilation timed out after {e.timeout} seconds!")
        print(f"    Command: {e.cmd}")
        if e.stdout:
            print(f"    STDOUT: {e.stdout.strip() if isinstance(e.stdout, str) else e.stdout.decode(errors='ignore').strip()}")
        if e.stderr:
            print(f"    STDERR: {e.stderr.strip() if isinstance(e.stderr, str) else e.stderr.decode(errors='ignore').strip()}")
        return False
    except Exception as e:
        print(f"[!] An unexpected error occurred during C compilation: {e}")
        return False