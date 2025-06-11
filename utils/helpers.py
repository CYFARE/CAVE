import os
from config import OUTPUT_DIR

def format_shellcode_to_hex(shellcode):
    """Formats raw shellcode bytes into a C-style hex string: 0x..,0x..,"""
    return ','.join([f"0x{byte:02x}" for byte in shellcode])

def get_output_path(filename):
    """Constructs the full path for an output file."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR, exist_ok=True) # Add exist_ok=True to avoid error if dir already exists
    return os.path.join(OUTPUT_DIR, filename)