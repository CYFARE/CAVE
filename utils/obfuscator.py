import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

def xor_encrypt(data):
    """Performs XOR encryption with a random single-byte key."""
    # Ensure data is bytes, if it's a string, encode it.
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    key_byte = os.urandom(1)[0]
    encrypted_data = bytes([b ^ key_byte for b in data])
    # Return key as a C-style hex string like "0xAB"
    return encrypted_data, f"0x{key_byte:02x}"

def aes_encrypt(data, key_size=16): # Common key_size for AES-128
    """
    Performs AES encryption with a random key of specified size (default 16 bytes for AES-128).
    Returns encrypted data and the raw key bytes.
    IV is static (all zeros) for simplicity in the C++ stub.
    In real-world scenarios, a random IV should be generated and handled securely.
    """
    # Ensure data is bytes, if it's a string, encode it.
    if isinstance(data, str):
        data = data.encode('utf-8')

    if key_size not in [16, 24, 32]:
        raise ValueError("Invalid key size for AES. Must be 16, 24, or 32 bytes.")

    key = os.urandom(key_size)
    iv = b'\x00' * 16 # AES block size is 16 bytes, static IV as per prompt's C++ stub plan.
    
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    
    # Data must be padded to be a multiple of AES.block_size (16 bytes)
    padded_data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data, key # Return the raw key bytes

def base64_encode(data):
    """Performs Base64 encoding."""
    # Ensure data is bytes, if it's a string, encode it.
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    encoded_data = base64.b64encode(data)
    return encoded_data, None # No key for Base64, return None for consistency