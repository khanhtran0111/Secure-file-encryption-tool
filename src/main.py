import ctypes
import os

# Load the C++ shared library
lib = ctypes.CDLL(os.path.abspath("libchacha20.so"))

# Define the function prototypes
lib.encrypt.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8)]
lib.encrypt.restype = None

lib.decrypt.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8)]
lib.decrypt.restype = None

def encrypt_file(input_file, output_file, key, nonce):
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    key_array = (ctypes.c_uint8 * len(key))(*key)
    nonce_array = (ctypes.c_uint8 * len(nonce))(*nonce)
    plaintext_array = (ctypes.c_uint8 * len(plaintext))(*plaintext)
    ciphertext_array = (ctypes.c_uint8 * len(plaintext))()

    lib.encrypt(key_array, nonce_array, plaintext_array, len(plaintext), ciphertext_array)
    
    with open(output_file, 'wb') as f:
        f.write(bytearray(ciphertext_array))

def decrypt_file(input_file, output_file, key, nonce):
    with open(input_file, 'rb') as f:
        ciphertext = f.read()
    
    key_array = (ctypes.c_uint8 * len(key))(*key)
    nonce_array = (ctypes.c_uint8 * len(nonce))(*nonce)
    ciphertext_array = (ctypes.c_uint8 * len(ciphertext))(*ciphertext)
    plaintext_array = (ctypes.c_uint8 * len(ciphertext))()

    lib.decrypt(key_array, nonce_array, ciphertext_array, len(ciphertext), plaintext_array)
    
    with open(output_file, 'wb') as f:
        f.write(bytearray(plaintext_array))

# Example usage
key = bytes([i for i in range(32)])  # Create key as in the C++ code
nonce = bytes([i for i in range(12)])  # Create nonce as in the C++ code

# Encrypt the file
encrypt_file('file.txt', 'file.enc', key, nonce)

# Decrypt the file
decrypt_file('file.enc', 'file.dec', key, nonce)