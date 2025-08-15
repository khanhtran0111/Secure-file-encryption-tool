# Secure file encryption tool

## Introduction

This project implements a secure file encryption system using the ChaCha20-Poly1305 AEAD encryption algorithm with Scrypt key derivation. Version 2 provides significant security improvements over the original implementation, including proper authentication, secure key derivation, and support for folder encryption using a tar-then-encrypt approach.

## Key Security Features

- **AEAD Encryption**: ChaCha20-Poly1305 provides both confidentiality and authenticity
- **Secure KDF**: Scrypt (N=2^15, r=8, p=1) replaces simple SHA-256 hashing  
- **Per-file nonces**: Each file uses a unique random 8-byte nonce prefix
- **Chunked processing**: 1MB chunks with per-chunk nonce counters for large files
- **Header authentication**: File metadata protected as Additional Authenticated Data (AAD)
- **Tamper detection**: Any modification to encrypted files is immediately detected
- **Folder support**: Tar-then-encrypt approach for secure folder encryption

## File Format (.cc20)

Encrypted files use the `.cc20` extension with this structure:
```
Magic: "CC20" (4 bytes)
Version: 2 (1 byte)  
KDF ID: 1 (Scrypt) (1 byte)
Algorithm ID: 1 (ChaCha20-Poly1305) (1 byte)
Flags: 0 (1 byte)
KDF params length: uint16 (2 bytes)
KDF params: JSON blob (salt, n, r, p)
Nonce prefix length: uint8 (1 byte) 
Nonce prefix: 8 bytes
Chunk size: uint32 (4 bytes)
Data: encrypted chunks (4-byte length + encrypted data per chunk)
```

## How to Use

### Prerequisites
- Python 3.12+
- Required libraries:
    ```bash
    pip install cryptography tkinterdnd2 pillow
    ```

### Setup
1. Clone the repository:
    ```bash
    git clone https://github.com/khanhtran0111/Secure-file-encryption-tool.git
    cd Secure-file-encryption-system
    ```

2. Install dependencies:
    ```bash
    pip install cryptography tkinterdnd2 pillow
    ```

### Usage

#### GUI Application (Recommended)
1. Run the graphical interface:
    ```bash
    python src/app.py
    ```

2. Enter your secret password in the input field
3. Choose from the available options:
   - **Encrypt File**: Select a file to encrypt (output: `.cc20`)
   - **Decrypt File**: Select a `.cc20` file to decrypt  
   - **Encrypt Folder**: Select a folder to encrypt as a single archive
   - **Decrypt Folder**: Select a `.cc20` archive to extract

4. **Drag & Drop**: Simply drag files or folders onto the application window
   - Files → Asks if you want to encrypt
   - `.cc20` files → Asks if you want to decrypt
   - Folders → Asks if you want to encrypt


### Security Notes

- **Password Security**: Use strong, unique passwords. The same password will always produce the same encryption key due to deterministic Scrypt parameters.
- **File Integrity**: Any tampering with encrypted files will be detected during decryption.
- **Secure Deletion**: Consider securely wiping original files after encryption if they contain sensitive data.
- **Backup**: Keep secure backups of both encrypted files AND passwords.

### Example Workflow

1. **Encrypt a Document:**
   ```bash
   python src/app.py
   # Enter password: "my_secure_password_123"
   # Select "Encrypt File" → choose document.pdf
   # Result: document.pdf.cc20
   ```

2. **Encrypt a Project Folder:**
   ```bash
   # Drag folder "MyProject" onto the app window
   # Choose "Encrypt folder" → save as MyProject.cc20  
   # Result: Single encrypted archive containing all files
   ```

3. **Decrypt and Extract:**
   ```bash
   # Drag MyProject.cc20 onto the app window
   # Choose "Decrypt folder" → select output directory
   # Result: MyProject folder extracted with all original files
   ```

## Migration from v1

If you have files encrypted with the original version (using the C++ executable), they can still be decrypted using the legacy method. However, we strongly recommend re-encrypting important files with v2 for improved security.

## What's New in v2

- ✅ **Authenticated encryption** prevents tampering
- ✅ **Secure key derivation** using Scrypt instead of raw SHA-256
- ✅ **Folder encryption** via tar-then-encrypt  
- ✅ **Per-file random nonces** eliminate nonce reuse
- ✅ **Chunked processing** supports large files efficiently
- ✅ **Header authentication** protects metadata
- ✅ **Standard library** using `cryptography` instead of custom C++
- ✅ **Cross-platform** works on any system with Python

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
