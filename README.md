# Secure-file-encryption-system
---
Name: Tran Gia Khanh

Student's ID: 23021599

University: University of Engineering and Technology - Vietnam National University Hanoi

---

## Overview
The Secure-file-encryption-system is a tool designed to encrypt and decrypt files using the ChaCha20 encryption algorithm. This system provides a secure way to protect sensitive data by converting files into an encrypted format and allowing them to be decrypted back to their original form.

## Features
- Encrypt files using the ChaCha20 algorithm.
- Decrypt files back to their original format.
- Support for binary output formats.
- Cross-platform compatibility with both Python and C++ implementations.

## How to Use

### Prerequisites
- Python 3.12
- C++ compiler (for compiling the C++ code)
- Install library 
    ```sh
    pip install pycryptodome
    pip install tk
    ```


### Setup
1. Clone the repository:
    ```sh
    git clone https://github.com/khanhtran0111/Secure-file-encryption-system.git
    cd Secure-file-encryption-system
    ```

2. Compile the C++ code:
    ```sh
    g++ -o chacha20_file_processor src/chacha20.cpp
    ```

### Usage

#### Encrypt a File
1. Run the Python application:
    ```sh
    python src/app.py
    ```

2. In the GUI, select the file you want to encrypt.
3. Enter your secret key, then it will be convert to the encryption key (32 bytes) and nonce (12 bytes).
4. Choose the output format (binary).
5. Click the "Encrypt" button.

#### Decrypt a File
1. Run the Python application:
    ```sh
    python src/app.py
    ```

2. In the GUI, select the file you want to decrypt.
3. Enter your previous secret key for encryption, then it will be convert to the encryption key (32 bytes) and nonce (12 bytes).
4. Choose the output format (the format before encrypt).
5. Click the "Decrypt" button.
