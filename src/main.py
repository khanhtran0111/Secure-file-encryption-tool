import os
import subprocess
from tkinter import Tk
from tkinter.filedialog import askopenfilename, asksaveasfilename

def main():
    Tk().withdraw()  # Hide the root window

    print("File Encryption/Decryption Interface")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Enter your choice (1 or 2): ")

    if choice not in ['1', '2']:
        print("Invalid choice!")
        return
    input_file = askopenfilename(title="Select input file")
    if not input_file:
        print("No input file selected!")
        return
    output_file = asksaveasfilename(title="Select output file")
    if not output_file:
        print("No output file selected!")
        return
    cpp_executable = "./chacha20_file_processor.exe" 
    if not os.path.exists(cpp_executable):
        print(f"Error: C++ executable '{cpp_executable}' not found!")
        return
    operation = "encrypt" if choice == '1' else "decrypt"
    try:
        subprocess.run([cpp_executable, operation, input_file, output_file], check=True)
        print(f"File {operation}ion completed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Error during {operation}ion: {e}")

if __name__ == "__main__":
    main()
