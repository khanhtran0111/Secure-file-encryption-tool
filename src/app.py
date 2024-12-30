import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import PhotoImage
from PIL import Image
from tkinterdnd2 import DND_FILES, TkinterDnD
import hashlib

path_cpp = "./chacha20_file_processor.exe"

def derive_key_and_nonce(input_string):
    if not input_string:
        raise ValueError("Input string must not be empty.")
    hash_object = hashlib.sha256(input_string.encode())
    hash_bytes = hash_object.digest()
    key = hash_bytes[:32]
    nonce_hash_object = hashlib.sha256((input_string + "nonce").encode())
    nonce_bytes = nonce_hash_object.digest()
    nonce = nonce_bytes[:12]
    return key, nonce

def encrypt_file(input_file=None, output_format="bin", key=None, nonce=None):
    if not input_file:
        input_file = filedialog.askopenfilename(title="Select File to Encrypt")
    if not input_file:
        messagebox.showwarning("No File Selected", "Please select a file to encrypt.")
        return
    
    output_file = filedialog.asksaveasfilename(title="Save Encrypted File As")
    if not output_file:
        messagebox.showwarning("No Output File Selected", "Please specify the output file for encryption.")
        return

    if not key or len(key) != 32:
        messagebox.showwarning("Invalid Key", "Please enter a valid key.")
        return

    if not nonce or len(nonce) != 12:
        messagebox.showwarning("Invalid Nonce", "Please enter a valid nonce.")
        return

    cpp_executable = path_cpp
    if not os.path.exists(cpp_executable):
        messagebox.showerror("Executable Not Found", f"C++ executable '{cpp_executable}' not found!")
        return

    command = [cpp_executable, "encrypt", input_file, output_file, key.hex(), nonce.hex()]
    if output_format == "hex":
        command.append("hex")
    
    try:
        subprocess.run(command, check=True)
        messagebox.showinfo("Success", f"File encrypted successfully!\nSaved at: {output_file}")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Error during encryption: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {e}")

def decrypt_file(input_file=None, output_format="bin", key=None, nonce=None):
    if not input_file:
        input_file = filedialog.askopenfilename(title="Select File to Decrypt")
    if not input_file:
        messagebox.showwarning("No File Selected", "Please select a file to decrypt.")
        return
    
    output_file = filedialog.asksaveasfilename(title="Save Decrypted File As")
    if not output_file:
        messagebox.showwarning("No Output File Selected", "Please specify the output file for decryption.")
        return

    if not key or len(key) != 32:
        messagebox.showwarning("Invalid Key", "Please enter a valid key.")
        return

    if not nonce or len(nonce) != 12:
        messagebox.showwarning("Invalid Nonce", "Please enter a valid nonce.")
        return

    cpp_executable = path_cpp
    if not os.path.exists(cpp_executable):
        messagebox.showerror("Executable Not Found", f"C++ executable '{cpp_executable}' not found!")
        return

    command = [cpp_executable, "decrypt", input_file, output_file, key.hex(), nonce.hex()]
    if output_format == "hex":
        command.append("hex")
    
    try:
        subprocess.run(command, check=True)
        messagebox.showinfo("Success", f"File decrypted successfully!\nSaved at: {output_file}")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Error during decryption: {e}")

def create_app():
    app = TkinterDnD.Tk()
    app.title("File Encryption/Decryption Tool")
    app.geometry("500x500")
    app.resizable(True, True)

    img = Image.open("../image/main app/lock.png")
    img = img.resize((128, 128))
    img.save("../image/main app/lock_resized.png")
    icon = PhotoImage(file="../image/main app/lock_resized.png")
    app.iconphoto(True, icon)

    tk.Label(app, text="File Encryption/Decryption Tool", font=("Arial", 16)).pack(pady=10)

    tk.Label(app, text="Enter your secret string:").pack(pady=5)
    string_entry = tk.Entry(app, show="•", width=50)
    string_entry.pack(pady=5)

    def encrypt_with_derived_key_and_nonce():
        input_string = string_entry.get()
        if not input_string:
            messagebox.showwarning("Input Required", "You have to fill the string.")
            return
        key, nonce = derive_key_and_nonce(input_string)
        encrypt_file(output_format="bin", key=key, nonce=nonce)

    def decrypt_with_derived_key_and_nonce():
        input_string = string_entry.get()
        if not input_string:
            messagebox.showwarning("Input Required", "You have to fill the string.")
            return
        key, nonce = derive_key_and_nonce(input_string)
        decrypt_file(output_format="bin", key=key, nonce=nonce)

    tk.Button(app, text="Encrypt File", command=encrypt_with_derived_key_and_nonce, width=20, height=2).pack(pady=10)
    tk.Button(app, text="Decrypt File", command=decrypt_with_derived_key_and_nonce, width=20, height=2).pack(pady=10)

    drop_box = tk.Label(app, text="Drag and Drop Files Here", relief="sunken", width=40, height=10)
    drop_box.pack(pady=20)

    def drop(event):
        file_path = event.data
        if file_path:
            input_string = string_entry.get()
            if not input_string:
                messagebox.showwarning("Input Required", "You have to fill the string.")
                return
            key, nonce = derive_key_and_nonce(input_string)
            if messagebox.askyesno("Encrypt or Decrypt", "Do you want to encrypt the file?"):
                encrypt_file(file_path, "bin", key, nonce)
            else:
                decrypt_file(file_path, "bin", key, nonce)

    drop_box.drop_target_register(DND_FILES)
    drop_box.dnd_bind('<<Drop>>', drop)

    app.mainloop()

if __name__ == "__main__":
    create_app()