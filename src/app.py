import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import PhotoImage
from PIL import Image
from tkinterdnd2 import DND_FILES, TkinterDnD

def encrypt_file(input_file=None):
    if not input_file:
        input_file = filedialog.askopenfilename(title="Select File to Encrypt")
    if not input_file:
        messagebox.showwarning("No File Selected", "Please select a file to encrypt.")
        return
    
    output_file = filedialog.asksaveasfilename(title="Save Encrypted File As")
    if not output_file:
        messagebox.showwarning("No Output File Selected", "Please specify the output file for encryption.")
        return

    output_hex = messagebox.askyesno("Hexadecimal Output", "Do you want the output in hexadecimal format?")
    cpp_executable = "./chacha20_file_processor"
    if not os.path.exists(cpp_executable):
        messagebox.showerror("Executable Not Found", f"C++ executable '{cpp_executable}' not found!")
        return

    command = [cpp_executable, "encrypt", input_file, output_file]
    if output_hex:
        command.append("hex")
    
    try:
        subprocess.run(command, check=True)
        messagebox.showinfo("Success", f"File encrypted successfully!\nSaved at: {output_file}")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Error during encryption: {e}")

def decrypt_file(input_file=None):
    if not input_file:
        input_file = filedialog.askopenfilename(title="Select File to Decrypt")
    if not input_file:
        messagebox.showwarning("No File Selected", "Please select a file to decrypt.")
        return
    
    output_file = filedialog.asksaveasfilename(title="Save Decrypted File As")
    if not output_file:
        messagebox.showwarning("No Output File Selected", "Please specify the output file for decryption.")
        return

    cpp_executable = "./chacha20_file_processor"
    if not os.path.exists(cpp_executable):
        messagebox.showerror("Executable Not Found", f"C++ executable '{cpp_executable}' not found!")
        return

    command = [cpp_executable, "decrypt", input_file, output_file]
    
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

    tk.Button(app, text="Encrypt File", command=encrypt_file, width=20, height=2).pack(pady=10)
    tk.Button(app, text="Decrypt File", command=decrypt_file, width=20, height=2).pack(pady=10)

    drop_box = tk.Label(app, text="Drag and Drop Files Here", relief="sunken", width=40, height=10)
    drop_box.pack(pady=20)

    def drop(event):
        file_path = event.data
        if file_path:
            if messagebox.askyesno("Encrypt or Decrypt", "Do you want to encrypt the file?"):
                encrypt_file(file_path)
            else:
                decrypt_file(file_path)

    drop_box.drop_target_register(DND_FILES)
    drop_box.dnd_bind('<<Drop>>', drop)

    app.mainloop()

if __name__ == "__main__":
    create_app()