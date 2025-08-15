import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import PhotoImage
from PIL import Image
from tkinterdnd2 import DND_FILES, TkinterDnD

from encfmt_v2 import (
    encrypt_file as enc_file_v2,
    decrypt_file as dec_file_v2,
    encrypt_folder_tar_then_encrypt as enc_folder_v2,
    decrypt_to_folder as dec_folder_v2,
    EncDecError
)

def encrypt_file(input_file=None, output_format="bin", key=None, nonce=None):
    if not input_file:
        input_file = filedialog.askopenfilename(title="Select File to Encrypt")
    if not input_file:
        messagebox.showwarning("No File Selected", "Please select a file to encrypt.")
        return
    
    output_file = filedialog.asksaveasfilename(
        title="Save Encrypted File As",
        defaultextension=".cc20",
        filetypes=[("CC20 Encrypted", "*.cc20"), ("All files", "*.*")]
    )
    if not output_file:
        messagebox.showwarning("No Output File Selected", "Please specify the output file for encryption.")
        return

    try:
        password = getattr(encrypt_file, '_current_password', '')
        if not password:
            messagebox.showwarning("No Password", "Please enter your secret password.")
            return
        
        enc_file_v2(password, input_file, output_file)
        messagebox.showinfo("Success", f"File encrypted successfully!\nSaved at: {output_file}")
    except EncDecError as e:
        messagebox.showerror("Error", f"Error during encryption: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {e}")

def decrypt_file(input_file=None, output_format="bin", key=None, nonce=None):
    if not input_file:
        input_file = filedialog.askopenfilename(
            title="Select File to Decrypt",
            filetypes=[("CC20 Encrypted", "*.cc20"), ("All files", "*.*")]
        )
    if not input_file:
        messagebox.showwarning("No File Selected", "Please select a file to decrypt.")
        return
    
    if input_file.endswith(".cc20"):
        suggested_name = input_file[:-5]
    else:
        suggested_name = input_file + ".dec"
    
    output_file = filedialog.asksaveasfilename(
        title="Save Decrypted File As",
        initialfile=os.path.basename(suggested_name),
        initialdir=os.path.dirname(suggested_name) if os.path.dirname(suggested_name) else None
    )
    if not output_file:
        messagebox.showwarning("No Output File Selected", "Please specify the output file for decryption.")
        return

    try:
        password = getattr(decrypt_file, '_current_password', '')
        if not password:
            messagebox.showwarning("No Password", "Please enter your secret password.")
            return
        
        dec_file_v2(password, input_file, output_file)
        messagebox.showinfo("Success", f"File decrypted successfully!\nSaved at: {output_file}")
    except EncDecError as e:
        messagebox.showerror("Error", f"Error during decryption: {e}")

def encrypt_folder(folder_path):
    if not folder_path:
        folder_path = filedialog.askdirectory(title="Select Folder to Encrypt")
    if not folder_path:
        messagebox.showwarning("No Folder Selected", "Please select a folder to encrypt.")
        return
    
    base_name = os.path.basename(folder_path.rstrip(os.sep)) or "output"
    suggested_name = base_name + ".cc20"
    
    output_file = filedialog.asksaveasfilename(
        title="Save Encrypted Archive As",
        initialfile=suggested_name,
        defaultextension=".cc20",
        filetypes=[("CC20 Encrypted", "*.cc20"), ("All files", "*.*")]
    )
    if not output_file:
        messagebox.showwarning("No Output File Selected", "Please specify the output file for encryption.")
        return

    try:
        password = getattr(encrypt_folder, '_current_password', '')
        if not password:
            messagebox.showwarning("No Password", "Please enter your secret password.")
            return
        
        enc_folder_v2(password, folder_path, output_file)
        messagebox.showinfo("Success", f"Folder encrypted successfully!\nSaved at: {output_file}")
    except EncDecError as e:
        messagebox.showerror("Error", f"Error during folder encryption: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {e}")

def decrypt_archive_to_folder(enc_path):
    if not enc_path:
        enc_path = filedialog.askopenfilename(
            title="Select Encrypted Archive",
            filetypes=[("CC20 Encrypted", "*.cc20"), ("All files", "*.*")]
        )
    if not enc_path:
        messagebox.showwarning("No File Selected", "Please select an encrypted archive.")
        return
    
    output_dir = filedialog.askdirectory(title="Select Output Folder to Extract Files")
    if not output_dir:
        messagebox.showwarning("No Output Folder Selected", "Please select a folder to extract files.")
        return

    try:
        password = getattr(decrypt_archive_to_folder, '_current_password', '')
        if not password:
            messagebox.showwarning("No Password", "Please enter your secret password.")
            return
        
        dec_folder_v2(password, enc_path, output_dir)
        messagebox.showinfo("Success", f"Archive decrypted successfully!\nExtracted to: {output_dir}")
    except EncDecError as e:
        messagebox.showerror("Error", f"Error during archive decryption: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {e}")

def create_app():
    app = TkinterDnD.Tk()
    app.title("File Encryption/Decryption Tool - v2 (Secure)")
    app.geometry("500x550")
    app.resizable(True, True)

    img = Image.open("./image/main app/lock.png")
    img = img.resize((128, 128))
    img.save("./image/main app/lock_resized.png")
    icon = PhotoImage(file="./image/main app/lock_resized.png")
    app.iconphoto(True, icon)

    tk.Label(app, text="File Encryption/Decryption Tool - v2", font=("Arial", 16)).pack(pady=10)

    tk.Label(app, text="Enter your secret password:").pack(pady=5)
    string_entry = tk.Entry(app, show="•", width=50)
    string_entry.pack(pady=5)

    def set_current_password():
        password = string_entry.get()
        if not password:
            messagebox.showwarning("Input Required", "You have to fill the password.")
            return None
        encrypt_file._current_password = password
        decrypt_file._current_password = password
        encrypt_folder._current_password = password
        decrypt_archive_to_folder._current_password = password
        return password

    def encrypt_with_password():
        if set_current_password():
            encrypt_file()

    def decrypt_with_password():
        if set_current_password():
            decrypt_file()

    def encrypt_folder_with_password():
        if set_current_password():
            encrypt_folder(None)

    def decrypt_folder_with_password():
        if set_current_password():
            decrypt_archive_to_folder(None)

    button_frame = tk.Frame(app)
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Encrypt File", command=encrypt_with_password, width=20, height=2).grid(row=0, column=0, padx=5, pady=5)
    tk.Button(button_frame, text="Decrypt File", command=decrypt_with_password, width=20, height=2).grid(row=0, column=1, padx=5, pady=5)
    tk.Button(button_frame, text="Encrypt Folder", command=encrypt_folder_with_password, width=20, height=2).grid(row=1, column=0, padx=5, pady=5)
    tk.Button(button_frame, text="Decrypt Folder", command=decrypt_folder_with_password, width=20, height=2).grid(row=1, column=1, padx=5, pady=5)

    drop_box = tk.Label(app, text="Drag and Drop Files/Folders Here", relief="sunken", width=40, height=10)
    drop_box.pack(pady=20)

    def drop(event):
        file_path = event.data.strip()
        if file_path.startswith("{") and file_path.endswith("}"):
            file_path = file_path[1:-1]
        
        if not os.path.exists(file_path):
            messagebox.showerror("Error", f"Path not found:\n{file_path}")
            return

        password = set_current_password()
        if not password:
            return

        try:
            if os.path.isdir(file_path):
                if messagebox.askyesno("Encrypt Folder?", f"Encrypt this folder?\n{file_path}"):
                    encrypt_folder(file_path)
            else:
                if file_path.endswith(".cc20"):
                    if messagebox.askyesno("Decrypt File?", f"Decrypt this file?\n{file_path}"):
                        decrypt_file(file_path, "bin", None, None)
                else:
                    if messagebox.askyesno("Encrypt File?", f"Encrypt this file?\n{file_path}"):
                        encrypt_file(file_path, "bin", None, None)
        except EncDecError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")

    drop_box.drop_target_register(DND_FILES)
    drop_box.dnd_bind('<<Drop>>', drop)

    app.mainloop()

if __name__ == "__main__":
    create_app()
