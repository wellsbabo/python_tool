# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext
import json
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

# Padding function: Pads the data to a 128-bit block size.
def pad(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

# Unpadding function: Removes padding from the data.
def unpad(padded_data):
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Encryption function: Encrypts data using AES128/ECB/PKCS7Padding.
def encrypt(key, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    padded_data = pad(data.encode('utf-8'))  # Encode as UTF-8
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(encrypted).decode('utf-8')

# Decryption function: Decrypts AES128/ECB/PKCS7Padding encrypted data.
def decrypt(key, encrypted_data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    encrypted_data_bytes = base64.urlsafe_b64decode(encrypted_data)
    decrypted_padded_data = decryptor.update(encrypted_data_bytes) + decryptor.finalize()
    decrypted_data = unpad(decrypted_padded_data)
    
    try:
        return decrypted_data.decode('utf-8')  # Decode as UTF-8
    except UnicodeDecodeError as e:
        messagebox.showwarning("한글 출력 불가", f"한글은 인코딩 문제로 ?로 표시됩니다.")
        return decrypted_data.decode('utf-8', errors='replace')  # Use 'replace' to handle decoding errors

# Returns the current time in the specified format.
def current_time():
    return datetime.now().strftime("%Y-%m-%d:%H-%M-%S")

# Function called when the Change Time button is clicked: Decrypts data, updates the createdAt value to the current time, and re-encrypts the data.
def change_time():
    key = entry_key.get()
    data = entry_data.get()
    request_type = request_type_var.get()

    if len(key) != 16:
        messagebox.showerror("Error", "Key must be 16 bytes long.")
        return

    try:
        decrypted_data = decrypt(key.encode(), data)
        decrypted_text.delete(1.0, tk.END)
        decrypted_text.insert(tk.END, decrypted_data)

        if request_type == "GET":
            params = dict(item.split("=") for item in decrypted_data.split("&"))
            params["createdAt"] = current_time()
            updated_data = "&".join(f"{k}={v}" for k, v in params.items())
        elif request_type == "POST":
            try:
                data_dict = json.loads(decrypted_data)
            except json.JSONDecodeError as e:
                messagebox.showerror("Error", f"Failed to parse JSON: {e}")
                return
            data_dict["createdAt"] = current_time()
            updated_data = json.dumps(data_dict)
        else:
            messagebox.showerror("Error", "Invalid request type.")
            return

        encrypted_data = encrypt(key.encode(), updated_data)
        
        encrypted_text.delete(1.0, tk.END)
        encrypted_text.insert(tk.END, encrypted_data)

        decrypted_text.delete(1.0, tk.END)
        decrypted_text.insert(tk.END, updated_data)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# Function called when the Encrypt button is clicked: Encrypts data and displays the result.
def on_submit():
    key = entry_key.get()
    data = entry_data.get()
    request_type = request_type_var.get()
    add_created_at = created_at_var.get()

    if len(key) != 16:
        messagebox.showerror("Error", "Key must be 16 bytes long.")
        return

    try:
        if add_created_at:
            if request_type == "GET":
                data += f"&createdAt={current_time()}"
            elif request_type == "POST":
                try:
                    data_dict = json.loads(data)
                except json.JSONDecodeError as e:
                    messagebox.showerror("Error", f"Failed to parse JSON: {e}")
                    return
                data_dict["createdAt"] = current_time()
                data = json.dumps(data_dict)
            else:
                messagebox.showerror("Error", "Invalid request type.")
                return

        encrypted_data = encrypt(key.encode(), data)
        
        encrypted_text.delete(1.0, tk.END)
        encrypted_text.insert(tk.END, encrypted_data)

        decrypted_text.delete(1.0, tk.END)
        decrypted_text.insert(tk.END, data)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Function called when the Decrypt button is clicked: Decrypts the input data and displays the result.
def decrypt_only():
    key = entry_key.get()
    encrypted_data = entry_decrypt.get()

    if len(key) != 16:
        messagebox.showerror("Error", "Key must be 16 bytes long.")
        return

    try:
        decrypted_data = decrypt(key.encode(), encrypted_data)
        decrypt_result_text.delete(1.0, tk.END)
        decrypt_result_text.insert(tk.END, decrypted_data)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# Copies the content of the text widget to the clipboard.
def copy_to_clipboard(text_widget):
    root.clipboard_clear()
    root.clipboard_append(text_widget.get(1.0, tk.END).strip())
    messagebox.showinfo("Copied", "Text copied to clipboard.")

# Create the main window
root = tk.Tk()
root.title("AES128 Encryption/Decryption")

# Left frame for encryption
frame_left = tk.Frame(root)
frame_left.pack(side=tk.LEFT, padx=10, pady=10)

# Right frame for decryption
frame_right = tk.Frame(root)
frame_right.pack(side=tk.LEFT, padx=10, pady=10)

# Left Frame: Create a label and entry for the key
label_key = tk.Label(frame_left, text="Enter 16-byte key:")
label_key.pack(pady=5)
entry_key = tk.Entry(frame_left, width=50)
entry_key.pack(pady=5)

# Left Frame: Create a label and entry for the data
label_data = tk.Label(frame_left, text="Enter data:")
label_data.pack(pady=5)
entry_data = tk.Entry(frame_left, width=50)
entry_data.pack(pady=5)

# Left Frame: Create radio buttons for request type
request_type_var = tk.StringVar(value="GET")

radio_get = tk.Radiobutton(frame_left, text="GET", variable=request_type_var, value="GET")
radio_get.pack(pady=5)

radio_post = tk.Radiobutton(frame_left, text="POST", variable=request_type_var, value="POST")
radio_post.pack(pady=5)

# Left Frame: Create a checkbox for adding createdAt
created_at_var = tk.BooleanVar()
checkbox_created_at = tk.Checkbutton(frame_left, text="Add createdAt", variable=created_at_var)
checkbox_created_at.pack(pady=5)

# Left Frame: Create a submit button
submit_button = tk.Button(frame_left, text="Encrypt", command=on_submit)
submit_button.pack(pady=10)

# Left Frame: Create a change time button
change_time_button = tk.Button(frame_left, text="Change Time", command=change_time)
change_time_button.pack(pady=10)

# Left Frame: Create a text widget for the encrypted result
encrypted_label = tk.Label(frame_left, text="Encrypted Data:")
encrypted_label.pack(pady=5)
encrypted_text = scrolledtext.ScrolledText(frame_left, width=60, height=5)
encrypted_text.pack(pady=5)
copy_encrypted_button = tk.Button(frame_left, text="Copy Encrypted Data", command=lambda: copy_to_clipboard(encrypted_text))
copy_encrypted_button.pack(pady=5)

# Left Frame: Create a text widget for the decrypted result
decrypted_label = tk.Label(frame_left, text="Decrypted Data:")
decrypted_label.pack(pady=5)
decrypted_text = scrolledtext.ScrolledText(frame_left, width=60, height=5)
decrypted_text.pack(pady=5)
copy_decrypted_button = tk.Button(frame_left, text="Copy Decrypted Data", command=lambda: copy_to_clipboard(decrypted_text))
copy_decrypted_button.pack(pady=5)

# Right Frame: Create a label and entry for the encrypted data to decrypt
label_decrypt = tk.Label(frame_right, text="Enter Encrypted Data:")
label_decrypt.pack(pady=5)
entry_decrypt = tk.Entry(frame_right, width=50)
entry_decrypt.pack(pady=5)

# Right Frame: Create a decrypt button
decrypt_button = tk.Button(frame_right, text="Decrypt", command=decrypt_only)
decrypt_button.pack(pady=10)

# Right Frame: Create a text widget for the decrypted result
decrypt_result_label = tk.Label(frame_right, text="Decrypted Result:")
decrypt_result_label.pack(pady=5)
decrypt_result_text = scrolledtext.ScrolledText(frame_right, width=60, height=15)
decrypt_result_text.pack(pady=5)
copy_decrypt_result_button = tk.Button(frame_right, text="Copy Decrypted Result", command=lambda: copy_to_clipboard(decrypt_result_text))
copy_decrypt_result_button.pack(pady=5)

# Run the application
root.mainloop()
