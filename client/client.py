import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests
import base64
import os

# Server URL
SERVER_URL = "http://localhost:5000"

# Disable SSL warnings for development
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SecureClient:
    def __init__(self):
        self.session_key = None
        self.session_id = None
        
    def encrypt_data(self, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.session_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()

    def decrypt_data(self, ciphertext, iv):
        cipher = Cipher(algorithms.AES(self.session_key), modes.CFB(base64.b64decode(iv)), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
        return plaintext.decode()

    def get_public_key(self, attack_type="normal"):
        url = f"{SERVER_URL}/get_public_key"
        params = {"attack_type": attack_type}
        response = requests.get(url, params=params, verify=False)
        if response.status_code == 200:
            return response.json()["public_key"], None
        return None, response.json()

    def exchange_key(self, attack_type="normal"):
        # Get public key
        public_key_pem, error = self.get_public_key(attack_type)
        if error:
            raise Exception(f"Failed to get public key: {error}")

        # Generate pre-master secret
        pre_master_secret = os.urandom(32)

        # Encrypt pre-master secret
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        encrypted_pre_master = public_key.encrypt(
            pre_master_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Exchange key with server
        url = f"{SERVER_URL}/exchange_key"
        payload = {
            "attack_type": attack_type,
            "encrypted_pre_master": base64.b64encode(encrypted_pre_master).decode()
        }
        response = requests.post(url, json=payload, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            self.session_key = base64.b64decode(data["session_key"])
            self.session_id = data["session_id"]
            return True, None
        return False, response.json()

    def send_message(self, message):
        if not self.session_key or not self.session_id:
            raise Exception("No active session. Please exchange keys first.")

        ciphertext, iv = self.encrypt_data(message)
        payload = {
            "ciphertext": ciphertext,
            "iv": iv,
            "session_id": self.session_id
        }
        
        response = requests.post(f"{SERVER_URL}/chat", json=payload, verify=False)
        if response.status_code == 200:
            data = response.json()
            return self.decrypt_data(data["ciphertext"], data["iv"]), None
        return None, response.json()

class ChatGUI:
    def __init__(self):
        self.client = SecureClient()
        self.root = tk.Tk()
        self.root.title("Secure Chat Client")
        self.setup_gui()

    def setup_gui(self):
        # Attack type selection
        tk.Label(self.root, text="Attack Type:").grid(row=0, column=0, padx=10, pady=10)
        self.attack_type_var = tk.StringVar(value="normal")
        attack_options = ["normal", "small_exponent", "common_modulus"]
        attack_type_menu = tk.OptionMenu(self.root, self.attack_type_var, *attack_options)
        attack_type_menu.grid(row=0, column=1, padx=10, pady=10)

        # Key exchange button
        self.exchange_button = tk.Button(self.root, text="Exchange Key", command=self.execute_exchange_key)
        self.exchange_button.grid(row=1, column=0, columnspan=2, pady=10)

        # Chat log
        tk.Label(self.root, text="Chat Log:").grid(row=2, column=0, columnspan=2, pady=10)
        self.chat_log = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=50, height=15)
        self.chat_log.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        # Message entry
        tk.Label(self.root, text="Message:").grid(row=4, column=0, padx=10, pady=10)
        self.message_entry = tk.Entry(self.root, width=40)
        self.message_entry.grid(row=4, column=1, padx=10, pady=10)

        # Send button
        self.send_button = tk.Button(self.root, text="Send", command=self.send_chat_message)
        self.send_button.grid(row=5, column=0, columnspan=2, pady=10)

    def execute_exchange_key(self):
        try:
            success, error = self.client.exchange_key(self.attack_type_var.get())
            if success:
                messagebox.showinfo("Success", "Key exchange completed successfully")
            else:
                messagebox.showerror("Error", f"Key exchange failed: {error}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_chat_message(self):
        message = self.message_entry.get()
        if not message:
            messagebox.showwarning("Warning", "Message cannot be empty")
            return

        try:
            response, error = self.client.send_message(message)
            if response:
                self.chat_log.insert(tk.END, f"You: {message}\nServer: {response}\n\n")
                self.message_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Error", f"Failed to send message: {error}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    chat_gui = ChatGUI()
    chat_gui.run()