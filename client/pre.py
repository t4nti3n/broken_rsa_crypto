import tkinter as tk
from tkinter import ttk, scrolledtext
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import requests
import base64
import os
import datetime

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

class CryptoClient:
    def __init__(self, server_url="http://localhost:5000"):
        self.server_url = server_url
        self.session_key = None
        self.session_id = None
        self.pre_master_secret = None
        self.client_random = None
        self.server_random = None
    
    def raw_rsa_encrypt(self, public_key, plaintext):
        """Raw RSA encryption without padding"""
        numbers = public_key.public_numbers()
        m = int.from_bytes(plaintext, byteorder='big')
        c = pow(m, numbers.e, numbers.n)
        return c.to_bytes((c.bit_length() + 7) // 8, byteorder='big')
    
    def derive_session_key(self, pre_master_secret, client_random, server_random):
        """Derive session key using HKDF"""
        key_material = pre_master_secret + client_random + server_random
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b"session key derivation",
            backend=default_backend()
        )
        return hkdf.derive(key_material)

    def aes_encrypt(self, plaintext):
        """Encrypt data using AES-CFB"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.session_key), modes.CFB(iv), backend=default_backend())
        ciphertext = cipher.encryptor().update(plaintext.encode()) + cipher.encryptor().finalize()
        return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()

    def aes_decrypt(self, ciphertext, iv):
        """Decrypt data using AES-CFB"""
        cipher = Cipher(
            algorithms.AES(self.session_key), 
            modes.CFB(base64.b64decode(iv)), 
            backend=default_backend()
        )
        plaintext = cipher.decryptor().update(base64.b64decode(ciphertext))
        return plaintext.decode()

    def get_server_public_key(self, attack_type="normal"):
        """Get server's public key"""
        response = requests.get(
            f"{self.server_url}/get_public_key",
            params={"attack_type": attack_type},
            verify=False
        )
        response.raise_for_status()
        return response.json()["public_key"]

    def establish_session(self, attack_type="normal"):
        """Establish a secure session with the server"""
        # Get server's public key
        public_key_pem = self.get_server_public_key(attack_type)
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )

        # Generate random values
        self.client_random = os.urandom(16)
        self.pre_master_secret = os.urandom(16)

        # Encrypt pre-master secret
        encrypted_secret = self.raw_rsa_encrypt(public_key, self.pre_master_secret)

        # Exchange key with server
        response = requests.post(
            f"{self.server_url}/exchange_key",
            json={
                "attack_type": attack_type,
                "encrypted_pre_master": base64.b64encode(encrypted_secret).decode(),
                "client_random": base64.b64encode(self.client_random).decode()
            },
            verify=False
        )
        response.raise_for_status()
        data = response.json()

        # Store session data
        self.session_id = data["session_id"]
        self.server_random = base64.b64decode(data["server_random"])
        self.session_key = self.derive_session_key(
            self.pre_master_secret,
            self.client_random, 
            self.server_random
        )

        return {
            "session_id": self.session_id,
            "pre_master_secret": self.pre_master_secret.hex(),
            "client_random": self.client_random.hex(),
            "server_random": self.server_random.hex(),
            "session_key": self.session_key.hex()
        }

    def send_message(self, message):
        """Send encrypted message to server"""
        if not all([self.session_key, self.session_id]):
            raise Exception("No active session")

        # Encrypt message
        ciphertext, iv = self.aes_encrypt(message)
        
        # Send to server
        response = requests.post(
            f"{self.server_url}/chat",
            json={
                "ciphertext": ciphertext,
                "iv": iv,
                "session_id": self.session_id
            },
            verify=False
        )
        response.raise_for_status()
        data = response.json()

        # Decrypt server response
        return self.aes_decrypt(data["ciphertext"], data["iv"])

class ChatGUI:
    def __init__(self):
        self.setup_window()
        self.setup_crypto_client()
        self.create_widgets()
        self.setup_layout()

    def setup_window(self):
        """Initialize main window"""
        self.root = tk.Tk()
        self.root.title("Vulnerable Chat Client")
        self.root.geometry("800x600")
        
    def setup_crypto_client(self):
        """Initialize crypto client"""
        self.client = CryptoClient()
        self.attack_type = tk.StringVar(value="normal")
        self.status = tk.StringVar(value="Not Connected")

    def create_widgets(self):
        """Create GUI elements"""
        # Main container
        self.container = ttk.Frame(self.root, padding=10)
        
        # Connection frame
        self.conn_frame = ttk.LabelFrame(self.container, text="Connection Control", padding=5)
        
        # Attack type selector
        ttk.Label(self.conn_frame, text="Attack Mode:").grid(row=0, column=0, padx=5)
        self.attack_menu = ttk.OptionMenu(
            self.conn_frame, 
            self.attack_type,
            "normal",
            "normal", 
            "small_exponent", 
            "common_modulus"
        )
        
        # Status and connect button
        ttk.Label(self.conn_frame, text="Status:").grid(row=0, column=2, padx=5)
        ttk.Label(self.conn_frame, textvariable=self.status).grid(row=0, column=3, padx=5)
        self.connect_btn = ttk.Button(
            self.conn_frame, 
            text="Connect", 
            command=self.handle_connection
        )
        
        # Chat frame
        self.chat_frame = ttk.LabelFrame(self.container, text="Chat", padding=5)
        
        # Chat log
        self.chat_log = scrolledtext.ScrolledText(
            self.chat_frame, 
            wrap=tk.WORD,
            height=20
        )
        
        # Message entry
        self.msg_frame = ttk.Frame(self.chat_frame)
        self.msg_entry = ttk.Entry(self.msg_frame)
        self.msg_entry.bind('<Return>', lambda e: self.send_message())
        
        self.send_btn = ttk.Button(
            self.msg_frame,
            text="Send",
            command=self.send_message,
            state='disabled'
        )

    def setup_layout(self):
        """Arrange widgets in the window"""
        # Main container
        self.container.pack(fill=tk.BOTH, expand=True)
        
        # Connection frame
        self.conn_frame.pack(fill=tk.X, padx=5, pady=5)
        self.attack_menu.grid(row=0, column=1, padx=5)
        self.connect_btn.grid(row=0, column=4, padx=5)
        
        # Chat frame
        self.chat_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.chat_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Message frame
        self.msg_frame.pack(fill=tk.X, padx=5, pady=5)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.send_btn.pack(side=tk.RIGHT, padx=5)

    def handle_connection(self):
        """Handle connection button click"""
        try:
            self.status.set("Connecting...")
            self.connect_btn.state(['disabled'])
            self.root.update()

            # Establish secure session
            session_info = self.client.establish_session(self.attack_type.get())
            
            # Update UI
            self.status.set("Connected")
            self.send_btn.state(['!disabled'])
            self.msg_entry.state(['!disabled'])
            self.msg_entry.focus()

            # Log connection details
            self.log_system_message("=== Connection Established ===")
            for key, value in session_info.items():
                self.log_system_message(f"{key}: {value}")
            self.log_system_message("============================")

        except Exception as e:
            self.status.set("Connection Failed")
            self.connect_btn.state(['!disabled'])
            self.log_system_message(f"Error: {str(e)}")

    def send_message(self):
        """Handle sending messages"""
        message = self.msg_entry.get().strip()
        if not message:
            return

        try:
            # Send message and get response
            self.log_message("You", message)
            response = self.client.send_message(message)
            self.log_message("Server", response)
            
            # Clear input
            self.msg_entry.delete(0, tk.END)
            
        except Exception as e:
            self.log_system_message(f"Error: {str(e)}")

    def log_message(self, sender, message):
        """Log chat messages"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.chat_log.insert(tk.END, f"[{timestamp}] {sender}: {message}\n")
        self.chat_log.see(tk.END)

    def log_system_message(self, message):
        """Log system messages"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.chat_log.insert(tk.END, f"[{timestamp}] SYSTEM: {message}\n")
        self.chat_log.see(tk.END)

    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = ChatGUI()
    app.run()