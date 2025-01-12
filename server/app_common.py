from flask import Flask, request, jsonify
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import traceback
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import datetime
import json
from pathlib import Path

# Global variables for RSA keys
common_modulus_n = None
p = None  # Prime factor 1
q = None  # Prime factor 2
private_keys = {}  # Dictionary to store private keys for different e values
public_keys = {}   # Dictionary to store public keys for different e values
current_e_index = 0
e_values = [65537, 65539] # Small e values

# Global variables
app = Flask(__name__)
gui = None
session_keys = {}
session_data = {}
user_sessions = {}

class ServerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Vulnerable Secure Chat Server")
        self.root.geometry("800x600")
        
        # Create main container
        self.main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel - Active Connections
        self.left_frame = ttk.LabelFrame(self.main_container, text="Active Connections")
        self.main_container.add(self.left_frame, weight=1)
        
        # Connection list with username and e value columns
        self.connection_list = ttk.Treeview(self.left_frame, 
                                          columns=("session_id", "username", "e_value", "timestamp"), 
                                          show="headings")
        self.connection_list.heading("session_id", text="Session ID")
        self.connection_list.heading("username", text="Username")
        self.connection_list.heading("e_value", text="Public Exponent (e)")
        self.connection_list.heading("timestamp", text="Connected At")
        self.connection_list.column("session_id", width=100)
        self.connection_list.column("username", width=100)
        self.connection_list.column("e_value", width=50)
        self.connection_list.column("timestamp", width=150)
        self.connection_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Right panel - Chat Logs
        self.right_frame = ttk.LabelFrame(self.main_container, text="Chat Logs")
        self.main_container.add(self.right_frame, weight=2)
        
        # Chat log text area
        self.chat_log = scrolledtext.ScrolledText(self.right_frame)
        self.chat_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Server Status: Running (Vulnerable Mode)", 
                                  relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=5)
        
        # Initialize logging
        self.setup_logging()
        
    def setup_logging(self):
        Path("logs").mkdir(exist_ok=True)
        
    def add_connection(self, session_id, username, e_value):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.connection_list.insert("", "end", values=(session_id, username, e_value, timestamp))
        self.log_event("connection", f"New connection established: {username} ({session_id}) with e={e_value}")
        
    def remove_connection(self, session_id):
        for item in self.connection_list.get_children():
            if self.connection_list.item(item)["values"][0] == session_id:
                username = self.connection_list.item(item)["values"][1]
                self.connection_list.delete(item)
                self.log_event("connection", f"Connection closed: {username} ({session_id})")
                break
                
    def log_chat(self, session_id, username, message, direction):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{username}] {direction}: {message}\n"
        self.chat_log.insert(tk.END, log_entry)
        self.chat_log.see(tk.END)
        self.log_event("chat", log_entry.strip())
        
    def log_event(self, event_type, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d")
        log_file = f"logs/server_{timestamp}.log"
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": event_type,
            "message": message
        }
        with open(log_file, "a") as f:
            json.dump(log_entry, f)
            f.write("\n")
            
    def run(self):
        self.root.mainloop()

def generate_initial_primes():
    """Generate initial RSA primes and modulus"""
    global p, q, common_modulus_n
    # Generate initial key pair to get modulus and prime factors
    key = rsa.generate_private_key(
        public_exponent=e_values[0],
        key_size=2048,
        backend=default_backend()
    )
    priv_numbers = key.private_numbers()
    p = priv_numbers.p
    q = priv_numbers.q
    common_modulus_n = p * q
    print(f"Generated modulus n = {hex(common_modulus_n)}")

def calculate_private_numbers(e):
    """Calculate all required RSA private numbers for given e"""
    global p, q, common_modulus_n
    
    # Calculate phi(n)
    phi = (p - 1) * (q - 1)
    
    # Calculate private exponent d
    d = pow(e, -1, phi)
    
    # Calculate CRT components
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)
    
    return d, dmp1, dmq1, iqmp

def generate_rsa_key_pair(e_value):
    """Generate RSA key pair with specific e value using common modulus"""
    global common_modulus_n, p, q
    
    if common_modulus_n is None:
        generate_initial_primes()
    
    # Calculate all private numbers
    d, dmp1, dmq1, iqmp = calculate_private_numbers(e_value)
    
    # Create private numbers object with all required parameters
    private_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e_value, common_modulus_n)
    )
    
    return private_numbers.private_key(backend=default_backend())

def setup_crypto():
    """Initialize cryptographic components with multiple e values"""
    global private_keys, public_keys
    print("Setting up cryptographic components...")
    
    # Generate key pairs for each e value
    for e in e_values:
        print(f"Generating key pair for e = {e}")
        private_key = generate_rsa_key_pair(e)
        private_keys[e] = private_key
        public_keys[e] = private_key.public_key()
    print("Cryptographic setup complete")

def get_next_public_key():
    """Get next public key with different e value"""
    global current_e_index
    e = e_values[current_e_index]
    current_e_index = (current_e_index + 1) % len(e_values)
    return public_keys[e], e

def raw_rsa_decrypt(private_key, ciphertext):
    """Raw RSA decryption"""
    private_numbers = private_key.private_numbers()
    c = int.from_bytes(ciphertext, byteorder='big')
    m = pow(c, private_numbers.d, private_numbers.public_numbers.n)
    return m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')

def derive_session_key(pre_master_secret: bytes, client_random: bytes, server_random: bytes) -> bytes:
    """Derive session key using HKDF"""
    key_material = pre_master_secret + client_random + server_random
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"session key derivation",
        backend=default_backend()
    ).derive(key_material)

def decrypt_pre_master_secret(encrypted_pre_master, e_value):
    """Decrypt pre-master secret using appropriate private key"""
    try:
        return raw_rsa_decrypt(private_keys[e_value], encrypted_pre_master)
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        raise e

def encrypt_data(session_key, plaintext):
    """Encrypt data using AES-CFB"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, iv

def decrypt_data(session_key, ciphertext, iv):
    """Decrypt data using AES-CFB"""
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

@app.route("/get_public_key", methods=["GET"])
def get_public_key():
    """Return next public key with its e value"""
    public_key, e_value = get_next_public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return jsonify({
        "public_key": pem.decode(),
        "e": e_value,
        "n": hex(common_modulus_n)  # Expose modulus for demonstration
    })

@app.route("/exchange_key", methods=["POST"])
def exchange_key():
    """Handle key exchange with client"""
    data = request.json
    encrypted_pre_master = data.get("encrypted_pre_master", "")
    client_random = base64.b64decode(data.get("client_random", ""))
    username = data.get("username", "Anonymous")
    e_value = int(data.get("e", e_values[0]))
    
    if not all([encrypted_pre_master, client_random]):
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        server_random = os.urandom(16)
        encrypted_pre_master = base64.b64decode(encrypted_pre_master)
        pre_master_secret = decrypt_pre_master_secret(encrypted_pre_master, e_value)
        
        session_key = derive_session_key(pre_master_secret, client_random, server_random)
        session_id = base64.b64encode(os.urandom(16)).decode()
        session_keys[session_id] = session_key
        
        session_data[session_id] = {
            'client_random': client_random,
            'server_random': server_random,
            'pre_master_secret': pre_master_secret,
            'username': username,
            'e_value': e_value
        }
        
        user_sessions[session_id] = username
        
        if gui:
            gui.add_connection(session_id, username, e_value)
        
        return jsonify({
            "session_id": session_id,
            "server_random": base64.b64encode(server_random).decode()
        })
    except Exception as e:
        print(f"Error in exchange_key: {str(e)}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/chat", methods=["POST"])
def chat():
    """Handle encrypted chat messages"""
    data = request.json
    ciphertext = data.get("ciphertext", "")
    session_id = data.get("session_id", "")
    iv = data.get("iv", "")
    
    if not all([ciphertext, session_id, iv]):
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        session_key = session_keys.get(session_id)
        if not session_key:
            return jsonify({"error": "Invalid session ID"}), 401

        username = user_sessions.get(session_id, "Anonymous")
        
        ciphertext = base64.b64decode(ciphertext)
        iv = base64.b64decode(iv)
        plaintext = decrypt_data(session_key, ciphertext, iv)
        client_message = plaintext.decode()

        if gui:
            gui.log_chat(session_id, username, client_message, "Client")

        server_response = client_message.upper()
        encrypted_response, response_iv = encrypt_data(session_key, server_response.encode())

        if gui:
            gui.log_chat(session_id, username, server_response, "Server")

        return jsonify({
            "ciphertext": base64.b64encode(encrypted_response).decode(),
            "iv": base64.b64encode(response_iv).decode()
        })
    except Exception as e:
        print(f"Error in chat: {str(e)}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

def run_flask():
    """Run Flask server in debug mode"""
    app.run(debug=False, use_reloader=False)

if __name__ == "__main__":
    try:
        setup_crypto()  # Initialize cryptographic components
        print("Starting server GUI...")
        gui = ServerGUI()
        print("Starting Flask server...")
        flask_thread = threading.Thread(target=run_flask, daemon=True)
        flask_thread.start()
        gui.run()
    except Exception as e:
        print(f"Server startup error: {str(e)}")
        traceback.print_exc()