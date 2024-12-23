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

class ServerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Chat Server")
        self.root.geometry("800x600")
        
        # Create main container
        self.main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel - Active Connections
        self.left_frame = ttk.LabelFrame(self.main_container, text="Active Connections")
        self.main_container.add(self.left_frame, weight=1)
        
        # Connection list with username column
        self.connection_list = ttk.Treeview(self.left_frame, 
                                          columns=("session_id", "username", "timestamp"), 
                                          show="headings")
        self.connection_list.heading("session_id", text="Session ID")
        self.connection_list.heading("username", text="Username")
        self.connection_list.heading("timestamp", text="Connected At")
        self.connection_list.column("session_id", width=100)
        self.connection_list.column("username", width=100)
        self.connection_list.column("timestamp", width=150)
        self.connection_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Right panel - Chat Logs
        self.right_frame = ttk.LabelFrame(self.main_container, text="Chat Logs")
        self.main_container.add(self.right_frame, weight=2)
        
        # Chat log text area
        self.chat_log = scrolledtext.ScrolledText(self.right_frame)
        self.chat_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Server Status: Running", 
                                  relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=5)
        
        # Initialize logging
        self.setup_logging()
        
    def setup_logging(self):
        Path("logs").mkdir(exist_ok=True)
        
    def add_connection(self, session_id, username):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.connection_list.insert("", "end", values=(session_id, username, timestamp))
        self.log_event("connection", f"New connection established: {username} ({session_id})")
        
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

# Global variables
app = Flask(__name__)
gui = None
session_keys = {}
session_data = {}
user_sessions = {}

# Cryptographic setup
def setup_crypto():
    global private_key_small, public_key_small
    global private_key_common, public_key_common
    global private_key_normal, public_key_normal, common_modulus_n
    
    key_size = 2048
    e_small = 3
    
    # Generate key for small exponent attack
    private_key_small = rsa.generate_private_key(public_exponent=e_small, key_size=key_size)
    public_key_small = private_key_small.public_key()
    
    # Generate key for common modulus attack
    private_key_common = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    common_modulus_n = private_key_common.private_numbers().public_numbers.n
    public_key_common = rsa.RSAPublicNumbers(65537, common_modulus_n).public_key()
    
    # Generate normal key
    private_key_normal = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key_normal = private_key_normal.public_key()

def raw_rsa_decrypt(private_key, ciphertext):
    private_numbers = private_key.private_numbers()
    c = int.from_bytes(ciphertext, byteorder='big')
    m = pow(c, private_numbers.d, private_numbers.public_numbers.n)
    return m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')

def derive_session_key(pre_master_secret: bytes, client_random: bytes, server_random: bytes) -> bytes:
    key_material = pre_master_secret + client_random + server_random
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"session key derivation",
        backend=default_backend()
    ).derive(key_material)

def decrypt_pre_master_secret(attack_type, encrypted_pre_master):
    try:
        if attack_type == "small_exponent":
            return raw_rsa_decrypt(private_key_small, encrypted_pre_master)
        elif attack_type == "common_modulus":
            return raw_rsa_decrypt(private_key_common, encrypted_pre_master)
        else:
            return raw_rsa_decrypt(private_key_normal, encrypted_pre_master)
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        raise e

def encrypt_data(session_key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, iv

def decrypt_data(session_key, ciphertext, iv):
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Flask routes
@app.route("/get_public_key", methods=["GET"])
def get_public_key():
    attack_type = request.args.get("attack_type", "normal")
    if attack_type == "small_exponent":
        public_key = public_key_small
    elif attack_type == "common_modulus":
        public_key = public_key_common
    else:
        public_key = public_key_normal

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return jsonify({"public_key": pem.decode()})

@app.route("/exchange_key", methods=["POST"])
def exchange_key():
    data = request.json
    attack_type = data.get("attack_type", "normal")
    encrypted_pre_master = data.get("encrypted_pre_master", "")
    client_random = base64.b64decode(data.get("client_random", ""))
    username = data.get("username", "Anonymous")
    
    if not all([encrypted_pre_master, client_random]):
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        server_random = os.urandom(16)
        encrypted_pre_master = base64.b64decode(encrypted_pre_master)
        pre_master_secret = decrypt_pre_master_secret(attack_type, encrypted_pre_master)
        
        session_key = derive_session_key(pre_master_secret, client_random, server_random)
        session_id = base64.b64encode(os.urandom(16)).decode()
        session_keys[session_id] = session_key
        
        session_data[session_id] = {
            'client_random': client_random,
            'server_random': server_random,
            'pre_master_secret': pre_master_secret,
            'username': username
        }
        
        user_sessions[session_id] = username
        
        if gui:
            gui.add_connection(session_id, username)
        
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
    app.run(debug=False, use_reloader=False)

if __name__ == "__main__":
    setup_crypto()  # Initialize cryptographic components
    gui = ServerGUI()
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    gui.run()