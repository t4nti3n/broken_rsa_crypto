import tkinter as tk
from tkinter import messagebox
import base64
import requests
from crypt_utils import (
    get_public_key,
    exchange_key,
    aes_encrypt,
    decrypt_data,
)


# Hàm gửi message
def send_message():
    attack_type = attack_var.get()

    try:
        # Fetch public key from server
        public_key_pem = get_public_key(attack_type)
        if public_key_pem:
            # Exchange keys with the server
            session_key = exchange_key(public_key_pem, attack_type)
            if session_key:
                # Encrypt the message
                encrypt_data(session_key)
    except Exception as e:
        messagebox.showerror("Error", str(e))


def encrypt_data(session_key):
    try:
        plaintext = message_entry.get("1.0", "end-1c")
        iv, ciphertext = aes_encrypt(session_key, plaintext)

        if iv and ciphertext:
            response = requests.post(
                "https://localhost:5000/encrypt_data",
                json={
                    "session_key": base64.b64encode(session_key).decode(),
                    "iv": iv,
                    "ciphertext": ciphertext,
                },
                verify="server_cert.pem",
            )
            result = response.json()
            output_text.delete("1.0", tk.END)
            output_text.insert(tk.END, f"Ciphertext:\n{result.get('ciphertext', 'Error')}")
    except Exception as e:
        messagebox.showerror("Error", f"AES Encryption Error: {str(e)}")


app = tk.Tk()
app.title("RSA Vulnerability Demo")

# Input message
tk.Label(app, text="Message:").pack()
message_entry = tk.Text(app, height=5, width=40)
message_entry.pack()

# Attack type
tk.Label(app, text="Attack Type:").pack()
attack_var = tk.StringVar(value="small_exponent")
tk.Radiobutton(app, text="Small Exponent", variable=attack_var, value="small_exponent").pack()
tk.Radiobutton(app, text="Common Modulus", variable=attack_var, value="common_modulus").pack()

# Submit button
tk.Button(app, text="Send", command=send_message).pack()

# Output
tk.Label(app, text="Output:").pack()
output_text = tk.Text(app, height=10, width=40)
output_text.pack()

app.mainloop()
