import tkinter as tk
from tkinter import messagebox
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def send_message():
    message = message_entry.get("1.0", "end-1c")
    attack_type = attack_var.get()

    try:
        response = requests.post(
            "https://localhost:5000/encrypt",
            json={"message": message, "attack_type": attack_type},
            verify="server_cert.pem",
        )
        result = response.json()
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Ciphertext:\n{result.get('ciphertext', 'Error')}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

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
