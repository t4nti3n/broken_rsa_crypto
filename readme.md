# RSA Vulnerability Demo

This project demonstrates vulnerabilities in RSA Encryption, including **Small Exponent Attack**, **Common Modulus Attack**, and **CRT Fault Attack**. It simulates these attacks in a Client-Server architecture and includes a graphical user interface (GUI) for the Client built with Tkinter.

## RSA Vulnerabilities Demonstrated


1. **Small Exponent Attack**: Exploits the use of a small exponent (e.g., `e = 3`) for faster decryption, allowing plaintext recovery from ciphertext.
2. **Common Modulus Attack**: Occurs when different systems use the same modulus `n` but with different public exponents, enabling attackers to potentially decrypt the message.
3. **CRT Fault Attack**: Takes advantage of faults during the computation of RSA signatures using the Chinese Remainder Theorem (CRT).

---

## Architecture Overview
<img src="image.png" alt="RSA Vulnerabilities" width="600" />

### **Server**
- **Functionality:**
  - Generates RSA key pairs for secure communication.
  - Provides functionality for the Client to encrypt messages using a session key after an RSA key exchange.
  - Simulates vulnerabilities to demonstrate risks in RSA-based key exchanges:
    - **Small Exponent Attack**: Exploits a small public exponent, such as `e = 3`, to recover plaintext from ciphertext.
    - **Common Modulus Attack**: Reuses the same modulus `n` for multiple RSA key pairs with different public exponents to decrypt information.
    - **CRT Fault Attack**: Introduces a fault in the RSA signature generation process using the Chinese Remainder Theorem (CRT) to exploit weaknesses in the signing process.

### **Client**
- **Functionality:**
  - Implements a GUI using **Tkinter**.
  - Allows the user to:
    - Input a message, encrypt it using a session key (via RSA key exchange), and send it to the Server.
    - View the Server's response after decryption or processing.
    - Ensure the integrity of communication by validating the Server's public certificate.

### **Attacker (MITM)**
- **Functionality:**
  - Simulates **Man-in-the-Middle (MITM)** attacks on the RSA-based session key exchange process:
    - **Small Exponent Attack**: Recovers plaintext from ciphertext by exploiting a small public exponent (`e = 3`).
    - **Common Modulus Attack**: Exploits two ciphertexts encrypted with the same modulus `n` but different public exponents to decrypt the messages.
    - **CRT Fault Attack**: Exploits a fault in the RSA signature computation process using CRT to recover private keys or forge signatures.

---

### **Directory Structure**

```plaintext
rsa-vulnerability-demo/
├── server/
│   ├── app.py                # Flask Server: API and communication logic for Client and vulnerability simulations
│
├── client/
│   ├── client.py             # Tkinter-based Client GUI for encrypting and sending messages
│
├── requirements.txt          # Python dependencies
└── README.md                 # Documentation and project description
```
