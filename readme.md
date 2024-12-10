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
- Generates RSA key pairs.
- Provides functionality for the Client to encrypt messages.
- Simulates vulnerabilities for the following attacks:
  - **Small Exponent Attack**: Uses a small public exponent, e.g., `e = 3`.
  - **Common Modulus Attack**: Uses the same modulus `n` for multiple key pairs with different exponents.
  - **CRT Fault Attack**: Introduces a fault in signature generation with CRT.

### **Client**
- Implements a GUI using **Tkinter**.
- Allows the user to:
  - Input a message, encrypt it, and send it to the Server.
  - View the Server's response and results.

### **Attacker (MITM)**
- Performs the following attacks:
  - **Small Exponent Attack**: Recovers plaintext from ciphertext using `e = 3`.
  - **Common Modulus Attack**: Exploits two ciphertexts with the same modulus but different exponents to decrypt.
  - **CRT Fault Attack**: Utilizes a fault in RSA signature computation with CRT.

---

## Directory Structure

```plaintext
rsa-vulnerability-demo/
├── server/
│   ├── app.py                # Flask Server
│   ├── generate_cert.py      # Script for generating RSA keys and certificates
│   ├── private_key.pem       # RSA private key
│   ├── server_cert.pem       # Server's public certificate
│
├── client/
│   ├── client.py             # Tkinter-based Client GUI
│   ├── server_cert.pem       # Server's public certificate
│
├── attacker/
│   ├── rsa_small_exponent.py # Implementation of Small Exponent Attack
│   ├── rsa_common_modulus.py # Implementation of Common Modulus Attack
│   ├── rsa_crt_fault.py      # Implementation of CRT Fault Attack
│   ├── requirements.txt      # Python dependencies
│
└── README.md                 # Project instructions and documentation
