import base64
import os
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

# Hàm mã hóa RSA (sử dụng pycryptodome)
def rsa_encrypt(public_key_pem, data):
    try:
        public_key = RSA.import_key(public_key_pem.encode())
        cipher_rsa = pkcs1_15.new(public_key)
        h = SHA256.new(data)
        encrypted_data = cipher_rsa.encrypt(h.digest())
        return encrypted_data
    except Exception as e:
        raise Exception(f"RSA Encryption Error: {str(e)}")


# Hàm lấy public key
def get_public_key(attack_type):
    try:
        response = requests.get(
            "https://localhost:5000/get_public_key",
            params={"attack_type": attack_type},
            verify="server_cert.pem",
        )
        result = response.json()
        public_key_pem = result.get("public_key", "")
        return public_key_pem
    except Exception as e:
        raise Exception(f"Error fetching public key: {str(e)}")


# Hàm tạo session key và mã hóa pre-master secret
def exchange_key(public_key_pem, attack_type):
    pre_master_secret = os.urandom(32)  # Pre-master secret ngẫu nhiên
    encrypted_pre_master = rsa_encrypt(public_key_pem, pre_master_secret)

    try:
        response = requests.post(
            "https://localhost:5000/exchange_key",
            json={"attack_type": attack_type, "encrypted_pre_master": base64.b64encode(encrypted_pre_master).decode()},
            verify=False,
        )
        result = response.json()
        session_key = base64.b64decode(result.get("session_key", ""))
        return session_key
    except Exception as e:
        raise Exception(f"Error exchanging keys: {str(e)}")


# Hàm mã hóa dữ liệu với AES (sử dụng pycryptodome)
def aes_encrypt(session_key, data):
    try:
        cipher = AES.new(session_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ciphertext = base64.b64encode(ct_bytes).decode('utf-8')
        return iv, ciphertext
    except Exception as e:
        raise Exception(f"AES Encryption Error: {str(e)}")


def decrypt_data(session_key, ciphertext, iv):
    cipher = AES.new(session_key, AES.MODE_CBC, iv=base64.b64decode(iv))
    decrypted = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return decrypted.decode()

