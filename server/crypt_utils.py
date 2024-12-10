from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

# RSA Keys
key_size = 2048

# Small Exponent Key
e_small = 3  # Small Exponent for attack
private_key_small = rsa.generate_private_key(public_exponent=e_small, key_size=key_size)
public_key_small = private_key_small.public_key()

# Common Modulus Key
private_key_common = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
common_modulus_n = private_key_common.private_numbers().public_numbers.n
public_key_common = rsa.RSAPublicNumbers(65537, common_modulus_n).public_key()

# Normal RSA Key (for CRT Fault and general purpose)
private_key_normal = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
public_key_normal = private_key_normal.public_key()


# Helper function to derive AES session key
def derive_session_key(pre_master_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"session key derivation",
        backend=default_backend(),
    ).derive(pre_master_secret)


def decrypt_pre_master_secret(attack_type, encrypted_pre_master):
    try:
        if attack_type == "small_exponent":
            return private_key_small.decrypt(
                encrypted_pre_master,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            )
        elif attack_type == "common_modulus":
            return private_key_common.decrypt(
                encrypted_pre_master,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            )
        else:
            return private_key_normal.decrypt(
                encrypted_pre_master,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            )
    except Exception as e:
        raise e


def encrypt_data(session_key, plaintext):
    iv = os.urandom(16)  # Initialization Vector for AES
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, iv


def decrypt_data(session_key, ciphertext, iv):
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def simulate_crt_fault():
    # Simulate CRT fault attack by generating a faulty signature
    return os.urandom(16)  # Fake faulty signature
