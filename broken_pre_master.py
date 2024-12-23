from sympy import Integer, root
from cryptography.hazmat.primitives import serialization
from Crypto.Util.number import long_to_bytes
import base64

# Dữ liệu từ server
server_public_key_pem = """-----BEGIN PUBLIC KEY-----\nMIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAqLJh6pEHvZBSI5Ckjuc9\nBaYHNjlPgI0NWPDHklFR+98RlI+6CcbhmOC0K1GfOQ2SaUUEhy18aOYva9SKP+LF\nwfVpjVEgCWYaNO3QVhUnfKgYVG+KORXbcMu+CLT0bMyZVMcrwepbdwATYnnrI153\nnnATk/pSIPZap3KeDKg+EdVQq2RF7jcnMRjKe7o3sIVBHcVr9QIujPKGEhEyylSh\n8msvzUOXwr/YzOPXydS9sJ4zKrR4nZz33ZD+U/O2i4J9sLZhQzN98gweIwkg/1q4\n2WDQs6aLkMoBmPlFntu8O3thAU6pqlxg9gszALxKifxE9M3WQdcUAvrj9BdFyevX\nCQIBAw==\n-----END PUBLIC KEY-----\n"""
encrypted_master_key_b64 = "AiwxxScSX2/LKp8t3EfRah7AjiqzaGUyzZcFGEok2QKURadwTD3dGM4hVaO5ziKI"

# Giải mã PEM key để lấy thông tin RSA public key
public_key = serialization.load_pem_public_key(server_public_key_pem.encode())
numbers = public_key.public_numbers()
n = numbers.n  # Modulus
e = numbers.e  # Exponent

# Decode encrypted master key từ base64
encrypted_master_key = int.from_bytes(base64.b64decode(encrypted_master_key_b64), byteorder="big")

# Hàm giải mã RSA với small exponent
def decrypt_rsa_small_e(ciphertext, n, e):
    # Tính toán căn bậc e của ciphertext
    m = root(Integer(ciphertext), e)
    if m.is_integer:
        return long_to_bytes(int(m))  # Chuyển về kiểu int
    else:
        raise ValueError("Cannot decrypt: result is not an integer.")

# Giải mã pre_master_secret
try:
    pre_master_secret = decrypt_rsa_small_e(encrypted_master_key, n, e)
    print("Recovered pre_master_secret (hex):", pre_master_secret.hex())
except ValueError as ex:
    print("Decryption failed:", ex)