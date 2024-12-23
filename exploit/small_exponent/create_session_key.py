## create session key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import binascii

# Các giá trị đã thu thập
client_random_b64 = "o7F3mmsIhASEB8LuuOLQKQ=="
server_random_b64 = "dDLq8o3zYZqy485cdHdYvw=="
pre_master_secret_hex = "3437de4f7abe779d656e93522a1280e2"

# Giải mã các giá trị base64 và hex
client_random = base64.b64decode(client_random_b64)
server_random = base64.b64decode(server_random_b64)
pre_master_secret = bytes.fromhex(pre_master_secret_hex)

# Kết hợp các giá trị lại để làm key material
key_material = pre_master_secret + client_random + server_random

# Sử dụng HKDF để tạo session key (16 byte)
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=16, 
    salt=None,  
    info=b"session key derivation",  
    backend=default_backend()
)

session_key = hkdf.derive(key_material)

print(f"Session Key: {session_key.hex()}")
