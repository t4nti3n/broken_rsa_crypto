from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

# Các giá trị đã thu thập
session_key_hex = "09ea8570b16b860bd4318b99e4c0e60a"  # session key đã tạo
ciphertext_1_b64 = "vqI="  # ciphertext từ message đầu tiên
iv_1_b64 = "uwXG0eM/zZPMCd71MnuKww=="  # iv từ message đầu tiên

ciphertext_2_b64 = "cTs="  # ciphertext từ message thứ hai
iv_2_b64 = "5/10QVN6zhlVMEqj2v4fuw=="  # iv từ message thứ hai

# Chuyển đổi session key từ hex thành bytes
session_key = bytes.fromhex(session_key_hex)

# Hàm giải mã AES
def aes_decrypt(ciphertext_b64, iv_b64):
    """Giải mã dữ liệu với AES-CFB sử dụng session key và iv"""
    # Giải mã Base64 để có ciphertext và iv dưới dạng bytes
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)

    # Khởi tạo cipher AES với CFB mode
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    
    # Giải mã
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Trả về plaintext dưới dạng chuỗi
    return plaintext.decode()

# Giải mã các thông điệp
plaintext_1 = aes_decrypt(ciphertext_1_b64, iv_1_b64)
plaintext_2 = aes_decrypt(ciphertext_2_b64, iv_2_b64)

# In kết quả giải mã
print(f"Plaintext 1: {plaintext_1}")
print(f"Plaintext 2: {plaintext_2}")
