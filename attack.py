from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import base64
import math

class SmallExponentAttack:
    def __init__(self):
        self.session_key = None
        self.session_id = None
        
    def extract_modulus_from_pem(self, pem_data):
        """Trích xuất modulus từ public key PEM"""
        public_key = serialization.load_pem_public_key(
            pem_data.encode(),
            backend=default_backend()
        )
        numbers = public_key.public_numbers()
        return numbers.n

    def find_cube_root(self, encrypted_value):
        """Tính căn bậc 3 chính xác"""
        # Sử dụng phương pháp nhị phân để tìm căn bậc 3
        left, right = 0, encrypted_value
        
        while left < right:
            mid = (left + right) // 2
            if mid ** 3 < encrypted_value:
                left = mid + 1
            else:
                right = mid
                
        return left

    def derive_session_key(self, pre_master_secret):
        """Tính session key từ pre-master secret"""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"session key derivation",
            backend=default_backend()
        ).derive(pre_master_secret)

    def decrypt_message(self, ciphertext, iv):
        """Giải mã tin nhắn sử dụng session key"""
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.CFB(base64.b64decode(iv)),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(base64.b64decode(ciphertext))

    def attack(self, public_key_pem, encrypted_pre_master_b64, captured_messages):
        """Thực hiện tấn công và giải mã tin nhắn"""
        print("[+] Starting small exponent attack...")
        
        # 1. Trích xuất modulus
        n = self.extract_modulus_from_pem(public_key_pem)
        print(f"[+] Extracted modulus: {n}")
        
        # 2. Decode encrypted pre-master secret
        encrypted_value = int.from_bytes(
            base64.b64decode(encrypted_pre_master_b64),
            'big'
        )
        print(f"[+] Encrypted value: {encrypted_value}")
        
        # 3. Tính căn bậc 3
        pre_master_secret = self.find_cube_root(encrypted_value)
        print(f"[+] Recovered pre-master secret: {pre_master_secret}")
        
        # 4. Tính session key
        pre_master_bytes = pre_master_secret.to_bytes(
            (pre_master_secret.bit_length() + 7) // 8,
            'big'
        )
        self.session_key = self.derive_session_key(pre_master_bytes)
        print(f"[+] Derived session key: {base64.b64encode(self.session_key).decode()}")
        
        # 5. Giải mã tin nhắn
        print("\n[+] Decrypting messages:")
        for msg in captured_messages:
            try:
                decrypted = self.decrypt_message(
                    msg['ciphertext'],
                    msg['iv']
                )
                print(f"Decrypted message: {decrypted.decode()}")
            except Exception as e:
                print(f"Error decrypting message: {e}")

def main():
    # Dữ liệu từ Wireshark
    public_key_pem = """-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEArwDEQCsfJ6LyTV7PeTf3
7B0IK16XSvgYxz3tDhbHcY7u3gbFNyxM6tl3Ts8cN+Mi9dWVl8aGVRA4S9LGDQvo
Af4/b8DoaZQR6HZIUGAOmp9Gos4EsJdtu71ILpPWECalUv6Ihrx8xXNmijQPhMr0
FjJVTNkN5fjijwxcmOlW7Em1vSEdgqOtHzWstxrCgbAhFqlgFtO3xwh92qQ+ULrl
HIckKzdSc4O33gxCFaXAXu9zMdURj18IsTTi8po+LJzPDJVbQOiISpeAQAvocvMZ
hefVL9H4ovjinH0zbmEnebrNalbzAD6T6nvhJUKvYiktMjNWswlgrpKmfeuyES4R
iwIBAw==
-----END PUBLIC KEY-----"""

    encrypted_pre_master = "ABADZb8QImAqxRVYtDlivKgY0yahQpaADaPJQLeReOp8jyiQX6L3uKFBbg/eyIQBSBscb0sBu2u/mmF59x1+dHeqJeBos+eVAyXXqO9ddpct9k9+Vg3XSZ6Vpozv0rWEOvKW5XJOP46TzF+5LrzuMvo4qM1o0O9hRTAXv5sIVNQx+vDcZj2bW9oLdnwsdry7zzS1sW7kMU36bOz+u9K7M7Lr709724yBnBqy2xZXZAGL/U5GlZN2uKvwCoYHnO+oPEaGwu5M5Om37pI4jkY3Sl7a/o9uNGUKYrg9Zd23cg0tmWFOQrdAmdA4KdliB1YscI1KfRiggbhlCy6uaBN78g=="

    captured_messages = [
        {
            "ciphertext": "nFQOR8g=",
            "iv": "B3nmqd0XbNiUzIbjgiAc1w=="
        },
        {
            "ciphertext": "YfkHMQ0=", 
            "iv": "COH2QqtsRliGknYm3RCNTw=="
        }
    ]

    attacker = SmallExponentAttack()
    attacker.attack(public_key_pem, encrypted_pre_master, captured_messages)

if __name__ == "__main__":
    main()