import requests
import math
import urllib3
from Crypto.Util.number import bytes_to_long, long_to_bytes

def get_public_key(mode='crt_fault'):
    # Vô hiệu hóa cảnh báo SSL
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    response = requests.get(
        f'https://localhost:5000/get_public_key?mode={mode}', 
        verify=False
    )
    return response.json()

def encrypt_with_crt_fault(public_key, message):
    e = public_key['e']
    n = public_key['n']
    plaintext = bytes_to_long(message.encode())
    
    if plaintext >= n:
        raise ValueError("Plaintext is too large!")
    
    # Lấy chữ ký lỗi từ server
    response = requests.post(
        'https://localhost:5000/encrypt', 
        json={'message': message, 'mode': 'crt_fault'},
        verify=False
    )
    
    # Kiểm tra phản hồi từ server
    if 'faulty_signature' not in response.json():
        raise ValueError("Không nhận được chữ ký lỗi từ server")
    
    return response.json()['faulty_signature']

def factorize_n(n):
    """Phân tích n thành các thừa số nguyên tố"""
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return i, n // i
    raise ValueError("Không thể phân tích n")

def crt_fault_attack(faulty_signature, n):
    """
    Khai thác lỗi CRT để phục hồi thông điệp
    """
    try:
        # Phân tích n thành các thừa số nguyên tố
        p, q = factorize_n(n)
        
        # Kiểm tra điều kiện CRT
        if p * q != n:
            raise ValueError("Phân tích n không chính xác")
        
        # Tính nghịch đảo modular của q mod p
        q_inv = pow(q, -1, p)
        
        # Khôi phục thông điệp 
        m = (faulty_signature * q_inv) % p
        
        return long_to_bytes(m)
    
    except Exception as e:
        print(f"Lỗi trong quá trình khai thác: {e}")
        return None

def main():
    try:
        # Thông điệp để thử nghiệm
        message = "Hello, this is a CRT fault test!"
        
        # Lấy khóa công khai
        public_key = get_public_key(mode='crt_fault')
        
        # Lấy chữ ký lỗi từ server
        faulty_signature = encrypt_with_crt_fault(public_key, message)
        print(f"Chữ ký lỗi: {faulty_signature}")
        
        # Khai thác CRT Fault Attack để phục hồi thông điệp
        recovered_message = crt_fault_attack(faulty_signature, public_key['n'])
        
        if recovered_message:
            print(f"Thông điệp được khôi phục: {recovered_message.decode('utf-8')}")
        else:
            print("Không thể khôi phục thông điệp")
    
    except Exception as e:
        print(f"Đã xảy ra lỗi: {e}")

if __name__ == '__main__':
    main()
