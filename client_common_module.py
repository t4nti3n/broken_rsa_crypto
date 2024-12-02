import requests
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
import math

def extended_gcd(a, b):
    """Thuật toán Euclid mở rộng để tìm BGCD và hệ số Bézout"""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def get_public_key(mode='common_modulus'):
    requests.packages.urllib3.disable_warnings()
    response = requests.get(f'https://localhost:5000/get_public_key?mode={mode}', 
                            verify=False)
    return response.json()

def encrypt_with_common_modulus(public_key, message, exponent):
    n = public_key['n']
    plaintext = bytes_to_long(message.encode())
    
    if plaintext >= n:
        print("Plaintext is too large!")
        return None
    
    ciphertext = pow(plaintext, exponent, n)
    return ciphertext

def common_modulus_attack(ciphertext1, ciphertext2, e1, e2, n):
    gcd, a, b = extended_gcd(e1, e2)
    
    if gcd != 1:
        raise ValueError("do not attack bc gcd !=1")
    
    if a < 0:
        a = -a
        ciphertext1 = pow(ciphertext1, -1, n)
    
    if b < 0:
        b = -b
        ciphertext2 = pow(ciphertext2, -1, n)
    
    # recover
    plaintext = (
        pow(ciphertext1, abs(a), n) * 
        pow(ciphertext2, abs(b), n)
    ) % n
    
    decoded_message = long_to_bytes(plaintext)
    
    try:
        return decoded_message.decode('utf-8')
    except UnicodeDecodeError:
        return f"Decoded message (hex): {decoded_message.hex()}"

def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    message = "Hello, World!"
    public_key = get_public_key(mode='common_modulus')
    
    ciphertext1 = encrypt_with_common_modulus(public_key, message, exponent=17)
    ciphertext2 = encrypt_with_common_modulus(public_key, message, exponent=65537)
    
    print(f"Ciphertext1 (e=17): {ciphertext1}")
    print(f"Ciphertext2 (e=65537): {ciphertext2}")
    
    try:
        recovered_message = common_modulus_attack(
            ciphertext1, 
            ciphertext2, 
            e1=17, 
            e2=65537, 
            n=public_key['n']
        )
        print(f"Recovered Message: {recovered_message}")
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
