import requests
import gmpy2
from Crypto.Util.number import bytes_to_long, long_to_bytes
import urllib3

def get_public_key(mode='small_exponent'):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    response = requests.get(
        f'https://localhost:5000/get_public_key?mode={mode}', 
        verify=False
    )
    return response.json()

def encrypt_with_small_exponent(public_key, message):
    e = public_key['e']
    n = public_key['n']
    
    # Chuyển đổi tin nhắn thành số
    plaintext = bytes_to_long(message.encode())
    
    if plaintext >= n:
        raise ValueError("Plaintext is too large!")

    ciphertext = pow(plaintext, e, n)
    return ciphertext

def small_exponent_attack(ciphertext, n):

    try:
        cube_root = gmpy2.root(gmpy2.mpz(ciphertext), 3)
        plaintext = int(cube_root)
        return long_to_bytes(plaintext)
    
    except Exception as e:
        print(f"Error: {e}")
        return None

def main():
    message = "Hello, this is a test message!"
    
    try:
        public_key = get_public_key(mode='small_exponent')
        
        # Encrypt
        ciphertext = encrypt_with_small_exponent(public_key, message)
        print(f"Ciphertext: {ciphertext}")
        
        # recover
        recovered_message = small_exponent_attack(ciphertext, public_key['n'])
        
        if recovered_message:
            print(f"Recovered Message: {recovered_message.decode('utf-8')}")
        else:
            print("Can't recover")
    
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
