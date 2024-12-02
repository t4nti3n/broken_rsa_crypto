from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
import random

app = Flask(__name__)

#  Create key
key1 = RSA.generate(2048)  # key RSA
key2 = RSA.construct((key1.n, 65537))  # Key RSA != e
key3 = RSA.generate(2048)  # Key RSA CRT

# Endpoint: get public key
@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    mode = request.args.get('mode', 'small_exponent')

    if mode == 'small_exponent':
        public_key = {'n': key1.n, 'e': 3}  # Small Exponent
    elif mode == 'common_modulus':
        public_key = {'n': key1.n, 'e': key2.e}  # Common Modulus
    elif mode == 'crt_fault':
        public_key = {'n': key3.n, 'e': key3.e}  # CRT Fault
    else:
        return jsonify({'error': 'Invalid mode specified'}), 400

    return jsonify(public_key)

# Endpoint: encrypt
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    plaintext = bytes_to_long(data.get('message', '').encode())
    mode = data.get('mode', 'small_exponent')

    if plaintext >= key1.n:
        return jsonify({'error': 'Plaintext must be smaller than modulus'}), 400

    if mode == 'small_exponent':
        ciphertext = pow(plaintext, 3, key1.n)  #  e = 3
    elif mode == 'common_modulus':
        ciphertext = pow(plaintext, key2.e, key1.n)  
    elif mode == 'crt_fault':
        p = key3.p
        faulty_signature = pow(plaintext, key3.d % (p - 1), p)  # CRT
        return jsonify({'faulty_signature': faulty_signature})
    else:
        return jsonify({'error': 'Invalid mode specified'}), 400

    return jsonify({'ciphertext': ciphertext})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context=('server.crt', 'server.key'))

