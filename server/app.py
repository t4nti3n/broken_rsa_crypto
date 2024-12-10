from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import random

app = Flask(__name__)

# Tạo cặp khóa RSA cho Small Exponent Attack
key_size = 2048
e_small = 3  # Small Exponent for RSA Small Exponent Attack
private_key_small = rsa.generate_private_key(public_exponent=e_small, key_size=key_size)
public_key_small = private_key_small.public_key()

# Tạo cặp khóa RSA chung modulus cho Common Modulus Attack
private_key_common = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
common_modulus_n = private_key_common.private_numbers().public_numbers.n
public_key_common = rsa.RSAPublicNumbers(65537, common_modulus_n).public_key()

@app.route("/encrypt", methods=["POST"])
def encrypt():
    attack_type = request.json.get("attack_type", "small_exponent")
    message = request.json.get("message", "").encode()

    if not message:
        return jsonify({"error": "Message is required"}), 400

    try:
        if attack_type == "small_exponent":
            ciphertext = public_key_small.encrypt(
                message,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            )
        elif attack_type == "common_modulus":
            ciphertext = public_key_common.encrypt(
                message,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            )
        else:
            return jsonify({"error": "Invalid attack type"}), 400

        return jsonify({"ciphertext": ciphertext.hex()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/crt_fault", methods=["POST"])
def crt_fault():
    # Giả lập lỗi CRT (ví dụ chữ ký bị lỗi)
    faulty_signature = random.randint(1, 2**128).to_bytes(16, "big")  # Fake faulty signature
    return jsonify({"faulty_signature": faulty_signature.hex()})


if __name__ == "__main__":
    # Đảm bảo các file chứng chỉ được tạo sẵn
    app.run(ssl_context=("server_cert.pem", "server_key.pem"), debug=True)
