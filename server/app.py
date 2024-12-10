from flask import Flask, request, jsonify
import base64
from crypt_utils import (
    public_key_small,
    public_key_common,
    public_key_normal,
    derive_session_key,
    decrypt_pre_master_secret,
    encrypt_data,
    decrypt_data,
    simulate_crt_fault
)

app = Flask(__name__)

@app.route("/get_public_key", methods=["GET"])
def get_public_key():
    attack_type = request.args.get("attack_type", "normal")

    if attack_type == "small_exponent":
        public_key = public_key_small
    elif attack_type == "common_modulus":
        public_key = public_key_common
    else:
        public_key = public_key_normal

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return jsonify({"public_key": pem.decode()})


@app.route("/exchange_key", methods=["POST"])
def exchange_key():
    data = request.json
    attack_type = data.get("attack_type", "normal")
    encrypted_pre_master = base64.b64decode(data.get("encrypted_pre_master", ""))

    try:
        pre_master_secret = decrypt_pre_master_secret(attack_type, encrypted_pre_master)
        session_key = derive_session_key(pre_master_secret)
        return jsonify({"session_key": base64.b64encode(session_key).decode()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/encrypt_data", methods=["POST"])
def encrypt_data_route():
    data = request.json
    plaintext = data.get("plaintext", "").encode()
    session_key = base64.b64decode(data.get("session_key", ""))

    ciphertext, iv = encrypt_data(session_key, plaintext)

    return jsonify({"ciphertext": base64.b64encode(ciphertext).decode(), "iv": base64.b64encode(iv).decode()})


@app.route("/decrypt_data", methods=["POST"])
def decrypt_data_route():
    data = request.json
    ciphertext = base64.b64decode(data.get("ciphertext", ""))
    session_key = base64.b64decode(data.get("session_key", ""))
    iv = base64.b64decode(data.get("iv", ""))

    plaintext = decrypt_data(session_key, ciphertext, iv)

    return jsonify({"plaintext": plaintext.decode()})


@app.route("/crt_fault", methods=["POST"])
def crt_fault():
    # Simulate CRT fault attack by generating a faulty signature
    faulty_signature = simulate_crt_fault()
    return jsonify({"faulty_signature": base64.b64encode(faulty_signature).decode()})


if __name__ == "__main__":
    app.run(ssl_context=("server_cert.pem", "server_key.pem"), debug=True)
