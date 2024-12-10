from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from datetime import datetime, timedelta

# Tạo khóa RSA
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Tạo chứng chỉ tự ký
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo Server"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

cert = x509.CertificateBuilder() \
    .subject_name(subject) \
    .issuer_name(issuer) \
    .public_key(private_key.public_key()) \
    .serial_number(x509.random_serial_number()) \
    .not_valid_before(datetime.utcnow()) \
    .not_valid_after(datetime.utcnow() + timedelta(days=365)) \
    .sign(private_key, hashes.SHA256())

# Lưu khóa và chứng chỉ
with open("private_key.pem", "wb") as key_file:
    key_file.write(private_key.private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    ))

with open("server_cert.pem", "wb") as cert_file:
    cert_file.write(cert.public_bytes(Encoding.PEM))
