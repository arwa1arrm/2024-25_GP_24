from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime

class CertificateManager:
    @staticmethod
    def generate_keys_and_certificate(user_name):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, user_name)
        ])
        
        certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).serial_number(
            x509.random_serial_number()
        ).public_key(public_key).sign(private_key, hashes.SHA256(), default_backend())
        
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)
        return private_key_bytes, certificate_bytes
