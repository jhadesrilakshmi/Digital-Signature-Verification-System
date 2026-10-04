"""
gen_cert.py
-----------
Generate a self-signed TLS certificate for the demo server.

Output: certs/server.crt  (certificate)
        certs/server.key  (private key)

Usage:
    python gen_cert.py
"""

import datetime
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")


def main():
    os.makedirs(CERTS_DIR, exist_ok=True)

    cert_path = os.path.join(CERTS_DIR, "server.crt")
    key_path  = os.path.join(CERTS_DIR, "server.key")

    print("Generating self-signed TLS certificate …")

    # Generate RSA key for TLS
    tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build the certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DSVS Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(tls_key, hashes.SHA256())
    )

    # Write private key
    with open(key_path, "wb") as f:
        f.write(tls_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"  Certificate -> {cert_path}")
    print(f"  Private key -> {key_path}")
    print("Done. (Valid for 365 days -- for demo use only.)")



if __name__ == "__main__":
    main()
