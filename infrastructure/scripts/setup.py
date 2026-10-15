"""Generate local lab credentials and a CA. Never prints secret values or replaces them."""
import ipaddress
import os
import secrets
from datetime import datetime, timezone, timedelta
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[2]


def save_private(path, value):
    with open(path, "xb") as file:
        file.write(value)
    os.chmod(path, 0o600)


def main():
    env = ROOT / ".env"
    if not env.exists():
        content = "\n".join(["POSTGRES_PASSWORD=" + secrets.token_hex(24), "ADMIN_USERNAME=admin",
            "ADMIN_PASSWORD=" + secrets.token_urlsafe(24), "CONTROLLER_TOKEN=" + secrets.token_urlsafe(48),
            "NOTIFIER_TOKEN=" + secrets.token_urlsafe(48),
            "ALLOWED_ORIGIN=https://localhost:8443", "RETENTION_DAYS=30", "HEARTBEAT_TIMEOUT=45", ""])
        save_private(env, content.encode())
    elif "CONTROLLER_TOKEN=" not in env.read_text(encoding="utf-8"):
        with env.open("a", encoding="utf-8") as stream:
            stream.write("\nCONTROLLER_TOKEN=" + secrets.token_urlsafe(48) + "\n")
        print("В существующий .env добавлен секрет контроллера узла; остальные значения сохранены.")
    if "NOTIFIER_TOKEN=" not in env.read_text(encoding="utf-8"):
        with env.open("a", encoding="utf-8") as stream:
            stream.write("\nNOTIFIER_TOKEN=" + secrets.token_urlsafe(48) + "\n")
    certs = ROOT / "infrastructure/certs"
    certs.mkdir(parents=True, exist_ok=True)
    os.chmod(certs, 0o700)
    if (certs / "server.crt").exists():
        print("Существующие учётные данные и сертификаты сохранены.")
        return
    ca_key, server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072), rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HoneyForge Local Lab CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False,
              data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    server = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"HoneyForge laboratory")]))
              .issuer_name(ca_name).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=90))
              .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("nginx"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
              .sign(ca_key, hashes.SHA256()))
    for name, key in [("ca.key",ca_key),("server.key",server_key)]:
        save_private(certs/name,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    for name, cert in [("ca.crt",ca),("server.crt",server)]:
        (certs/name).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(certs/"server.key",0o644)
    print("Локальное окружение создано. Прочитайте ADMIN_PASSWORD в .env; не публикуйте и не передавайте этот файл.")
    print("Перед открытием https://localhost:8443 добавьте infrastructure/certs/ca.crt в доверенные сертификаты лаборатории.")


if __name__ == "__main__":
    main()
