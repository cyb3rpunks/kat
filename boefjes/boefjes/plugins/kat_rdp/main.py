
from typing import List, Tuple, Union

import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
import datetime
import json

from boefjes.job_models import BoefjeMeta

def run_rdp(args: List[str]) -> str:
    """Remote Desktop Security Check"""
    port = 3389
    context = ssl.create_default_context()
    context.check_hostname = False

    # Test SSL/TLS verions
    context.verify_mode = ssl.CERT_NONE
    ssl_disabled = False

    try:
        with socket.create_connection((args, port)) as sock:
            with context.wrap_socket(sock, server_hostname=args) as ssock:
                print("[!]", ssock.version(),"is enabled")
    except ConnectionRefusedError:
        print("SSL is not enabled")
        ssl_disabled = True

    # Test if certificate is selfsigned.
    if ssl_disabled == False:
        detection_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cert = ssl.get_server_certificate((args, port))
        x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
        if x509_cert.issuer == x509_cert.subject:
            print("[!] The certificate is self-signed.")
        else:
            print("The certificate is not self-signed.")

        # Printing certificate information in Windows format
        print("Detection time:", detection_time)
        print("Version:", x509_cert.version)
        print("Serialnumber:", hex(x509_cert.serial_number)[2:])
        print("Signature hashalgorithm:", x509_cert.signature_hash_algorithm.name)
        print("Issuer:", x509_cert.issuer.rfc4514_string())
        print("valid from:", x509_cert.not_valid_before)
        print("Valid until:", x509_cert.not_valid_after)
        print("Subject:", x509_cert.subject.rfc4514_string())
        print("PublicKey Hex:", x509_cert.public_key().public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo).hex())
        print("PublicKey Data:", x509_cert.public_key().public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo).decode())
        
        data = {
                "address": args, 
                "time": detection_time,
                "ssl_enabled": ssl_disabled,
                "version": x509_cert.version,
                "serialnumber":hex(x509_cert.serial_number)[2:],
                "sig":x509_cert.signature_hash_algorithm.name,
                "issuer":x509_cert.issuer.rfc4514_string(),
                "validfrom":x509_cert.not_valid_before,
                "validuntil":x509_cert.not_valid_after,
                "subject":x509_cert.subject.rfc4514_string(),
                "pubhex":x509_cert.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo).hex(),
                "pubdata":x509_cert.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo).decode(),
                }
        return data


def run(boefje_meta: BoefjeMeta) -> List[Tuple[set, Union[bytes, str]]]:
    """return results to normalizer."""
    args = boefje_meta.arguments["input"]
    results = run_rdp(args)
    return [(set(), json.dumps(results))]

