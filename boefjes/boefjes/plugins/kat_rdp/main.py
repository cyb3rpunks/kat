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

    detection_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cert = ssl.get_server_certificate((args, port))
    x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
    if x509_cert.issuer == x509_cert.subject:
        print("[!] The certificate is self-signed.")
    else:
        print("The certificate is not self-signed.")

    data = {
            "address": args, 
            "time": detection_time,
            "serialnumber":hex(x509_cert.serial_number)[2:],
            "sig_algorithm":x509_cert.signature_hash_algorithm.name,
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
    input_ = boefje_meta.arguments["input"]
    ip_address = input_["address"]
    results = run_rdp(ip_address)
    return [(set(), json.dumps(results))]

