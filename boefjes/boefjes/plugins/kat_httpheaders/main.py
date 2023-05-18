import json
import requests
from requests.exceptions import Timeout
from typing import List, Tuple, Union
from boefjes.job_models import BoefjeMeta


def run_httpheaders(url: List[str]) -> dict:
    """Checks HTTPHeaders"""
    # Create an SSH client
    try:
        response = requests.get(url, timeout=30)
        headers = dict(response.headers)
        headers_json = json.dumps(headers, indent=4).replace("'", '"')
    except Timeout:
        print("Timeout occurred while making the request.")
        return headers_json

def run(boefje_meta: BoefjeMeta) -> List[Tuple[set, Union[bytes, str]]]:
    """return results to normalizer."""
    url = boefje_meta.arguments["input"]["url"]
    results = run_httpheaders(url)
    return [(set(), json.dumps(results))]



