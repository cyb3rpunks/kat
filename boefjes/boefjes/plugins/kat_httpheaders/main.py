import json
import requests
from requests.exceptions import Timeout
from requests.structures import CaseInsensitiveDict
from typing import List, Tuple, Union
from boefjes.job_models import BoefjeMeta


def run_httpheaders(url: List[str]) -> dict:
    """Checks HTTPHeaders"""
    try:
        response = requests.get(url, timeout=10)
        headers = CaseInsensitiveDict(response.headers)  # Convert to CaseInsensitiveDict
        headers_dict = dict(headers)  # Convert CaseInsensitiveDict to regular dictionary
        result = {"url": url, "headers": headers_dict}  # Use the converted dictionary
        return result
    except Timeout:
        print("Timeout occurred while making the request.")
        result = {"url": url, "timeout": "timeout"}
        return result

def run(boefje_meta: BoefjeMeta) -> List[Tuple[set, Union[bytes, str]]]:
    """return results to normalizer."""
    input_ = boefje_meta.arguments["input"]
    hostname = input_["netloc"]["name"]
    path = input_["path"]
    scheme = input_["scheme"]
    url = f"{scheme}://{hostname}{path}"
    results = run_httpheaders(url)
    return [(set(), json.dumps(results))]




