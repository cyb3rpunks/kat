import json
from typing import Iterable, Union

from boefjes.job_models import NormalizerMeta
from octopoes.models import OOI, Reference
from octopoes.models.ooi.findings import Finding, KATFindingType


def run(normalizer_meta: NormalizerMeta, raw: Union[bytes, str]) -> Iterable[OOI]:
    ip_address = Reference.from_str(normalizer_meta.raw_data.boefje_meta.input_ooi)
    data = json.loads(raw)
    
    # DES check
    ciphers = data.get("Available SSH Ciphers")
    for cipher in ciphers:
        if cipher == "3des-cbc":
            des = KATFindingType(id="SSH DES possible")
            yield des
        
        # DES Finding
        nla_finding = Finding(
            finding_type=des.reference,
            ooi=ip_address,
            proof=raw,
            description="DES is Available as a cipher in the SSH connection",
            reproduce=None  
        )
        yield nla_finding


