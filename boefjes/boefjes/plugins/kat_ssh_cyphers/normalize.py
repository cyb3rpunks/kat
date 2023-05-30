import json
from typing import Iterable, Union

from boefjes.job_models import NormalizerMeta
from octopoes.models import OOI, Reference
from octopoes.models.ooi.findings import Finding, KATFindingType


def run(normalizer_meta: NormalizerMeta, raw: Union[bytes, str]) -> Iterable[OOI]:
    ip_address = Reference.from_str(normalizer_meta.raw_data.boefje_meta.input_ooi)
    data = json.loads(raw)
    
    # 3DES check
    ciphers = data["Available SSH Ciphers"]
    for cipher in ciphers:
        if "3des" in cipher.lower():
            three_des = KATFindingType(id="SSH 3DES possible")
            yield three_des
            
            # DES Finding
            three_des_finding = Finding(
                finding_type=three_des.reference,
                ooi=ip_address,
                proof=raw,
                description="3DES is available as a cipher in the SSH connection",
                reproduce=None  
            )
            yield three_des_finding

        if "des" in cipher.lower() and "3des" not in cipher.lower():
            des = KATFindingType(id="SSH DES possible")
            yield des
            
            # DES Finding
            des_finding = Finding(
                finding_type=des.reference,
                ooi=ip_address,
                proof=raw,
                description="DES is available as a cipher in the SSH connection",
                reproduce=None  
            )
            yield des_finding        

