import json
from typing import Iterable, Union

from boefjes.job_models import NormalizerMeta
from octopoes.models import OOI, Reference
from octopoes.models.ooi.findings import Finding, KATFindingType

def run(normalizer_meta: NormalizerMeta, raw: Union[bytes, str]) -> Iterable[OOI]:
    ip_address = Reference.from_str(normalizer_meta.raw_data.boefje_meta.input_ooi)
    if raw:
        data = json.loads(raw)
        subject = data["subject"]
        issuer = data["issuer"]
        subject = data["subject"]
        serialnumber = data["serialnumber"]
        # NLA Check
        if serialnumber == None:
            nla = KATFindingType(id="RDP-NLA-NOT-ENFORCED")
        yield nla
        # NLA Finding
        nla_finding = Finding(
            finding_type=nla.reference,
            ooi=ip_address,
            proof=raw,
            description="Authentication without NLA possible",
            reproduce=None,  
        )
        yield nla_finding

        # Self-Signed Check
        if issuer == subject:
            selfsigned = KATFindingType(id="RDP-CERT-SELFSIGNED")
        yield selfsigned
        # Self-Signed Finding
        nla_finding = Finding(
            finding_type=selfsigned.reference,
            ooi=ip_address,
            proof=raw,
            description="MITM Attack possible",
            reproduce=None,  
        )
        yield nla_finding
