import json
from typing import Iterable, Union

from boefjes.job_models import NormalizerMeta
from octopoes.models import OOI
from octopoes.models.ooi.dns.zone import Hostname, ResolvedHostname
from octopoes.models.ooi.network import IPAddressV4, IPAddressV6, Network

def run(normalizer_meta: NormalizerMeta, raw: Union[bytes, str]) -> Iterable[OOI]:
    results = json.loads(raw)
    hostname = results["Hostname"]
    
    internet = Network(name="internet")
    yield internet

    hostname_ooi = Hostname(
        name=hostname
    )
    yield hostname_ooi
