from dataclasses import dataclass
from typing import Optional, List

from whois_vu.atypes import Available


@dataclass
class _TLDBaseResponse:
    domain: str
    available: Available
    type: Optional[str]
    whois: str


@dataclass
class _TLDWithDefaultsResponse:
    created: Optional[int] = None  # unixtime
    statuses: Optional[List[str]] = None


@dataclass
class TLDResponse(_TLDWithDefaultsResponse, _TLDBaseResponse):
    pass


@dataclass
class _WhoisBaseResponse:
    registrar: str
    expires: int
    deletion: int


@dataclass
class WhoisResponse(_TLDWithDefaultsResponse, _WhoisBaseResponse, _TLDBaseResponse):
    pass
