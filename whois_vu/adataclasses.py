from dataclasses import dataclass
from typing import Optional, List

from whois_vu.atypes import Available

# Many values can be not returned from API
# All time like expires, created or deletion in unixtime


@dataclass
class _TLDBaseResponse:
    domain: str
    available: Available
    type: Optional[str]
    whois: str


@dataclass
class _TLDWithDefaultsResponse:
    created: Optional[int] = None
    statuses: Optional[List[str]] = None


@dataclass
class TLDResponse(_TLDWithDefaultsResponse, _TLDBaseResponse):
    pass


@dataclass
class _WhoisBaseResponse:
    expires: int


@dataclass
class WhoisResponse(_TLDWithDefaultsResponse, _WhoisBaseResponse, _TLDBaseResponse):
    registrar: Optional[str] = None
    deletion: Optional[int] = None

