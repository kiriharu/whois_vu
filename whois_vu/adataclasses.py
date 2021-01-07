from dataclasses import dataclass
from typing import Optional, List

from .atypes import Available


@dataclass
class DomainResponse:
    domain: str
    available: Available
    type: Optional[str]
    created: Optional[int]  # unixtime
    whois: str
    statuses: Optional[List[str]] = None
