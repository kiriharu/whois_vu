from requests import Session
from whois_vu.atypes import Source
from whois_vu.errors import QueryNotMatchRegexp
from whois_vu.adataclasses import DomainResponse
import re

API_URL = "http://api.whois.vu/"


class WhoisVuAPIBase:

    r_expression = "*"

    def __init__(self, source: Source):
        self.session = Session()
        self.source = source

    def check(self, query: str, **kwargs):
        expression = re.compile(self.r_expression)
        if not expression.match(query):
            raise QueryNotMatchRegexp

    def get(self, query: str, **kwargs):
        raise NotImplementedError


class DomainSource(WhoisVuAPIBase):

    r_expression = "^[A-Za-z]+$"

    def __init__(self):
        super().__init__(Source.DOMAIN)

    def get(self, query: str, **kwargs) -> DomainResponse:
        self.check(query)
        res = self.session.get(
            API_URL, params=dict(**kwargs, q=query)
        )
        return DomainResponse(**res.json())
