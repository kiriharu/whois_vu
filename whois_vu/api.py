from requests import Session
from whois_vu.atypes import Source, Available
from whois_vu.errors import QueryNotMatchRegexp, IncorrectZone
from whois_vu.adataclasses import TLDResponse, WhoisResponse
import re

API_URL = "http://api.whois.vu/"


class WhoisVuAPIBase:

    r_expression = "*"

    def __init__(self, source: Source, session: Session = None, *args, **kwargs):
        if not session:
            self.session = Session()
        else:
            self.session = session
        self.source = source

    def validate(self, query: str, **kwargs):
        expression = re.compile(self.r_expression)
        if not expression.match(query):
            raise QueryNotMatchRegexp

    def get(self, query: str, **kwargs):
        raise NotImplementedError


class TLDSource(WhoisVuAPIBase):

    r_expression = "^[A-Za-z]+$"

    def __init__(self, **kwargs):
        super().__init__(Source.TLD, **kwargs)

    def get(self, query: str, **kwargs) -> TLDResponse:
        self.validate(query)
        res = self.session.get(
            API_URL, params=dict(**kwargs, q=query)
        )
        return TLDResponse(**res.json())


class WhoisSource(WhoisVuAPIBase):

    r_expression = r"^[\w\d_-]+\.[\w\d_-]+(\.[\w\d_-]+)*$"

    def __init__(self, **kwargs):
        super().__init__(Source.WHOIS, **kwargs)

    def get(self, query: str, **kwargs) -> WhoisResponse:
        self.validate(query)
        res = self.session.get(
            API_URL, params=dict(**kwargs, q=query)
        )
        whois_rsp = WhoisResponse(**res.json())
        if "Incorrect Zone" in whois_rsp.whois or whois_rsp.available == Available.INCORRECT:
            raise IncorrectZone
        return whois_rsp

