from whois_vu.api import DomainSource
from whois_vu.errors import QueryNotMatchRegexp
from requests import Session

source = DomainSource(session=Session())

r1 = source.get("ru")
print(r1)

try:
    r2 = source.get(".test")
except QueryNotMatchRegexp as e:
    print("Got exception")
