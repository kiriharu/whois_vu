from whois_vu.api import TLDSource, WhoisSource
from whois_vu.errors import QueryNotMatchRegexp
from requests import Session

source = TLDSource(session=Session())

r1 = source.get("org")
print(r1)

try:
    r2 = source.get(".test")
except QueryNotMatchRegexp as e:
    print("Got exception")

source2 = WhoisSource()
for src in ["kiriha.ru", "nic.gay"]:
    print(source2.get(src))
