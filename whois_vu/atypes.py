from enum import Enum


class Source(str, Enum):
    WHOIS = ""
    DEFAULT = ""
    TLD = ""
    IP = "ip"
    MANUAL = "manual"
    DIG = "dig"


class Available(str, Enum):
    YES = "yes"
    NO = "no"
    UNDEFINED = "undefined"
    INCORRECT = "incorrect"
