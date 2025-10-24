from .parsers import GwshareTxt
from .parsers import StaticTxt
from .parsers import WindowsTxt


class Resources:
    parsers = {
        "gw": GwshareTxt("gwshare.txt"),
        "st": StaticTxt("static.txt"),
        "wt": WindowsTxt("windows.txt"),
    }

    def __class_getitem__(cls, item):
        return cls.parsers[item].data

    @classmethod
    def load(cls):
        for parser in cls.parsers.values():
            parser.load()
        pass
