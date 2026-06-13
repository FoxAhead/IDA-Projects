from .parsers import LabelsTxt
from .parsers import GameTxt
from civ2.config import Config


class Resources:
    _loaded = False
    parsers = {}

    def __class_getitem__(cls, item):
        if not cls._loaded:
            cls.load()
        return cls.parsers[item].data

    @classmethod
    def load(cls):
        cls.parsers = {
            "labels": LabelsTxt(Config["LABELSTXT_FNAME"]),
            "game": GameTxt(Config["GAMETXT_FNAME"]),
            "debug": GameTxt(Config["DEBUGTXT_FNAME"]),
        }
        for parser in cls.parsers.values():
            parser.load()
        cls._loaded = True
