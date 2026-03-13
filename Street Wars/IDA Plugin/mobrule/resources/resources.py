from .parsers import TextAme


class Resources:
    parsers = {
        "ta": TextAme("TEXT.AME"),
    }

    def __class_getitem__(cls, item):
        return cls.parsers[item].data

    @classmethod
    def load(cls):
        for parser in cls.parsers.values():
            parser.load()
        pass

