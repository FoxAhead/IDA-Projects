import os
import ida_nalt
import idc
import yaml


class Config:
    NAME_ADDRESSES = None
    target: str = None
    crc32: int = 0
    startea: int = 0

    @classmethod
    def init(cls, filename="config.yaml"):
        script_dir = os.path.dirname(__file__)
        filepath = os.path.join(script_dir, filename)
        with open(filepath) as file:
            cls.NAME_ADDRESSES = yaml.safe_load(file)
        startea = idc.get_entry(idc.get_entry_ordinal(0))
        crc32 = ida_nalt.retrieve_input_file_crc32()
        cls.set_target(crc32, startea)
        return cls.target is not None

    @classmethod
    def set_target(cls, crc32, startea):
        cls.target = None
        cls.crc32 = 0
        cls.startea = 0
        for target, names in cls.NAME_ADDRESSES.items():
            if crc32 in names["CRC32"] and startea == names["start"]:
                cls.target = target
                cls.crc32 = crc32
                cls.startea = startea
                break

    @classmethod
    def get_name_address(cls, name):
        return cls.NAME_ADDRESSES[cls.target].get(name, 0)

    @classmethod
    def info(cls):
        return "target=%s (CRC32=0x%.08X, start=0x%.08X)" % (cls.target, cls.crc32, cls.startea)
