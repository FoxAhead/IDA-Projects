import idc

NAME_ADDRESSES = {
    "ASCEND.EXE": {
        "start": 0x73774,
        "strcpy": 0x743E0,
        "strcat": 0,
        "StaticTxtRead": 0x1CE70,
        "WinMgr_FindWnd": 0x5216C,
        "WinMgr_FindWndWithState": 0x521DC,
        "GwshareShpCacheIndexes": 0,  #TODO
    },
    "PATCH.EXE": {
        "start": 0x737C4,
        "strcpy": 0x74430,
        "strcat": 0,
        "StaticTxtRead": 0,  #TODO
        "WinMgr_FindWnd": 0,  #TODO
        "WinMgr_FindWndWithState": 0,  #TODO
        "GwshareShpCacheIndexes": 0,  #TODO
    },
    "ANTAG.EXE": {
        "start": 0x783B4,
        "strcpy": 0x79020,
        "strcat": 0,
        "StaticTxtRead": 0x1CEA8,
        "WinMgr_FindWnd": 0x56DA8,
        "WinMgr_FindWndWithState": 0x56DA8,
        "GwshareShpCacheIndexes": 0xFFEA0,
    },
}


class Config:
    target: str = None
    startea: int = 0

    @classmethod
    def init(cls):
        cls.set_target(idc.get_root_filename(), idc.get_entry(idc.get_entry_ordinal(0)))
        return cls.target is not None

    @classmethod
    def set_target(cls, name, start):
        normalized = name.upper()
        # Get expected start address
        startea = NAME_ADDRESSES.get(normalized, {}).get("start", 0)
        if start == startea:
            # Validate if provided start address matches expected start address
            cls.target = normalized
            cls.startea = startea
        else:
            # Clear configuration if validation fails
            cls.target = None
            cls.startea = 0

    @classmethod
    def get_name_address(cls, name):
        return NAME_ADDRESSES[cls.target].get(name, 0)
