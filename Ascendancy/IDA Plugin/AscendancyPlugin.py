"""
summary: Ascendancy IDA Plugin

description:

  Ascendancy IDA Plugin

"""

import ascendancy.core
from ida_hexrays import *


def PLUGIN_ENTRY():
    return AscendancyPlugin()


class AscendancyPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Ascendancy IDA Plugin"
    help = ""
    wanted_name = "AscendancyPlugin"
    wanted_hotkey = ""

    def init(self):
        self.core = ascendancy.core.AscendancyCore()
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        self.core.unload()

    def run(self, arg):
        pass
