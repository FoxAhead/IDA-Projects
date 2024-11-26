"""
summary: Civ2 IDA Plugin

description:

  Civ2 IDA Plugin

"""

import civ2.core
from ida_hexrays import *


def PLUGIN_ENTRY():
    return Civ2Plugin()


class Civ2Plugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Civ2 IDA Plugin"
    help = ""
    wanted_name = "Civ2Plugin"
    wanted_hotkey = ""

    def init(self):
        self.core = civ2.core.Civ2Core()
        return ida_idaapi.PLUGIN_KEEP if self.core.installed else ida_idaapi.PLUGIN_SKIP

    def term(self):
        self.core.unload()

    def run(self, arg):
        pass
