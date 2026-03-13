"""
summary: Mob Rule IDA Plugin

description:

  Mob Rule IDA Plugin

"""

import mobrule.core
from ida_hexrays import *


def PLUGIN_ENTRY():
    return MobRulePlugin()


class MobRulePlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Mob Rule IDA Plugin"
    help = ""
    wanted_name = "MobRulePlugin"
    wanted_hotkey = ""

    def init(self):
        self.core = mobrule.core.MobRuleCore()
        return ida_idaapi.PLUGIN_KEEP if self.core.installed else ida_idaapi.PLUGIN_SKIP

    def term(self):
        self.core.unload()

    def run(self, arg):
        pass
