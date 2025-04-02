"""
summary: FxTools IDA Plugin

description:

  FxTools IDA Plugin

"""

import fxtools.core
import ida_idaapi


def PLUGIN_ENTRY():
    return FxToolsPlugin()


class FxToolsPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "FxTools IDA Plugin"
    help = ""
    wanted_name = "FxToolsPlugin"
    wanted_hotkey = ""

    def init(self):
        self.core = fxtools.core.FxToolsCore()
        return ida_idaapi.PLUGIN_KEEP if self.core.installed else ida_idaapi.PLUGIN_SKIP

    def term(self):
        self.core.unload()

    def run(self, arg):
        pass
