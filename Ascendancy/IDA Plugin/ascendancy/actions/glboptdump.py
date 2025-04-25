from ascendancy.actions import AscendancyPluginAction
from ascendancy.opts import GlbOptManager


class ActionGlbOptDump(AscendancyPluginAction):
    label = "Dump GlbOpt"

    def _activate(self, ctx):
        GlbOptManager.dump_to_files = True
