from ascendancy.actions import AscendancyPluginAction
from ascendancy.utils import LoopManager


class ActionPrintLoopsGroups(AscendancyPluginAction):
    label = "Print loops groups"

    def _activate(self, ctx):
        LoopManager.print_groups(True)
