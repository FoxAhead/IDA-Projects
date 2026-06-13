import ida_kernwin

from civ2.actions import Civ2PluginAction


class ActionDeactivate(Civ2PluginAction):
    label = "Deactivate"

    def _activate(self, ctx):
        pass
