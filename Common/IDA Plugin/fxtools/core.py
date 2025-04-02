import fxtools.hooks
from fxtools.actions.actions import *
import ida_kernwin


class FxToolsCore(object):

    def __init__(self):
        self._registered_actions = {}
        self._hxe_hooks = None
        self.installed = self.load()

    def load(self):
        self._registered_actions = {}
        self._hxe_hooks = None
        self._register_action(ActionSplitArray())
        self._register_action(ActionExtractElement())
        self._register_action(ActionConvertTo8())
        self._register_action(ActionConvertTo16())
        self._register_action(ActionConvertTo32())
        self._register_action(ActionExportToKaitai())
        self._register_action(ActionExportToGraphML())
        self._register_action(ActionUnspoil())
        self._hxe_hooks = fxtools.hooks.HxeHooks(self._registered_actions)
        self._hxe_hooks.hook()
        print("FxTools IDA Plugin - enabled")
        return True

    def unload(self):
        if self.installed:
            self._hxe_hooks.unhook()
            self._hxe_hooks = None
            for name in self._registered_actions:
                ida_kernwin.unregister_action(name)

    def _register_action(self, action, shortcut=None):
        if ida_kernwin.register_action(ida_kernwin.action_desc_t(
                action.name,
                action.label,
                action,
                shortcut)):
            self._registered_actions[action.name] = (action.label, shortcut)
        else:
            ida_kernwin.warning("FxToolsPlugin: failed to register action")


