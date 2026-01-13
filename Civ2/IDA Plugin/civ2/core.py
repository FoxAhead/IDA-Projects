import civ2.hooks
import civ2.config
from civ2.actions import *
import ida_kernwin
from ida_hexrays import *
import idc

import ida_ua
import ida_allins
import ida_frame


class Civ2Core(object):

    def __init__(self):
        self._registered_actions = {}
        self._hxe_hooks = None
        self.installed = self.load()

    def load(self):
        self._registered_actions = {}
        self._hxe_hooks = None
        fname = idc.get_root_filename().upper()
        if not civ2.config.Config.init():
            return False
        self._register_action(ActionEnable(self))
        self._register_action(ActionDisable(self))
        self._register_action(ActionSplitArray())
        self._register_action(ActionExtractElement())
        self._register_action(ActionConvertTo8())
        self._register_action(ActionConvertTo16())
        self._register_action(ActionConvertTo32())
        self._hxe_hooks = civ2.hooks.HxeHooks(self._registered_actions)
        self._hxe_hooks.hook()
        print("Civ2 IDA Plugin - loaded for %s" % civ2.config.Config.info())
        return True

    def unload(self):
        if self.installed:
            self._hxe_hooks.unhook()
            self._hxe_hooks = None
            for name in self._registered_actions:
                ida_kernwin.unregister_action(name)

    def _register_action(self, action, shortcut=None):
        name, label = action.get_description()
        if ida_kernwin.register_action(ida_kernwin.action_desc_t(
                name,
                label,
                action,
                shortcut)):
            self._registered_actions[name] = (label, shortcut)
        else:
            ida_kernwin.warning("Civ2Plugin: failed to register action")


class Civ2PluginAction(ida_kernwin.action_handler_t):
    def __init__(self, core=None):
        self.core = core
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        print('Action', self.get_description())
        self._activate(ctx)
        return 1

    # This action is always available.
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

    def get_description(self):
        raise NotImplementedError("Please Implement this method")

    def _activate(self, ctx):
        raise NotImplementedError("Please Implement this method")


class ActionEnable(Civ2PluginAction):
    def get_description(self):
        return 'Civ2Plugin:Enable', 'Enable'

    def _activate(self, ctx):
        self.core._hxe_hooks.hook()


class ActionDisable(Civ2PluginAction):
    def get_description(self):
        return 'Civ2Plugin:Disable', 'Disable'

    def _activate(self, ctx):
        self.core._hxe_hooks.unhook()


class ActionSplitArray(Civ2PluginAction):
    def get_description(self):
        return 'Civ2Plugin:SplitArray', 'SplitArray'

    def _activate(self, ctx):
        ActionArray().split_array()


class ActionExtractElement(Civ2PluginAction):
    def get_description(self):
        return 'Civ2Plugin:ExtractElement', 'ExtractElement'

    def _activate(self, ctx):
        ActionArray().extract_element()


class ActionConvertTo8(Civ2PluginAction):
    def get_description(self):
        return 'Civ2Plugin:ConvertTo8', 'ConvertTo8'

    def _activate(self, ctx):
        ActionArray().convert_to(ida_typeinf.BT_INT8)


class ActionConvertTo16(Civ2PluginAction):
    def get_description(self):
        return 'Civ2Plugin:ConvertTo16', 'ConvertTo16'

    def _activate(self, ctx):
        ActionArray().convert_to(ida_typeinf.BT_INT16)


class ActionConvertTo32(Civ2PluginAction):
    def get_description(self):
        return 'Civ2Plugin:ConvertTo32', 'ConvertTo32'

    def _activate(self, ctx):
        ActionArray().convert_to(ida_typeinf.BT_INT)
