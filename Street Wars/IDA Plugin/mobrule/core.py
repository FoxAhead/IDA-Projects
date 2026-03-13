import ida_hexrays
import ida_idaapi
import ida_kernwin
import idaapi
import idc
import mobrule.config
from mobrule.resources import Resources
import mobrule.hooks
from mobrule.actions import *


class MobRuleCore(object):

    def __init__(self):
        self.active = False
        self._hxe_hooks = None
        self.action_manager = ActionManager()
        self.installed = self.load()

    def activate(self, ctx=None):
        if not self.active:
            self._hxe_hooks.hook()
            self.active = True

    def deactivate(self, ctx=None):
        if self.active:
            self._hxe_hooks.unhook()
            self.active = False

    def load(self):
        if not ida_hexrays.init_hexrays_plugin():
            return False
        self._hxe_hooks = None
        if not mobrule.config.Config.init():
            return False
        Resources.load()
        self.action_manager.register_action(ActionReload(acb=self.reload))
        self._hxe_hooks = mobrule.hooks.HxeHooks()
        self.activate()
        print("Mob Rule IDA Plugin - loaded for %s" % mobrule.config.Config.info())
        return True

    def unload(self):
        if self.installed:
            self.deactivate()
            self._hxe_hooks = None
            self.action_manager.unload()

    def reload(self, ctx=None):
        self.deactivate()
        self._hxe_hooks = None
        idaapi.require("mobrule.config")
        mobrule.config.Config.init()
        idaapi.require("mobrule.utils.util")
        idaapi.require("mobrule.utils")
        idaapi.require("mobrule.opts.opt1")
        idaapi.require("mobrule.opts")
        idaapi.require("mobrule.hooks")
        self._hxe_hooks = mobrule.hooks.HxeHooks()
        self.activate()
