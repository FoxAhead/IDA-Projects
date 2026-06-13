import ida_kernwin
import idaapi
from ida_hexrays import *
import idc
import civ2.config
#from civ2.resources import Resources
import civ2.hooks
from civ2.actions import *

import ida_ua
import ida_allins
import ida_frame


class Civ2Core(object):

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
        self._hxe_hooks = None
        fname = idc.get_root_filename().upper()
        if not civ2.config.Config.init():
            return False
        #Resources.load()
        self.action_manager.register_action(ActionActivate(ucb=lambda ctx: not self.active, acb=self.activate))
        self.action_manager.register_action(ActionDeactivate(ucb=lambda ctx: self.active, acb=self.deactivate))
        self.action_manager.register_action(ActionReload(acb=self.reload))
        self._hxe_hooks = civ2.hooks.HxeHooks()
        self.activate()
        print("Civ2 IDA Plugin - loaded for %s" % civ2.config.Config.info())
        return True

    def unload(self):
        if self.installed:
            self.deactivate()
            self._hxe_hooks = None
            self.action_manager.unload()

    def reload(self, ctx=None):
        self.deactivate()
        self._hxe_hooks = None
        idaapi.require("civ2.config")
        civ2.config.Config.init()
        idaapi.require("civ2.utils.util")
        idaapi.require("civ2.utils.insn_builder")
        idaapi.require("civ2.utils")
        idaapi.require("civ2.opts.opt1")
        idaapi.require("civ2.opts.opt2")
        idaapi.require("civ2.opts.opt5")
        idaapi.require("civ2.opts")
        idaapi.require("civ2.hooks")
        idaapi.require("civ2.resources.parsers.gametxt")
        idaapi.require("civ2.resources.parsers")
        idaapi.require("civ2.resources.resources")
        idaapi.require("civ2.resources")
        self._hxe_hooks = civ2.hooks.HxeHooks()
        self.activate()
