import ida_hexrays
import ida_idaapi
import ida_kernwin
import idaapi
import idc
import ascendancy.hooks
from ascendancy.actions import *

ida_idaapi.require("ascendancy.hooks")


class AscendancyCore(object):

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

        fname = idc.get_root_filename().upper()
        if "ANTAG.EXE" in fname:
            print("Ascendancy plugin enabled")
        else:
            return False
        self.action_manager.register_action(ActionActivate(ucb=lambda ctx: not self.active, acb=self.activate))
        self.action_manager.register_action(ActionDeactivate(ucb=lambda ctx: self.active, acb=self.deactivate))
        self.action_manager.register_action(ActionFuncSavedRegs(wt=[ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE]), "Ctrl+F11")
        # self.action_manager.register_action(ActionPropagateVar(wt=[ida_kernwin.BWN_PSEUDOCODE]))
        self.action_manager.register_action(ActionGlbOptDump(wt=[ida_kernwin.BWN_PSEUDOCODE]))
        self.action_manager.register_action(ActionPrintLoopsGroups(wt=[ida_kernwin.BWN_PSEUDOCODE]))
        self.action_manager.register_action(ActionReload(acb=self.reload))
        self._hxe_hooks = ascendancy.hooks.HxeHooks()
        self.activate()
        return True

    def unload(self):
        if self.installed:
            self.deactivate()
            self._hxe_hooks = None
            self.action_manager.unload()

    def reload(self, ctx=None):
        self.deactivate()
        self._hxe_hooks = None
        idaapi.require("ascendancy.utils")
        idaapi.require("ascendancy.utils.util")
        idaapi.require("ascendancy.utils.insn_builder")
        idaapi.require("ascendancy.hooks")
        idaapi.require("ascendancy.opts")
        idaapi.require("ascendancy.opts.opt10")
        idaapi.require("ascendancy.opts.opt11")
        idaapi.require("ascendancy.opts.opt13")
        idaapi.require("ascendancy.opts.opt16")
        self._hxe_hooks = ascendancy.hooks.HxeHooks()
        self.activate()
