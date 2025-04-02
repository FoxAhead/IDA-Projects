import ascendancy.hooks
from ascendancy.actions import *
import ida_kernwin
from ida_hexrays import *
import idc

import ida_ua
import ida_allins
import ida_frame


class AscendancyCore(object):

    def __init__(self):
        self._registered_actions = {}
        self._hxe_perm_hooks = None
        self._hxe_hooks = None
        self.installed = self.load()

    def load(self):
        if not ida_hexrays.init_hexrays_plugin():
            return False
        self._registered_actions = {}
        self._hxe_perm_hooks = None
        self._hxe_hooks = None
        fname = idc.get_root_filename().upper()
        if "ANTAG.EXE" in fname:
            print("Ascendancy plugin enabled")
        else:
            return False
        self._register_action(ActionEnable(self))
        self._register_action(ActionDisable(self))
        self._register_action(ActionTest1(), "Ctrl+F11")
        self._hxe_perm_hooks = ascendancy.hooks.HxePermHooks(self._registered_actions)
        self._hxe_perm_hooks.hook()
        self._hxe_hooks = ascendancy.hooks.HxeHooks()
        self._hxe_hooks.hook()
        return True

    def unload(self):
        if self.installed:
            self._hxe_hooks.unhook()
            self._hxe_hooks = None
            self._hxe_perm_hooks.unhook()
            self._hxe_perm_hooks = None
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
            ida_kernwin.warning("AscendancyPlugin: failed to register action")


class AscendancyPluginAction(ida_kernwin.action_handler_t):
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


class ActionEnable(AscendancyPluginAction):
    def get_description(self):
        return 'AscendancyPlugin:Enable', 'Enable'

    def _activate(self, ctx):
        print("AscendancyPluginEnableAction")
        self.core._hxe_hooks.hook()


class ActionDisable(AscendancyPluginAction):
    def get_description(self):
        return 'AscendancyPlugin:Disable', 'Disable'

    def _activate(self, ctx):
        print("AscendancyPluginDisableAction")
        self.core._hxe_hooks.unhook()


class ActionTest1(AscendancyPluginAction):
    def get_description(self):
        return 'AscendancyPlugin:Test1', 'Test1'

    def _activate(self, ctx):
        print("AscendancyPluginTest1Action")
        func = ida_funcs.get_func(ctx.cur_ea)
        if func:
            fii = ida_funcs.func_item_iterator_t()
            insn = ida_ua.insn_t()
            ok = fii.set(func)
            i = 0
            pushes = 0
            val = 0
            while ok and i < 10:
                ea = fii.current()
                ida_ua.decode_insn(insn, ea)
                if insn.itype == ida_allins.NN_push and insn.Op1.type == ida_ua.o_reg and insn.Op1.reg in [0, 1, 2, 3, 5, 6, 7]:
                    # print(insn.Op1.reg)
                    pushes = pushes + 1
                elif insn.itype == ida_allins.NN_sub:
                    if insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_imm:
                        # print(insn.Op1.reg)
                        val = insn.Op2.value
                    break
                else:
                    pushes = 0
                    val = 0
                    break
                i = i + 1
                ok = fii.next_code()
            if pushes > 0 and val > 0:
                print("pushes: %X, val: %X, purged: %X" % (pushes, val, func.argsize))
                ida_frame.set_frame_size(func, val, pushes * 4, func.argsize)
