from civ2.hooks import *
import ida_kernwin
from ida_hexrays import *
import ida_ua
import ida_allins
import ida_frame


class Civ2Core(object):

    def __init__(self):
        self.load()

    def load(self):
        self._registered_actions = []
        self._hxe_hooks = HxeHooks()
        fname = idc.get_root_filename().upper()
        if "CIV2.540.EXE" in fname:
            print("Civ2 MGE plugin enabled")
            self._hxe_hooks.hook()
            self._hxe_hooks.mode = 0
        elif "CIV2TOTX64.EXE" in fname:
            print("Civ2 ToT plugin enabled")
            self._hxe_hooks.hook()
            self._hxe_hooks.mode = 1
        self._register_action("Civ2Plugin:Enable", "Enable")
        self._register_action("Civ2Plugin:Disable", "Disable")
        #self._register_action("Civ2Plugin:Test1", "Test1", "Ctrl+F11")

    def unload(self):
        self._hxe_hooks.unhook()
        self._hxe_hooks = None
        for action_name in self._registered_actions:
            ida_kernwin.unregister_action(action_name)

    def _register_action(self, actname, desc, shortcut=None):
        if ida_kernwin.register_action(ida_kernwin.action_desc_t(
                actname,
                desc,
                Civ2PluginAction(self._plugin_action),
                shortcut,
                None,
                -1)):
            self._registered_actions.append(actname)
        else:
            ida_kernwin.warning("Civ2Plugin: failed to register action")

    def _plugin_action(self, ctx):
        if ctx.action == "Civ2Plugin:Enable":
            print("Civ2PluginEnableAction")
            self._hxe_hooks.hook()
        elif ctx.action == "Civ2Plugin:Disable":
            print("Civ2PluginDisableAction")
            self._hxe_hooks.unhook()
        #elif ctx.action == "Civ2Plugin:Test1":
        #    print("Civ2PluginTest1Action")
        #    func = ida_funcs.get_func(ctx.cur_ea)
        #    if func:
        #        fii = ida_funcs.func_item_iterator_t()
        #        insn = ida_ua.insn_t()
        #        ok = fii.set(func)
        #        i = 0
        #        pushes = 0
        #        val = 0
        #        while ok and i < 10:
        #            ea = fii.current()
        #            ida_ua.decode_insn(insn, ea)
        #            if insn.itype == ida_allins.NN_push and insn.Op1.type == ida_ua.o_reg and insn.Op1.reg in [0, 1, 2, 3, 5, 6, 7]:
        #                # print(insn.Op1.reg)
        #                pushes = pushes + 1
        #            elif insn.itype == ida_allins.NN_sub:
        #                if insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_imm:
        #                    # print(insn.Op1.reg)
        #                    val = insn.Op2.value
        #                break
        #            else:
        #                pushes = 0
        #                val = 0
        #                break
        #            i = i + 1
        #            ok = fii.next_code()
        #        if pushes > 0 and val > 0:
        #            print("pushes: %X, val: %X, purged: %X" % (pushes, val, func.argsize))
        #            ida_frame.set_frame_size(func, val, pushes * 4, func.argsize)


class Civ2PluginAction(ida_kernwin.action_handler_t):
    def __init__(self, action_function):
        ida_kernwin.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function(ctx)
        return 1

    # This action is always available.
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
