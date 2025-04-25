import ida_allins
import ida_frame
import ida_funcs
import ida_ua

from ascendancy.actions import AscendancyPluginAction


class ActionFuncSavedRegs(AscendancyPluginAction):
    label = "Calculate saved registers"

    def _activate(self, ctx):
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
