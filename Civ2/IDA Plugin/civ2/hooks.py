import ida_kernwin
import ida_hexrays
from civ2.opts import *
from civ2.util import *


class HxeHooks(ida_hexrays.Hexrays_Hooks):
    cnt = 0
    ea = 0

    def __init__(self, mode, actions):
        self.mode = mode
        self.actions = actions
        ida_hexrays.Hexrays_Hooks.__init__(self)

    def flowchart(self, fc):
        # BEGIN OF OPTIMIZATIONS
        LogMessages.clear()
        ea = 0
        return 0

    def refresh_pseudocode(self, vu):
        # END OF OPTIMIZATIONS
        if LogMessages:
            self.cnt = self.cnt + 1
            print("# %d - Civ2 Plugin: %.8X" % (self.cnt, self.ea))
            for msg in LogMessages:
                print(msg)
            print()
        LogMessages.clear()
        ea = 0
        return 0

    def microcode(self, mba):
        # self.ea = mba.entry_ea
        # opt3.run(mba)
        return 0

    def preoptimized(self, mba):
        # print("PREOPTIMIZED BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        # opt9.run(mba)    # JUMPOUT
        # opt6.run(mba)    # __CHP
        # opt2.run_a(mba)  # mov 0 assertion
        # opt7.run(mba)    # Prolog/Epilog
        # opt8.run(mba)    # SAR EDX, 1Fh
        # print("PREOPTIMIZED END")
        return 0

    def locopt(self, mba):
        # opt2.run_b(mba)
        return 0

    def resolve_stkaddrs(self, mba):
        # print_mba(mba)
        # print_mba(mba)
        return 0

    def combine(self, blk, insn):
        # opt1.run(blk, insn)
        return 0

    def glbopt(self, mba):
        r1 = 0
        # print("GLBOPT BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        # r1 = opt4.run(mba)
        # print("GLBOPT END")
        return r1

    def populating_popup(self, widget, popup_handle, vu):
        for name, data in self.actions.items():
            label, shotcut = data
            ida_kernwin.attach_action_to_popup(
                vu.ct,
                popup_handle,
                name,
                "Civ2Plugin/"
            )
        return 0

    def print_func(self, cfunc, printer):
        # Note: we can't print/str()-ify 'cfunc' here,
        # because that'll call print_func() us recursively.
        # opt5.run(cfunc)
        return 0

    def func_printed(self, cfunc):
        opt5.run(cfunc, self.mode)
        return 0

