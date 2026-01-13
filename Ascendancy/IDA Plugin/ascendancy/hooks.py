import inspect

import ida_hexrays
from ascendancy.opts import *
from ascendancy.opts import GlbOptManager
from ascendancy.utils import *


class HxeHooks(ida_hexrays.Hexrays_Hooks):

    def __init__(self, *args):
        self.debug = False
        self.cnt = 0
        self.ea = 0
        self.opt1 = None
        GlbOptManager.clear()
        # GlbOptManager.register(opt4.Opt())  OBSOLETE
        GlbOptManager.register(opt12.Opt())  # Move ADDs and ZEROes
        GlbOptManager.register(opt10.Opt())  # Loops optimizations
        GlbOptManager.register(opt11.Opt())  # Fold consecutive offset arithmetic
        GlbOptManager.register(opt15.Opt())  # (Delayed) Combine var++
        GlbOptManager.register(opt13.Opt())  # (Delayed) Reuse complex ADDs destinations
        GlbOptManager.register(opt17.Opt())  # (Delayed) Swap ADD l,r in STX
        #GlbOptManager.register(opt0.Opt())
        super().__init__(*args)

    def flowchart(self, fc):
        # BEGIN OF OPTIMIZATIONS
        self.opt1 = opt1.Opt()
        LogMessages.clear()
        self.ea = 0
        GlbOptManager.iteration = 0
        return 0

    def debug_print_func(self, p=""):
        if self.debug:
            name = inspect.stack()[1].function.upper()
            print("%s %s:" % (name, p))

    def refresh_pseudocode(self, vu):
        # END OF OPTIMIZATIONS
        if LogMessages or self.opt1:
            self.cnt = self.cnt + 1
            print("# %d - Ascendancy Plugin: %.8X" % (self.cnt, self.ea))
            if self.opt1:
                self.opt1.print_results()
            for msg in LogMessages:
                print(msg)
            print()
        LogMessages.clear()
        self.ea = 0
        GlbOptManager.iteration = 0
        return 0

    # maturity = 0
    def stkpnts(self, mba, _sps):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        self.debug_print_func("END")
        return 0

    # maturity = 0
    def prolog(self, mba, fc, reachable_blocks, decomp_flags):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        self.debug_print_func("END")
        return 0

    # maturity = 0
    def microcode(self, mba):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        self.ea = mba.entry_ea
        opt14.run(mba)  # Print floats
        opt3.run(mba)  # SAR 10h; SAR 18h -> Word; Byte
        self.debug_print_func("END")
        return 0

    # maturity = 1 (MMAT_GENERATED)
    def preoptimized(self, mba):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        opt9.run(mba)  # JUMPOUT
        opt6.run(mba)  # __CHP
        opt2.run_a(mba)  # mov 0 assertion
        opt7.run(mba)  # Prolog/Epilog
        opt8.run(mba)  # SAR EDX, 1Fh -> CDQ
        opt16.run(mba)  # Inlined StrCpy
        self.debug_print_func("END")
        return 0

    # maturity = 2 (MMAT_PREOPTIMIZED)
    def locopt(self, mba):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        # opt2.run_b(mba)
        # opt12.run(mba)
        self.debug_print_func("END")
        return 0

    # maturity = 3 (MMAT_LOCOPT)
    def resolve_stkaddrs(self, mba):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        # print_mba(mba)
        # print_mba(mba)
        self.debug_print_func("END")
        return 0

    # maturity = 4? (MMAT_CALLS)
    def build_callinfo(self, blk, type, callinfo):
        self.debug_print_func("BEGIN: blk=%d, flags=%.8X" % (blk.serial, blk.flags), )
        self.debug_print_func("END")
        return 0

    # maturity = 5 (MMAT_GLBOPT1)
    def prealloc(self, mba):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        self.debug_print_func("END")
        return MERR_OK

    # maturity = 6 (MMAT_GLBOPT2)
    def glbopt(self, mba):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        r = GlbOptManager.run(mba)
        self.debug_print_func("END")
        return MERR_OK if r else MERR_LOOP

    def maturity(self, cfunc: cfunc_t, new_maturity):
        # print("MATURITY BEGIN: cfunc.maturity=%d, new_maturity=%d" % (cfunc.maturity, new_maturity))
        # if cfunc.maturity == CMAT_TRANS2:
        opt18.run(cfunc)  # WinMgr_FindWnd cast return type
        opt19.run(cfunc)  # Float comparisons
        # print("MATURITY END")
        return 0

    def combine(self, blk, insn):
        self.debug_print_func("BEGIN: insn=%s" % (text_insn(insn, blk)))
        self.opt1.run(blk, insn)
        self.debug_print_func("END")
        return 0

    def print_func(self, cfunc, printer):
        # Note: we can't print/str()-ify 'cfunc' here,
        # because that'll call print_func() us recursively.
        # opt5.run(cfunc)
        return 0

    def func_printed(self, cfunc):
        opt5.run(cfunc)  # Static comments
        opt20.run(cfunc)  # Gwshare comments
        # opt21.run(cfunc)
        # opt18.run(cfunc)
        return 0
