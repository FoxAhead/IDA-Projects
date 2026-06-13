import inspect

import ida_kernwin
import ida_hexrays
from civ2.opts import *
from civ2.opts import GlbOptManager
from civ2.utils import *


class HxeHooks(ida_hexrays.Hexrays_Hooks):

    def __init__(self, *args):
        self.debug = False
        self.cnt = 0
        self.ea = 0

        self.opt2 = None

        GlbOptManager.clear()
        GlbOptManager.register(opt1.Opt())
        #GlbOptManager.register(opt2.Opt())
        super().__init__(*args)

    def flowchart(self, fc):
        self.debug_print_func("BEGIN")
        # BEGIN OF OPTIMIZATIONS
        self.opt2 = opt2.Opt()
        LogMessages.clear()
        self.ea = 0
        GlbOptManager.iteration = 0
        self.debug_print_func("END")
        return 0

    def debug_print_func(self, p=""):
        if self.debug:
            name = inspect.stack()[1].function.upper()
            print("%s %s:" % (name, p))

    def refresh_pseudocode(self, vu):
        # END OF OPTIMIZATIONS
        if LogMessages:
            self.cnt = self.cnt + 1
            print("# %d - Civ2 Plugin: %.8X" % (self.cnt, self.ea))
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
        self.ea = mba.entry_ea
        #self.opt2.spds(mba)
        self.debug_print_func("END")
        return 0

    # maturity = 0
    def prolog(self, mba, fc, reachable_blocks, decomp_flags):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        self.opt2.collect_eh_info(mba, fc, reachable_blocks)
        self.debug_print_func("END")
        return 0

    # maturity = 0
    def microcode(self, mba):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        #self.opt2.keep_blocks(mba)
        #self.opt2.run1(mba)  # JUMPOUT
        #print_mba(mba)
        self.debug_print_func("END")
        return 0

    # maturity = 1 (MMAT_GENERATED)
    def preoptimized(self, mba):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        #self.opt2.run(mba)  # JUMPOUT
        #print_mba(mba)
        # self.opt2.run_make_goto_back(mba)
        #self.opt2.run_copy_cleanup_insns(mba)
        # print_mba(mba)
        self.opt2.run_copy_cleanup_blocks(mba)
        # print_mba(mba)
        #self.opt2.spds(mba)
        self.debug_print_func("END")
        return 0

    # maturity = 2 (MMAT_PREOPTIMIZED)
    def locopt(self, mba):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        #print_mba(mba)
        self.debug_print_func("END")
        return 0

    # maturity = 3 (MMAT_LOCOPT)
    def resolve_stkaddrs(self, mba):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        #self.opt2.run2(mba)  # JUMPOUT
        #self.opt2.run_mmat_locopt(mba)
        #self.opt2.spds(mba)
        #print_mba(mba)
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
        r = MERR_OK
        #r = self.opt2.run_change_eas(mba)
        #print_mba(mba)
        self.debug_print_func("END")
        return r

    # maturity = 6 (MMAT_GLBOPT2)
    def glbopt(self, mba):
        self.debug_print_func("BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        r = GlbOptManager.run(mba)
        self.debug_print_func("END")
        #print_mba(mba)
        return MERR_OK if r else MERR_LOOP

    def maturity(self, cfunc: cfunc_t, new_maturity):
        self.debug_print_func("BEGIN: cfunc.maturity=%d, new_maturity=%d" % (cfunc.maturity, new_maturity))
        #opt19.run(cfunc)
        opt1.set_enums(cfunc)
        # opt1.fix_casts(cfunc)
        self.debug_print_func("END")
        return 0

    def combine(self, blk, insn):
        # self.debug_print_func("BEGIN: blk=%d, flags=%.8X" % (blk.serial, blk.flags), )
        # self.debug_print_func("END")
        return 0

    def print_func(self, cfunc, printer):
        # Note: we can't print/str()-ify 'cfunc' here,
        # because that'll call print_func() us recursively.
        self.debug_print_func("BEGIN: maturity=%s" % (cfunc.maturity))
        self.debug_print_func("END")
        return 0

    def func_printed(self, cfunc):
        self.debug_print_func("BEGIN: maturity=%s" % (cfunc.maturity))
        opt5.run(cfunc)  # LABELS.TXT
        self.debug_print_func("END")
        return 0
