import ida_hexrays
from ascendancy.opts import *
from ascendancy.opts import GlbOptManager
from ascendancy.utils import *


class HxeHooks(ida_hexrays.Hexrays_Hooks):

    def __init__(self, *args):
        self.cnt = 0
        self.ea = 0
        GlbOptManager.register(opt4.Opt())
        GlbOptManager.register(opt10.Opt())
        GlbOptManager.register(opt11.Opt())
        GlbOptManager.register(opt12.Opt())
        GlbOptManager.register(opt15.Opt())
        GlbOptManager.register(opt13.Opt())  # TODO
        # GlbOptManager.register(opt16.Opt())
        super().__init__(*args)

    def flowchart(self, fc):
        # BEGIN OF OPTIMIZATIONS
        LogMessages.clear()
        self.ea = 0
        GlbOptManager.iteration = 0
        return 0

    def refresh_pseudocode(self, vu):
        # END OF OPTIMIZATIONS
        if LogMessages:
            self.cnt = self.cnt + 1
            print("# %d - Ascendancy Plugin: %.8X" % (self.cnt, self.ea))
            for msg in LogMessages:
                print(msg)
            print()
        LogMessages.clear()
        self.ea = 0
        GlbOptManager.iteration = 0
        return 0

    def microcode(self, mba):
        self.ea = mba.entry_ea
        opt14.run(mba)  # Print floats
        opt3.run(mba)  # SAR 10h; SAR 18h -> Word; Byte
        return 0

    def preoptimized(self, mba):
        # print("PREOPTIMIZED BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        opt9.run(mba)  # JUMPOUT
        opt6.run(mba)  # __CHP
        opt2.run_a(mba)  # mov 0 assertion
        opt7.run(mba)  # Prolog/Epilog
        opt8.run(mba)  # SAR EDX, 1Fh -> CDQ
        # print("PREOPTIMIZED END")
        return 0

    def locopt(self, mba):
        # print("LOCOPT BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        # opt2.run_b(mba)
        # print("LOCOPT END")
        return 0

    def resolve_stkaddrs(self, mba):
        # print_mba(mba)
        # print_mba(mba)
        return 0

    def combine(self, blk, insn):
        opt1.run(blk, insn)
        return 0

    def glbopt(self, mba):
        # print("GLBOPT BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
        r = GlbOptManager.run(mba)
        # print("GLBOPT END")
        return MERR_OK if r else MERR_LOOP

    # def prealloc(self, mba):
    #     print("PREALLOC BEGIN: maturity=%s, reqmat=%s" % (mba.maturity, mba.reqmat))
    #     print("PREALLOC END")

    def print_func(self, cfunc, printer):
        # Note: we can't print/str()-ify 'cfunc' here,
        # because that'll call print_func() us recursively.
        # opt5.run(cfunc)
        return 0

    def func_printed(self, cfunc):
        opt5.run(cfunc)
        return 0
