"""
summary: Optimization 6

description:

    Remove call to FPU-related "__CHP" function

test:

    13A28
    50D70
    1320B (EXCEPTION: fstp, needs to add (int) casting)

"""

from ida_hexrays import *
from ascendancy.util import *

def run(mba):
    if is_func_lib(mba.entry_ea):
        return 0
    mba.for_all_topinsns(vstr := Visitor6())
    if vstr.cnt:
        return MERR_LOOP
    else:
        return MERR_OK


class Visitor6(minsn_visitor_t):
    cnt = 0
    def visit_minsn(self):
        insn = self.curins
        if insn.opcode == m_call and insn.l.t == mop_v and insn.l.g == 0x76E98:
            print_to_log("Optimization 6 - Removed %.8X: %s" % (insn.ea, insn.dstr()))
            self.blk.make_nop(insn)
            self.cnt = self.cnt + 1
        return 0