"""
summary: Optimization 17

description:

    Swap ADD l,r in STX insns if l has more subinsns than r

test:

    45A54

"""

from ascendancy.opts import GlbOpt
from ascendancy.utils import *


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(17, "Swap ADD l,r in STX", True)

    def _init(self):
        pass

    def _run(self):
        for self.blk in all_blocks_in_mba(self.mba):
            self.blk_changed = False
            for self.insn in all_insns_in_block(self.blk):
                if self.insn.opcode == m_stx:
                    # print("Optimize STX dest:", hex_addr(insn.ea, blk), insn.d.dstr())
                    self.optimize_subinsn(self.insn.d)
            if self.blk_changed:
                self.mark_dirty(self.blk)

    def optimize_subinsn(self, op: mop_t):
        if op.is_insn(m_add):
            insn = op.d
            nl = self.count_sub_d(insn.l)
            nr = self.count_sub_d(insn.r)
            # print("  l%d: %s" % (nl, insn.l.dstr()))
            # print("  r%d: %s" % (nr, insn.r.dstr()))
            if nl > 0 and 0 < nr < nl:
                self.blk_changed = True
                # print("    Before:", insn.dstr())
                self.print_to_log("  %s: Swap: %s and %s" % (hex_addr(self.insn.ea, self.blk), insn.l.dstr(), insn.r.dstr()))
                insn.l.swap(insn.r)
                # print("    After:", insn.dstr())
            self.optimize_subinsn(insn.l)
            self.optimize_subinsn(insn.r)

    def count_sub_d(self, op: mop_t):
        op.for_all_ops(vstr := VisitorCounter())
        return vstr.count

    def swap_lr_ops(self, insn: minsn_t):
        insn.l.swap(insn.r)


class VisitorCounter(mop_visitor_t):
    def __init__(self):
        super().__init__()
        self.count = 0

    def visit_mop(self, op, type, is_target):
        if op.is_insn():
            self.count += 1
        return 0
