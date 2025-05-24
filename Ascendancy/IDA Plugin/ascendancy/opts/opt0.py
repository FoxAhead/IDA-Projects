"""
summary: Optimization 0

description:

    Just for tests

test:

    00045B5E

"""

from ascendancy.opts import GlbOpt
from ascendancy.utils import *



class Opt(GlbOpt):

    def __init__(self):
        super().__init__(0, "Just for tests", True)

    def _init(self):
        pass

    def _run(self):
        if self.mba.entry_ea == 0x45A54:
            self.test()

    def test(self):
        blk = self.mba.get_mblock(10)
        insns = list(all_insns_in_block(blk))
        insn4 = insns[4]
        if insn4.l.unsigned_value() == 0xF7:
            #insn4.l.update_numop_value(0x1EE)
            insn5 = insns[5]
            #insn5.d.d.r.d.r.d.l.update_numop_value(1)
            insn5.d.d.r.d.r.d.r.create_from_insn(insn4)
            insn6 = insns[6]
            #insn6.d.d.r.d.r.d.l.update_numop_value(1)
            insn6.d.d.r.d.r.d.r.create_from_insn(insn4)
            self.mark_dirty(blk)


