"""
summary: Optimization 0

description:

    Just for tests

test:

    00045B5E
    0004A797 - need new var

"""

from ascendancy.opts import GlbOpt
from ascendancy.utils import *


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(0, "Just for tests", True)

    def _init(self):
        pass

    def _run(self):
        # if self.mba.entry_ea == 0x45A54:
        #     self.test()
        # if self.mba.entry_ea == 0x4A6AC:
        #     self.test_4A6AC()
        if self.mba.entry_ea == 0x3CCE4:
            self.test_3CCE4()

    def test_3CCE4(self):
        for blk in all_blocks_in_mba(self.mba):
            for insn in all_insns_in_block(blk):
                if insn.opcode == m_ldx and insn.d.t == mop_r and insn.d.size == 1:
                    op = mop_t(insn.d.r, 4)
                    if is_op_used_in_insn(blk, insn, op):
                        insnn = InsnBuilder(insn.ea, m_xdu).r(insn.d.r, 1).r(insn.d.r, 4).insn()
                        blk.insert_into_block(insnn, insn)
                        self.mark_dirty(blk)

    def test(self):
        blk = self.mba.get_mblock(10)
        insns = list(all_insns_in_block(blk))
        insn4 = insns[4]
        if insn4.l.unsigned_value() == 0xF7:
            # insn4.l.update_numop_value(0x1EE)
            insn5 = insns[5]
            # insn5.d.d.r.d.r.d.l.update_numop_value(1)
            insn5.d.d.r.d.r.d.r.create_from_insn(insn4)
            insn6 = insns[6]
            # insn6.d.d.r.d.r.d.l.update_numop_value(1)
            insn6.d.d.r.d.r.d.r.create_from_insn(insn4)
            self.mark_dirty(blk)

    def test_4A6AC(self):
        blk: mblock_t = self.mba.get_mblock(7)
        insns = list(all_insns_in_block(blk))
        insn12 = insns[12]
        if insn12.ea == 0x0004A797:
            insnn = InsnBuilder(insn12.ea, m_mov).n(0).r(REG_EBX).insn()
            blk.insert_into_block(insnn, insn12.prev)
            self.mark_dirty(blk)
