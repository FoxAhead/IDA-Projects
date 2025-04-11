"""
summary: Optimization 16

description:

    Just for tests

test:

    1B254

"""

from ascendancy.utils import *


def run(mba):
    if is_func_lib(mba.entry_ea):
        return True
    LoopManager.init(mba)
    mba.for_all_topinsns(vstr := Visitor16())
    return vstr.err_code == MERR_OK


class Visitor16(minsn_visitor_t):

    def __init__(self):
        minsn_visitor_t.__init__(self)
        self.err_code = MERR_OK

    def visit_minsn(self):
        insn = self.curins
        if insn.ea == 0x1B254:
            #n = insn.d.d.r.unsigned_value()
            #if n == 0x63E:
            if insn.d.d.r.t == mop_n and insn.d.d.r.unsigned_value() == 0x63E:
                insn.d.d.r.make_number(0x640, 4)
                #op = insn.d.d.l.d.r.d.r
                #insnn = InsnBuilder(insn.ea, m_sub).r(op.r).n(1).insn()
                #op.create_from_insn(insnn)

                #kreg = self.mba.alloc_kreg(4)
                #insnn = InsnBuilder(insn.ea, m_sub).r(20).n(1).r(20).insn()
                #self.blk.insert_into_block(insnn, insnn.prev)
                #insnn.clr_combinable()
                #insnn.set_persistent()

                #insnn1 = InsnBuilder(insn.ea, m_sub).r(20).n(1).insn()
                #insnn2 = InsnBuilder(insn.ea, m_mul).n(2).i(insnn1).insn()
                insnn2 = InsnBuilder(insn.ea, m_mul).n(2).r(20).insn()
                insnn3 = InsnBuilder(insn.ea, m_add).r(36).n(0x640).insn()
                insnn4 = InsnBuilder(insn.ea, m_add).i(insnn3).i(insnn2).insn()
                insn.d.create_from_insn(insnn4)
                insn.clr_combinable()

                self.blk.mark_lists_dirty()
                self.err_code = MERR_LOOP
                print_blk(self.blk)
            return 1
        return 0
