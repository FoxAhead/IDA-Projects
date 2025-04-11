"""
summary: Optimization 8

description:

    from:
        mov    edx, eax
        sar    edx, 1Fh
    to:
        cdq

    Test:
        1E19D

"""

from ascendancy.utils import *


def run(mba):
    if is_func_lib(mba.entry_ea):
        return 0
    mba.for_all_topinsns(Visitor8b())
    return 0


class Visitor8b(minsn_visitor_t):

    def visit_minsn(self):
        insns = []
        if (insn1 := self.topins) and is_insn_sar_edx_1fh(insn1):
            # if (insn0 := insn1.prev) and is_insn_mov_edx_eax(insn0):
            if self.collect_until_sar_eax(insn1, insns):
                #print_insns(insns)
                #print_to_log("\n")
                # self.blk.make_nop(insn0)
                self.blk.make_nop(insn1)
                for insn in insns:
                    if insn.opcode in [m_cfshl, m_mul, m_add, m_sub]:
                        self.blk.make_nop(insn)
                insn = insns[-1]
                insn.opcode = m_sdiv
                val = 2 ** insn.r.signed_value()
                insn.r.make_number(val, 4)
                print_to_log("Optimization 8 changed: [%s]" % text_insn(insn))

        return 0

    def collect_until_sar_eax(self, insn1, lst):
        lst.clear()
        insn = insn1.next
        while insn:
            if is_insn_mov_edx_eax(insn):
                return False
            lst.append(insn)
            if insn.opcode == m_sar and insn.d.is_reg(mr_first):
                return True
            insn = insn.next
        return False


class Visitor8(minsn_visitor_t):
    def visit_minsn(self):
        insn = self.topins
        if insn.opcode == m_sar and insn.d.is_reg(12) and insn.r.is_equal_to(0x1F):
            if insn1 := self.get_prev_mov(insn):
                print_to_log("Optimization 8 changed: [%s]" % text_insn(insn))
                insn1.opcode = m_xds
                insn1.d.make_reg(8, 8)
                self.blk.make_nop(insn)
                self.blk.mark_lists_dirty()
        return 0

    def get_prev_mov(self, insn):
        if (insn1 := insn.prev) and insn1.opcode == m_mov and insn1.d == insn.d and insn1.l.is_reg(mr_first):
            return insn1
        elif (insn1 := insn.prev) and (insn1 := insn1.prev) and insn1.opcode == m_mov and insn1.d == insn.d and insn1.l.is_reg(mr_first):
            return insn1


def is_insn_sar_edx_1fh(insn):
    if insn and insn.opcode == m_sar and insn.d.is_reg(12) and insn.r.is_equal_to(0x1F):
        return True
    return False


def is_insn_mov_edx_eax(insn):
    if insn and insn.opcode == m_mov and insn.d.is_reg(12) and insn.l.is_reg(mr_first):
        return True
    return False
