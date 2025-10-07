"""
summary: Optimization 8

description:

    Detect signed division and avoid placing __CFSHL__ pseudo-function

    from:
3.21 mov    eax.4, edx.4                          ; 0001E1B2 (or reversed  mov  edx.4, eax.4  ; 0004EDA0)
3.22 sar    edx.4, #0x1F.1, edx.4                 ; 0001E1B4
3.23 cfshl  edx.4, #2.1, cf.1                     ; 0001E1B7
3.24 mul    #4.4, edx.4, edx.4                    ; 0001E1B7
3.25 add    xdu.4(cf.1), edx.4, ett.4             ; 0001E1BA
3.26 sub    eax.4, ett.4, eax.4                   ; 0001E1BA
3.27 sar    eax.4, #2.1, eax.4                    ; 0001E1BC
    to:
3.26 sdiv   eax.4, #4.4, eax.4                    ; 0001E1BC

    # from:
    #     mov    edx, eax
    #     sar    edx, 1Fh
    # to:
    #     cdq


    Test:
        1E19D
        4E758 - At 4EDA0 there is reversed assignment  MOV EAX, EDX

"""

from ascendancy.utils import *


def run(mba):
    if is_func_lib(mba.entry_ea):
        return 0
    mba.for_all_topinsns(Visitor8c())
    return 0


class Visitor8c(minsn_visitor_t):

    def visit_minsn(self):
        insns = []
        if (insn1 := self.topins) and (is_insn_mov_edx_eax(insn1) or is_insn_mov_eax_edx(insn1)):
            if (insn2 := insn1.next) and is_insn_sar_edx_1fh(insn2):
                if (insn3 := insn2.next) and insn3.opcode == m_cfshl and insn3.l.is_reg(REG_EDX):
                    val = insn3.r.signed_value()
                    if (insn4 := insn3.next) and insn4.opcode == m_mul and insn4.r.is_reg(REG_EDX) and insn4.d.is_reg(REG_EDX):
                        if (insn5 := insn4.next) and insn5.opcode == m_add and insn5.r.is_reg(REG_EDX) and insn5.d.is_reg(72):
                            if (insn6 := insn5.next) and insn6.opcode == m_sub and insn6.l.is_reg(REG_EAX) and insn6.r.is_reg(72) and insn6.d.is_reg(REG_EAX):
                                if (insn7 := insn6.next) and is_insn_sar(insn7, REG_EAX, val):
                                    if is_insn_mov_edx_eax(insn1):
                                        insns = [insn1, insn2, insn3, insn4, insn5, insn6]
                                    else:
                                        insns = [insn2, insn3, insn4, insn5, insn6]
                                    for insn in insns:
                                        self.blk.make_nop(insn)
                                    insn = insn7
                                    insn.opcode = m_sdiv
                                    val = 2 ** val
                                    insn.r.make_number(val, 4)
                                    print_to_log("Optimization 8 changed: [%s]" % text_insn(insn))
        return 0


class Visitor8b(minsn_visitor_t):

    def visit_minsn(self):
        insns = []
        if (insn1 := self.topins) and is_insn_sar_edx_1fh(insn1):
            if collect_until_sar_eax(insn1, insns):
                print(text_insn(insn1, self.blk))
                self.blk.make_nop(insn1)
                for insn in insns:
                    print(" ", text_insn(insn, self.blk))
                    if insn.opcode in [m_cfshl, m_mul, m_add, m_sub]:
                        self.blk.make_nop(insn)
                insn = insns[-1]
                insn.opcode = m_sdiv
                val = 2 ** insn.r.signed_value()
                insn.r.make_number(val, 4)
                print_to_log("Optimization 8 changed: [%s]" % text_insn(insn))

        return 0


class Visitor8(minsn_visitor_t):
    def visit_minsn(self):
        insn = self.topins
        if insn.opcode == m_sar and insn.d.is_reg(REG_EDX) and insn.r.is_equal_to(0x1F):
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


def collect_until_sar_eax(insn1, lst):
    lst.clear()
    insn = insn1.next
    while insn:
        if is_insn_mov_edx_eax(insn):
            return False
        lst.append(insn)
        if insn.opcode == m_sar and insn.d.is_reg(REG_EAX):
            return True
        insn = insn.next
    return False


def is_insn_sar_edx_1fh(insn):
    # SAR EDX, 1Fh
    if insn and insn.opcode == m_sar and insn.d.is_reg(REG_EDX) and insn.r.is_equal_to(0x1F):
        return True
    return False


def is_insn_mov_edx_eax(insn):
    # MOV EDX, EAX
    if insn and insn.opcode == m_mov and insn.d.is_reg(REG_EDX) and insn.l.is_reg(REG_EAX):
        return True
    return False


def is_insn_mov_eax_edx(insn):
    # MOV EAX, EDX
    if insn and insn.opcode == m_mov and insn.d.is_reg(REG_EAX) and insn.l.is_reg(REG_EDX):
        return True
    return False


def is_insn_sar(insn, r, v):
    # SAR r, v
    if insn and insn.opcode == m_sar and insn.d.is_reg(r) and insn.r.is_equal_to(v):
        return True
    return False
