"""
summary: Optimization 7

description:

    Prolog

    Test:
        53FB0
        26360 - TODO - check all ret blocks


"""

from ascendancy.utils import *


def run(mba):
    if is_func_lib(mba.entry_ea):
        return 0
    # mba.for_all_topinsns(Visitor7())
    blkret = None
    blk = mba.blocks
    lst = []
    ea_lst = []
    while blk:
        if insn := blk.tail:
            if insn.opcode == m_ret:
                # print("7: found ret")
                blkret = blk
                insn1 = insn.prev
                while insn1 and insn1.opcode == m_pop and is_op_reg(insn1.d, [12, 16, 20, 24, 32, 36]):
                    # print("7: found pop")
                    lst.append(insn1)
                    insn1 = insn1.prev
                break
        blk = blk.nextb
    if lst and (blk := mba.get_mblock(1)) and (insn1 := blk.head):
        # print_insns(lst)
        for insn in lst:
            if insn1.opcode == m_push and insn1.l == insn.d:
                ea_lst.append(insn1.ea)
                ea_lst.append(insn.ea)
                blk.make_nop(insn1)
                blkret.make_nop(insn)
                insn1 = insn1.next
                if insn1 is None:
                    break
    if ea_lst:
        print_to_log("Optimization 7 removed prolog/epilog at: %s" % list(map(hex, ea_lst)))

    return 0


def is_op_reg(op, lst):
    if op.is_reg() and op.size == 4 and op.r in lst:
        return True
    return False
# class Visitor7(minsn_visitor_t):
#     def visit_minsn(self):
