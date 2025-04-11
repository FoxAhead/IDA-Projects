"""
summary: Optimization 2

description:

    After:
        test    eax, eax
        jnz     short loc_1B054
    add assertion:
        mov     eax, 0

    Test:
        1B041
        10E3A
        117C6 (test    dh, dh)
        1C605
        2625C (jz)

"""

from ascendancy.utils import *


def run_a(mba):
    # if is_func_lib(mba.entry_ea):
    #     return 0
    mba.for_all_topinsns(Visitor2())
    return 0


def run_b(mba):
    if is_func_lib(mba.entry_ea):
        return 0
    mba.for_all_topinsns(Visitor2b())
    return 0


def check_locopt_insn_jz(insn):
    if insn.opcode == m_jz and insn.next is None:
        #print(insn.dstr())
        if insn.l.is_reg() and insn.l.size == 4 and insn.l.r in (8, 12, 16, 20) and insn.r.is_zero():  # and insn.d.t == mop_b:
            return True
    return False


def check_no_move_next_block(blk, op_reg):
    if (blk := blk.nextb) and (insn := blk.head):
        if insn.opcode == m_mov and insn.d == op_reg:
            return False
    return True


def make_insn_mov_zero(ea, op_reg):
    insn = minsn_t(ea)
    insn.opcode = m_mov
    insn.l.make_number(0, 4)
    insn.d.make_reg(op_reg.r, 4)
    return insn


def make_insn_goto(ea, op_jmp):
    insn = minsn_t(ea)
    insn.opcode = m_goto
    insn.l = mop_t(op_jmp)
    return insn


class Visitor2b(minsn_visitor_t):
    def visit_minsn(self):
        insn = self.topins
        if check_locopt_insn_jz(insn):
            insn_jz = insn
            op_reg = insn.l
            op_jmp = insn.d
            ea = self.blk.tail.ea
            blk = self.mba.insert_block(self.mba.qty - 1)
            blk.start = ea
            blk.end = ea
            insnn = make_insn_goto(ea, op_jmp)
            blk.insert_into_block(insnn, None)
            insnn = make_insn_mov_zero(ea, op_reg)
            blk.insert_into_block(insnn, None)
            blk.flags = blk.flags | MBL_FAKE
            blk.mark_lists_dirty()

            insn_jz.d.make_blkref(blk.serial)
            self.blk.mark_lists_dirty()

            print_to_log("Optimization 2b added: [%s]" % text_insn(insnn))

            # elif var == 2:
            #     blk = self.blk
            #     while blk := blk.nextb:
            #         if blk.start == jmp_ea:
            #             insnn = minsn_t(blk.start)
            #             insnn.opcode = m_mov
            #             insnn.l.make_number(0, 4)
            #             insnn.d.make_reg(op_reg.r, 4)
            #             blk.insert_into_block(insnn, None)
            #             blk.mark_lists_dirty()
            #             print_to_log("Ascendancy Plugin - Optimization 2 added: [%s]" % text_insn(insnn))
        return 0


class Visitor2(minsn_visitor_t):
    def visit_minsn(self):
        insn = self.topins
        if insn.opcode == m_jcnd and insn.next is None:
            var = 0
            jmp_ea = 0
            if insn.l.is_insn(m_lnot) and insn.l.d.l.is_reg(mr_zf):
                var = 1
            elif insn.l.is_reg(mr_zf) and insn.d.t == mop_v:
                jmp_ea = insn.d.g
                var = 2
            if var > 0:
                insns = []
                if collect_insns_up(insn.prev, insns) == 5:
                    insn = insns[2]
                    if insn.opcode == m_setz and insn.d.is_reg(mr_zf) and insn.r.is_zero() and insn.l.is_reg() and insn.l.size == 4 and insn.l.r in (
                            8, 12, 16, 20):
                        # print_insn(insn)
                        op_reg = insn.l
                        if var == 1:
                            if (blk := self.blk.nextb) and (insn := blk.head):
                                if insn.opcode == m_mov and insn.d == op_reg:
                                    return 0
                            blk = self.blk
                            insnn = minsn_t(blk.tail.ea)
                            insnn.opcode = m_mov
                            insnn.l.make_number(0, 4)
                            insnn.d.make_reg(op_reg.r, 4)
                            # insnn.set_assert()
                            # print_insn(insnn)
                            # blk.insert_into_block(insnn, blk.tail)
                            # blk.mark_lists_dirty()

                            blk = self.mba.insert_block(self.blk.nextb.serial)
                            blk.start = insnn.ea
                            blk.end = insnn.ea
                            bp = vd_printer_t()
                            blk.flags = blk.flags | MBL_FAKE
                            blk.insert_into_block(insnn, None)
                            blk.mark_lists_dirty()

                            print_to_log("Optimization 2a added: [%s]" % text_insn(insnn))

                        # elif var == 2:
                        #     blk = self.blk
                        #     while blk := blk.nextb:
                        #         if blk.start == jmp_ea:
                        #             insnn = minsn_t(blk.start)
                        #             insnn.opcode = m_mov
                        #             insnn.l.make_number(0, 4)
                        #             insnn.d.make_reg(op_reg.r, 4)
                        #             blk.insert_into_block(insnn, None)
                        #             blk.mark_lists_dirty()
                        #             print_to_log("Ascendancy Plugin - Optimization 2 added: [%s]" % text_insn(insnn))
        return 0
