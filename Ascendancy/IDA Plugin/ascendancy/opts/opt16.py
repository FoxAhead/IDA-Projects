"""
summary: Optimization 16

description:

    Inlined functions

test:

    261B8

"""
import ida_bytes
from ida_typeinf import tinfo_t, STI_PCCHAR, STI_PCHAR

from ascendancy.opts.glbopt import GlbOpt
from ascendancy.utils import *

PATTERN = {
    1: "strcpy",
    2: "strcat",
}


def run(mba: mba_t):
    opt16 = Opt()
    opt16.run(mba)


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(16, "Inlined functions")

    def _init(self):
        self.pattern = 0
        self.begin = 0
        self.end = 0

    def _run(self):
        for blk in all_blocks_in_mba(self.mba):
            if self.find_pattern(blk):
                self.print_to_log("  %s at %s" % (PATTERN[self.pattern], hex_addr(blk.tail.ea)))
                if self.pattern == 1:
                    self.optimize_strcpy(blk)
                elif self.pattern == 2:
                    self.optimize_strcat(blk)

    def optimize_strcpy(self, blk: mblock_t):
        insns1 = []
        for insn in all_insns_in_block(blk):
            blk.make_nop(insn)
            insns1.append(insn)
        self.mark_dirty(blk)
        next_blk = blk.nextb
        insns2 = []
        for insn in all_insns_in_block(next_blk):
            next_blk.make_nop(insn)
            insns2.append(insn)
        self.mark_dirty(next_blk)

        edx_insn = self.find_edx_def(blk)

        after_insn = None
        ea = blk.head.ea

        kreg_eax = self.mba.alloc_kreg(4)
        # insnn = InsnBuilder(insns1[0].ea, m_push).r(8).insn()
        insnn = InsnBuilder(insns1[0].ea, m_mov).r(REG_EAX).r(kreg_eax).insn()
        after_insn = blk.insert_into_block(insnn, after_insn)

        if edx_insn is None:
            kreg_edx = self.mba.alloc_kreg(4)
            # insnn = InsnBuilder(insns1[1].ea, m_push).r(12).insn()
            insnn = InsnBuilder(insns1[1].ea, m_mov).r(REG_EDX).r(kreg_edx).insn()
            after_insn = blk.insert_into_block(insnn, after_insn)

        insnn = InsnBuilder(insns1[2].ea, m_mov).r(REG_ESI).r(REG_EDX).insn()
        after_insn = blk.insert_into_block(insnn, after_insn)

        insnn = InsnBuilder(insns1[3].ea, m_mov).r(REG_EDI).r(REG_EAX).insn()
        after_insn = blk.insert_into_block(insnn, after_insn)

        insnn = InsnBuilder(insns1[-1].ea, m_call).v(0x79020).insn()
        after_insn = blk.insert_into_block(insnn, blk.tail)

        # blk.flags = blk.flags | MBL_PUSH
        self.mark_dirty(blk)

        after_insn = None
        ea = next_blk.head.ea

        if edx_insn is None:
            # insnn = InsnBuilder(insns2[0].ea, m_pop).r(12).insn()
            insnn = InsnBuilder(insns2[0].ea, m_mov).r(kreg_edx).r(REG_EDX).insn()
            after_insn = next_blk.insert_into_block(insnn, after_insn)
        else:
            insnn = minsn_t(edx_insn)
            insnn.ea = insns2[0].ea
            after_insn = next_blk.insert_into_block(insnn, after_insn)

        # insnn = InsnBuilder(insns2[1].ea, m_pop).r(8).insn()
        insnn = InsnBuilder(insns2[1].ea, m_mov).r(kreg_eax).r(REG_EAX).insn()
        after_insn = next_blk.insert_into_block(insnn, after_insn)

        # next_blk.flags = next_blk.flags | MBL_PUSH
        self.mark_dirty(next_blk)

    def optimize_strcat(self, blk: mblock_t):
        blks = self.collect_blocks_up(blk.nextb, 7)
        for blk in blks:
            self.nop_blk(blk)

        blk = blks[1]
        ea = blk.tail.ea

        # kreg_eax = self.mba.alloc_kreg(4)
        # insnn = InsnBuilder(ea, m_mov).r(REG_EAX).r(kreg_eax).insn()
        # blk.insert_into_block(insnn, blk.tail)
        #
        # kreg_edx = self.mba.alloc_kreg(4)
        # insnn = InsnBuilder(ea, m_mov).r(REG_EDX).r(kreg_edx).insn()
        # blk.insert_into_block(insnn, blk.tail)
        #
        # insnn = InsnBuilder(ea, m_mov).r(REG_ESI).r(REG_EDX).insn()
        # blk.insert_into_block(insnn, blk.tail)
        #
        # insnn = InsnBuilder(ea, m_mov).r(REG_EDI).r(REG_EAX).insn()
        # blk.insert_into_block(insnn, blk.tail)

        callargs = mcallargs_t()
        fa = mcallarg_t(mop_t(REG_EDI, 4))
        fa.type = tinfo_t.get_stock(STI_PCHAR)
        fa.name = "dst"
        callargs.push_back(fa)
        fa = mcallarg_t(mop_t(REG_ESI, 4))
        fa.type = tinfo_t.get_stock(STI_PCCHAR)
        fa.name = "src"
        callargs.push_back(fa)
        rettype = tinfo_t.get_stock(STI_PCHAR)
        insnn = self.mba.create_helper_call(ea, "strcat", rettype, callargs)
        blk.insert_into_block(insnn, blk.tail)

        self.mark_dirty(blk)

        blk = blks[0]
        ea = blk.tail.ea

        # insnn = InsnBuilder(ea, m_mov).r(kreg_edx).r(REG_EDX).insn()
        # after_insn = blk.insert_into_block(insnn, blk.tail)
        #
        # insnn = InsnBuilder(ea, m_mov).r(kreg_eax).r(REG_EAX).insn()
        # after_insn = blk.insert_into_block(insnn, blk.tail)
        #
        # self.mark_dirty(blk)

    def nop_blk(self, blk: mblock_t):
        for insn in all_insns_in_block(blk):
            if self.begin <= insn.ea < self.end:
                blk.make_nop(insn)
        self.mark_dirty(blk)

    def collect_blocks_up(self, blk, n):
        blks = []
        while n > 0:
            blks.append(blk)
            blk = blk.prevb
            n -= 1
        return blks

    def find_pattern(self, blk: mblock_t):
        self.pattern = 0
        insn = blk.head
        if insn:
            if b := ida_bytes.get_bytes(insn.ea, 25):
                if b.hex().upper() == '8A0688073C0074108A460183C60288470183C7023C0075E85F':
                    if b := ida_bytes.get_bytes(insn.ea - 9, 9):
                        if b.hex().upper() == '572BC949B000F2AE4F':
                            self.pattern = 2  # strcat
                            self.begin = blk.start - 8
                            self.end = blk.start + 24
                        else:
                            self.pattern = 1  # strcpy
                            self.begin = blk.start
                            self.end = blk.start + 24
        return self.pattern > 0

    def find_edx_def(self, blk: mblock_t):
        if blk := blk.prevb:
            op = mop_t(REG_EDX, 4)
            for insn in all_insns_in_block(blk, backwards=True):
                if is_op_defined_in_insn(blk, op, insn):
                    return insn
        return None
