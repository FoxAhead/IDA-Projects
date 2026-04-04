"""
summary: Optimization 1

description:
    Change
        SLOBYTE(Game.MapFlags) < 0
    to
        (Game.MapFlags & 0x80) != 0

test:

    sub_40E017

"""
from civ2.opts import GlbOpt
from civ2.utils import *


class Opt(GlbOpt):
    def __init__(self):
        super().__init__(1, "Opt1")

    def _init(self):
        pass

    def _run(self):
        for self.blk in all_blocks_in_mba(self.mba):
            self.blk_changed = False
            for self.insn in all_insns_in_block(self.blk):
                if self.insn.opcode == m_jge and self.insn.l.t == mop_v and self.insn.l.g in [0x655AF0, 0x655AEA]:
                    if self.insn.r.t == mop_n and self.insn.r.is_zero():
                        insnl = InsnBuilder(self.insn.r.nnn.ea, m_and, 1).v(self.insn.l.g).n(0x80, self.insn.r.nnn.ea).insn()
                        insnl.l.size = 1
                        self.insn.l.create_from_insn(insnl)
                        self.insn.opcode = m_jz
                        self.blk_changed = True
            if self.blk_changed:
                self.mark_dirty(self.blk)
