"""
summary: Optimization 3

description:

    Changes

    Variant 1 (word)

        mov     edx, [eax+460Ch]
        sar     edx, 10h
    to
        movsx   edx, word ptr [eax+460Eh]

    Variant 2 (byte)
        mov     edx, [esp+25h]
        sar     edx, 18h
    to
        movsx   edx, [esp+40h+var_18]

    to prevent generation of unnecesary right shifts
        *(int *)(a1 + 0x460C) >> 0x10
    and convert to
        *(_WORD *)(a1 + 0x460E)
    which is better recognized as WORD (or BYTE) field access


    More precize fix in microcode event:
    Find pattern 2:
9.27 mov    #0x10.1, t1.1                         ; 0001458A
9.28 cfshr  edx.4, t1.1, cf.1                     ; 0001458A
9.29 sar    edx.4, t1.1, edx.4                    ; 0001458A
    Then find pattern 1:
9.22 add    eoff.4, #0x1BCC.4, eoff.4             ; 0001457E
(or  sub    eoff.4, #3.4, eoff.4                  ; 0001456D)
(or  mov    &($dword_D35E5).4, eoff.4             ; 0001D7C6)
(or  mov    &($dword_D35E5).4, eoff.4             ; 0001D7C6)
(or  mov    eax.4, eoff.4                         ; 00034ECB
     mov    ds.2, seg.2                           ; 00034ECB )
9.23 ldx    seg.2, eoff.4, et1.4                  ; 0001457E
9.24 mov    et1.4, edx.4                          ; 0001457E



tests:

    1D794
    143C9 (sar 24)
    1E19F (long distance between SAR and eoff at 1E172)
    34ED1
    47DD5
    39EBD, 3A18B, 3A287 - Fixed for SUB
    3F15C - pattern 2 is first in the block and pattern 1 is located at previous block
    4B7A0 - pattern 2 is NOT first in the block and pattern 1 is located at previous block

"""

from ascendancy.utils import *


def run(mba):
    if is_func_lib(mba.entry_ea):
        return 0
    mba.for_all_topinsns(vstr := Visitor3b())
    if vstr.result:
        print_to_log("Optimization 3 (SAR 10h; SAR 18h -> Word; Byte): %s" % vstr.result)


class Visitor3b(minsn_visitor_t):

    def __init__(self):
        super().__init__()
        self.insns1 = []  # Group with pattern 1
        self.insns2 = []  # Group with pattern 2
        self.mode = 0
        self.result = {}

    def visit_minsn(self):
        if self._check_insn2(self.curins):
            # print("found insn2: %s" % text_insn(self.curins))
            if self._check_insn1(self.insns2[-1].prev) or self._check_insn1(self.ensure_prev_insn(None)):
                # print("found insn1")
                before = text_insn(self.insn1)
                self.insns2[2].l.nnn.update_value(0)
                shift = int(self.val2 / 8)
                bytes = 4 - shift
                if self.mode == 1:
                    if self.insn1.opcode == m_add:
                        self.insn1.r.nnn.update_value(self.val1 + shift)
                    if self.insn1.opcode == m_sub:
                        self.insn1.r.nnn.update_value(self.val1 - shift)
                elif self.mode == 2:
                    self.insn1.l.a.g = self.val1 + shift
                elif self.mode == 3:
                    before = text_insn(self.insn1)
                    insnn = minsn_t(self.insn1.ea)
                    insnn.opcode = m_add
                    insnn.l = self.insn1.l
                    insnn.r.make_number(shift, 4, self.insn1.ea)
                    insnn.d = insnn.l
                    self.insn1.l.create_from_insn(insnn)
                after = text_insn(self.insn1)
                self.insns1[1].d.change_size(bytes)
                self.insns1[0].l.change_size(bytes)
                self.insns1[0].opcode = m_xds
                self.blk.mark_lists_dirty()
                self.result[hex_addr(self.insn1.ea)] = self.insn1.r.dstr()
                #print_to_log("Optimization 3 changed: [%s] to: [%s]" % (before, after))
        return 0

    def _check_insn2(self, insn):
        # Find the instructions group with SAR
        if insn and insn.opcode == m_sar:
            if collect_insns_up(insn, self.insns2) == 3:
                insn0, insn1, insn2 = self.insns2
                if insn1.opcode == m_cfshr and insn1.l == insn0.l and insn1.r == insn0.r:
                    if insn2.opcode == m_mov and insn2.l.is_constant() and insn2.d == insn0.r:
                        self.val2 = insn2.l.unsigned_value()
                        if self.val2 in (16, 24):
                            self.op = insn0.l
                            return True

    def _check_insn1(self, insn):
        # Now check uppper instructions in the block
        while insn:
            # print("_check_insn1: %s" % text_insn(insn))
            if self.analize_upper_insns(insn, self.insns1):
                return True
            elif self.is_op_modified_here(self.op, self.insns1):
                return False
            elif len(self.insns1) > 0:
                insn = self.insns1[-1].prev
            else:
                return False

    def analize_upper_insns(self, insn, lst):
        len = collect_insns_up(insn, lst)
        if len >= 3:
            if len == 3:
                insn0, insn1, insn2 = self.insns1
            else:
                insn0, insn1, insn2, insn3, *other = self.insns1
            if insn0.opcode == m_mov and insn0.d == self.op:
                # print_insns(self.insns1)
                # print("len(self.insns1) = %d" % len(self.insns1))
                if insn1.opcode == m_ldx and insn1.d == insn0.l:
                    if insn2.d == insn1.r:
                        if is_mcode_addsub(insn2.opcode) and insn2.l == insn2.d and insn2.r.is_constant():
                            # if insn2.opcode == m_add and insn2.l == insn1.r and insn2.l == insn2.d and insn2.r.is_constant():
                            # if insn2.opcode == m_add:
                            self.val1 = insn2.r.signed_value()
                            # if insn2.opcode == m_sub:
                            #    self.val1 = -insn2.r.signed_value()
                            self.mode = 1
                            self.insn1 = insn2
                            return True
                        elif insn2.opcode == m_mov and insn2.l.is_glbaddr():
                            self.val1 = insn2.l.a.g
                            self.mode = 2
                            self.insn1 = insn2
                            return True
                        elif insn2.opcode == m_add and insn2.l.is_glbaddr():
                            self.val1 = insn2.l.a.g
                            self.mode = 2
                            self.insn1 = insn2
                            return True
                    elif len > 3 and is_insn_mov_ds_seg(insn2) and insn3 and insn3.opcode == m_mov and insn3.d == insn1.r:
                        self.mode = 3
                        self.insn1 = insn3
                        return True
        return False

    def is_op_modified_here(self, op, insns):
        for insn in insns:
            if insn.d == op:
                return True
        return False

    def ensure_prev_insn(self, insn):
        """
        Get previous insn from previous block if needed
        """
        if insn is None and (blk := self.blk.prevb):
            prev_insn = blk.tail
            if prev_insn.opcode != m_goto:
                return blk.tail
        return insn
