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
    3F3F8 - Had to build simple graph with preds for searching multiple patterns 1
    4E758 - Consider goto block number

"""

from ascendancy.utils import *


def run(mba):
    if is_func_lib(mba.entry_ea):
        return 0
    dpreds = build_simple_preds(mba)
    mba.for_all_topinsns(vstr := Visitor3b(dpreds))
    if vstr.result:
        print_to_log("Optimization 3 (SAR 10h; SAR 18h -> Word; Byte): %s" % vstr.result)


class Visitor3b(minsn_visitor_t):

    def __init__(self, dpreds):
        super().__init__()
        self.dpreds = dpreds
        self.p1_infos = []  # Pattern 1 infos
        self.p2_info = None  # Pattern 2 info
        self.result = {}

    def visit_minsn(self):
        if self._find_pattern2(self.curins):
            # self._debug_print_p2()
            if self._find_pattern1(self.p2_info.insns[-1].prev):
                # self._debug_print_p1()
                self.p2_info.insns[2].l.nnn.update_value(0)
                shift = int(self.p2_info.val / 8)
                bytes = 4 - shift
                for p1_info in self.p1_infos:
                    if p1_info.variant == 1:
                        if p1_info.insn.opcode == m_add:
                            p1_info.insn.r.nnn.update_value(p1_info.val + shift)
                        if p1_info.insn.opcode == m_sub:
                            p1_info.insn.r.nnn.update_value(p1_info.val - shift)
                    elif p1_info.variant == 2:
                        p1_info.insn.l.a.g = p1_info.val + shift
                    elif p1_info.variant == 3:
                        insnn = minsn_t(p1_info.insn.ea)
                        insnn.opcode = m_add
                        insnn.l = p1_info.insn.l
                        insnn.r.make_number(shift, 4, p1_info.insn.ea)
                        insnn.d = insnn.l
                        p1_info.insn.l.create_from_insn(insnn)
                    p1_info.insns[1].d.change_size(bytes)
                    p1_info.insns[0].l.change_size(bytes)
                    p1_info.insns[0].opcode = m_xds
                    p1_info.blk.mark_lists_dirty()
                    self.result[hex_addr(p1_info.insn.ea)] = p1_info.insn.r.dstr()
                #print_to_log("Optimization 3 changed: [%s] to: [%s]" % (before, after))
        return 0

    def _find_pattern2(self, insn):
        # Find the instructions group with SAR (pattern 2)
        # insn2: 1.31 mov    #0x18.1, t1.1                         ; 0003F415 d=t1.1
        # insn1: 1.32 cfshr  edi.4, t1.1, cf.1                     ; 0003F415 u=edi.4, t1.1   d=cf.1
        # insn0: 1.33 sar    edi.4, t1.1, edi.4                    ; 0003F415 u=edi.4, t1.1   d=edi.4
        self.p2_info = PatternInfo()
        if insn and insn.opcode == m_sar:
            if collect_insns_up(insn, self.p2_info.insns) == 3:
                insn0, insn1, insn2 = self.p2_info.insns
                if insn1.opcode == m_cfshr and insn1.l == insn0.l and insn1.r == insn0.r:
                    if insn2.opcode == m_mov and insn2.l.is_constant() and insn2.d == insn0.r:
                        val = insn2.l.unsigned_value()
                        if val in (16, 24):
                            self.p2_info.blk = self.blk
                            self.p2_info.op = insn0.l
                            self.p2_info.val = val
                            return True

    def _find_pattern1(self, insn):
        self.p1_infos.clear()
        self._find_pattern1_recursive(self.blk, insn, set())
        return bool(self.p1_infos)

    def _find_pattern1_recursive(self, blk, insn, visited):
        if blk.serial in visited:
            return False
        visited.add(blk.serial)
        # Now check uppper instructions in the block
        p1_info = PatternInfo()
        while insn:
            if self.analize_upper_insns(insn, p1_info):
                p1_info.blk = blk
                self.p1_infos.append(p1_info)
                return True
            elif self.is_op_modified_here(self.p2_info.op, p1_info.insns):
                return False
            elif len(p1_info.insns) > 0:
                insn = p1_info.insns[-1].prev
            else:
                return False
        for prev_blk_serial in self.dpreds[blk.serial]:
            prev_blk = self.mba.get_mblock(prev_blk_serial)
            self._find_pattern1_recursive(prev_blk, prev_blk.tail, visited)

    # def _check_insn1(self, insn):
    #     # Now check uppper instructions in the block
    #     while insn:
    #         # print("_check_insn1: %s" % text_insn(insn))
    #         if self.analize_upper_insns(insn, self.insns1):
    #             return True
    #         elif self.is_op_modified_here(self.op, self.insns1):
    #             return False
    #         elif len(self.insns1) > 0:
    #             insn = self.insns1[-1].prev
    #         else:
    #             return False

    def analize_upper_insns(self, insn, p1_info):
        len = collect_insns_up(insn, p1_info.insns)
        if len >= 3:
            if len == 3:
                insn0, insn1, insn2 = p1_info.insns
            else:
                insn0, insn1, insn2, insn3, *other = p1_info.insns
            if insn0.opcode == m_mov and insn0.d == self.p2_info.op:
                # print_insns(self.insns1)
                # print("len(self.insns1) = %d" % len(self.insns1))
                if insn1.opcode == m_ldx and insn1.d == insn0.l:
                    if insn2.d == insn1.r:
                        if is_mcode_addsub(insn2.opcode) and insn2.l == insn2.d and insn2.r.is_constant():
                            p1_info.val = insn2.r.signed_value()
                            p1_info.variant = 1
                            p1_info.insn = insn2
                            return True
                        elif insn2.opcode == m_mov and insn2.l.is_glbaddr():
                            p1_info.val = insn2.l.a.g
                            p1_info.variant = 2
                            p1_info.insn = insn2
                            return True
                        elif insn2.opcode == m_add and insn2.l.is_glbaddr():
                            p1_info.val = insn2.l.a.g
                            p1_info.variant = 2
                            p1_info.insn = insn2
                            return True
                    elif len > 3 and is_insn_mov_ds_seg(insn2) and insn3 and insn3.opcode == m_mov and insn3.d == insn1.r:
                        p1_info.variant = 3
                        p1_info.insn = insn3
                        return True
        return False

    def is_op_modified_here(self, op, insns):
        for insn in insns:
            if insn.d == op:
                return True
        return False

    # def ensure_prev_insn(self, insn):
    #     """
    #     Get previous insn from previous block if needed
    #     """
    #     if insn is None and (blk := self.blk.prevb):
    #         prev_insn = blk.tail
    #         if prev_insn.opcode != m_goto:
    #             return blk.tail
    #     return insn

    def _debug_print_p2(self):
        print("found pattern 2: %s; val=%d" % (text_insn(self.p2_info.insns[0], self.p2_info.blk), self.p2_info.val))

    def _debug_print_p1(self):
        print("found patterns 1:")
        for p1_info in self.p1_infos:
            print("  %s; variant=%d; val=%d" % (text_insn(p1_info.insns[0], p1_info.blk), p1_info.variant, p1_info.val))


def build_simple_preds(mba):
    dea = {}
    d = {}
    for blk in all_blocks_in_mba(mba):
        d[blk.serial] = []
        if not (blk.flags & MBL_FAKE):
            dea[blk.start] = blk.serial
    for blk in all_blocks_in_mba(mba):
        if (insn_j := blk.tail) and (m_jcnd <= insn_j.opcode <= m_goto):
            if is_mcode_jcond(insn_j.opcode):
                if insn_j.d.g in dea:
                    d[dea[insn_j.d.g]].append(blk.serial)
                if blk.nextb:
                    d[blk.nextb.serial].append(blk.serial)
            elif insn_j.opcode == m_goto:
                if insn_j.l.t == mop_v:
                    if insn_j.l.g in dea:
                        d[dea[insn_j.l.g]].append(blk.serial)
                    elif blk.nextb:
                        d[blk.nextb.serial].append(blk.serial)
                elif insn_j.l.t == mop_b:
                    d[insn_j.l.b].append(blk.serial)
            elif insn_j.opcode == m_ijmp:
                d[mba.qty - 1].append(blk.serial)
            elif insn_j.opcode == m_jtbl:
                for t in list(insn_j.r.c.targets):
                    d[t].append(blk.serial)
        elif blk.nextb:
            if insn := blk.tail:
                if insn.opcode == m_call and insn.l.t == mop_v:
                    if insn.is_noret_call():
                        continue
            d[blk.nextb.serial].append(blk.serial)
    return d


@dataclass
class PatternInfo:
    blk: mblock_t = None
    insns: List[minsn_t] = field(default_factory=list)
    variant: int = 0
    op: mop_t = None
    val: int = 0
    insn: minsn_t = None
