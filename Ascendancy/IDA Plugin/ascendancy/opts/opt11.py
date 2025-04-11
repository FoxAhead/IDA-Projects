"""
summary: Optimization 11

description:

    Fix ADD and SUB to EAX to absolute offset to temporary kreg kr00

    Change this:
1. 1 add    eax.4, #0xBE.4, eax.4{1}              ; 00015EE5
1. 2 call   $__wcpp_2_ctor_array__ <fast:"void *array" eax.4{1},"unsigned int count" #0x64.4,"rt_type_sig_clss *sig" &($stru_959D8).4>.0 ; 00015EEA
1. 3 add    eax.4{1}, #0x4B0.4, eax.4{2}          ; 00015EF9
1. 4 call   $__wcpp_2_ctor_array__ <fast:"void *array" eax.4{2},"unsigned int count" #0x64.4,"rt_type_sig_clss *sig" &($stru_95A3C).4>.0 ; 00015EFE
1. 5 add    eax.4{2}, #0xFA0.4, eax.4{3}          ; 00015F0D
1. 6 call   $__wcpp_2_ctor_array__ <fast:"void *array" eax.4{3},"unsigned int count" #0x64.4,"rt_type_sig_clss *sig" &($stru_959D8).4>.0 ; 00015F12
1. 7 add    eax.4{3}, #0x7FC.4, eax.4{4}          ; 00015F17
1. 8 stx    #0.4, ds.2{5}, eax.4{4}               ; 00015F1C
1. 9 add    eax.4{4}, #0x14.4, eax.4{6}           ; 00015F22
1.10 stx    #0.4, ds.2{5}, (eax.4{6}-#0x10.4)     ; 00015F25
1.11 stx    #0.4, ds.2{5}, (eax.4{6}-#0xC.4)      ; 00015F2C
1.12 stx    #0.4, ds.2{5}, (eax.4{6}+#4.4)        ; 00015F33
1.13 stx    #0.4, ds.2{5}, (eax.4{6}+#8.4)        ; 00015F3A
1.14 stx    #0.4, ds.2{5}, eax.4{6}               ; 00015F41
    to:
1. 1 call   $__wcpp_2_ctor_array__ <fast:"void *array" (eax.4+#0xBE.4),"unsigned int count" #0x64.4,"rt_type_sig_clss *sig" &($stru_959D8).4>.0 ; 00015EEA
1. 2 call   $__wcpp_2_ctor_array__ <fast:"void *array" (eax.4+#0x56E.4),"unsigned int count" #0x64.4,"rt_type_sig_clss *sig" &($stru_95A3C).4>.0 ; 00015EFE
1. 3 call   $__wcpp_2_ctor_array__ <fast:"void *array" (eax.4+#0x150E.4),"unsigned int count" #0x64.4,"rt_type_sig_clss *sig" &($stru_959D8).4>.0 ; 00015F12
1. 4 stx    #0.4, ds.2{5}, (eax.4+#0x1D0A.4)      ; 00015F1C
1. 5 stx    #0.4, ds.2{5}, (eax.4+#0x1D0E.4)      ; 00015F25
1. 6 stx    #0.4, ds.2{5}, (eax.4+#0x1D12.4)      ; 00015F2C
1. 7 stx    #0.4, ds.2{5}, (eax.4+#0x1D22.4)      ; 00015F33
1. 8 stx    #0.4, ds.2{5}, (eax.4+#0x1D26.4)      ; 00015F3A
1. 9 stx    #0.4, ds.2{5}, (eax.4+#0x1D1E.4)      ; 00015F41

    etc...

    Some functions need to be set to return void and __spoils<>

    Test:
        1DE64
        15ED4

        48B40
        1B4F0
        16120 - Do not optimize inside loop
        46CAC - Do not optimize inside loop
        54448 - TODO - optimize before loop 00054554

"""
from ascendancy.opts import GlbOpt
from ascendancy.utils import *


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(11)

    def _init(self):
        pass

    def _run(self):
        for reg in [mr_first, 12]:
            self.run_with_reg(reg)

    def run_with_reg(self, reg):
        self.mba.for_all_topinsns(vstr := Visitor11a(reg))
        for def_block in vstr.def_blocks:
            if def_block["uses"] > 0:
                # print_mba(mba)
                print_to_log("Optimization 11 start from %.8X (reg=%d):" % (def_block["ea"], reg))
                for addsub in def_block["addsubs"]:
                    blk = addsub["blk"]
                    insn = addsub["insn"]
                    off = addsub["off"]
                    ea = insn.ea
                    print_to_log("  %.2d  make_nop (off=0x%X): %s:" % (reg, off, text_insn(insn)))
                    blk.make_nop(insn)
                    # if prev_insn := insn.prev:  # Trying to fix combinable here (opt1)
                    #    prev_insn.clr_combinable()
                    self.mark_dirty(blk)
                    insnn = minsn_t(ea)
                    insnn.opcode = m_add
                    insnn.l.make_reg(reg, 4)
                    insnn.r.make_number(off, 4)
                    insnn.d.make_reg(reg, 4)
                    for op in addsub["useops"]:
                        insnn.ea = op["topins"].ea
                        print_to_log("  %.2d    create_from_insn: %s:" % (reg, text_insn(insnn)))
                        op["op"].create_from_insn(insnn)
                        self.mark_dirty(blk)


def is_reg_defined_here(blk, ml, insn):
    # _def = blk.build_def_list(insn, MAY_ACCESS | FULL_XDSU)
    _def = blk.build_def_list(insn, MUST_ACCESS)
    return _def.includes(ml)


def get_reg_addsub_off(insn, reg):
    # print("get_reg_addsub_off %d" % reg)
    if insn.opcode in [m_add, m_sub] and insn.l.is_reg(reg, 4) and insn.r.t == mop_n and insn.d.is_reg(reg, 4):
        sign = 1 if insn.opcode == m_add else -1
        return sign * insn.r.unsigned_value()
    else:
        return 0


class Visitor11a(minsn_visitor_t):

    def __init__(self, reg):
        minsn_visitor_t.__init__(self)
        self.reg = reg
        self.insn_def = None  # First definition
        self.off = 0
        self.ul_reg = mlist_t(reg, 4)
        self.def_blocks = []
        self.inside_loop = False

    def visit_minsn(self):
        # self.inside_loop = bool(is_inside_loop(self.mba, self.blk))
        self.inside_loop = LoopManager.serial_in_cycles(self.blk.serial)
        insn = self.curins
        # print("curins = %s, inside_loop = %s" % (text_insn(self.curins), self.inside_loop))
        if not self.insn_def and not self.inside_loop:
            if is_reg_defined_here(self.blk, self.ul_reg, insn):
                # print("First def: %.8X: %s" % (insn.ea, insn.dstr()))
                self.insn_def = insn
                self.off = 0
                self.def_blocks.append({"ea": insn.ea, "uses": 0, "addsubs": []})
        if (off := get_reg_addsub_off(insn, self.reg)) != 0:
            if not self.inside_loop:
                self.off = self.off + off
                # print("  Offset eax: %.8X: %X" % (insn.ea, self.off))
                self.def_blocks[-1]["addsubs"].append({"blk": self.blk, "insn": insn, "off": self.off, "useops": []})
        elif self.insn_def and len(self.def_blocks[-1]["addsubs"]) > 0:
            if not self.inside_loop:
                # print("    Search uses: %.8X: %s" % (insn.ea, insn.dstr()))
                self.blk.for_all_uses(self.ul_reg, insn, insn.next, vstr_uses := Visitor11b())
                for op in vstr_uses.ops:
                    # print("      Use: %s" % op["op"].dstr())
                    self.def_blocks[-1]["addsubs"][-1]["useops"].append(op)
                    self.def_blocks[-1]["uses"] = self.def_blocks[-1]["uses"] + 1
            if (insn != self.insn_def) and is_reg_defined_here(self.blk, self.ul_reg, insn):
                self.insn_def = None
        return 0


class Visitor11b(mlist_mop_visitor_t):

    def __init__(self):
        mlist_mop_visitor_t.__init__(self)
        self.ops = []

    def visit_mop(self, op):
        if op.t == mop_r and op.size == 4:
            self.ops.append({"op": op, "topins": self.topins})
        return 0
