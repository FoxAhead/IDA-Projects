"""
summary: Optimization 12

description:

    Move ADDs down inside block

10. 0 add    edx.4, #2.4, edx.4{9}                ; 0001F0B3
10. 1 stx    al.1, ds.2{10}, (edx.4{9}-#1.4)      ; 0001F0B6
10. 2 stx    cl.1, ds.2{10}, (edx.4{9}-#2.4)      ; 0001F0B9
10. 3 add    eax.4, #1.4, eax.4                   ; 0001F0BC
10. 4 goto   @9                                   ; 0001F0CA

    After:
10. 0 stx    al.1, ds.2{10}, (edx.4{9} + 2 -#1.4) ; 0001F0B6
10. 1 stx    cl.1, ds.2{10}, (edx.4{9} + 2 -#2.4) ; 0001F0B9
10. 2 add    edx.4, #2.4, edx.4{9}                ; 0001F0B3
10. 3 add    eax.4, #1.4, eax.4                   ; 0001F0BC
10. 4 goto   @9                                   ; 0001F0CA

    Test:
        0001F0B3
        0001F10E

"""
from ascendancy.util import *


def run(mba):
    if is_func_lib(mba.entry_ea):
        return True
    return Fix12(mba).run()


class Fix12(object):

    def __init__(self, mba):
        self.mba = mba
        self.err_code = MERR_OK
        self.add_blk = None
        self.add_insns = []
        self.mult = 0
        self.loops = {}

    def run(self):
        self.iterate_blocks()
        return self.err_code == MERR_OK

    def iterate_blocks(self):
        blk = self.mba.blocks
        while blk:
            #if blk.serial == 10 and self.mba.entry_ea == 0x1F038:
            if self.block_needs_optimization(blk):
                #print("block_needs_optimization %d" % blk.serial)
                self.optimize_block(blk)
            blk = blk.nextb

    def block_needs_optimization(self, blk):
        d = {}
        self.add_insns.clear()
        insn = blk.head
        while insn:
            if insn_is_add_var(insn) and insn.l.size == 4:
                key = var_as_key(insn.l)
                d.setdefault(key, []).append(insn)
            insn = insn.next
        for key, insns in d.items():
            if len(insns) == 1:
                add_insn = insns[0]
                if add_insn.next is None or not blk.is_rhs_redefined(add_insn, add_insn.next, None):
                    self.add_insns.append(add_insn)
        return len(self.add_insns) > 0

    def optimize_block(self, blk):
        #print_blk(blk)
        add_insns = []
        for add_insn in self.add_insns:
            add_op = add_insn.l
            size = add_op.size
            mult = add_insn.r.unsigned_value()
            were_uses = False
            after_insn = None
            insn = add_insn.next
            while insn:
                if not is_insn_j(insn):
                    changed = False
                    ml = mlist_t()
                    blk.append_use_list(ml, add_op, MUST_ACCESS)
                    blk.for_all_uses(ml, insn, insn.next, vstr_uses := Visitor12())
                    for use in vstr_uses.uses:
                        if add_op.t == mop_r:
                            insnn = InsnBuilder(insn.ea, m_add, size).r(add_op.r).n(mult).insn()
                        else:
                            insnn = InsnBuilder(insn.ea, m_add, size).S(self.mba, add_op.s.off).n(mult).insn()
                        use["op"].create_from_insn(insnn)
                        changed = True
                    if changed:
                        print_to_log("Optimization 12: Change: %s" % (text_insn(insn, blk)))
                        were_uses = True
                        after_insn = insn
                        self.err_code = MERR_LOOP
                        blk.mark_lists_dirty()
                insn = insn.next
            if were_uses:
                add_insns.append((add_insn, after_insn))
        for add_insn in self.add_insns:
            after_insn = find_last_blk_insn_not_jump(blk)
            if add_insn.ea != after_insn.ea:
                insnn = minsn_t(add_insn)
                insnn.ea = after_insn.ea
                print_to_log("Optimization 12: Moved: %.8X to %s" % (add_insn.ea, text_insn(insnn, blk)))
                #print_to_log("  Insert: %s" % text_insn(insnn, blk))
                blk.insert_into_block(insnn, after_insn)
                #print_to_log("  NOP:    %s" % text_insn(add_insn, blk))
                blk.make_nop(add_insn)
                blk.mark_lists_dirty()
                self.err_code = MERR_LOOP
        #for add_insn, after_insn in add_insns:
        #    #after_insn = find_last_blk_insn_not_jump(blk)
        #    insnn = minsn_t(add_insn)
        #    insnn.ea = after_insn.ea
        #    print_to_log("  Insert: %s" % text_insn(insnn))
        #    blk.insert_into_block(insnn, after_insn)
        #    print_to_log("  NOP:    %s" % text_insn(add_insn))
        #    blk.make_nop(add_insn)
        #    blk.mark_lists_dirty()
        #    self.err_code = MERR_LOOP
        #print_blk(blk)


def find_single_add_reg_insn_in_block(blk):
    insns = []
    insn = blk.head
    while insn:
        if insn_is_add_reg(insn) and insn.r.unsigned_value() > 1:
            insns.append(insn)
        insn = insn.next
    if len(insns) == 1:
        return insns[0]


def insn_is_add_reg(insn):
    return insn.opcode == m_add and insn.l.is_reg() and insn.r.t == mop_n and insn.d.is_reg() and insn.l.r == insn.d.r and not insn.l.is_kreg()


def is_reg_defined_here(blk, ml, insn):
    # _def = blk.build_def_list(insn, MAY_ACCESS | FULL_XDSU)
    _def = blk.build_def_list(insn, MUST_ACCESS)
    return _def.includes(ml)


class Visitor12(mlist_mop_visitor_t):

    def __init__(self):
        mlist_mop_visitor_t.__init__(self)
        self.uses = []

    def visit_mop(self, op):
        if op.t == mop_r and op.size == 4:
            self.uses.append({"op": op, "topins": self.topins})
        return 0


def is_reg_defined_here(blk, ml, insn):
    # _def = blk.build_def_list(insn, MAY_ACCESS | FULL_XDSU)
    _def = blk.build_def_list(insn, MUST_ACCESS)
    return _def.includes(ml)


def is_op_redefined(op, blk, insn1, insn2):
    # _def = blk.build_def_list(insn, MAY_ACCESS | FULL_XDSU)
    ml = mlist_t()
    blk.append_def_list(ml, op, MUST_ACCESS)
    return blk.is_redefined(ml, insn1, insn2, MUST_ACCESS)


def insn_is_add_var(insn):
    """
    add    var, #0xD.4, var
    """
    return insn.opcode == m_add and insn.r.t == mop_n and insn.l.t in {mop_r, mop_S} and insn.l == insn.d


