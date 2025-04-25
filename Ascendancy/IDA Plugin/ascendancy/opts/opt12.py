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
        1F0B3
        1F10E
        466FC

"""
from ascendancy.opts import GlbOpt
from ascendancy.utils import *


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(12, "Move ADDs down inside block")

    def _init(self):
        self.add_blk = None
        self.add_insns = []
        self.mult = 0
        self.loops = {}

    def _run(self):
        self.iterate_blocks()

    def iterate_blocks(self):
        blk = self.mba.blocks
        while blk:
            if self.block_needs_optimization(blk):
                # print("block_needs_optimization %d" % blk.serial)
                # for insn in self.add_insns:
                #    print(text_insn(insn))
                self.optimize_block(blk)
            blk = blk.nextb

    def block_needs_optimization(self, blk):
        # print("block_needs_optimization? %d" % blk.serial)
        d = {}
        self.add_insns.clear()
        insn = blk.head
        while insn:
            if insn_is_add_var(insn, True) and insn.l.size == 4:
                key = var_as_key(insn.l)
                d.setdefault(key, []).append(insn)
            insn = insn.next
        for key, insns in d.items():
            if len(insns) == 1:
                add_insn = insns[0]
                defs = get_number_of_definitions(add_insn.l, [blk])
                if defs == 1:
                    self.add_insns.append(add_insn)
        return len(self.add_insns) > 0

    def optimize_block(self, blk):
        # print_blk(blk)
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
                        insnn = InsnBuilder(insn.ea, m_add, size).v(self.mba, add_op).n(mult).insn()
                        # if add_op.t == mop_r:
                        #     insnn = InsnBuilder(insn.ea, m_add, size).r(add_op.r).n(mult).insn()
                        # else:
                        #     insnn = InsnBuilder(insn.ea, m_add, size).S(self.mba, add_op.s.off).n(mult).insn()
                        use["op"].create_from_insn(insnn)
                        changed = True
                    if changed:
                        self.print_to_log("  Change: %s" % (text_insn(insn, blk)))
                        were_uses = True
                        after_insn = insn
                        self.mark_dirty(blk)
                insn = insn.next
            if were_uses:
                add_insns.append((add_insn, after_insn))
        for add_insn in self.add_insns:
            after_insn = find_last_blk_insn_not_jump(blk)
            if add_insn.ea != after_insn.ea:
                insnn = minsn_t(add_insn)
                insnn.ea = after_insn.ea
                self.print_to_log("  Moved : %s to %s" % (hex_addr(add_insn.ea), text_insn(insnn, blk)))
                # print_to_log("  Insert: %s" % text_insn(insnn, blk))
                blk.insert_into_block(insnn, after_insn)
                # print_to_log("  NOP:    %s" % text_insn(add_insn, blk))
                blk.make_nop(add_insn)
                self.mark_dirty(blk)


def insn_is_add_reg(insn):
    return insn.opcode == m_add and insn.l.is_reg() and insn.r.t == mop_n and insn.d.is_reg() and insn.l.r == insn.d.r and not insn.l.is_kreg()


class Visitor12(mlist_mop_visitor_t):

    def __init__(self):
        mlist_mop_visitor_t.__init__(self)
        self.uses = []

    def visit_mop(self, op):
        if op.t == mop_r and op.size == 4:
            self.uses.append({"op": op, "topins": self.topins})
        return 0


def get_number_of_definitions(op, blocks):
    definitions = 0
    for blk in blocks:
        insn = blk.head
        while insn:
            if is_op_defined_here(blk, op, insn):
                definitions = definitions + 1
            insn = insn.next
    return definitions


def is_op_defined_here(blk, op, insn):
    ml = mlist_t()
    blk.append_def_list(ml, op, MUST_ACCESS)
    _def = blk.build_def_list(insn, MUST_ACCESS)
    return _def.includes(ml)
