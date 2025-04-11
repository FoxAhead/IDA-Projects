"""
summary: Optimization 10

description:

    Optimize simple do while loops

1. 3 add    eax.4{1}, #0x190.4, edx.4{3}          ; 00016142

2. 0 add    eax.4, #4.4, eax.4{4}                 ; 00016152
2. 1 stx    #0.4, ds.2, (eax.4{4}+#0x137A.4)      ; 00016155
2. 2 jnz    eax.4{4}, edx.4{3}, @2                ; 00016161

    into something like:

1.  kreg_00 = 0
1.  kreg_01 = eax

2.  kreg_00 = kreg_00 + 1
2.  stx    #0.4, ds.2, (kreg_01 + kreg_00 * 4 + +#0x137A.4)      ; 00016155
2.  jnz    kreg_00, 0x190 / 4, @2

    Test:
        16161 - Variant 1
        16331 - TODO Variant 2
        46CF0 - TODO Variant 3 (other counter in condition jump),
        46EDE - Complex nested loops
        1AE54
        2106C - Nested loops
        5A294 - Try to fix end condition
        1E150 -
        3EBDC - Was problem with stack variable
        15E1C - TODO Nested loops - Vars initializations should be placed in individual subentry block, not in the main entry

"""

from ascendancy.opts import GlbOpt
from ascendancy.utils import *


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(10, "Optimize do while loops")

    def _init(self):
        self.add_insn = None
        self.add_op = None
        self.add_blk = None
        self.kreg0 = None
        self.mult = 0
        self.loops = {}

    def _run(self):
        self.iterate_groups2()
        #if self.err_code == MERR_OK:
        #    self.optimize_jumps()
        # print_mba(self.mba)

    def optimize_jumps(self):
        self.mba.for_all_topinsns(vstr := Visitor10b())
        self.err_code = vstr.err_code

    def iterate_groups2(self):
        for group in LoopManager.all_groups():
            if self.group_needs_optimization2(group):
                self.optimize_group(group)
                #print("group_needs_optimization2 %s" % group.title())

    def group_needs_optimization2(self, group):
        if add_blk := unsingle_goto_block(group.end_block(self.mba)):
            if add_insn := find_first_single_add_var_insn_in_block(add_blk):
                if def_insn := find_single_def_op_insn_in_block(group.entry_block(self.mba), add_insn.l):
                    self.def_insn = def_insn
                    self.add_blk = add_blk
                    self.add_insn = add_insn
                    self.add_op = add_insn.l
                    self.mult = add_insn.r.unsigned_value()
                    return True
        return False

    def iterate_groups(self):
        for group in LoopManager.groups:
            # print("Group: %s" % group.entry)
            if self.group_needs_optimization(group):
                self.optimize_group(group)
                self.try_optimize_end_condition(group)

    def group_needs_optimization(self, group):
        # t1 = time.time()
        if group.begin is not None and group.end is not None:
            if d := find_single_add_var_insn_in_blocks(group.all_loops_blocks(self.mba)):
                insn = d["insn"]
                blk = d["blk"]
                # if insn.l.t == mop_S:
                #    print("mop_S", insn.l.s.off)
                #    ml = mlist_t()
                #    blk.append_use_list(ml, insn.l, MUST_ACCESS)
                #    print(ml.mem.dstr())
                #    return False
                if group.all_loops_contain_block(blk):
                    # print("  Found add insn (block %d): %s" % (blk.serial, text_insn(insn)))
                    self.add_insn = insn
                    self.add_op = mop_t(insn.l)
                    self.add_blk = blk
                    self.mult = insn.r.unsigned_value()
                    # self.iteration = 1
                    # print("group_needs_optimization = %.3f" % (time.time() - t1))
                    return True
        # print("group_needs_optimization = %.3f" % (time.time() - t1))
        return False

    def optimize_group(self, group):
        # t1 = time.time()
        self.print_to_log("  Group: %s %s" % (group, group.all_serials))
        size = self.add_insn.l.size
        kreg0 = self.mba.alloc_kreg(size)
        self.kreg0 = kreg0
        kregc = self.mba.alloc_kreg(4)
        # Insert into entry block before loop
        entry_blk = group.entry_block(self.mba)
        prev_insn = find_last_blk_insn_not_jump(entry_blk)
        ea = prev_insn.ea if prev_insn else entry_blk.tail.ea
        # Insert kregc = 0
        insnn = InsnBuilder(ea, m_mov).n(0).r(kregc).insn()
        entry_blk.insert_into_block(insnn, prev_insn)
        self.print_to_log("    Insert: %s" % text_insn(insnn, entry_blk))
        # Insert kreg0 = add_reg into entry block
        if self.add_op.t == mop_r:
            insnn = InsnBuilder(ea, m_mov, size).r(self.add_op.r).r(kreg0).insn()
        else:
            insnn = InsnBuilder(ea, m_mov, size).S(self.mba, self.add_op.s.off).r(kreg0).insn()
        entry_blk.insert_into_block(insnn, prev_insn)
        self.print_to_log("    Insert: %s" % text_insn(insnn, entry_blk))
        self.mark_dirty(entry_blk)
        # Replace with new counter in all uses inside loops group
        for blk in group.all_loops_blocks(self.mba):
            after_add = False
            insn = blk.head
            while insn:
                changed = False
                if insn.equal_insns(self.add_insn, 0) and insn.ea == self.add_insn.ea and blk.serial == self.add_blk.serial:
                    after_add = True
                else:
                    ml = mlist_t()
                    blk.append_use_list(ml, self.add_op, MUST_ACCESS)
                    blk.for_all_uses(ml, insn, insn.next, vstr_uses := Visitor10a(size))
                    for op in vstr_uses.ops:
                        # mult * kregc
                        insnn1 = InsnBuilder(insn.ea, m_mul).n(self.mult).r(kregc).insn()
                        if not after_add or (insn.ea == blk.tail.ea and is_insn_j(insn)):
                            insnn2 = insnn1
                        else:
                            # mult * kregc + mult
                            insnn2 = InsnBuilder(insn.ea, m_add).i(insnn1).n(self.mult).insn()
                        # kreg0 + insnn2
                        insnn3 = InsnBuilder(insn.ea, m_add).r(kreg0).i(insnn2).insn()
                        op["op"].create_from_insn(insnn3)
                        changed = True
                if changed:
                    self.print_to_log("    Change: %s" % text_insn(insn, blk))
                    self.mark_dirty(blk)
                insn = insn.next
        # Now add kregc = kregc + 1 to the end of the block
        blk = self.add_blk
        after_insn = find_last_blk_insn_not_jump(blk)
        insnn = InsnBuilder(after_insn.ea, m_add).r(kregc).n(1).r(kregc).insn()
        blk.insert_into_block(insnn, after_insn)
        self.print_to_log("    Move  : %s to %s" % (hex_addr(self.add_insn.ea), text_insn(insnn, blk)))
        # And erase add_insn
        blk.make_nop(self.add_insn)
        self.mark_dirty(blk)
        # print("optimize_group = %.3f" % (time.time() - t1))

    def try_optimize_end_condition(self, group):
        serial = group.end
        blk = self.mba.get_mblock(serial)
        j_insn = blk.tail
        if is_insn_j(j_insn) and j_insn.r.t in {mop_r, mop_S}:
            entry_blk = group.entry_block(self.mba)
            insn = entry_blk.head
            insns = []
            while insn:
                if insn.opcode == m_add and insn.l.t == mop_r and insn.d == j_insn.r:
                    if (prev_insn := insn.prev) and prev_insn.opcode == m_mov and prev_insn.l.is_reg(insn.l.r):
                        if self.add_op.t == mop_r and prev_insn.d.is_reg(self.add_op.r):
                            insns.append(insn)
                insn = insn.next
            if len(insns) == 1:
                insn = insns[0]
                size = insn.l.size
                insnn = minsn_t(insn)
                insnn.l.make_reg(self.kreg0, size)
                j_insn.r.create_from_insn(insnn)
                self.print_to_log("  Optimize end conditions: %s" % text_insn(j_insn))
                self.mark_dirty(blk)


class Visitor10a(mlist_mop_visitor_t):

    def __init__(self, size):
        mlist_mop_visitor_t.__init__(self)
        self.size = size
        self.ops = []

    def visit_mop(self, op):
        if op.t in {mop_r, mop_S} and op.size == self.size:
            self.ops.append({"op": op, "topins": self.topins})
        return 0


class Visitor10b(minsn_visitor_t):

    def __init__(self):
        minsn_visitor_t.__init__(self)
        self.err_code = MERR_OK
        self.j_l = None
        self.j_r = None
        self.optimization = 0

    def visit_minsn(self):
        if is_mcode_jcond(self.curins.opcode):
            if self.check_j_insn_needs_optimization():
                # print("  needs optimization %d" % self.optimization)
                self.optimize_j_insn()
        return 0

    def check_j_insn_needs_optimization(self):
        insn = self.curins
        # print("Check if j_insn needs optimization %s" % text_insn(insn))
        if insn.l.is_insn() and insn.r.is_insn():
            insn1 = insn.l.d
            insn2 = insn.r.d
            if insn1.opcode == m_add and insn2.opcode == m_add:
                if insn1.l.is_reg() and insn2.l.is_reg() and insn1.l.r == insn2.l.r:
                    self.j_l = insn1
                    self.j_r = insn2
                    self.optimization = 1
                    return True
        elif insn.l.is_insn() and insn.l.d.l.t == mop_n and insn.r.t == mop_n:
            self.j_l = insn.l.d
            self.j_r = insn.r
            self.optimization = 2
            return True

    def optimize_j_insn(self):
        if self.optimization == 1:
            self.optimize_j_insn1()
        elif self.optimization == 2:
            self.optimize_j_insn2()

    def optimize_j_insn1(self):
        # print("optimize_j_insn1")
        self.j_l.l.make_number(0, 4)
        self.j_r.l.make_number(0, 4)
        print_to_log("Optimization 10 - Optimize jump 1 (%s)" % text_insn(self.curins))
        self.blk.mark_lists_dirty()
        self.err_code = MERR_LOOP

    def optimize_j_insn2(self):
        # print("optimize_j_insn2")
        n1 = self.j_l.l.unsigned_value()
        n2 = self.j_r.unsigned_value()
        if n2 % n1 == 0:
            self.j_l.l.make_number(1, 4)
            self.j_r.make_number(n2 // n1, 4)
            print_to_log("Optimization 10 - Optimize jump 2 (%s)" % text_insn(self.curins))
            self.blk.mark_lists_dirty()
            self.err_code = MERR_LOOP


def find_single_add_var_insn_in_blocks(blocks):
    d = {}
    for blk in blocks:
        insn = blk.head
        while insn:
            if insn_is_add_var(insn) and insn.r.unsigned_value() > 1:
                var = insn.l.r if insn.l.t == mop_r else insn.l.s.off
                if var not in d:
                    d[var] = []
                d[var].append({"insn": insn, "blk": blk})
            insn = insn.next
    for var, insns in d.items():
        if len(insns) == 1:
            return insns[0]


def find_first_single_add_var_insn_in_block(blk):
    d = {}
    for insn in all_insns_in_block(blk):
        if insn_is_add_var(insn) and insn.r.unsigned_value() > 1:
            d.setdefault(var_as_key(insn.l), []).append(insn)
    for var, insns in d.items():
        if len(insns) == 1:
            return insns[0]


def find_single_def_op_insn_in_block(blk, op):
    insns = []
    for insn in all_insns_in_block(blk):
        if is_op_defined_in_insn(blk, op, insn):
            insns.append(insn)
    if len(insns) == 1:
        return insns[0]
