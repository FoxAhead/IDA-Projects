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
        16331 - Variant 2
        46CF0 - Variant 3 (other counter in condition jump),
        46EDE - Complex nested loops (3 levels)
        1AE54
        2106C - Nested loops
        5A294 - Try to fix end condition
        1E150 -
        3EBDC - Was problem with stack variable
        15E1C - Nested loops - Vars initializations should be placed in individual subentry block, not in the main entry
        46FA2 - TODO - May be not all adds should be converted. v33 += 0x1E stands for 30 degrees, not offset
        45958 - Error if optimizing ADD 1 - Don't optimize here
        35C38 - The counter is used after the loop
        434E4 - Error if using recursive block traversal

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
        self.def_insns = {}  # [entry_blk.serial, def_insn]
        self.loops = {}
        self.visited_blocks = set()

    def _run(self):
        self.iterate_groups()
        if self.err_code == MERR_OK:
            self.optimize_jumps()
        # print_mba(self.mba)

    def optimize_jumps(self):
        self.mba.for_all_topinsns(vstr := Visitor10b())
        self.err_code = vstr.err_code

    def iterate_groups(self):
        for group in LoopManager.all_groups():
            if self.group_needs_optimization(group):
                self.optimize_group(group)
                self.try_optimize_end_condition(group)
                # print("group_needs_optimization2 %s" % group.title())

    def group_needs_optimization(self, group: LoopsGroup):
        # Looking at the valid end-block
        if add_blk := unsingle_goto_block(self.mba, group.end_block(self.mba)):
            # Add op should be added once in the end-block
            if add_insn := find_first_single_add_var_insn_in_block(add_blk):
                # Add op should be defined (actually added) once in the whole group
                if get_number_of_op_definitions_in_blocks(add_insn.l, group.all_loops_blocks(self.mba)) == 1:
                    # Add op should be defined (set initial value) once in the entry-block or entry-block is the first (then assume op is function argument)
                    for entry_block in group.entry_blocks(self.mba, True):
                        if (def_insn := find_single_def_op_insn_in_block(entry_block, add_insn.l)) or (entry_block.serial == 1 and entry_block.type == BLT_1WAY):
                            self.def_insns[entry_block.serial] = def_insn
                        else:
                            return False
                    self.add_blk = add_blk
                    self.add_insn = add_insn
                    self.add_op = mop_t(add_insn.l)  # Make a copy of the operand because it will be NOPed
                    self.mult = add_insn.r.unsigned_value()
                    return True
        return False

    def optimize_group(self, group: LoopsGroup):
        # t1 = time.time()
        self.print_to_log("  Group: %s %s" % (group.title(), group.all_serials))
        self.print_to_log("    ADD   : %s" % text_insn(self.add_insn, self.add_blk))
        size = self.add_op.size
        self.kreg0 = self.mba.alloc_kreg(size)
        self.kregc = self.mba.alloc_kreg(4)
        # Insert into entry block before loop
        for entry_blk in group.entry_blocks(self.mba, True):
            after_insn = find_last_blk_insn_not_jump(entry_blk)
            ea = after_insn.ea if after_insn else entry_blk.tail.ea
            # Insert kregc = 0
            insnn = InsnBuilder(ea, m_mov).n(0).r(self.kregc).insn()
            entry_blk.insert_into_block(insnn, after_insn)
            self.print_to_log("    Insert: %s" % text_insn(insnn, entry_blk))
            # Insert kreg0 = add_reg into entry block
            after_insn = self.def_insns[entry_blk.serial]
            if self.add_op.t == mop_r:
                insnn = InsnBuilder(ea, m_mov, size).r(self.add_op.r).r(self.kreg0).insn()
            else:
                insnn = InsnBuilder(ea, m_mov, size).S(self.mba, self.add_op.s.off).r(self.kreg0).insn()
            entry_blk.insert_into_block(insnn, after_insn)
            self.print_to_log("    Insert: %s" % text_insn(insnn, entry_blk))
            self.mark_dirty(entry_blk)
        # Replace with new counter in all uses inside loops group
        # self.visited_blocks.clear()
        # self.optimize_block_recursive(group, self.add_blk)
        #for blk in group.all_loops_blocks(self.mba):
        for blk in self.get_blocks_for_traversal(group):
            self.optimize_block(blk, blk not in group)
        # Now add kregc = kregc + 1 to the end of the block
        blk = self.add_blk
        after_insn = find_last_blk_insn_not_jump(blk)
        insnn = InsnBuilder(after_insn.ea, m_add).r(self.kregc).n(1).r(self.kregc).insn()
        blk.insert_into_block(insnn, after_insn)
        self.print_to_log("    Move  : %s to %s" % (hex_addr(self.add_insn.ea), text_insn(insnn, blk)))
        # And erase add_insn
        blk.make_nop(self.add_insn)
        self.mark_dirty(blk)
        # print("optimize_group = %.3f" % (time.time() - t1))

    def get_blocks_for_traversal(self, group):
        blocks = []
        # Take all group blocks and their succesors that lead to exit
        for blk in group.all_loops_blocks(self.mba):
            blocks.append(blk)
            for succ in list(blk.succset):
                if succ not in group:
                    succ_blk = self.mba.get_mblock(succ)
                    if block_is_exit(self.mba, succ_blk):
                        #print("block_is_exit %d" % succ_blk.serial)
                        blocks.append(succ_blk)
        return blocks

    def optimize_block_recursive(self, group, blk):
        if blk.serial in self.visited_blocks or blk.serial in group.entries:
            return
        self.visited_blocks.add(blk.serial)
        op_was_redefined = self.optimize_block(blk)
        # Stop traversal if op was redefined
        if op_was_redefined:
            return
        for succ in list(blk.succset):
            succ_block = self.mba.get_mblock(succ)
            self.optimize_block_recursive(group, succ_block)

    def optimize_block(self, blk, check_redef=True):
        after_add = False
        blk_changed = False
        op_was_redefined = False
        for insn in all_insns_in_block(blk):
            #print("optimize_block", text_insn(insn, blk))
            if blk.serial == self.add_blk.serial and insn.equal_insns(self.add_insn, EQ_CMPDEST) and insn.ea == self.add_insn.ea:
                after_add = True
            else:
                vstr = find_op_uses_in_insn(blk, insn, self.add_op, VisitorSimpleSearchUses(blk, self.add_op.size, {mop_r, mop_S}))
                for var_use in vstr.uses:
                    # mult * kregc
                    insnn1 = InsnBuilder(insn.ea, m_mul).n(self.mult).r(self.kregc).insn()
                    if not after_add or (insn.ea == blk.tail.ea and is_insn_j(insn)):
                        insnn2 = insnn1
                    else:
                        # Because we are "moving" addition towards tail of the end-block,
                        # we should compensate usage with +mult addition in all overtaken instruction
                        # mult * kregc + mult
                        insnn2 = InsnBuilder(insn.ea, m_add).i(insnn1).n(self.mult).insn()
                    # kreg0 + insnn2
                    insnn3 = InsnBuilder(insn.ea, m_add).r(self.kreg0).i(insnn2).insn()
                    self.print_to_log("    Change: %s" % text_insn(insn, blk))
                    var_use.op.create_from_insn(insnn3)
                    blk_changed = True
            # Check if op is redefined here
            if check_redef and is_op_defined_in_insn(blk, self.add_op, insn):
                op_was_redefined = True
                # Don't go futher
                break
        if blk_changed:
            self.mark_dirty(blk)
        return op_was_redefined

    def try_optimize_end_condition(self, group: LoopsGroup):
        if end_blk := unsingle_goto_block(self.mba, group.end_block(self.mba)):
            j_insn = end_blk.tail
            # If tail insn of end-block is jcond and r-operand is var
            if is_insn_j(j_insn) and j_insn.r.t in {mop_r, mop_S}:
                insns = []
                # Then look at entry block
                for entry_blk in group.entry_blocks(self.mba, True):
                    insns.clear()
                    for insn in all_insns_in_block(entry_blk):
                        # And search ADD instruction with destination of r-operand
                        if insn.opcode == m_add and insn.l.t == mop_r and insn.d == j_insn.r:
                            # Preceded with MOV instruction
                            if (prev_insn := insn.prev):
                                if (prev_insn := prev_insn.prev) and prev_insn.opcode == m_mov and prev_insn.l.is_reg(insn.l.r):
                                    if self.add_op.t == mop_r and prev_insn.d.is_reg(self.add_op.r):
                                        insns.append(insn)
                    if len(insns) != 1:
                        return
                if len(insns) == 1:
                    insn = insns[0]
                    size = insn.l.size
                    insnn = minsn_t(insn)
                    insnn.l.make_reg(self.kreg0, size)
                    j_insn.r.create_from_insn(insnn)
                    self.print_to_log("  Optimize end conditions: %s" % text_insn(j_insn))
                    self.mark_dirty(end_blk)


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
        if insn_is_good_add_var(insn):
            d.setdefault(var_as_key(insn.l), []).append(insn)
    for var, insns in d.items():
        if len(insns) == 1:
            return insns[0]


def find_def_op_insns_in_block(blk, op):
    """
    Find insns with op definitions in the block
    """
    insns = []
    for insn in all_insns_in_block(blk):
        if is_op_defined_in_insn(blk, op, insn):
            insns.append(insn)
    return insns


def find_single_def_op_insn_in_block(blk, op):
    """
    Find insns with op definitions in the block
    Return insn if there is only one
    """
    if len(insns := find_def_op_insns_in_block(blk, op)) == 1:
        return insns[0]


def insn_is_good_add_var(insn):
    if insn_is_add_var(insn):
        if insn.r.unsigned_value() > 1:
            return True
        elif not insn.l.is_kreg() and insn.l.size == 4:
            return True
    return False


