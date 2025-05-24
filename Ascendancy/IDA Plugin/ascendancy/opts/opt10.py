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
        12AE4 - The counter is used after the loop
        434E4 - Error if using recursive block traversal
        17430 - Add op is defined far before entry-block
        12AE4 - Add op is defined before entry-block
        4937C - If first add_op is rejected, process other in this iteration
        40224 - Use recursion and graph.is_redefined_globally() to find earlier definitions
        1B354 - Add_op is used in two subsequent loops without redefenition
        10010 - Don't add exit-assertion if add_op is not used further

"""
import math

from ascendancy.opts import GlbOpt
from ascendancy.utils import *


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(10, "Optimize do while loops")

    def _init(self):
        self.add_insn: minsn_t = None
        self.add_op: mop_t = None
        self.add_blk: mblock_t = None
        self.kreg0: int = None
        self.mult: int = 0
        self.defs = {}  # [entry_blk.serial, def_insn]
        # self.loops = {}
        self.visited_blocks = set()

    def _run(self):
        self.iterate_groups()
        if self.err_code == MERR_OK:
            self.optimize_jumps()
        # print_mba(self.mba)

    def optimize_jumps(self):
        self.mba.for_all_topinsns(vstr := VisitorJumpsOptimizator())
        self.err_code = vstr.err_code

    def iterate_groups(self):
        for group in LoopManager.all_groups():
            if self.group_needs_optimization(group):
                # self.debug_print(group)
                self.optimize_group(group)
                self.try_optimize_end_condition(group)
                # print("group_needs_optimization %s" % group.title())

    def group_needs_optimization(self, group: LoopsGroup):
        # Looking at the valid end-block
        if add_blk := unsingle_goto_block(self.mba, group.end_block(self.mba)):
            # Add op should be added once in the end-block
            for add_insn in find_single_add_var_insns_in_block(add_blk):
                # Add op should be defined (actually added) once in the whole group
                if get_number_of_op_definitions_in_blocks(add_insn.l, group.all_loops_blocks(self.mba)) == 1:
                    # Add op should be defined (set initial value) once in the entry-block or entry-block is the first (then assume op is function argument)
                    self.defs.clear()
                    if self.find_add_op_initialization_in_entry(group, add_insn.l) or self.find_add_op_initialization_earlier2(group, add_insn.l):
                        # if self.find_add_op_initialization_in_entry(group, add_insn.l):
                        self.add_blk = add_blk
                        self.add_insn = add_insn
                        self.add_op = mop_t(add_insn.l)  # Make a copy of the operand because it will be NOPed
                        self.mult = add_insn.r.unsigned_value()
                        if self.def_and_mult_are_good():
                            # if group.begin == 49 and self.add_op.t == mop_S and self.add_op.s.off == 128:  # and self.add_op.is_reg(8):
                            return True
        return False

    def debug_print(self, group: LoopsGroup):
        print(group.title())
        print("  ADD_OP: %s" % self.add_op.dstr())
        print("  DEFS:")
        for serial, def_insn in self.defs.items():
            print("    %s" % text_insn(def_insn, serial))
        # print("  ADD_BLK: %d" % self.add_blk.serial)
        print("  ADD_INSN: %s" % text_insn(self.add_insn, self.add_blk))
        # print("  MULT: %d" % self.mult)

    def def_and_mult_are_good(self):
        # If mult == 1 and def is add_op = 0, then don't take this add_op for optimization
        all_zero_def = all(insn_is_zero_var(def_insn) for def_insn in self.defs.values())
        return not (all_zero_def and self.mult == 1)

    def find_add_op_initialization_in_entry(self, group, add_op):
        # Look for definition in entry blocks
        for entry_block in group.entry_blocks(self.mba, True):
            if def_insn := find_single_def_op_insn_in_block(entry_block, add_op):
                self.defs[entry_block.serial] = def_insn
            else:
                self.defs.clear()
                return False
        return True

    def find_add_op_initialization_earlier(self, group, add_op):
        # In some cases add_op is initialized earlier than entry block
        if len(group.entries) == 1:  # For simplicity
            for entry_blk in group.entry_blocks(self.mba):
                blk = self.get_single_pred_block(entry_blk)
                while blk:
                    if blk.serial == 0:
                        if is_op_defined_in_block(blk, add_op):
                            self.defs[entry_blk.serial] = None
                            return True
                    else:
                        for insn in all_insns_in_block(blk, backwards=True):
                            if is_op_defined_in_insn(blk, add_op, insn):
                                self.defs[blk.serial] = insn
                                return True
                    blk = self.get_single_pred_block(blk)
        return False

    def find_add_op_initialization_earlier2(self, group, add_op):
        # In some cases add_op is initialized earlier than entry block
        self.defs.clear()
        if len(group.entries) == 1:  # For simplicity
            for entry_blk in group.entry_blocks(self.mba):
                self.visited_blocks.clear()
                self.find_add_op_initialization_earlier_recursive(add_op, entry_blk, entry_blk, entry_blk.tail)
        return len(self.defs) > 0

    def find_add_op_initialization_earlier_recursive(self, add_op, blk, blk_to, insn_to):
        if blk.serial in self.visited_blocks:
            return
        self.visited_blocks.add(blk.serial)
        if blk.serial == 0:
            if is_op_defined_in_block(blk, add_op):
                blk1 = self.mba.get_mblock(1)
                if not is_op_defined_between(self.mba.get_graph(), add_op, blk1, blk_to, blk1.head, insn_to):
                    self.defs[0] = None
                    return
        else:
            for insn in all_insns_in_block(blk, backwards=True):
                if is_op_defined_in_insn(blk, add_op, insn):
                    # print("defined in", text_insn(insn))
                    if insn.next is None or not is_op_defined_between(self.mba.get_graph(), add_op, blk, blk_to, insn.next, insn_to):
                        self.defs[blk.serial] = insn
                        return
        for pred_blk in all_pred_blocks(self.mba, blk):
            self.find_add_op_initialization_earlier_recursive(add_op, pred_blk, blk_to, insn_to)

    def get_single_pred_block(self, blk):
        if blk.npred() == 1 or blk.npred() == 2 and blk.serial in blk.predset:
            for pred_blk in all_pred_blocks(self.mba, blk):
                if pred_blk.serial != blk.serial:
                    return pred_blk

    def optimize_group(self, group: LoopsGroup):
        # t1 = time.time()
        self.print_to_log("  Group: %s %s" % (group.title(), group.all_serials))
        self.print_to_log("    ADD   : %s" % text_insn(self.add_insn, self.add_blk))
        size = self.add_op.size
        self.kreg0 = self.mba.alloc_kreg(size)
        self.kregc = self.mba.alloc_kreg(4)
        # Initialize counter: Insert kregc = 0 into entry block before loop
        for entry_blk in group.entry_blocks(self.mba, True):
            after_insn = find_last_blk_insn_not_jump(entry_blk)
            ea = after_insn.ea if after_insn else entry_blk.tail.ea
            # kregc = 0
            insnn = InsnBuilder(ea, m_mov).n(0).r(self.kregc).insn()
            entry_blk.insert_into_block(insnn, after_insn)
            self.print_to_log("    Insert: %s" % text_insn(insnn, entry_blk))
            self.mark_dirty(entry_blk)
        # Define starting value: Insert kreg0 = add_reg into definition block
        for def_blk_serial, def_insn in self.defs.items():
            self.print_to_log("    DEF   : %s" % text_insn(def_insn, def_blk_serial))
            # print("Definition %s: " % text_insn(def_insn, def_blk_serial))
            if def_blk_serial == 0 or def_blk_serial not in group.entries:
                # Assume that there is a single entry block
                for entry_blk in group.entry_blocks(self.mba):
                    def_blk = entry_blk
                    after_insn = None
                    ea = entry_blk.head.ea
            else:
                def_blk = self.mba.get_mblock(def_blk_serial)
                after_insn = def_insn
                ea = after_insn.ea
            # kreg0 = initial add_op
            insnn = InsnBuilder(ea, m_mov, size).var(self.mba, self.add_op).r(self.kreg0).insn()
            def_blk.insert_into_block(insnn, after_insn)
            self.print_to_log("    Insert: %s" % text_insn(insnn, def_blk))
            self.mark_dirty(def_blk)
        # Add assertions to exits
        self.optimize_exits(group)
        # Replace with new counter in all uses inside loops group
        # self.visited_blocks.clear()
        # self.optimize_block_recursive(group, self.add_blk)
        for blk in group.all_loops_blocks(self.mba):
            # for blk in self.get_blocks_for_traversal(group):
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
        """
            Sometimes the counter is used after the loop
            Try to build blocks list for traversal which include some outer blocks
        """
        blocks = []
        # Take all group blocks and their succesors
        for blk in group.all_loops_blocks(self.mba):
            blocks.append(blk)
            for succ in list(blk.succset):
                if succ not in group:
                    succ_blk = self.mba.get_mblock(succ)
                    # if block_is_exit(self.mba, succ_blk):
                    if succ_blk.type == BLT_1WAY:
                        # print("block_is_exit %d" % succ_blk.serial)
                        blocks.append(succ_blk)
        return blocks

    def optimize_block_recursive(self, group, blk):
        if blk.serial in self.visited_blocks or blk.serial in group.entries:
            return
        self.visited_blocks.add(blk.serial)
        op_was_redefined = self.optimize_block(blk, blk not in group)
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
            # print("optimize_block", text_insn(insn, blk))
            if blk.serial == self.add_blk.serial and insn.equal_insns(self.add_insn, EQ_CMPDEST) and insn.ea == self.add_insn.ea:
                after_add = True
            else:
                vstr = find_op_uses_in_insn(blk, insn, self.add_op)
                for var_use in vstr.uses:
                    insnn = self.build_new_counter_insn(insn.ea, after_add and not (insn.ea == blk.tail.ea and is_insn_j(insn)))
                    self.print_to_log("    Change: %s" % (text_insn(insn, blk)))
                    var_use.op.create_from_insn(insnn)
                    self.print_to_log("    Changed: %s" % (text_insn(insn, blk)))
                    blk_changed = True
            # Check if op is redefined here
            if check_redef and is_op_defined_in_insn(blk, self.add_op, insn):
                op_was_redefined = True
                # Don't go futher
                break
        if blk_changed:
            self.mark_dirty(blk)
        return op_was_redefined

    def optimize_exits(self, group):
        for exit_blk in group.all_exit_blocks(self.mba):
        # exits = set()
        # # Find exits - not cycle blocks after this loops group
        # for blk in group.all_loops_blocks(self.mba):
        #     for succ in list(blk.succset):
        #         # if succ not in group:
        #         if not LoopManager.serial_in_cycles(succ):
        #             exits.add(succ)
        # # print("Exits: ", exits)
        # for serial in exits:
        #     exit_blk = self.mba.get_mblock(serial)
        #     # If it is empty block - ignore it
        #     if exit_blk.head is None:
        #         continue
            # Process if add_op is used further from this block
            if is_op_used_starting_from_this_block(self.mba, self.add_op, exit_blk):
                j_insn = None
                use_j_insn = False
                ea = exit_blk.head.ea
                # Try to get end condition from j_cond
                if exit_blk.npred() == 1:
                    end_blk = self.mba.get_mblock(exit_blk.pred(0))
                    if end_blk.serial == group.end:
                        if is_mcode_jcond(end_blk.tail.opcode):
                            j_insn = end_blk.tail
                            if j_insn.opcode == m_jnz and j_insn.d.b == group.begin and j_insn.l == self.add_op:
                                use_j_insn = True
                            elif j_insn.opcode == m_jz and j_insn.d.b == exit_blk.serial and j_insn.l == self.add_op:
                                use_j_insn = True
                if use_j_insn:
                    # Use end condition
                    insnn = InsnBuilder(ea, m_mov, self.add_op.size).r(mr_none).var(self.mba, self.add_op).insn()
                    insnn.l = mop_t(j_insn.r)
                else:
                    insnn1 = self.build_new_counter_insn(ea, False)
                    insnn = InsnBuilder(ea, m_mov, self.add_op.size).i(insnn1).var(self.mba, self.add_op).insn()
                exit_blk.insert_into_block(insnn, None)
                self.print_to_log("    Exit: %s" % text_insn(insnn, exit_blk))
                self.mark_dirty(exit_blk)

    def build_new_counter_insn(self, ea, compensate):
        if self.mult > 1:
            # mult * kregc
            insnn1 = InsnBuilder(ea, m_mul).n(self.mult).r(self.kregc).insn()
            if not compensate:
                insnn2 = insnn1
            else:
                # Because we are "moving" addition towards tail of the end-block,
                # we should compensate usage with +mult addition in all overtaken instruction
                # mult * kregc + mult
                insnn2 = InsnBuilder(ea, m_add).i(insnn1).n(self.mult).insn()
            # kreg0 + insnn2
            insnn3 = InsnBuilder(ea, m_add).r(self.kreg0).i(insnn2).insn()
        else:
            if not compensate:
                insnn3 = InsnBuilder(ea, m_add).r(self.kreg0).r(self.kregc).insn()
            else:
                insnn2 = InsnBuilder(ea, m_add).r(self.kregc).n(self.mult).insn()
                insnn3 = InsnBuilder(ea, m_add).r(self.kreg0).i(insnn2).insn()
        return insnn3

    def try_optimize_end_condition(self, group: LoopsGroup):
        if end_blk := unsingle_goto_block(self.mba, group.end_block(self.mba)):
            j_insn = end_blk.tail
            # If tail insn of end-block is jcond and r-operand is var
            if is_insn_j(j_insn) and j_insn.r.t in {mop_r, mop_S}:
                variant = self.find_init_of_end_condition(group, j_insn, found_init := FoundInsn())
                # insns = []
                ## Then look at entry block
                # for entry_blk in group.entry_blocks(self.mba, True):
                #    insns.clear()
                #    for insn in all_insns_in_block(entry_blk):
                #        # Variant 1: Search ADD instruction with destination of r-operand
                #        if insn.opcode == m_add and insn.l.t == mop_r and insn.d == j_insn.r:
                #            # Preceded with MOV instruction
                #            if prev_insn := insn.prev:
                #                if (prev_insn := prev_insn.prev) and prev_insn.opcode == m_mov and prev_insn.l.is_reg(insn.l.r):
                #                    if self.add_op.t == mop_r and prev_insn.d.is_reg(self.add_op.r):
                #                        insns.append(insn)
                #    if len(insns) != 1:
                #        return
                if variant == 1:
                    insn = found_init.insn
                    size = insn.l.size
                    insnn = minsn_t(insn)
                    insnn.l.make_reg(self.kreg0, size)
                    j_insn.r.create_from_insn(insnn)
                    self.print_to_log("  Optimize end conditions: %s" % text_insn(j_insn))
                    self.mark_dirty(end_blk)
                elif variant == 2:
                    insn = found_init.insn
                    size = insn.r.size
                    kreg = self.mba.alloc_kreg(size)
                    insnn = InsnBuilder(insn.ea, m_mov, size).r(insn.r.r).r(kreg).insn()
                    found_init.blk.insert_into_block(insnn, found_init.insn)
                    self.mark_dirty(found_init.blk)
                    insnn = minsn_t(insn)
                    insnn.r.make_reg(kreg, size)
                    j_insn.r.create_from_insn(insnn)
                    self.mark_dirty(end_blk)
                    self.print_to_log("  Optimize end conditions (var2): %s" % text_insn(j_insn))

    def find_init_of_end_condition(self, group: LoopsGroup, j_insn: minsn_t, found_insn: "FoundInsn"):
        if len(group.entries) != 1:
            return 0
        d = {}
        variant = 0
        for entry_blk in group.entry_blocks(self.mba, True):
            d.clear()
            for insn in all_insns_in_block(entry_blk):
                # Variant 1: Search ADD instruction with destination of r-operand
                if insn.opcode == m_add and insn.l.t == mop_r and insn.d == j_insn.r:
                    # Preceded with MOV instruction
                    if prev_insn := insn.prev:
                        if (prev_insn := prev_insn.prev) and prev_insn.opcode == m_mov and prev_insn.l.is_reg(insn.l.r):
                            if self.add_op.t == mop_r and prev_insn.d.is_reg(self.add_op.r):
                                d.setdefault(1, []).append(insn)
                # Variant 2: mul    #4.4, eax.4{73}, %var_3C.4
                if insn.opcode == m_mul and insn.l.t == mop_n and insn.r.t == mop_r and insn.d == j_insn.r:
                    d.setdefault(2, []).append(insn)
            if len(d) != 1:
                return 0
            for var, insns in d.items():
                if len(insns) != 1:
                    return 0
                found_insn.blk = entry_blk
                found_insn.insn = insns[0]
                variant = var
        return variant


class VisitorJumpsOptimizator(minsn_visitor_t):

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
        # Variant 1: reg + X < reg + Y
        if insn.l.is_insn(m_add) and insn.r.is_insn(m_add):
            insn1 = insn.l.d
            insn2 = insn.r.d
            if insn1.l.is_reg() and insn2.l.is_reg() and insn1.l.r == insn2.l.r:
                self.j_l = insn1
                self.j_r = insn2
                self.optimization = 1
                return True
        # Variant 2: N1 * var < N2
        elif insn.l.is_insn(m_mul) and insn.l.d.l.t == mop_n and insn.r.t == mop_n:
            self.j_l = insn.l.d
            self.j_r = insn.r
            self.optimization = 2
            return True
        # Variant 3: N1 * var1 < N2 * var2
        elif insn.l.is_insn(m_mul) and insn.r.is_insn(m_mul):
            insn1 = insn.l.d
            insn2 = insn.r.d
            if insn1.l.is_constant() and insn2.l.is_constant():
                self.j_l = insn1
                self.j_r = insn2
                self.optimization = 3
                return True

    def optimize_j_insn(self):
        if self.optimization == 1:
            self.optimize_j_insn1()
        elif self.optimization == 2:
            self.optimize_j_insn2()
        elif self.optimization == 3:
            self.optimize_j_insn3()

    def optimize_j_insn1(self):
        # print("optimize_j_insn1")
        self.j_l.l.make_number(0, 4)
        self.j_r.l.make_number(0, 4)
        print_to_log("Optimization 10 - Optimize jump 1 (%s)" % text_insn(self.curins))
        mark_dirty(self.mba, self.blk)
        # self.blk.mark_lists_dirty()
        self.err_code = MERR_LOOP

    def optimize_j_insn2(self):
        # print("optimize_j_insn2")
        n1 = self.j_l.l.unsigned_value()
        n2 = self.j_r.unsigned_value()
        if n2 % n1 == 0:
            self.j_l.l.make_number(1, 4)
            self.j_r.make_number(n2 // n1, 4)
            print_to_log("Optimization 10 - Optimize jump 2 (%s)" % text_insn(self.curins))
            mark_dirty(self.mba, self.blk)
            # self.blk.mark_lists_dirty()
            self.err_code = MERR_LOOP

    def optimize_j_insn3(self):
        # print("optimize_j_insn3")
        n1 = self.j_l.l.unsigned_value()
        n2 = self.j_r.l.unsigned_value()
        m = math.gcd(n1, n2)
        if m > 1:
            self.j_l.l.make_number(n1 // m, 4)
            self.j_r.l.make_number(n2 // m, 4)
            print_to_log("Optimization 10 - Optimize jump 3 (%s)" % text_insn(self.curins))
            mark_dirty(self.mba, self.blk)
            # self.blk.mark_lists_dirty()
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


def find_single_add_var_insns_in_block(blk):
    """
    Take add instructions that are only one for each var
    """
    d = {}
    for insn in all_insns_in_block(blk):
        if insn_is_good_add_var(insn):
            d.setdefault(var_as_key(insn.l), []).append(insn)
    out_insns = []
    for var, insns in d.items():
        if len(insns) == 1:
            out_insns.append(insns[0])
    return out_insns


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
        # Consider mult=1 only for non kregs with size=4
        elif not insn.l.is_kreg() and insn.l.size == 4:
            return True
    return False


@dataclass
class FoundInsn:
    blk: mblock_t = None
    insn: minsn_t = None


def mark_dirty(mba: mba_t, blk: mblock_t, verify=True):
    blk.mark_lists_dirty()
    blk.make_lists_ready()
    # self.err_code = MERR_LOOP
    if verify:
        try:
            mba.verify(True)
        except RuntimeError as e:
            print("Error in opt%d (blk=%d): %s" % (10, blk.serial, e))
            print_blk(blk)
            print("mustbdef", blk.mustbdef.dstr())
            print("maybdef", blk.maybdef.dstr())
            # print_mba(self.mba)
            raise e


