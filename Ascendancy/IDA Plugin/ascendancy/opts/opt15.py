"""
summary: Optimization 15

description:

    Combine several kreg++ in loops inside on block
    Move zeroes down in entry block
    TODO - need to check that combined regs starts from the same value!

test:

    54048
    46D81
    466FC
    3B5B8 - No optimization here: ops should be of the same size
    4E809 - Was infinite moving zeroes down. Fixed by using fict_ea

"""
from ascendancy.opts.glbopt import GlbOpt
from ascendancy.utils import *


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(15, "Combine var++", True)

    def _init(self):
        self.zero_blks = []
        self.zeroes = {}  # key = var_key, value = insn
        self.adds = {}  # key = block.serial, value = insns[]

    def _run(self):
        self.iterate_groups()

    def iterate_groups(self):
        for group in LoopManager.all_groups():
            self.collect_zeroes(group)
            self.collect_adds(group)
            #self.debug_print_collections(group)
            if self.need_to_combine_adds():
                self.combine_adds(group)
            self.try_to_move_zero_down(group)

    def collect_zeroes(self, group: LoopsGroup):
        self.zero_blks.clear()
        self.zeroes.clear()
        for entry_blk in group.entry_blocks(self.mba):
            if zero_blk := unsingle_goto_block(self.mba, entry_blk):
                self.zero_blks.append(zero_blk)
                zero_insns = []
                for insn in all_insns_in_block(zero_blk):
                    if insn_is_zero_var(insn):
                        zero_insns.append(insn)
                for zero_insn in zero_insns:
                    if get_number_of_op_definitions_in_blocks(zero_insn.d, [zero_blk]) == 1:
                        self.zeroes[var_as_key(zero_insn.d)] = zero_insn

    def collect_adds(self, group: LoopsGroup):
        self.adds.clear()
        # Find all var++ insns
        d = {}
        for blk, insn in group.all_loops_blocks_insns(self.mba):
            # print(blk.serial, text_insn(insn))
            if insn_is_inc_var(insn):
                var_key = var_as_key(insn.l)
                # Must have corresponding zero_insn with the same size
                if var_key in self.zeroes:
                    zero_insn = self.zeroes[var_key]
                    if insn.l.size == zero_insn.d.size:
                        d.setdefault(var_key, []).append((blk.serial, insn))
        # Take only single var++ insns not redefined elsewere in the loops group
        all_group_blocks = list(group.all_loops_blocks(self.mba))
        d2 = {}
        for key, adds in d.items():
            if len(adds) == 1:
                serial, add_insn = adds[0]
                if get_number_of_op_definitions_in_blocks(add_insn.l, all_group_blocks) == 1:
                    d2.setdefault(serial, []).append(add_insn)
        # ADD insns are now grouped by block
        for serial, add_insns in d2.items():
            add_insns_new = []
            # Don't combine regular regs or stack vars. Put only one infront of the list.
            has_regular_var = False
            for add_insn in add_insns:
                if add_insn.l.is_kreg():
                    add_insns_new.append(add_insn)
                elif not has_regular_var:
                    has_regular_var = True
                    add_insns_new.insert(0, add_insn)
            if len(add_insns_new) > 0:
                self.adds[serial] = add_insns_new

    def need_to_combine_adds(self):
        for serial, add_insns in self.adds.items():
            if len(add_insns) > 1:
                # Need to be several insns with the same size
                add_insn0 = add_insns[0]
                size0 = add_insn0.l.size
                for add_insn in add_insns[1:]:
                    if add_insn.l.size != size0:
                        return False
                return True
        return False

    def combine_adds(self, group: LoopsGroup):
        for serial, add_insns in self.adds.items():
            if len(add_insns) > 1:
                add_blk = self.mba.get_mblock(serial)
                add_insn0 = add_insns[0]
                add_op0 = add_insn0.l
                for add_insn in add_insns[1:]:
                    add_op = mop_t(add_insn.l)
                    self.print_to_log("  Merged: %s %s with %s" % (hex_addr(add_insn.ea, serial), add_op.dstr(), add_op0.dstr()))
                    add_blk.make_nop(add_insn)
                    self.mark_dirty(add_blk)
                    for blk, insn in group.all_loops_blocks_insns(self.mba):
                        for op in uses_of_op(add_op, blk, insn):
                            # print("USE %s" % op.dstr())
                            if add_op0.t == mop_r:
                                op.make_reg(add_op0.r, add_op0.size)
                            elif add_op0.t == mop_S:
                                op.make_stkvar(self.mba, add_op0.s.off)
                                op.size = add_op0.size
                            self.mark_dirty(blk)

    def try_to_move_zero_down(self, group: LoopsGroup):
        # In every block take first add_insn and get its corresponding zero_insn
        for serial, add_insns in self.adds.items():
            # Take only end block of group
            if serial == group.end:
                add_insn0 = add_insns[0]
                zero_insn = self.zeroes[var_as_key(add_insn0.l)]
                zero_op = zero_insn.d
                if zero_insn and not is_fict_ea(self.mba, zero_insn.ea):
                    ml = mlist_t()
                    for zero_blk in self.zero_blks:
                        zero_blk.append_use_list(ml, zero_op, MUST_ACCESS)
                        if zero_insn.next is None or not zero_blk.is_used(ml, zero_insn.next, None, MUST_ACCESS):
                            #print("zero_blk: %d" % zero_blk.serial)
                            after_insn = find_last_blk_insn_not_jump(zero_blk)
                            if not after_insn.equal_insns(zero_insn, EQ_CMPDEST):
                                # print("Zero insn: %s" % text_insn(zero_insn, blk))
                                insnn = minsn_t(zero_insn)
                                insnn.ea = self.mba.alloc_fict_ea(zero_insn.ea)
                                self.print_to_log("  Moved : %s to %s" % (hex_addr(zero_insn.ea), text_insn(insnn, zero_blk)))
                                zero_blk.insert_into_block(insnn, after_insn)
                                zero_blk.make_nop(zero_insn)
                                self.mark_dirty(zero_blk)

    def debug_print_collections(self, group: LoopsGroup):
        print("Group %d contains ADDs:" % group.entry)
        for serial, add_insns in self.adds.items():
            print("  Block %d:" % serial)
            for add_insn in add_insns:
                print("    %s" % text_insn(add_insn))
        print("Zero block %d contains ZEROes:" % self.zero_blk.serial)
        for var_key, zero_insn in self.zeroes.items():
            print("  %s" % text_insn(zero_insn))


def insn_is_inc_reg(insn):
    return insn.opcode == m_add and insn.l.is_reg() and insn.r.t == mop_n and insn.l == insn.d and insn.r.unsigned_value() == 1


def insn_is_inc_var(insn):
    """
        opcode l    r   d
        add    var, #1, var
    """
    return insn.opcode == m_add and insn.l.t in {mop_r, mop_S} and insn.r.is_one() and insn.l == insn.d


def insn_is_zero_var(insn):
    """
        opcode l   d
        mov    #0, var
    """
    return insn.opcode == m_mov and insn.l.is_zero() and insn.d.t in {mop_r, mop_S}


def is_op_defined_here(blk, op, insn):
    ml = mlist_t()
    blk.append_def_list(ml, op, MUST_ACCESS)
    _def = blk.build_def_list(insn, MUST_ACCESS)
    return _def.includes(ml)


def uses_of_op(op, blk, insn):
    ml = mlist_t()
    blk.append_use_list(ml, op, MUST_ACCESS)
    blk.for_all_uses(ml, insn, insn.next, vstr := VisitorOpUses())
    return vstr.ops


class VisitorOpUses(mlist_mop_visitor_t):

    def __init__(self):
        mlist_mop_visitor_t.__init__(self)
        self.ops = []

    def visit_mop(self, op):
        if op.t != mop_d:
            self.ops.append(op)
        return 0
