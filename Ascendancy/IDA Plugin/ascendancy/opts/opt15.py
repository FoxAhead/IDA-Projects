"""
summary: Optimization 15

description:

    Combine several reg++ in loops

test:

    54048
    46D81

"""

from ida_hexrays import *
import os
from ascendancy.opts.statictxt import *
from ascendancy.util import *


def run(mba):
    if is_func_lib(mba.entry_ea):
        return True
    LoopManager.init(mba)
    return Fix15(mba).run()


class Fix15(object):

    def __init__(self, mba):
        self.mba = mba
        self.add_insns = []
        self.add_blk = None
        self.err_code = MERR_OK

    def run(self):
        self.iterate_groups()
        return self.err_code == MERR_OK

    def iterate_groups(self):
        for group in LoopManager.groups:
            if self.group_need_optimization(group):
                # print("group_need_optimization")
                # for insn in self.add_insns:
                #    print(text_insn(insn))
                self.optimize_group(group)
                self.try_to_move_zero_down(group)

    def group_need_optimization(self, group):
        d = {}
        self.add_insns.clear()
        for blk, insn in group.all_loops_blocks_insns(self.mba):
            # print(blk.serial, text_insn(insn))
            if insn_is_inc_reg(insn):
                d.setdefault(var_as_key(insn.l), []).append((blk.serial, insn))
        d2 = {}
        add_insns = []
        for key, value in d.items():
            if len(value) == 1:
                serial, add_insn = value[0]
                add_op = add_insn.l
                defines = 0
                for blk, insn in group.all_loops_blocks_insns(self.mba):
                    ml = mlist_t(add_op.r, add_op.size)
                    if is_reg_defined_here(blk, ml, insn):
                        defines = defines + 1
                        if defines > 1:
                            break
                if defines == 1:
                    d2.setdefault(serial, []).append(add_insn)
                    add_insns.append(add_insn)
        # Check all insn are from the same block
        if len(d2) != 1:
            add_insns.clear()
        else:
            self.add_blk = self.mba.get_mblock(list(d2.keys())[0])
        # Leave only one regular reg
        has_regular_reg = False
        for add_insn in add_insns:
            if add_insn.l.is_kreg():
                self.add_insns.append(add_insn)
            elif has_regular_reg == 0:
                has_regular_reg = True
                self.add_insns.insert(0, add_insn)
        return len(self.add_insns) > 1

    def optimize_group(self, group):
        print_to_log("Optimization 15")
        add_insn0 = self.add_insns[0]
        add_op0 = add_insn0.l
        for add_insn in self.add_insns[1:]:
            add_op = mop_t(add_insn.l)
            print_to_log("  %.8X: Changed %s to %s" % (add_insn.ea, add_op.dstr(), add_op0.dstr()))
            self.add_blk.make_nop(add_insn)
            self.add_blk.mark_lists_dirty()
            for blk, insn in group.all_loops_blocks_insns(self.mba):
                for op in uses_of_op(add_op, blk, insn):
                    # print("USE %s" % op.dstr())
                    op.r = add_op0.r
                    blk.mark_lists_dirty()
        self.err_code = MERR_LOOP

    def try_to_move_zero_down(self, group):
        add_insn0 = self.add_insns[0]
        add_op0 = add_insn0.l
        blk = group.entry_block(self.mba)
        zero_insn = None
        insn = blk.head
        while insn:
            if zero_insn is None:
                if insn_is_zero_reg(insn) and insn.d.r == add_op0.r:
                    zero_insn = insn
                    break
            insn = insn.next
        if zero_insn:
            #print_blk(blk)
            ml = mlist_t(zero_insn.d.r, zero_insn.d.size)
            if zero_insn.next is None or not blk.is_used(ml, zero_insn.next, None, MUST_ACCESS):
                after_insn = find_last_blk_insn_not_jump(blk)
                #print(text_insn(zero_insn))
                #print(text_insn(after_insn))
                #print(zero_insn.equal_insns(after_insn, EQ_CMPDEST))
                if not after_insn.equal_insns(zero_insn, EQ_CMPDEST):
                #if after_insn.ea != zero_insn.ea:
                    insnn = minsn_t(zero_insn)
                    insnn.ea = after_insn.ea
                    print_to_log("  Moved : %.8X to %s" % (zero_insn.ea, text_insn(insnn, blk)))
                    blk.insert_into_block(insnn, after_insn)
                    blk.make_nop(zero_insn)
                    blk.mark_lists_dirty()
                    self.err_code = MERR_LOOP


def insn_is_inc_reg(insn):
    return insn.opcode == m_add and insn.l.is_reg() and insn.r.t == mop_n and insn.l == insn.d and insn.r.unsigned_value() == 1


def insn_is_zero_reg(insn):
    return insn.opcode == m_mov and insn.l.t == mop_n and insn.d.is_reg() and insn.l.unsigned_value() == 0


def is_reg_defined_here(blk, ml, insn):
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
