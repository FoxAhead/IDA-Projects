"""
summary: Optimization 4

description:

    Fix FOR-loop optimizations
    for correct struct fields detection

test:
    sub_5A144 (Variant 1)
    sub_56400 (Variant 1)
    sub_5A094 (Variant 2)
    5A094 (needs manual arg mapping)

"""

from ida_hexrays import *
from dataclasses import dataclass

from ascendancy.opts import GlbOpt
from ascendancy.util import *


@dataclass
class ForContext:
    mba: mba_t
    blk: mblock_t = None  # Block cursor
    insn: minsn_t = None  # Instruction cursor
    blk0: mblock_t = None
    blk1: mblock_t = None
    blk2: mblock_t = None
    blk3: mblock_t = None
    insn0: minsn_t = None
    insn1: minsn_t = None
    insn2: minsn_t = None
    insn2_opc: mop_t = None  # Counter operand
    insn3: minsn_t = None
    insn3_bak: minsn_t = None  # Instruction backup before make_nop
    insn3_opc: mop_t = None  # Counter operand
    op_to_replace: mop_t = None  # Destination operand
    op_counter: mop_t = None
    blk_endn: int = 0  # Block number after for-loop
    in_for: bool = False
    dirty: bool = False
    variant: int = 0

    def __post_init__(self):
        self.blk = self.mba.blocks


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(4)

    def _init(self):
        pass

    def _run(self):
        ctx = ForContext(self.mba)
        self.iterate_blocks(ctx)
        if ctx.dirty:
            self.mba.verify(True)
            self.err_code = MERR_LOOP
            # vp = vd_printer_t()
            # mba._print(vp)

    def iterate_blocks(self, ctx):
        while ctx.blk:
            self.block_begin(ctx)
            self.iterate_insns(ctx)
            ctx.blk = ctx.blk.nextb

    def iterate_insns(self, ctx):
        if ctx.in_for:
            while ctx.insn:
                self.iterate_insns_inside_for_loop(ctx)
                ctx.insn = ctx.insn.next

    def block_begin(self, ctx):
        ctx.insn = ctx.blk.head
        if ctx.in_for:
            if ctx.blk.serial >= ctx.blk_endn:
                print_to_log("%.8X: Found for-loop end" % ctx.blk.start)
                ctx.in_for = False
            else:
                return
        for check in (self.check_insn0, self.check_insn1, self.check_insn2, self.check_insn3):
            if not check(ctx):
                break
        else:
            self.for_loop_just_found(ctx)
            ctx.in_for = True

    def check_insn0(self, ctx):
        # mov    #0.2, ax.2
        # goto   @ 5
        if ctx.insn and ctx.blk.nextb and ctx.insn.opcode == m_mov and ctx.insn.l.is_zero() and ctx.insn.d.is_reg():  # and not ctx.insn.d.is_kreg():
            if ctx.insn.next and ctx.insn.next.opcode == m_goto:
                ctx.blk0 = ctx.blk
                ctx.insn0 = ctx.insn
                ctx.op_counter = ctx.insn.d
                self.switch_to_next_block(ctx)
                return True

    def check_insn1(self, ctx):
        # add    ax.2, #1.2, ax.2
        if ctx.insn and ctx.blk.nextb and ctx.insn.opcode == m_add and ctx.insn.r.is_one() and ctx.insn.l == ctx.op_counter and ctx.insn.l == ctx.insn.d:
            ctx.blk1 = ctx.blk
            ctx.insn1 = ctx.insn
            self.switch_to_next_block(ctx)
            return True

    def check_insn2(self, ctx):
        # jge    xds.4(dx.2), #0x180.4, @8
        if ctx.insn and ctx.insn.opcode == m_jge and self.has_counter(ctx.insn.l, ctx.op_counter):
            ctx.blk2 = ctx.blk
            ctx.insn2 = ctx.insn
            ctx.insn2_opc = self.has_counter(ctx.insn.l, ctx.op_counter)
            ctx.blk_endn = ctx.insn.d.b
            self.switch_to_next_block(ctx)
            return True

    def check_insn3(self, ctx):
        if ctx.insn:
            # Variant 1
            # add    esi.4{2}, (#0x16.4*xds.4(ax.2)), edx.4{5}
            if ctx.insn.opcode == m_add:
                insn_mul = ctx.insn.find_opcode(m_mul)
                if insn_mul and self.has_counter(insn_mul.r, ctx.op_counter):
                    ctx.blk3 = ctx.blk
                    ctx.insn3 = ctx.insn
                    ctx.insn3_opc = self.has_counter(insn_mul.r, ctx.op_counter)
                    ctx.op_to_replace = mop_t(ctx.insn3.d)
                    self.switch_to_next_insn(ctx)
                    ctx.variant = 1
                    return True
            # Variant 2
            # mul    #0x20.4, xds.4(dx.2), eax.4{5}
            # add    esi.4{1}, eax.4{5}, ecx.4{6}
            if ctx.insn.opcode == m_mul:
                ctx.insn3_opc = self.has_counter(ctx.insn.r, ctx.op_counter)
                if ctx.insn3_opc:
                    ctx.blk3 = ctx.blk
                    ctx.insn3 = ctx.insn
                    ctx.op_to_replace = mop_t(ctx.insn3.d)
                    self.switch_to_next_insn(ctx)
                    ctx.variant = 2
                    return True

    def switch_to_next_block(self, ctx):
        ctx.blk = ctx.blk.nextb
        ctx.insn = ctx.blk.head if ctx.blk else None

    def switch_to_next_insn(self, ctx):
        ctx.insn = ctx.insn.next

    def has_counter(self, op, opc):
        if op == opc:
            return op
        elif op.is_insn(m_xds) and op.d.l == opc:
            return op.d.l

    def for_loop_just_found(self, ctx):
        print_to_log("\nOptimization 4 (variant %d):" % ctx.variant)
        print_to_log("%.8X: Found for-loop begin" % ctx.insn0.ea)
        if ctx.variant == 1:
            if not ctx.op_counter.is_kreg():
                size = ctx.op_counter.size
                kreg = ctx.mba.alloc_kreg(size)
                ctx.insn0.d.make_reg(kreg, size)
                ctx.insn1.l.make_reg(kreg, size)
                ctx.insn1.d.make_reg(kreg, size)
                ctx.insn2_opc.make_reg(kreg, size)
                ctx.insn3_opc.make_reg(kreg, size)
                ctx.blk0.mark_lists_dirty()
                ctx.blk1.mark_lists_dirty()
                ctx.blk2.mark_lists_dirty()
                ctx.blk3.mark_lists_dirty()
            ctx.insn3_bak = minsn_t(ctx.insn3)
            ctx.blk3.make_nop(ctx.insn3)
        elif ctx.variant == 2:
            size = ctx.op_counter.size
            kreg = ctx.mba.alloc_kreg(size)
            ctx.insn0.d.make_reg(kreg, size)
            ctx.insn1.l.make_reg(kreg, size)
            ctx.insn1.d.make_reg(kreg, size)
            ctx.insn2_opc.make_reg(kreg, size)
            ctx.insn3_opc.make_reg(kreg, size)
            ctx.insn3_bak = minsn_t(ctx.insn3)
            ctx.blk3.make_nop(ctx.insn3)
            ctx.blk0.mark_lists_dirty()
            ctx.blk1.mark_lists_dirty()
            ctx.blk2.mark_lists_dirty()
            ctx.blk3.mark_lists_dirty()
        ctx.dirty = True

    def iterate_insns_inside_for_loop(self, ctx):
        ctx.insn.for_all_insns(vstr := Visitor4(ctx.op_to_replace, ctx.variant))
        if insn := vstr.found_insn:
            print_to_log("%.8X: %s" % (insn.ea, insn.dstr()))
            vstr.found_op.create_from_insn(ctx.insn3_bak)
            ctx.blk.mark_lists_dirty()

    def insert_dummy_mov(self, blk):
        insn = minsn_t(blk.start)
        insn.opcode = m_mov
        insn.l.make_reg(mr_first, 4)
        insn.d.make_reg(mr_first, 4)
        blk.insert_into_block(insn, None)


class Visitor4(minsn_visitor_t):
    found_insn = None
    found_op = None

    def __init__(self, op, variant):
        self.op = op
        self.variant = variant
        minsn_visitor_t.__init__(self)

    def visit_minsn(self):
        insn = self.curins
        if self.variant == 1:
            if insn.opcode == m_add and insn.l == self.op and insn.r.is_constant():
                self.found_insn = insn
                self.found_op = insn.l
                return 1
        elif self.variant == 2:
            if insn.opcode == m_add and insn.r == self.op:  # and insn.l.is_insn(m_add) and insn.l.d.r.is_constant():
                self.found_insn = insn
                self.found_op = insn.r
                return 1
        return 0
