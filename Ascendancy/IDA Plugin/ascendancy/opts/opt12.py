"""
summary: Optimization 12

description:

    Move ADDs down inside block
    Move ZEROes closer to loop

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
        1F119 - May be change offset of stack var? %var_474@999 -> %var_474@1000 -> %var_8C
        466FC
        347CC
        493BC - Move ZEROes closer to loop
        0001F38E - TODO: Move SUBs down inside block

"""
from ascendancy.opts import GlbOpt
from ascendancy.utils import *


def run(mba):
    opt12 = Opt()
    opt12.run(mba)


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(12, "Move ADDs/SUBs down inside block. Move ZEROes closer to loop.")

    def _init(self):
        self.add_blk = None
        self.add_insns = []  # ADDs/SUBs
        self.mult = 0
        self.loops = {}

    def _run(self):
        self.iterate_blocks()
        self.move_zeroes()

    def iterate_blocks(self):
        for blk in all_blocks_in_mba(self.mba):
            if self.block_needs_optimization(blk):
                # print("block_needs_optimization %d" % blk.serial)
                # for insn in self.add_insns:
                #    print(text_insn(insn))
                self.optimize_block(blk)

    def block_needs_optimization(self, blk: mblock_t):
        # print("block_needs_optimization? %d" % blk.serial)
        d = {}
        self.add_insns.clear()
        for insn in all_insns_in_block(blk):
            #if insn_is_add_var(insn, True) and insn.l.size == 4:
            if insn_is_addsub_var(insn, True) and insn.l.size == 4:
                d.setdefault(var_as_key(insn.l), []).append(insn)
        # Add op should be defined only once in the block
        for key, insns in d.items():
            if len(insns) == 1:
                add_insn = insns[0]
                if get_number_of_op_definitions_in_blocks(add_insn.l, [blk]) == 1:
                    self.add_insns.append(add_insn)
        return len(self.add_insns) > 0

    def optimize_block(self, blk: mblock_t):
        # print_blk(blk)
        add_insns = []
        for add_insn in self.add_insns:
            if insn := add_insn.next:
                add_op = add_insn.l
                size = add_op.size
                mult = get_addsub_value(add_insn)
                changed = False
                after_insn = None
                vstr = find_op_uses(blk, insn, None, add_op)
                if any([is_mcode_set(use.topins.opcode) for use in vstr.uses]):
                    continue
                for use in vstr.uses:
                    if is_insn_j(use.topins):
                        continue
                    if use.curins.opcode == m_add and use.curins.l.t == mop_a and use.curins.l.a.t == mop_S:
                        use.curins.l.a.s.off += mult
                    elif use.curins.opcode in {m_add, m_sub} and use.curins.r.is_constant():
                        update_addsub_insn(use.curins, get_addsub_value(use.curins) + mult)
                    else:
                        insnn = InsnBuilder(use.topins.ea, add_insn.opcode, size).var(self.mba, add_op).n(mult).insn()
                        use.op.create_from_insn(insnn)
                    self.print_to_log("  Change: %s" % (text_insn(use.topins, blk)))
                    after_insn = use.topins
                    changed = True
                if changed:
                    self.mark_dirty(blk)
                    add_insns.append((add_insn, after_insn))
        for add_insn, after_insn in add_insns:
            insnn = minsn_t(add_insn)
            insnn.ea = self.mba.alloc_fict_ea(add_insn.ea)
            self.print_to_log("  Moved : %s to %s" % (hex_addr(add_insn.ea), text_insn(insnn, blk)))
            blk.insert_into_block(insnn, after_insn)
            blk.make_nop(add_insn)
            self.mark_dirty(blk)

    def move_zeroes(self):
        self.zeroes = []
        self.collect_zeroes()
        for zero in self.zeroes:
            self.optimize_zero(zero)

    def collect_zeroes(self):
        for blk in all_blocks_in_mba(self.mba):
            if not LoopManager.serial_in_cycles(blk.serial):
                for insn in all_insns_in_block(blk):
                    if insn_is_zero_var(insn):
                        self.zeroes.append(ZeroInsn(blk, insn))

    def optimize_zero(self, zero: "ZeroInsn"):
        blk = zero.blk
        op = zero.insn.d
        if not is_op_used_in_block(blk, op):
            using_succ_blks = []
            for succ_blk in all_succ_blocks(self.mba, blk):
                if is_op_used_starting_from_this_block(self.mba, op, succ_blk):
                    using_succ_blks.append(succ_blk)
            if len(using_succ_blks) == 1:
                succ_blk = using_succ_blks[0]
                if not LoopManager.serial_in_cycles(succ_blk.serial) and succ_blk.npred() == 1:
                    self.move_zero(zero, succ_blk)

    def move_zero(self, zero: "ZeroInsn", to_blk: mblock_t):
        insnn = minsn_t(zero.insn)
        # insnn.ea = self.mba.alloc_fict_ea(zero.insn.ea)
        self.print_to_log("  Moved0: %s to %s" % (text_insn(zero.insn, zero.blk), text_insn(insnn, to_blk)))
        zero.blk.make_nop(zero.insn)
        self.mark_dirty(zero.blk)
        to_blk.insert_into_block(insnn, None)
        self.mark_dirty(to_blk)


def insn_is_add_reg(insn: minsn_t):
    return insn.opcode == m_add and insn.l.is_reg() and insn.r.t == mop_n and insn.d.is_reg() and insn.l.r == insn.d.r and not insn.l.is_kreg()


@dataclass
class ZeroInsn:
    blk: mblock_t = None
    insn: minsn_t = None
