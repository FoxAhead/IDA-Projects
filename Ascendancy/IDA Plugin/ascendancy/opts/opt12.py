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
        1F119 - May be change offset of stack var? %var_474@999 -> %var_474@1000 -> %var_8C
        466FC
        347CC

"""
from ascendancy.opts import GlbOpt
from ascendancy.utils import *


def run(mba):
    opt12 = Opt()
    opt12.run(mba)


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
            if insn_is_add_var(insn, True) and insn.l.size == 4:
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
                mult = add_insn.r.unsigned_value()
                changed = False
                after_insn = None
                vstr = find_op_uses(blk, insn, None, add_op)
                if any([is_mcode_set(use.topins.opcode) for use in vstr.uses]):
                    continue
                for use in vstr.uses:
                    if is_insn_j(use.topins):
                        continue
                    # print("topins=%s, curins=%s, op=%s" %(text_insn(use.topins), text_insn(use.curins), use.op.dstr()))
                    # if use.curins.opcode == m_add and use.curins.l.is_insn(m_add) and use.curins.l.d.r.is_constant():
                    #     n = use.curins.l.d.r.unsigned_value()
                    #     use.curins.l.d.r.update_numop_value(n + mult)
                    # else:
                    if use.curins.opcode == m_add and use.curins.l.t == mop_a and use.curins.l.a.t == mop_S:
                        use.curins.l.a.s.off += mult
                    elif use.curins.opcode in {m_add, m_sub} and use.curins.r.is_constant():
                        n = use.curins.r.unsigned_value() if use.curins.opcode == m_add else - use.curins.r.unsigned_value()
                        n += mult
                        use.curins.opcode = m_sub if n < 0 else m_add
                        use.curins.r.update_numop_value(abs(n))
                    else:
                        insnn = InsnBuilder(use.topins.ea, m_add, size).var(self.mba, add_op).n(mult).insn()
                        use.op.create_from_insn(insnn)
                    self.print_to_log("  Change: %s" % (text_insn(use.topins, blk)))
                    after_insn = use.topins
                    changed = True
                    # use.topins.for_all_insns(Visitor())
                if changed:
                    self.mark_dirty(blk)
                    add_insns.append((add_insn, after_insn))
        for add_insn, after_insn in add_insns:
            # after_insn = find_last_blk_insn_not_jump(blk)
            # if add_insn.ea != after_insn.ea:
            insnn = minsn_t(add_insn)
            # insnn.ea = after_insn.ea
            insnn.ea = self.mba.alloc_fict_ea(add_insn.ea)
            self.print_to_log("  Moved : %s to %s" % (hex_addr(add_insn.ea), text_insn(insnn, blk)))
            # print_to_log("  Insert: %s" % text_insn(insnn, blk))
            blk.insert_into_block(insnn, after_insn)
            # print_to_log("  NOP:    %s" % text_insn(add_insn, blk))
            blk.make_nop(add_insn)
            self.mark_dirty(blk)


def insn_is_add_reg(insn: minsn_t):
    return insn.opcode == m_add and insn.l.is_reg() and insn.r.t == mop_n and insn.d.is_reg() and insn.l.r == insn.d.r and not insn.l.is_kreg()


