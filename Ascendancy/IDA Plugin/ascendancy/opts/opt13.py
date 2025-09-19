"""
summary: Optimization 13

description:

    Take complex ADD destination and put it in consequent uses

26. 0 add    esi.4{1}, (#0xA.4*xds.4([ds.2{11}:(esi.4{1}+#0x475C.4)].2)), ebp.4{12} ; 00055D5C
26. 1 xds    [ss.2{11}:(ebp.4{12}+#0x475E.4)].2, ecx.4{13} ; 00055D5F
26. 2 ldx    ss.2{11}, (ebp.4{12}+#0x4760.4), eax.4{14} ; 00055D65
26. 3 ldx    ss.2{11}, (ebp.4{12}+#0x4764.4){15}, %var_1C.4{17} ; 00055D74
26. 4 jb     ecx.4{13}, #9.4, @40                 ; 00055D7B


    Test:
        433E0
        492F8
        55B74 - Complex ADD
        46480 - TODO - Uncommented condition for loops. May be errors
        209AB - add_insn's ops can be changed along the way. Need to copy redefined ops
        2EC50
        45958 - use of destination reg should be in form ADD reg
        571B8 - No need of optimization here
        57220 - Need to opimize one add_ins at a time, because next one could be optimized and become wrong
                Also used op is redefined in shorter form (eax -> ax). Need to copy this op also.
        45D50 - TODO - (00045DA7) In complex add_insn reg == d. Need to optimize this also
        4A988 - TODO - Opposite to 45D50 reg and d and should be different. Have to detect this cases
        364B4 - TODO - If add.reg_op == dest_reg then add.blk should be non-loop

"""
from typing import Dict

from ascendancy.opts import GlbOpt
from ascendancy.utils import *


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(13, "Propagate ADDs", True)

    def _init(self):
        self.adds: List[ComplexAddReg] = []
        self.add: ComplexAddReg = None
        # self.add_blk: mblock_t = None
        # self.add_insn: minsn_t = None
        # self.used_ops: List[OpUsedInAddInsn] = None
        self.processed = set()  # Recursively processed blocks serials
        self.dest_uses: List[OpUse] = []

    def _run(self):
        # Search complex add_reg insns
        self.mba.for_all_topinsns(vstr_adds := VisitorSearchComplexAddRegInsns())
        self.adds = vstr_adds.adds
        for self.add in reversed(self.adds):
            # print("add.insn=%s, add.used_ops:" % text_insn(self.add.insn, self.add.blk))
            # for op in self.add.used_ops:
            #    print("  %s" % op.op.dstr())
            self.processed.clear()
            self.dest_uses.clear()
            self.process_block(self.add.blk, self.add.insn)
            if self.dest_uses:
                # print("add_insn=%s" % text_insn(self.add_insn, self.add_blk))
                # print("  USED_OPS")
                # for used_op in self.used_ops:
                #    print("    op=%s, ops:%s, was_redefined=%s, need_copy=%s" %(used_op.op.dstr(), [op.dstr() for op in used_op.ops], used_op.was_redefined, used_op.need_copy))
                # print("  DEST_USES")
                # for use in self.dest_uses:
                #    print("    blk=%d, insn=%s, op=%s" % (use.blk.serial, text_insn(use.insn), use.op.dstr()))
                if self.optimize_uses():
                    break

    def process_block(self, blk, start_insn):
        # Recursively collect all destination reg uses
        if blk.serial not in self.processed:
            # print("processing_block %d" % blk.serial)
            self.processed.add(blk.serial)
            # Start either from first insn of block or next insn after start_insn
            insn = blk.head if start_insn is None else start_insn.next
            while insn:
                for used_op in self.add.used_ops:
                    if is_op_defined_in_insn(blk, used_op.op, insn):
                        # print("op %s is redefined in %s" % (used_op.op.dstr(), text_insn(insn)))
                        used_op.was_redefined = True
                # Search uses of destination reg
                ml = mlist_t(self.add.insn.d.r, self.add.insn.d.size)
                blk.for_all_uses(ml, insn, insn.next, vstr_uses := VisitorSearchDestRegUses(blk))
                if vstr_uses.other:
                    self.dest_uses.clear()
                    return False
                if vstr_uses.uses:
                    # If it is another complex add, then don't optimize current
                    if self.is_insn_another_complex_add(insn):
                        self.dest_uses.clear()
                        return False
                    self.dest_uses.extend(vstr_uses.uses)
                    for used_op in self.add.used_ops:
                        if used_op.was_redefined:
                            used_op.need_copy = True
                # Stop traversing if destination reg is redefined here
                if is_op_defined_in_insn(blk, self.add.insn.d, insn):
                    # print("reg_defined_here")
                    return True
                insn = insn.next
            for succ_blk in all_succ_blocks(self.mba, blk):
                if not self.process_block(succ_blk, None):
                    return False
        return True

    def optimize_uses(self):
        # print("optimize_uses")
        changed = False
        # self.add_insn_insn_op.for_all_ops(vstr := Visitor13b())
        # vstr.ops.setdefault(var_as_key(self.add_insn_reg_op), []).append(self.add_insn_reg_op)
        for used_op in self.add.used_ops:
            op_copy = mop_t(used_op.op)
            if used_op.need_copy:
                kreg = self.mba.alloc_kreg(op_copy.size)
                insnn = InsnBuilder(self.add.insn.ea, m_mov, op_copy.size).var(self.mba, op_copy).r(kreg).insn()
                self.add.blk.insert_into_block(insnn, self.add.insn.prev)
                for op in used_op.ops:
                    op.make_reg(kreg, op_copy.size)
                self.mark_dirty(self.add.blk, False)
        for use in self.dest_uses:
            # print("  Changing (blk=%d): %s" % (use.blk.serial, text_insn(use.insn)))
            # print(use.blk.serial, text_insn(use.insn), use.op.dstr())
            insnn = minsn_t(self.add.insn)
            insnn.ea = use.insn.ea
            use.op.create_from_insn(insnn)
            # print("  Changed (blk=%d): %s" % (use.blk.serial, text_insn(use.insn)))
            self.print_to_log("  Change (blk=%d): %s" % (use.blk.serial, text_insn(use.insn)))
            changed = True
        if changed:
            self.print_to_log("  NOP    (blk=%d): %s" % (self.add.blk.serial, text_insn(self.add.insn)))
            self.add.blk.make_nop(self.add.insn)
            self.mark_dirty(self.add.blk, False)
        return changed

    def is_insn_another_complex_add(self, insn: minsn_t):
        for add in self.adds:
            if insn.equal_insns(add.insn, EQ_CMPDEST):
                return True
        return False


@dataclass
class OpUse:
    blk: mblock_t
    insn: minsn_t
    op: mop_t


@dataclass
class VarUsedInAddInsn:
    op: mop_t
    ops: List[mop_t] = field(default_factory=list)
    was_redefined: bool = False
    need_copy: bool = False


@dataclass
class ComplexAddReg:
    blk: mblock_t = None
    insn: minsn_t = None
    sub_insn: minsn_t = None
    sub_insn2: minsn_t = None
    reg_op: mop_t = None
    used_ops: List[VarUsedInAddInsn] = field(default_factory=list)


class VisitorSearchDestRegUses(mlist_mop_visitor_t):
    """
    Find usage of destination reg
    """

    def __init__(self, blk: mblock_t):
        mlist_mop_visitor_t.__init__(self)
        self.blk: mblock_t = blk
        self.uses: List[OpUse] = []
        self.other = False

    def visit_mop(self, op):
        if op.is_reg() and op.size == 4:
            # print("VisitorSearchOpUses curins: %s" % text_insn(self.curins))
            # Reg should be used in any ADD subinstruction
            if (insn := self.curins) and insn.opcode == m_add:
                self.uses.append(OpUse(self.blk, self.topins, op))
            else:
                # If there is also some other form of usage then don't optimize this reg
                self.uses.clear()
                self.other = True
                return 1
        return 0


class VisitorSearchComplexAddRegInsns(minsn_visitor_t):
    """
    Find complex ADDs: one part is reg and another is insn, destination is reg
    """

    def __init__(self):
        minsn_visitor_t.__init__(self)
        self.adds: List[ComplexAddReg] = []

    def visit_minsn(self):
        if add := get_complex_add_reg_insn(self.curins):
            add.blk = self.blk
            if add.reg_op:
                # If add.reg_op == destination reg then add.blk should not be loop-block
                if add.reg_op != add.insn.d or not LoopManager.serial_in_cycles(add.blk.serial):
                    # Also collect all ops used in this add_insn (l + r)
                    add.used_ops = get_ops_used_in_add_insn(self.curins)
                    self.adds.append(add)
            else:
                add.used_ops = get_ops_used_in_add_insn(self.curins)
                self.adds.append(add)
        return 0


def get_complex_add_reg_insn(insn) -> ComplexAddReg:
    # l is regular reg / insn
    # r is insn / regular reg
    # d is reg (may be == l/r)
    if insn.opcode == m_add and insn.d.is_reg() and insn.d.size == 4:
        if insn.l.is_reg() and insn.r.t == mop_d:
            return ComplexAddReg(insn=insn, sub_insn=insn.r.d, reg_op=insn.l)
        if insn.r.is_reg() and insn.l.t == mop_d:
            return ComplexAddReg(insn=insn, sub_insn=insn.l.d, reg_op=insn.r)
        # Some special cases. May be enhanced in future for general use
        if insn.ea == 0x435B5 and insn.l.is_insn(m_add) and insn.r.is_insn(m_mul):
            return ComplexAddReg(insn=insn, sub_insn=insn.l.d, sub_insn2=insn.r.d, reg_op=None)
        if insn.ea == 0x43A97 and insn.l.t == mop_a and insn.r.is_insn(m_mul):
            return ComplexAddReg(insn=insn, sub_insn=insn.r.d, reg_op=insn.l)
    return None


class VisitorGetVarOpsFromInsn(mop_visitor_t):

    def __init__(self):
        super().__init__()
        self.var_ops: Dict[str, VarUsedInAddInsn] = {}

    def visit_mop(self, op, type, is_target):
        if op.t in {mop_r, mop_S}:
            self.var_ops.setdefault(var_as_key(op), VarUsedInAddInsn(op)).ops.append(op)
        return 0


def get_ops_used_in_add_insn(insn) -> List[VarUsedInAddInsn]:
    # print("get_ops_used_in_add_insn %X" % insn.ea)
    insn.l.for_all_ops(vstrl := VisitorGetVarOpsFromInsn())
    insn.r.for_all_ops(vstrr := VisitorGetVarOpsFromInsn())
    for k, v in vstrr.var_ops.items():
        op = v.op
        vstrl.var_ops.setdefault(var_as_key(op), VarUsedInAddInsn(op)).ops.extend(v.ops)
    used_ops = list(vstrl.var_ops.values())
    # for used_op in used_ops:
    #    print(hex(insn.ea), used_op.op.dstr(), used_op.ops)
    return used_ops
