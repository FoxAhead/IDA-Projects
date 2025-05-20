"""
summary: Optimization 13

description:

    Take ADD destination and put it in consequent uses

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

"""
from typing import Dict

from ascendancy.opts import GlbOpt
from ascendancy.utils import *


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(13, "Propagate ADDs", True)

    def _init(self):
        self.add_blk: mblock_t = None
        self.add_insn: minsn_t = None
        self.used_ops: List[OpUsedInAddInsn] = None
        self.processed = set()
        self.uses = []

    def _run(self):
        # Search complex add_reg insns
        self.mba.for_all_topinsns(vstr_adds := VisitorSearchComplexAddRegInsns())
        for self.add_blk, self.add_insn, self.used_ops in reversed(vstr_adds.adds):
            self.processed.clear()
            self.uses.clear()
            # print("process_block:", self.add_blk.serial, text_insn(self.add_insn))
            # for op in self.used_ops:
            #    print(op.op.dstr(), op.op.valnum)
            self.process_block(self.add_blk, self.add_insn)
            if self.uses:
                # print("add_insn=%s" % text_insn(self.add_insn, self.add_blk))
                # print("  USED_OPS")
                # for used_op in self.used_ops:
                #    print("    op=%s, ops:%s, was_redefined=%s, need_copy=%s" %(used_op.op.dstr(), [op.dstr() for op in used_op.ops], used_op.was_redefined, used_op.need_copy))
                # print("  DEST_USES")
                # for use in self.uses:
                #    print("    blk=%d, insn=%s, op=%s" % (use.blk.serial, text_insn(use.insn), use.op.dstr()))
                if self.optimize_uses():
                    break

        return self.err_code == MERR_OK

    def process_block(self, blk, start_insn):
        # Recursively collect all destination reg uses
        if blk.serial not in self.processed:
            # print("processing_block %d" % blk.serial)
            self.processed.add(blk.serial)
            if start_insn is None:
                insn = blk.head
            else:
                insn = start_insn.next
            while insn:
                for used_op in self.used_ops:
                    if is_op_defined_in_insn(blk, used_op.op, insn):
                        # print("op %s is redefined in %s" % (used_op.op.dstr(), text_insn(insn)))
                        used_op.was_redefined = True
                # ml = self.add_blk.build_use_list(self.add_insn, MUST_ACCESS)
                # if is_any_op_defined_here(blk, ml, insn):
                #    print("any_op_defined_here:", ml.dstr(), text_insn(insn))
                #    return
                ml = mlist_t(self.add_insn.d.r, self.add_insn.d.size)
                blk.for_all_uses(ml, insn, insn.next, vstr_uses := VisitorSearchOpUses(blk))
                if vstr_uses.other:
                    return
                if vstr_uses.uses:
                    self.uses.extend(vstr_uses.uses)
                    for used_op in self.used_ops:
                        if used_op.was_redefined:
                            used_op.need_copy = True
                # Stop traversing if destination reg is redefined here
                if is_op_defined_in_insn(blk, self.add_insn.d, insn):
                    # print("reg_defined_here")
                    return
                insn = insn.next
            for succ_blk in all_succ_blocks(self.mba, blk):
                self.process_block(succ_blk, None)

    def optimize_uses(self):
        # print("optimize_uses")
        changed = False
        # self.add_insn_insn_op.for_all_ops(vstr := Visitor13b())
        # vstr.ops.setdefault(var_as_key(self.add_insn_reg_op), []).append(self.add_insn_reg_op)
        for used_op in self.used_ops:
            op_copy = mop_t(used_op.op)
            if used_op.need_copy:
                kreg = self.mba.alloc_kreg(op_copy.size)
                insnn = InsnBuilder(self.add_insn.ea, m_mov, op_copy.size).var(self.mba, op_copy).r(kreg).insn()
                self.add_blk.insert_into_block(insnn, self.add_insn.prev)
                for op in used_op.ops:
                    op.make_reg(kreg, op_copy.size)
                self.mark_dirty(self.add_blk, False)
        for use in self.uses:
            # print("  Changing (blk=%d): %s" % (use.blk.serial, text_insn(use.insn)))
            # print(use.blk.serial, text_insn(use.insn), use.op.dstr())
            insnn = minsn_t(self.add_insn)
            insnn.ea = use.insn.ea
            use.op.create_from_insn(insnn)
            # print("  Changed (blk=%d): %s" % (use.blk.serial, text_insn(use.insn)))
            self.print_to_log("  Change (blk=%d): %s" % (use.blk.serial, text_insn(use.insn)))
            changed = True
        if changed:
            self.print_to_log("  NOP    (blk=%d): %s" % (self.add_blk.serial, text_insn(self.add_insn)))
            self.add_blk.make_nop(self.add_insn)
            self.mark_dirty(self.add_blk, False)
        return changed


# def is_reg_defined_here(blk, ml, insn):
#     # _def = blk.build_def_list(insn, MAY_ACCESS | FULL_XDSU)
#     _def = blk.build_def_list(insn, MUST_ACCESS)
#     return _def.includes(ml)


# def is_any_op_defined_here(blk, ml, insn):
#     # _def = blk.build_def_list(insn, MAY_ACCESS | FULL_XDSU)
#     _def = blk.build_def_list(insn, MUST_ACCESS)
#     # return _def.has_common(ml)
#     return _def.intersect(ml)


class VisitorSearchOpUses(mlist_mop_visitor_t):
    """
    Find usage of reg
    """

    def __init__(self, blk):
        mlist_mop_visitor_t.__init__(self)
        self.blk = blk
        self.uses = []
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
    Find complex ADDs: one part is reg and another is insn, destination is another reg
    """

    def __init__(self):
        minsn_visitor_t.__init__(self)
        self.adds = []

    def visit_minsn(self):
        lr = {}
        if insn_is_complex_add_reg(self.curins, lr):  # and not LoopManager.serial_in_cycles(self.blk.serial):
            used_ops = get_ops_used_in_add_insn(self.curins)
            self.adds.append((self.blk, self.curins, used_ops))
        return 0


def insn_is_complex_add_reg(insn, lr):
    # l is regular reg / insn
    # r is insn / regular reg
    # d is reg (not l/r)
    if insn.opcode == m_add and insn.d.is_reg() and insn.d.size == 4:
        if pair := get_ops_pair_from_complex_add_reg_insn(insn):
            if pair["reg"] != insn.d:
                lr.update(pair)
                return True
    return False


def get_ops_pair_from_complex_add_reg_insn(insn):
    """
    {"reg": reg_op, "insn": insn_op)
    """
    if insn.l.is_reg() and insn.r.t == mop_d:
        return {"reg": insn.l, "insn": insn.r}
    if insn.r.is_reg() and insn.l.t == mop_d:
        return {"reg": insn.r, "insn": insn.l}
    # if insn.l.is_reg() and not insn.l.is_kreg() and insn.r.t == mop_d:
    #     return {"reg": insn.l, "insn": insn.r}
    # if insn.r.is_reg() and not insn.r.is_kreg() and insn.l.t == mop_d:
    #     return {"reg": insn.r, "insn": insn.l}
    return None


class VisitorGetVarOpsFromInsn(mop_visitor_t):

    def __init__(self):
        super().__init__()
        self.var_ops: Dict[str, OpUsedInAddInsn] = {}

    def visit_mop(self, op, type, is_target):
        if op.t in {mop_r, mop_S}:
            self.var_ops.setdefault(var_as_key(op), OpUsedInAddInsn(op)).ops.append(op)
        return 0


@dataclass
class OpUse:
    blk: mblock_t
    insn: minsn_t
    op: mop_t


@dataclass
class OpUsedInAddInsn:
    op: mop_t
    ops: List[mop_t] = field(default_factory=list)
    was_redefined: bool = False
    need_copy: bool = False


def get_ops_used_in_add_insn(insn):
    # print("get_ops_used_in_add_insn %X" % insn.ea)
    insn.l.for_all_ops(vstrl := VisitorGetVarOpsFromInsn())
    insn.r.for_all_ops(vstrr := VisitorGetVarOpsFromInsn())
    for k, v in vstrr.var_ops.items():
        op = v.op
        vstrl.var_ops.setdefault(var_as_key(op), OpUsedInAddInsn(op)).ops.extend(v.ops)
    used_ops = list(vstrl.var_ops.values())
    # for used_op in used_ops:
    #    print(hex(insn.ea), used_op.op.dstr(), used_op.ops)
    return used_ops
