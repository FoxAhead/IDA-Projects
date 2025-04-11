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
        46480 - Uncommented condition for loops. May be errors
        209AB - TODO - add_insn's ops can be changed along the way. Need more complex checks

"""
from ascendancy.utils import *


def run(mba):
    if is_func_lib(mba.entry_ea):
        return True
    LoopManager.init(mba)
    return Fix13(mba).run()


class Fix13(object):

    def __init__(self, mba):
        self.mba = mba
        self.err_code = MERR_OK
        self.add_blk = None
        self.add_insn = None
        self.mult = 0
        self.loops = {}
        self.processed = set()
        self.uses = []

    def run(self):
        self.mba.for_all_topinsns(vstr_adds := Visitor13a())
        for self.add_insn, self.add_blk in vstr_adds.adds:

            #ml = self.add_blk.build_use_list(self.add_insn, MUST_ACCESS)
            #print(text_insn(self.add_insn, self.add_blk), ml.dstr())

            self.processed.clear()
            self.uses.clear()
            print("process_block:", self.add_blk.serial, text_insn(self.add_insn))
            self.process_block(self.add_blk, self.add_insn)
            if self.uses:
                self.optimize_uses()

        return self.err_code == MERR_OK

    def process_block(self, blk, insn):
        if blk.serial not in self.processed:
            # print(blk.serial)
            self.processed.add(blk.serial)
            if insn is None:
                insn = blk.head
            else:
                insn = insn.next
            while insn:
                ml = self.add_blk.build_use_list(self.add_insn, MUST_ACCESS)
                if is_any_op_defined_here(blk, ml, insn):
                    print(ml.dstr(), text_insn(insn))
                    return
                ml = mlist_t(self.add_insn.d.r, self.add_insn.d.size)
                blk.for_all_uses(ml, insn, insn.next, vstr_uses := Visitor13(blk))
                self.uses.extend(vstr_uses.uses)
                ml = mlist_t(self.add_insn.d.r, self.add_insn.d.size)
                if is_reg_defined_here(blk, ml, insn):
                    return
                insn = insn.next
            for succ in list(blk.succset):
                succ_block = self.mba.get_mblock(succ)
                self.process_block(succ_block, None)

    def optimize_uses(self):
        changed = False
        for use in self.uses:
            print("  Changing (blk=%d): %s" % (use.blk.serial, text_insn(use.insn)))
            # print(use.blk.serial, text_insn(use.insn), use.op.dstr())
            insnn = minsn_t(self.add_insn)
            insnn.ea = use.insn.ea
            use.op.create_from_insn(insnn)
            if not changed:
                print_to_log("Optimization 13")
            print("  Changed (blk=%d): %s" % (use.blk.serial, text_insn(use.insn)))
            print_to_log("  Change (blk=%d): %s" % (use.blk.serial, text_insn(use.insn)))
            changed = True
        if changed:
            print_to_log("  NOP    (blk=%d): %s" % (self.add_blk.serial, text_insn(self.add_insn)))
            self.add_blk.make_nop(self.add_insn)
            self.add_blk.mark_lists_dirty()
            print("MERR_LOOP")
            self.err_code = MERR_LOOP


def is_reg_defined_here(blk, ml, insn):
    # _def = blk.build_def_list(insn, MAY_ACCESS | FULL_XDSU)
    _def = blk.build_def_list(insn, MUST_ACCESS)
    return _def.includes(ml)


def is_any_op_defined_here(blk, ml, insn):
    # _def = blk.build_def_list(insn, MAY_ACCESS | FULL_XDSU)
    _def = blk.build_def_list(insn, MUST_ACCESS)
    return _def.has_common(ml)


class Visitor13(mlist_mop_visitor_t):

    def __init__(self, blk):
        mlist_mop_visitor_t.__init__(self)
        self.blk = blk
        self.uses = []

    def visit_mop(self, op):
        if op.t == mop_r and op.size == 4:
            self.uses.append(OpUse(self.blk, self.topins, op))
        return 0


class Visitor13a(minsn_visitor_t):
    """
    Find complex ADDs
    """

    def __init__(self):
        minsn_visitor_t.__init__(self)
        self.adds = []

    def visit_minsn(self):
        if insn_is_complex_add_reg(self.curins):  # and not LoopManager.serial_in_cycles(self.blk.serial):
            self.adds.append((self.curins, self.blk))
        return 0


def insn_is_complex_add_reg(insn):
    # l is regular reg
    # d is reg
    # r is insn
    if insn.opcode == m_add and insn.l.is_reg() and insn.d.is_reg() and not insn.l.is_kreg():
        if insn.r.t == mop_d:
            return True
    return False


@dataclass
class OpUse:
    blk: mblock_t
    insn: minsn_t
    op: mop_t
