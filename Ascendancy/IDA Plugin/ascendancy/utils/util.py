import time
from dataclasses import dataclass
from typing import List

import idaapi
from ida_hexrays import *
import ida_pro
import ida_lines
import idc

REG_EAX = 8
REG_EDX = 12
REG_ECX = 16
REG_EBX = 20
REG_EDI = 32
REG_ESI = 36
REG_DS = 104

LogMessages = []


def text_expr(expr):
    return "%.6X: (op=%s) (type=%s) %s" % (expr.ea, get_ctype_name(expr.op), expr.type, get_expr_name(expr))


def text_insn(insn, blk=None):
    return "%s %s" % (hex_addr(insn.ea if insn else 0, blk), insn.dstr() if insn else None)


def hex_addr(ea, blk=None):
    if blk is not None:
        serial = blk.serial if type(blk) == mblock_t else blk
        return "%.5X: %d." % (ea, serial)
    else:
        return "%.5X:" % ea


def get_expr_name(expr):
    name = expr.print1(None)
    name = ida_lines.tag_remove(name)
    # name = ida_pro.str2user(name)
    return name


def print_insn(insn):
    print_to_log(text_insn(insn))


def print_insns(insns):
    for insn in insns:
        print_insn(insn)


def collect_insns_up(insn, lst):
    """
    Collects group of instructions from the same address upwards
    """
    lst.clear()
    if insn:
        ea = insn.ea
        while insn and insn.ea == ea:
            lst.append(insn)
            insn = insn.prev
    return len(lst)


def collect_insns_down(insn, lst):
    lst.clear()
    if insn:
        ea = insn.ea
        while insn and insn.ea == ea:
            lst.append(insn)
            insn = insn.next
    return len(lst)


def print_expr(expr):
    print_to_log(text_expr(expr))


def print_to_log(msg):
    LogMessages.append(msg)


def is_func_lib(ea):
    function_flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)
    if function_flags & idc.FUNC_LIB:
        return True
    return False


def is_insn_mov_ds_seg(insn):
    if insn and insn.opcode == m_mov and insn.l.is_reg() and insn.l.r == 104 and insn.d.is_reg() and insn.d.r == 84:
        return True
    return False


def print_mba(mba):
    vp = vd_printer_t()
    mba._print(vp)


def print_blk(blk):
    vp = vd_printer_t()
    blk._print(vp)


def rotate(l, n):
    return l[n:] + l[:n]


def is_insn_j(insn):
    return is_mcode_jcond(insn.opcode) or insn.opcode == m_goto


def find_last_blk_insn_not_jump(blk):
    insn = blk.tail
    if insn and is_insn_j(insn):
        insn = insn.prev
    return insn


def var_as_key(op):
    if op.t == mop_r:
        return "r-%d" % op.r
    elif op.t == mop_S:
        return "S-%d" % op.s.off
    else:
        return op.dstr()


class XInsn(object):

    def __init__(self, blk, idx):
        self.blk = blk
        self.idx = idx


class XBlock(object):

    def __init__(self, mba, blk):
        self.mba = mba
        self.blk = blk
        self.xinsns = []
        insn = blk.head
        idx = 0
        while insn:
            self.xinsns = XInsn(blk, idx)
            insn = insn.next


def all_blocks_in_mba(mba: mba_t):
    blk = mba.blocks
    while blk:
        yield blk
        blk = blk.nextb


def all_insns_in_block(blk: mblock_t, i1: minsn_t = None, backwards: bool = False):
    if backwards:
        insn = blk.tail if i1 is None else i1
        while insn:
            yield insn
            insn = insn.prev
    else:
        insn = blk.head if i1 is None else i1
        while insn:
            yield insn
            insn = insn.next


def all_pred_blocks(mba: mba_t, blk: mblock_t):
    for pred in list(blk.predset):
        yield mba.get_mblock(pred)


def all_succ_blocks(mba: mba_t, blk: mblock_t):
    for succ in list(blk.succset):
        yield mba.get_mblock(succ)


def is_op_defined_in_insn(blk: mblock_t, op: mop_t, insn: minsn_t):
    # print("is_op_defined_in_insn op=%s" % op.dstr())
    # print(text_insn(insn))
    ml = mlist_t()
    blk.append_def_list(ml, op, MUST_ACCESS)
    _def = blk.build_def_list(insn, MUST_ACCESS)
    return _def.has_common(ml)


def is_op_defined_between(graph, op, blk1, blk2, m1, m2):
    """
    Check if op is defined in range [blk1.m1, blk2.m2)
    """
    ml = mlist_t()
    blk1.append_def_list(ml, op, MUST_ACCESS)
    a = graph.is_redefined_globally(ml, blk1.serial, blk2.serial, m1, m2, MUST_ACCESS)
    # print(op.dstr(), blk1.serial, blk2.serial, text_insn(m1), text_insn(m2), a)
    return a


def is_op_defined_in_block(blk: mblock_t, op: mop_t):
    ml = mlist_t()
    blk.append_def_list(ml, op, MUST_ACCESS)
    # return blk.maybdef.includes(ml)
    return blk.maybdef.has_common(ml)


def is_op_used_in_insn(blk: mblock_t, insn: minsn_t, op: mop_t):
    ml = mlist_t()
    blk.append_use_list(ml, op, MUST_ACCESS)
    _use = blk.build_use_list(insn, MUST_ACCESS)
    return _use.has_common(ml)


def is_op_used_in_block(blk: mblock_t, op: mop_t):
    ml = mlist_t()
    blk.append_use_list(ml, op, MUST_ACCESS)
    # return blk.mustbuse.includes(ml)
    return blk.mustbuse.has_common(ml)


def get_number_of_op_definitions_in_blocks(op: mop_t, blocks: List[mblock_t]):
    definitions = 0
    for blk in blocks:
        for insn in all_insns_in_block(blk):
            if is_op_defined_in_insn(blk, op, insn):
                definitions = definitions + 1
    return definitions


def get_number_of_op_definitions_in_block(op: mop_t, blk: mblock_t, i1: minsn_t = None):
    definitions = 0
    for insn in all_insns_in_block(blk, i1=i1):
        if is_op_defined_in_insn(blk, op, insn):
            definitions = definitions + 1
    return definitions


def is_fict_ea(mba, ea):
    return mba.map_fict_ea(ea) != ea


def block_is_single_goto(blk):
    return blk and blk.head and blk.head.opcode == m_goto and not blk.head.next


def block_is_exit(mba, blk):
    """
        Block is 1WAY-block and leads to STOP-block
    """
    if blk and blk.type == BLT_1WAY:
        succ_blk = mba.get_mblock(blk.succ(0))
        # print("block_is_exit: succ_blk.type=%d succ_blk.nsucc=%d" % (succ_blk.type, succ_blk.nsucc()))
        return succ_blk.type == BLT_STOP and succ_blk.nsucc() == 0
    return False


def unsingle_goto_block(mba: mba_t, blk: mblock_t):
    """
    If blk is 1WAY-BLOCK and single GOTO, then try get previous
    """
    if blk and blk.type == BLT_1WAY and block_is_single_goto(blk):
        return mba.get_mblock(blk.pred(0))
    return blk


def insn_is_add_var(insn, no_kregs=False):
    """
    Check if register or stack variable addition:
        add    var, #0xD, var
    """
    return insn.opcode == m_add and insn.r.t == mop_n and insn.l.t in {mop_r, mop_S} and insn.l == insn.d and not (no_kregs and insn.l.is_kreg())


def insn_is_addsub_var(insn, no_kregs=False):
    """
    Check if register or stack variable addition:
        add    var, #0xD, var
    """
    return insn.opcode in {m_add, m_sub} and insn.r.t == mop_n and insn.l.t in {mop_r, mop_S} and insn.l == insn.d and not (no_kregs and insn.l.is_kreg())


def get_addsub_value(insn: minsn_t) -> int:
    return insn.r.unsigned_value() if insn.opcode == m_add else -insn.r.unsigned_value()


def update_addsub_insn(insn: minsn_t, new_value: int):
    insn.opcode = m_sub if new_value < 0 else m_add
    insn.r.update_numop_value(abs(new_value))


def insn_is_zero_var(insn):
    """
    Check if zero is assigned to var:
        opcode l   d
        mov    #0, var
    """
    return insn and insn.opcode == m_mov and insn.l.is_zero() and insn.d.t in {mop_r, mop_S}


@dataclass
class OpUse:
    blk: mblock_t
    topins: minsn_t
    curins: minsn_t
    op: mop_t


class VisitorSimpleSearchUses(mlist_mop_visitor_t):

    def __init__(self, blk: mblock_t, size: int, mopts):
        mlist_mop_visitor_t.__init__(self)
        self.blk = blk
        self.size = size
        self.mopts = mopts
        self.uses = []

    def visit_mop(self, op: mop_t):
        if op.t in self.mopts and op.size == self.size:
            self.uses.append(OpUse(self.blk, self.topins, self.curins, op))
        return 0


def find_op_uses_in_insn(blk: mblock_t, insn: minsn_t, op: mop_t, vstr: mlist_mop_visitor_t = None):
    ml = mlist_t()
    blk.append_use_list(ml, op, MUST_ACCESS)
    if vstr is None:
        vstr = VisitorSimpleSearchUses(blk, op.size, {mop_r, mop_S})
    blk.for_all_uses(ml, insn, insn.next, vstr)
    return vstr


def find_op_uses(blk: mblock_t, i1: minsn_t, i2: minsn_t, op: mop_t, vstr: mlist_mop_visitor_t = None):
    ml = mlist_t()
    blk.append_use_list(ml, op, MUST_ACCESS)
    if vstr is None:
        vstr = VisitorSimpleSearchUses(blk, op.size, {mop_r, mop_S})
    blk.for_all_uses(ml, i1, i2, vstr)
    return vstr


def is_op_used_starting_from_this_block(mba: mba_t, op: mop_t, blk: mblock_t):
    visited = set()
    return is_op_used_in_block_recursive(mba, op, blk, visited)


def is_op_used_in_block_recursive(mba: mba_t, op: mop_t, blk: mblock_t, visited):
    if blk.serial in visited:
        return False
    visited.add(blk.serial)
    if is_op_used_in_block(blk, op):
        return True
    for succ_blk in all_succ_blocks(mba, blk):
        if is_op_used_in_block_recursive(mba, op, succ_blk, visited):
            return True
    return False


def get_tinfo_by_ordinal(ordinal: int):
    local_typestring = idc.get_local_tinfo(ordinal)
    if local_typestring:
        p_type, fields = local_typestring
        local_tinfo = ida_typeinf.tinfo_t()
        local_tinfo.deserialize(idaapi.cvar.idati, p_type, fields)
        return local_tinfo
    return None
