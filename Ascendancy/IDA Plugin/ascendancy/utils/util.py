import time
from ida_hexrays import *
import ida_pro
import ida_lines
import idc

LogMessages = []


def text_expr(expr):
    return "%.6X: (%s) %s" % (expr.ea, get_ctype_name(expr._op), get_expr_name(expr))


def text_insn(insn, blk=None):
    return "%s %s" % (hex_addr(insn.ea if insn else 0, blk), insn.dstr() if insn else None)


def hex_addr(ea, blk=None):
    if blk:
        serial = blk.serial if type(blk) == mblock_t else blk
        return "%.5X: %d." % (ea, serial)
    else:
        return "%.5X:" % ea


def get_expr_name(expr):
    name = expr.print1(None)
    name = ida_lines.tag_remove(name)
    name = ida_pro.str2user(name)
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


def all_blocks_in_mba(mba):
    blk = mba.blocks
    while blk:
        yield blk
        blk = blk.nextb


def all_insns_in_block(blk):
    insn = blk.head
    while insn:
        yield insn
        insn = insn.next


def is_op_defined_in_insn(blk, op, insn):
    # print("is_op_defined_in_insn op=%s" % op.dstr())
    # print(text_insn(insn))
    ml = mlist_t()
    blk.append_def_list(ml, op, MUST_ACCESS)
    _def = blk.build_def_list(insn, MUST_ACCESS)
    return _def.includes(ml)


def get_number_of_op_definitions_in_blocks(op, blocks):
    definitions = 0
    for blk in blocks:
        for insn in all_insns_in_block(blk):
            if is_op_defined_in_insn(blk, op, insn):
                definitions = definitions + 1
    return definitions


def is_fict_ea(mba, ea):
    return mba.map_fict_ea(ea) != ea


def block_is_single_goto(blk):
    return blk and blk.head and blk.head.opcode == m_goto and not blk.head.next


def unsingle_goto_block(blk):
    """
        If blk is 1WAY-BLOCK and single GOTO, then try get prevb
    """
    if blk and blk.type == BLT_1WAY and block_is_single_goto(blk) and blk.prevb:
        return blk.prevb
    return blk


def insn_is_add_var(insn, kregs=False):
    """
    Find register or stack variable addition:
        add    var, #0xD.4, var
    """
    return insn.opcode == m_add and insn.r.t == mop_n and insn.l.t in {mop_r, mop_S} and insn.l == insn.d and not (kregs and insn.l.is_kreg())
