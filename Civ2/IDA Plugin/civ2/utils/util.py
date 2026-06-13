from ida_hexrays import *
import ida_pro
import ida_lines
import idc

REG_EAX = 8
REG_EDX = 12
REG_ECX = 16
REG_EBX = 20
REG_ESP = 24
REG_EDI = 32
REG_ESI = 36
REG_DS = 104

LogMessages = []


def text_expr(expr):
    return "%.8X: (%s) %s" % (expr.ea, get_ctype_name(expr.op), get_expr_name(expr))


def text_insn(insn):
    return "%.8X: %s" % (insn.ea if insn else 0, insn.dstr() if insn else None)


def hex_eas(eas):
    return ", ".join("%.6X" % ea for ea in eas)


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
    print_to_log(text_expr)


def print_blk(blk):
    vp = vd_printer_t()
    blk._print(vp)


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
