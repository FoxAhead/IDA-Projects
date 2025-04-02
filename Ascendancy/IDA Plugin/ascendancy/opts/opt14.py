"""
summary: Optimization 14

description:

    Print float and double constants

tests:

    4A8FC
    14B18
    496E0 - double

"""
import struct

import ida_ieee
import ida_name
import idautils
from ida_hexrays import *
import ida_bytes

from ascendancy.util import *


def run(mba):
    if is_func_lib(mba.entry_ea):
        return 0
    # mba.for_all_ops(vstr := Visitor14a())
    # if vstr.op_fn:
    # mba.for_all_ops(Visitor14(vstr.op_fn))
    # print_mba(mba)
    mba.for_all_insns(vstr2 := Visitor14b())
    if vstr2.changes:
        print_to_log("Optmization 14:")
        for ea, t1, t2 in vstr2.changes:
            print_to_log("  %.8X: Change %s to %f" % (ea, t1, t2))

        # print_mba(mba)


class Visitor14a(mop_visitor_t):

    def __init__(self):
        mop_visitor_t.__init__(self)
        self.op_fn = None

    def visit_mop(self, op, type, is_target):
        if op.t == mop_fn:
            self.op_fn = op
            return 1
        return 0


class Visitor14b(minsn_visitor_t):

    def __init__(self):
        minsn_visitor_t.__init__(self)
        self.changes = []

    def visit_minsn(self):
        insn = self.curins
        # if insn.opcode == m_f2f and insn.l.t == mop_v:
        #    insn.l = mop_t(self.op_fn)
        #    insn.l.size = 4
        op = insn.l
        if insn.opcode == m_mov and op.is_glbaddr() and op.size == 4:
            if (insn2 := insn.next) and insn2.opcode == m_ldx and insn.d.r == insn2.r.r:
                if (insn3 := insn2.next) and insn3.opcode in [m_f2f, m_fadd, m_fsub, m_fmul, m_setb]:
                    ea = op.a.g
                    if HasOnlyRXrefs(ea):
                        size = insn2.d.size
                        if size == 4:
                            val = ida_bytes.get_dword(ea)
                            t2 = struct.unpack(">f", bytes.fromhex("%.8X" % val))[0]
                        elif size == 8:
                            val = ida_bytes.get_qword(ea)
                            t2 = struct.unpack(">d", bytes.fromhex("%.16X" % val))[0]
                        else:
                            return 0
                        # t1 = op.a.dstr()
                        t1 = ida_name.get_ea_name(ea)
                        insn.l.make_number(val, size)
                        insn.d.make_reg(insn2.d.r, size)
                        self.blk.make_nop(insn2)
                        self.changes.append((insn.ea, t1, t2))
        return 0


class Visitor14(mop_visitor_t):

    def __init__(self, op_fn):
        mop_visitor_t.__init__(self)
        self.op_fn = op_fn

    def visit_mop(self, op, type, is_target):
        if op.is_glbaddr() and op.size == 4:
            ea = op.a.g
            val = ida_bytes.get_dword(ea)
            print(op.a.insize, op.a.outsize, op.size, "%X" % val)
            print(op.dstr())
            op = mop_t(self.op_fn)
            op.size = 4
            print(op.dstr(), op.fpc.fnum.w)
        return 0


def HasOnlyRXrefs(ea):
    for xref in idautils.XrefsTo(ea):
        if xref.type != ida_xref.dr_R:
            return False
    return True
