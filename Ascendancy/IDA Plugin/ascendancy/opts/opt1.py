"""
summary: Optimization 1

description:

    Prevent combination of
        if ( a1->e == 0xFFFFFFFF && a1->d )
    into 64bit comparison
        if ( *(_QWORD *)&a1->d > 0xFFFFFFFF00000000i64 )

test:
    sub_1BBC8

"""

from ida_hexrays import *
from ascendancy.util import *


def run(blk, insn):
    if is_func_lib(insn.ea):
        return 0
    # buf = insn.dstr()
    # if ("jnz " in buf) and ("0xFFFFFFFF.4" in buf):
    if is_mcode_jcond(insn.opcode) and insn.r.is_equal_to(0xFFFFFFFF, False) and insn.l.is_insn(m_ldx):
        print_to_log("Optimization 1 - Clear combinable: [%s]" % text_insn(insn))
        insn.clr_combinable()
