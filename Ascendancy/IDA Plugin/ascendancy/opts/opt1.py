"""
summary: Optimization 1

description:

    Case 1:
    Prevent combination of
        if ( a1->e == 0xFFFFFFFF && a1->d )
    into 64bit comparison
        if ( *(_QWORD *)&a1->d > 0xFFFFFFFF00000000i64 )


    Case 2:
void __fastcall __spoils<> sub_1B4F0(P_Matrices a1)
{
  *(_QWORD *)&a1->matrix_00._[0][0] = 0i64;
  a1->matrix_00._[0][2] = 0.0;
  *(_QWORD *)&a1->matrix_00._[1][0] = 0i64;

    After Opt11:
1. 0 stx    #0.4, ds.2{2}, eax.4{3} ; 1B4F1 u=eax.4,ds.2 d=(GLBLOW,GLBHIGH)
1. 1 nop                            ; 1B4F7 u=
1. 2 stx    #0.4, ds.2{2}, ((eax.4+#0xC.4)-#8.4) ; 1B4FA u=eax.4,ds.2 d=(GLBLOW,GLBHIGH)
1. 3 stx    #0.4, ds.2{2}, ((eax.4+#0xC.4)-#4.4) ; 1B501 u=eax.4,ds.2 d=(GLBLOW,GLBHIGH)
    Becomes:
1. 0 stx    #0.8, ds.2{2}, eax.4{3} ; 1B4F1 combined u=eax.4,ds.2 d=(GLBLOW,GLBHIGH)
1. 1 stx    #0.4, ds.2{2}, (eax.4+#8.4) ; 1B501 u=eax.4,ds.2 d=(GLBLOW,GLBHIGH)


test:
    sub_1BBC8
    1B4F0 - TODO - Case 2

"""

from ida_hexrays import *
from ascendancy.util import *


def run(blk, insn):
    # print("combine: %s" % text_insn(insn, blk))
    # print_blk(blk)
    if is_func_lib(insn.ea):
        return 0
    # buf = insn.dstr()
    # if ("jnz " in buf) and ("0xFFFFFFFF.4" in buf):
    if is_mcode_jcond(insn.opcode) and insn.r.is_equal_to(0xFFFFFFFF, False) and insn.l.is_insn(m_ldx):
        print_to_log("Optimization 1 - Clear combinable: [%s]" % text_insn(insn))
        insn.clr_combinable()
    # elif (next_insn := insn.next) and next_insn.opcode == m_nop:
    #    print_to_log("Optimization 1 - Clear combinable: [%s]" % text_insn(insn))
    #    insn.clr_combinable()
    elif insn.opcode == m_stx:
        if (next_insn := insn.next) and next_insn.opcode == m_stx:
            print_to_log("Optimization 1 - Clear combinable: [%s]" % text_insn(insn))
            insn.clr_combinable()
    elif insn.opcode == m_ldx:
        if (next_insn := insn.next) and next_insn.opcode == m_ldx:
            print_to_log("Optimization 1 - Clear combinable: [%s]" % text_insn(insn))
            insn.clr_combinable()
