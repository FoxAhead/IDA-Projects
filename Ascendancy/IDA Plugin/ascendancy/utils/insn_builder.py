from ida_hexrays import *


class InsnBuilder(object):

    def __init__(self, ea, opcode, size=4):
        self.size = size
        self._insn = minsn_t(ea)
        self._insn.opcode = opcode
        self.opn = 1
        # print("InsnBuilder __init__: %s" % text_insn(self._insn))
        if self._insn.opcode in {m_pop}:
            self.opn = 3

    def _op(self) -> mop_t:
        if self.opn == 1:
            #print("InsnBuilder._op(): l, opcode=%s" % self._insn.opcode)
            op = self._insn.l
            if self._insn.opcode in {m_mov, m_xdu}:
                self.opn = self.opn + 1
            elif self._insn.opcode in {m_push}:
                self.opn = self.opn + 2
        elif self.opn == 2:
            #print("InsnBuilder._op(): r")
            op = self._insn.r
        elif self.opn == 3:
            #print("InsnBuilder._op(): d")
            op = self._insn.d
        else:
            return None
        self.opn = self.opn + 1
        #print("InsnBuilder._op(): %d" % self.opn)
        return op

    def skip(self):
        self.opn = self.opn + 1
        return self

    def n(self, n):
        # print("InsnBuilder n: %s" % n)
        self._op().make_number(n, self.size)
        # print("InsnBuilder n: %s" % text_insn(self._insn))
        return self

    def r(self, r, size=None):
        # print("InsnBuilder r: %s" % r)
        self._op().make_reg(r, self.size if size is None else size)
        # print("InsnBuilder r: %s" % text_insn(self._insn))
        return self

    def i(self, i):
        self._op().create_from_insn(i)
        # print("InsnBuilder i: %s" % text_insn(self._insn))
        return self

    def S(self, mba, off):
        op = self._op()
        op.make_stkvar(mba, off)
        op.size = self.size
        return self

    def var(self, mba, var_op):
        if var_op.t == mop_r:
            return self.r(var_op.r)
        elif var_op.t == mop_S:
            return self.S(mba, var_op.s.off)
        else:
            return None

    def v(self, ea):
        self._op().make_gvar(ea)
        return self

    def insn(self):
        # print("self.opn = %d" % self.opn)
        if self.opn == 3:
            self.r(mr_none)
        #if self.opn != 4:
        #    #print("self.opn != 4:")
        #    return None
        # print("InsnBuilder: %s" % text_insn(self._insn))
        return self._insn
