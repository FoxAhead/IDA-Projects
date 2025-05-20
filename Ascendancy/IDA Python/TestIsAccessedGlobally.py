from ida_hexrays import *
from ida_idp import WRITE_ACCESS

from utils import *

import lib

ida_idaapi.require("lib")


def main():
    mba = lib.get_current_microcode(MMAT_GLBOPT2)
    Test().run(mba)
    #for insn in all_insns_in_block(blk1):
    #    print(text_insn(insn, blk1))
    #    ml = mlist_t(8, 4)
    #    a = graph.is_redefined_globally(ml, 1, 3, insn, blk3.head, MUST_ACCESS)
    #    print(a)


class Test():

    def run(self, mba):
        self.mba = mba
        self.graph: mbl_graph_t = mba.get_graph()
        op = mop_t(8, 4)
        self.find_add_op_initialization_earlier(op)

    def find_add_op_initialization_earlier(self, add_op: mop_t):
        blk3 = self.mba.get_mblock(3)
        blk_to = self.mba.get_mblock(3)
        self.visited = set()
        self.def_insns = []
        self.check_in_block(blk3, blk_to, add_op)
        for def_insn in self.def_insns:
            print(text_insn(def_insn))

    def check_in_block(self, blk: mblock_t, blk_to: mblock_t, add_op: mop_t):
        print("check_in_block", blk.serial)
        if blk.serial in self.visited:
            return
        self.visited.add(blk.serial)
        for insn in all_insns_in_block(blk, backwards=True):
            if is_op_defined_in_insn(blk, add_op, insn):
                print("defined in", text_insn(insn))
                if insn.next is None or not self.is_op_defined_between(add_op, blk, blk_to, insn.next, blk_to.tail):
                    self.def_insns.append(insn)
                    return
        for pred_blk in all_pred_blocks(self.mba, blk):
            self.check_in_block(pred_blk, blk_to, add_op)

    def is_op_defined_between(self, op, blk1, blk2, m1, m2):
        ml = mlist_t()
        blk1.append_def_list(ml, op, MUST_ACCESS)
        a = self.graph.is_redefined_globally(ml, blk1.serial, blk2.serial, m1, m2, MUST_ACCESS)
        print(op.dstr(), blk1.serial, blk2.serial, text_insn(m1), text_insn(m2), a)
        return a


if __name__ == '__main__':
    main()
