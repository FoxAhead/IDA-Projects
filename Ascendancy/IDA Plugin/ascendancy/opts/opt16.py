"""
summary: Optimization 15

description:


test:

    2EC82

"""
from ascendancy.actions import ActionPropagateVar
from ascendancy.opts.glbopt import GlbOpt
from ascendancy.utils import *


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(16, "Propagate variable")

    def _init(self):
        self.processed = set()

    def _run(self):
        self.processed.clear()
        self.mba.for_all_topinsns(vstr := Visitor16())
        for insn in vstr.insns:
            pass



class Visitor16(minsn_visitor_t):

    def __init__(self, reg):
        minsn_visitor_t.__init__(self)
        self.insns = []

    def visit_minsn(self):
        if self.curins.ea in ActionPropagateVar.eas:
            self.insn.append(self.curins)
        return 0
