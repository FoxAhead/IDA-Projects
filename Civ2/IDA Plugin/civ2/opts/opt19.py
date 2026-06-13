from ida_ieee import fpvalue_t, EONE
from ida_typeinf import tinfo_t

from civ2.utils import *


def run(cfunc):
    if is_func_lib(cfunc.entry_ea):
        return 0
    print("cfunc.maturity=%d" % cfunc.maturity)
    vstr = Visitor19(cfunc)
    vstr.apply_to(cfunc.body, None)
    if vstr.result:
        print_to_log("Optimization 19 (Float comparisons): %s" % vstr.result)


class Visitor19(cfunc_parentee_t):

    def __init__(self, f: cfunc_t):
        super().__init__(f)
        self.var_expr: cexpr_t = None
        self.variant: int = 0
        self.result = {}

    def visit_expr(self, expr: cexpr_t):
        print_expr_deep(expr)
        print_expr_deep(self.var_expr)
        return 0

def print_expr_deep(expr: cexpr_t, indent: str = ""):
    if expr:
        print("%s: %s" % (indent, text_expr(expr)))
        print_expr_deep(expr.x, indent + ".x")
        print_expr_deep(expr.y, indent + ".y")
