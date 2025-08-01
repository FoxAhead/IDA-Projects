"""
summary: Optimization 19

description:

    Float comparisons

        Replace
            if ( (LODWORD(a2) & 0x7FFFFFFF) != 0 )               =>  if ( a2 )
            if ( (LODWORD(a1) & 0x7FFFFFFF) == 0 )               =>  if ( !a1 )
            LODWORD(V_Game.ships[v3].position.y) != 0x3F800000)  =>  V_Game.ships[v3].position.y != 1.0

test:

    5358C
    3C968
    1D834

"""
from ida_ieee import fpvalue_t, EONE
from ida_typeinf import tinfo_t

from ascendancy.utils import *


def run(cfunc):
    if is_func_lib(cfunc.entry_ea):
        return 0
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
        if self.func.maturity == 0 and self.is_expr_comp(expr):
            # print_expr_deep(expr)
            # print_expr_deep(self.var_expr)
            self.var_expr.type = get_float_type(4)
            tinf = tinfo_t()
            tinf.create_ptr(get_float_type(4))
            self.var_expr.x.type = tinf
            if self.variant == 1:
                if expr.op == cot_ne:
                    expr.replace_by(self.var_expr)
                elif expr.op == cot_eq:
                    nexpr = cexpr_t(cot_lnot, cexpr_t(self.var_expr))
                    nexpr.type = expr.type  # bool
                    expr.replace_by(nexpr)
                self.recalc_parent_types()
            elif self.variant == 2:
                nyexpr = cexpr_t()
                nyexpr.op = cot_fnum
                nyexpr.fpc = fnumber_t()
                nyexpr.type = get_float_type(4)
                nyexpr.fpc.fnum = fpvalue_t(EONE)
                expr.y.replace_by(nyexpr)
                expr.exflags = EXFL_FPOP
                self.recalc_parent_types()
            self.result[hex_addr(expr.ea)] = get_expr_name(expr)
            # print("after:", text_expr(expr))
            # print_expr_deep(expr)
        return 0
        # if expr.op == cit_if and expr.ea == 0x5359A:
        if self.func.maturity == 0 and expr.ea == 0x5359A:
            print_expr_deep(expr)
            print("exflags", expr.exflags)
            xexpr = expr.x.x.x.x.x
            yexpr = expr.y

            nyexpr = cexpr_t()

            # nyexpr.op = cot_num
            # nyexpr.n = cnumber_t()
            # nyexpr.n.assign(1, 4, 1)
            # nyexpr.type = yexpr.type

            nyexpr.op = cot_fnum
            nyexpr.fpc = fnumber_t()
            nyexpr.type = get_float_type(4)

            # nyexpr.calc_type(False)
            print(text_expr(nyexpr))

            nexpr = cexpr_t(cot_ne, cexpr_t(xexpr), cexpr_t(nyexpr))
            nexpr.ea = 0x5359B
            nexpr.type = expr.type
            nexpr.exflags = EXFL_FPOP
            print("exflags", nexpr.exflags)
            # nexpr.y = cexpr_t()
            # nexpr.y.op = cot_fnum
            # nexpr.y.type = xexpr.type
            nexpr.calc_type(True)
            print(text_expr(nexpr))
            print("x:", text_expr(nexpr.x))
            print("y:", text_expr(nexpr.y))

            expr.replace_by(xexpr)
            self.recalc_parent_types()
            print("after:", text_expr(expr))

            # nexpr.op = cot_eq
            # nexpr.ea = expr.ea
            # nexpr.x = cexpr_t()
        return 0

    def is_expr_comp(self, expr: cexpr_t):
        self.variant = 0
        if expr.op in {cot_ne, cot_eq}:
            # print_expr_deep(expr)
            if (xexpr := expr.x) and xexpr.op == cot_band and xexpr.y and xexpr.y.is_const_value(0x7FFFFFFF):
                self.variant = 1
            elif (xexpr := expr) and expr.y and expr.y.is_const_value(0x3F800000):
                self.variant = 2
            if self.variant > 0 and (xexpr := xexpr.x) and xexpr.op == cot_ptr:
                var_expr = xexpr
                if (xexpr := xexpr.x) and (xexpr.op == cot_cast):
                    self.var_expr = var_expr
                    return True
                    if (xexpr := xexpr.x) and (xexpr.op == cot_ref):
                        if (xexpr := xexpr.x) and (xexpr.op == cot_var):
                            if xexpr.type.is_floating():
                                self.var_expr = xexpr
                                return True
                    elif xexpr:
                        self.var_expr = xexpr
                        return True

        return False


def print_expr_deep(expr: cexpr_t, indent: str = ""):
    if expr:
        print("%s: %s" % (indent, text_expr(expr)))
        print_expr_deep(expr.x, indent + ".x")
        print_expr_deep(expr.y, indent + ".y")
