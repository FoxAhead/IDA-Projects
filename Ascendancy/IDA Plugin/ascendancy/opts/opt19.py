"""
summary: Optimization 19

description:

    Float comparisons

        Replace
            if ( (LODWORD(v1) & 0x7FFFFFFF) != 0 )
                or
            if ( (LODWORD(v1) & 0x7FFFFFFF) == 0 )
        with
            if ( v1 )
                or
            if ( !v1 )

test:

    5358C
    3C968
    1D834

"""
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
        self.result = {}

    def visit_expr(self, expr: cexpr_t):
        if self.func.maturity == 0 and self.is_expr_band(expr):
            # print_expr_deep(expr)
            if expr.op == cot_ne:
                expr.replace_by(self.var_expr)
            elif expr.op == cot_eq:
                nexpr = cexpr_t(cot_lnot, cexpr_t(self.var_expr))
                nexpr.type = expr.type
                expr.replace_by(nexpr)
            self.recalc_parent_types()
            self.result[hex_addr(expr.ea)] = get_expr_name(expr)
            #print("after:", text_expr(expr))
            #print_expr_deep(expr)
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

    def is_expr_band(self, expr: cexpr_t):
        if expr.op in {cot_ne, cot_eq}:
            if (xexpr := expr.x) and (xexpr.op == cot_band) and (yexpr := xexpr.y) and (yexpr.is_const_value(0x7FFFFFFF)):
                if (xexpr := xexpr.x) and (xexpr.op != cot_var):
                    self.var_expr = xexpr
                    if xexpr := xexpr.x:
                        #print_expr_deep(expr)
                        self.var_expr.type = get_float_type(4)
                        #self.var_expr.exflags = EXFL_FPOP
                        tinf = tinfo_t()
                        tinf.create_ptr(get_float_type(4))
                        self.var_expr.x.type = tinf
                        #self.var_expr.x.exflags = EXFL_FPOP
                        return True
                        if (xexpr := xexpr.x) and (xexpr.op == cot_ptr):
                            if (xexpr := xexpr.x) and (xexpr.op == cot_cast):
                                if (xexpr := xexpr.x) and (xexpr.op == cot_ref):
                                    if (xexpr := xexpr.x) and (xexpr.op == cot_var):
                                        if xexpr.type.is_floating():
                                            self.var_expr = xexpr
                                            return True
                                elif xexpr:
                                    self.var_expr = xexpr
                                    return True
        return False


def print_expr_deep(expr: cexpr_t):
    s = ""
    while expr:
        print(s, text_expr(expr))
        s = s + '.x'
        expr = expr.x
