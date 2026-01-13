"""
summary: Optimization 21

description:

    Optimization 21

test:


"""
from ascendancy.utils import *


def run(cfunc):
    if is_func_lib(cfunc.entry_ea):
        return 0
    vstr = Visitor21(cfunc)
    vstr.apply_to(cfunc.body, None)
    # if vstr.ea_lst:
    #     print_to_log("Optimization 20 static comments: %s" % list(map(hex, vstr.ea_lst)))


class Visitor21(cfunc_parentee_t):
    def visit_expr(self, expr):
        if expr.op == cot_call and expr.x and expr.x.op == cot_obj and expr.x.obj_ea == 0x34AE4 and expr.a:
            call_expr = expr
            a = call_expr.a[1]
            print(text_expr(a))
            if a.op == cot_num:
                print(a.n.nf.flags)
                print(a.n.nf.opnum)
                print(a.n.nf.props)

        return 0
