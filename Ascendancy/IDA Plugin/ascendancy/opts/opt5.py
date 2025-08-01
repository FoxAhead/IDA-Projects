"""
summary: Optimization 5

description:

    Add comments with static strings from STATIC.TXT file

test:

    3A6BC
    1E094
    521C0
    50D70

"""

from ascendancy.opts.statictxt import *
from ascendancy.utils import *


def run(cfunc):
    if is_func_lib(cfunc.entry_ea):
        return 0
    # cfunc.del_orphan_cmts()
    # cfunc.save_user_cmts()
    vstr = Visitor5(cfunc)
    vstr.apply_to(cfunc.body, None)
    if vstr.ea_lst:
        print_to_log("Optimization 5 static comments: %s" % list(map(hex, vstr.ea_lst)))
    # cfunc.del_orphan_cmts()
    # cfunc.save_user_cmts()
    # vstr.apply_to_exprs(cfunc.body, None)


class Visitor5(cfunc_parentee_t):
    ea_lst = []

    def __init__(self, cfunc):
        self.ea_lst.clear()
        cfunc_parentee_t.__init__(self, cfunc)

    # def visit_expr(self, expr):
    #     print("%.8X:" % expr.ea, self._get_expr_name(expr))
    #     return 0

    def visit_expr(self, expr):
        if expr.op == cot_call and expr.x and expr.x.op == cot_obj and expr.x.obj_ea == 0x1CEA8 and expr.a:
            if expr.a[0].op == cot_num:
                # print("%.8X: %s" % (expr.ea, self._get_expr_name(expr)))
                val = expr.a[0].get_const_value()
                self.create_cmt(self._get_parent_expr_ea(expr), val)
                # print("%.8X: %s" % (tl.ea, cmt))
            elif expr.a[0].op == cot_add and expr.a[0].x.op == cot_var and expr.a[0].y.op == cot_num:
                val = expr.a[0].y.get_const_value()
                self.create_cmt(self._get_parent_expr_ea(expr), val)
            else:
                self._find_and_comment_arg_var(expr)
        return 0

    def _get_parent_expr_ea(self, expr):
        parent = expr
        while parent:
            if parent.op == cit_expr:
                break
            parent = self.func.body.find_parent_of(parent)
        return parent.ea if parent else expr.ea

    def _find_and_comment_arg_var(self, expr):
        (vstr := Visitor5a()).apply_to(expr, None)
        if vstr.found_expr_var:
            (vstr := Visitor5b(self.func, vstr.found_expr_var)).apply_to(self.func.body, None)
            for ea, val in vstr.found_places:
                self.create_cmt(ea, val)

    def create_cmt(self, ea, val):
        self.ea_lst.append(ea)
        # cmt = "Static text %d: %s" % (val, self.texts[val])
        cmt = "%d: %s" % (val, st.texts[val])
        tl = treeloc_t()
        tl.ea = ea
        tl.itp = ITP_SEMI
        self.func.set_user_cmt(tl, cmt)
        self.func.save_user_cmts()


class Visitor5a(ctree_visitor_t):
    found_expr_var = None

    def __init__(self):
        ctree_visitor_t.__init__(self, CV_FAST)

    def visit_expr(self, expr):
        if expr.op == cot_var:
            # print("%.8X: (%s) %s" % (expr.ea, get_ctype_name(expr.op), _get_expr_name(expr)))
            self.found_expr_var = expr
            return 1
        return 0


class Visitor5b(cfunc_parentee_t):

    def __init__(self, cfunc, expr_var):
        self.expr_var = expr_var
        self.found_places = []
        cfunc_parentee_t.__init__(self, cfunc)

    def visit_expr(self, expr):
        if expr.op == cot_var and expr == self.expr_var:
            parent = expr
            while parent := self.func.body.find_parent_of(parent):
                parent = parent.to_specific_type
                if parent.op == cot_asg and parent.y.op == cot_num:
                    # print_expr(parent)
                    self.found_places.append((parent.ea, parent.y.get_const_value()))
                    break
                elif parent.op == cot_call:
                    break
        return 0
