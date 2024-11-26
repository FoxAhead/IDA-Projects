"""
summary: Optimization 4

description:

    Add comments with static strings from LABELS.TXT file

test:

    sub_40C7D0
    sub_42F293
    Q_PrepareTaxWindow_sub_40CD64 - 0040D2C0

"""
import idaapi
from ida_hexrays import *
import os
from civ2.opts.statictxt import *
from civ2.util import *

ADDRESSES = [[0x00401BF4, 0x00403995, 0x00403387], [0x00409520, 0x0048F30B, 0x0042095E]]


def run(cfunc, mode=0):
    if is_func_lib(cfunc.entry_ea):
        return 0
    # cfunc.del_orphan_cmts()
    # cfunc.save_user_cmts()
    vstr = Visitor5(cfunc, mode)
    vstr.apply_to(cfunc.body, None)
    if vstr.ea_lst:
        print_to_log("Optimization 5 (%d) static comments: %s" % (mode, list(map(hex, vstr.ea_lst))))
    # cfunc.del_orphan_cmts()
    # cfunc.save_user_cmts()
    # vstr.apply_to_exprs(cfunc.body, None)


class Visitor5(cfunc_parentee_t):
    ea_lst = []

    def __init__(self, cfunc, mode):
        self.ea_lst.clear()
        self.mode = mode
        cfunc_parentee_t.__init__(self, cfunc)

    # def visit_expr(self, expr):
    #     print("%.8X:" % expr.ea, self._get_expr_name(expr))
    #     return 0

    def visit_expr(self, expr):
        if expr.op == cot_call and expr.x and expr.x.op == cot_obj and expr.a:
            if expr.x.obj_ea == ADDRESSES[self.mode][0]:
                if expr.a[0].op == cot_num:
                    # print("%.8X: %s" % (expr.ea, self._get_expr_name(expr)))
                    val = expr.a[0].get_const_value()
                    self.create_cmt(self._get_parent_expr_ea(expr), val, st.labels[self.mode][val])
                    # print("%.8X: %s" % (tl.ea, cmt))
                elif expr.a[0].op == cot_add:
                    if expr.a[0].y and expr.a[0].y.op == cot_num:
                        val = expr.a[0].y.get_const_value()
                        self.create_cmt(self._get_parent_expr_ea(expr), val, st.labels[self.mode][val])
                # else:
                #    self._find_and_comment_arg_var(expr)
            elif expr.x.obj_ea == ADDRESSES[self.mode][1]:
                if expr.a[1].op == cot_num:
                    val = expr.a[1].get_const_value()
                    self.create_cmt(self._get_parent_expr_ea(expr), val, st.labels[self.mode][val])
            elif expr.x.obj_ea == ADDRESSES[self.mode][2]:
                if expr.a[0].y and expr.a[0].y.op == idaapi.cot_num:
                    val = expr.a[0].y.get_const_value()
                    self.create_cmt(self._get_parent_expr_ea(expr), val, st.labels[self.mode][val])

            # elif expr.x.obj_ea == 0x00402C48:  # j_Q_CityHasImprovement_sub_43D20A
            #    if expr.a[1].op == cot_num:
            #        val = expr.a[1].get_const_value()
            #        self.create_cmt(self._get_parent_expr_ea(expr), val, st.improve[val], ITP_BLOCK1)
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
                self.create_cmt(ea, val, st.labels[val])

    def create_cmt(self, ea, val, text, itp1=ITP_SEMI):
        self.ea_lst.append(ea)
        cmt = "%d: %s" % (val, text)
        tl = treeloc_t()
        tl.ea = ea
        tl.itp = itp1
        self.func.set_user_cmt(tl, cmt)
        self.func.save_user_cmts()
        # return
        commentSet = False
        # since the public documentation on IDAs APIs is crap and I don't know any other way, we have to brute force the item preciser
        # we do this by setting the comments with different idaapi.ITP_* types until our comment does not create an orphaned comment
        # for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        #    tl.itp = itp
        #    self.func.set_user_cmt(tl, cmt)
        #    self.func.save_user_cmts()
        #    #apparently you have to cast cfunc to a string, to make it update itself
        #    unused = self.__str__()
        #    if not self.func.has_orphan_cmts():
        #        commentSet = True
        #        self.func.save_user_cmts()
        #        break
        #    self.func.del_orphan_cmts()
        #    #self.func.save_user_cmts()
        #    #unused = self.__str__()


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
