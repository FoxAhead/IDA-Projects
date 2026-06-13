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
from civ2.config import Config
from civ2.resources import Resources
from civ2.utils import *


def run(cfunc):
    if is_func_lib(cfunc.entry_ea):
        return 0
    # cfunc.del_orphan_cmts()
    # cfunc.save_user_cmts()
    add_labels_comments(cfunc)
    add_dialog_comments(cfunc)
    # cfunc.del_orphan_cmts()
    # cfunc.save_user_cmts()
    # vstr.apply_to_exprs(cfunc.body, None)


def add_labels_comments(cfunc):
    vstr = Visitor5(cfunc)
    vstr.apply_to(cfunc.body, None)
    if vstr.ea_lst:
        print_to_log("Optimization 5 static comments: " + ", ".join("%.6X" % ea for ea in vstr.ea_lst))


def add_dialog_comments(cfunc):
    vstr = Visitor5dlg(cfunc)
    vstr.apply_to(cfunc.body, None)
    if vstr.ea_lst:
        print_to_log("Optimization 5 dialog comments: " + ", ".join("%.6X" % ea for ea in vstr.ea_lst))


class Visitor5(cfunc_parentee_t):
    def __init__(self, cfunc):
        self.ea_lst = []
        self.val = 0
        super().__init__(cfunc)

    def visit_expr(self, expr: cexpr_t):
        if self._is_string_indexes_array(expr):
            self.create_cmt(self._get_parent_expr_ea(expr), self.val, Resources["labels"][self.val])
        elif expr.op == cot_call and expr.x and expr.x.op == cot_obj and expr.a:
            if (expr.x.obj_ea == Config["txtStrcatLabelString"]) or (expr.x.obj_ea == Config["txtAppendLabelString"]):
                if expr.a[0].op == cot_num:
                    val = expr.a[0].get_const_value()
                    self.create_cmt(self._get_parent_expr_ea(expr), val, Resources["labels"][val])
                elif expr.a[0].op == cot_add:
                    if expr.a[0].y and expr.a[0].y.op == cot_num:
                        val = expr.a[0].y.get_const_value()
                        self.create_cmt(self._get_parent_expr_ea(expr), val, Resources["labels"][val])
                # else:
                #    self._find_and_comment_arg_var(expr)
            elif expr.x.obj_ea == Config["StrcatLabelString"]:
                if expr.a[1].op == cot_num:
                    val = expr.a[1].get_const_value()
                    self.create_cmt(self._get_parent_expr_ea(expr), val, Resources["labels"][val])
            elif expr.x.obj_ea == Config["GetStringInList"]:
                if expr.a[0].y and expr.a[0].y.op == idaapi.cot_num:
                    val = expr.a[0].y.get_const_value()
                    self.create_cmt(self._get_parent_expr_ea(expr), val, Resources["labels"][val])
            elif expr.x.obj_ea == Config["UpdateMenuItem"]:
                if expr.a[1].op == cot_num:
                    val = expr.a[1].get_const_value()
                    self.create_cmt(self._get_parent_expr_ea(expr), val, Resources["labels"][val])

        return 0

    def _is_string_indexes_array(self, expr: cexpr_t):
        if expr.op == cot_idx and expr.x.op == cot_obj and expr.x.obj_ea == 0x628420:  # g_StringIndexes
            e = expr.y
            while e:
                if e.op == cot_num:
                    self.val = e.numval()
                    return True
                e = e.y
        return False


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
                self.create_cmt(ea, val, Resources["labels"][val])

    def create_cmt(self, ea, val, text, itp1=ITP_SEMI):
        if ea in self.ea_lst:
            return
        self.ea_lst.append(ea)
        cmt = "%d: %s" % (val, text)
        tl = treeloc_t()
        tl.ea = ea
        tl.itp = itp1
        self.func.set_user_cmt(tl, cmt)
        self.func.save_user_cmts()
        # return
        # commentSet = False
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


class Visitor5dlg(cfunc_parentee_t):
    def __init__(self, cfunc):
        self.ea_lst = []
        super().__init__(cfunc)

    def visit_expr(self, expr: cexpr_t):
        if expr.op == cot_call and expr.x and expr.x.op == cot_obj and expr.a:
            aidx = -1
            if expr.x.obj_ea in [0x4012EE, 0x401EFB, 0x402167, 0x4025EA, 0x403904, 0x401B59, 0x402CCF, 0x4023E2, 0x4031CA, 0x4034A9, 0x4034FE]:
                aidx = 0
            elif expr.x.obj_ea in [0x403B25, 0x4037CE]:
                aidx = 1
            if aidx >= 0 and expr.a[aidx].op == cot_obj:
                str_addr = expr.a[aidx].obj_ea
                found_string = idc.get_strlit_contents(str_addr)
                if found_string:
                    section = found_string.decode('utf-8', errors='ignore')
                    if section in Resources["game"]:
                        self.create_cmt(self._get_parent_expr_ea(expr), Resources["game"][section])
        return 0

    def create_cmt(self, ea, text, itp1=ITP_BLOCK1):
        self.ea_lst.append(ea)
        cmt = "%s" % text
        tl = treeloc_t()
        tl.ea = ea
        tl.itp = itp1
        self.func.set_user_cmt(tl, cmt)
        self.func.save_user_cmts()

    def _get_parent_expr_ea(self, expr):
        parent = expr
        while parent:
            if parent.op > cot_last:
                break
            parent = self.func.body.find_parent_of(parent)
        return parent.ea if parent else expr.ea