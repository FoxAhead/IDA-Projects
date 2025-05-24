"""
summary: Optimization 18

description:

    Q_WinMgr_FindWnd_sub_56DA8
    Q_WinMgr_FindWnd_sub_56E18

test:

    5294C - (00052B76)

"""
import re

from ida_typeinf import tinfo_t

from ascendancy.opts.windowstxt import *
from ascendancy.utils import *


def run(cfunc):
    if is_func_lib(cfunc.entry_ea):
        return 0
    # ida_kernwin.msg_clear()
    vstr = Visitor18(cfunc)
    vstr.apply_to(cfunc.body, None)
    if vstr.result:
        print_to_log("Optimization 18 (WinMgr_FindWnd): %s" % vstr.result)


class Visitor18(cfunc_parentee_t):

    def __init__(self, f: cfunc_t):
        super().__init__(f)
        self.typ0 = get_tinfo_by_ordinal(37)
        self.typ: tinfo_t = None
        self.call_expr: cexpr_t = None
        self.pexpr: cexpr_t = None
        self.wnd_name: str = ""
        self.ordinal: int = 0
        self.variant: int = 0
        self.result = {}

    def visit_expr(self, expr: cexpr_t):
        if self.is_expr_call_findwnd(expr):
            # root_expr = self._get_root_expr(expr)
            # print(" ", self.wnd_name)
            # print("    Call expr:", self.call_expr.type, get_expr_name(self.call_expr))
            # print("    Prnt expr:", text_expr(self.pexpr))
            # print("    Root expr:", get_expr_name(root_expr))
            # if self.variant == 0:
            #     return 0
            # print("    CHANGING: Variant=%d" %self.variant)
            if self.variant == 1:
                self.call_expr.type = self.typ0
                cast_expr = cexpr_t(cot_cast, cexpr_t(self.call_expr))
                cast_expr.type = self.typ
                # print("    Cast expr:", get_expr_name(cast_expr))
                self.call_expr.replace_by(cast_expr)
                self.recalc_parent_types()
                self.result[hex_addr(self.call_expr.ea)] = self.typ.dstr()
            elif self.variant == 2:
                self.call_expr.type = self.typ
            # print("    Call expr:", self.call_expr.type, get_expr_name(self.call_expr))
            # print("    Prnt expr:", text_expr(self.pexpr))
            # print("    Root expr:", get_expr_name(root_expr))
        return 0

    def is_expr_call_findwnd(self, expr: cexpr_t):
        if expr.op == cot_call and expr.x and expr.x.op == cot_obj and expr.x.obj_ea in {0x56DA8, 0x56E18} and expr.a:
            self.call_expr = expr
            self.wnd_name = get_expr_name(self.call_expr.a[1]).replace('"', '').replace('&', '')
            if self.wnd_name in wt.names:
                self.ordinal = find_ordinal_by_wnd_typen(wt.names[self.wnd_name])
                if self.ordinal > 0:
                    self.typ = get_tinfo_by_ordinal(self.ordinal)
                    self.pexpr = self.parent_expr()
                    if self.func.maturity == 3 and self.pexpr.op == cot_add:
                        self.variant = 2
                    elif self.func.maturity == 5 and self.pexpr.op != cot_cast:
                        self.variant = 1
                    else:
                        self.variant = 0
                    return True
        return False

    def _get_root_expr(self, expr):
        parent = expr
        while parent:
            if parent.op == cit_expr:
                break
            parent = self.func.body.find_parent_of(parent)
        return parent


def find_ordinal_by_wnd_typen(wnd_typen: int) -> int:
    for ordinal in range(1, idc.get_ordinal_qty()):
        name = idc.get_numbered_type_name(ordinal)
        if match := re.search(r'P_Wnd(\d{1,2})[a-zA-Z]+', name):
            d = int(match[1])
            if wnd_typen == d:
                return ordinal
    return 0
