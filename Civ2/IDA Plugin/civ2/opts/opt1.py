"""
summary: Optimization 1

description:
    Change
        SLOBYTE(Game.MapFlags) < 0
    to
        (Game.MapFlags & 0x80) != 0

test:

    40E017
    486E6F - SLOBYTE(Game.MapFlags) >= 0
    4308AE - SLOBYTE(Civs[aCiv1].Treaties[aIndex]) < 0

"""
import ida_bytes
import ida_hexrays
import ida_ua
import idaapi

from civ2.config import Config
from civ2.opts import GlbOpt
from civ2.utils import *


class Opt(GlbOpt):
    def __init__(self):
        super().__init__(1, "Opt1")

    def _init(self):
        pass

    def _run(self):
        # return
        opcodes = {m_jge: m_jz, m_jl: m_jnz}
        veas = [Config["Game_GraphicAndGameOptions"], Config["Game_MapFlags"], 0x655AE8, 0x655AF2, 0x655AF4]
        eas = []
        for self.blk in all_blocks_in_mba(self.mba):
            self.blk_changed = False
            for self.insn in all_insns_in_block(self.blk):
                if self.insn.opcode in opcodes and self.insn.r.t == mop_n and self.insn.r.is_zero():
                    # print(text_insn(self.insn))
                    if test80ea := self.find_test80ea(self.insn.ea):
                        insnl = None
                        if self.insn.l.t == mop_v and self.insn.l.g in veas:
                            insnl = InsnBuilder(test80ea, m_and, 1).v(self.insn.l.g).n(0x80, test80ea, 1).insn()
                            insnl.l.size = 1
                        elif self.insn.l.t == mop_d:
                            subinsn = self.insn.l.d
                            #if not subinsn.r.is_insn(m_call):
                            insnl = InsnBuilder(test80ea, m_and, 1).i(subinsn).n(0x80, test80ea, 1).insn()
                            insnl.l.size = 1
                            insnl.r.size = 1
                        if insnl:
                            #insnl.r.ea = self.insn.ea
                            #self.insn.r.nnn.ea = test80ea
                            self.insn.r.nnn.ea = self.insn.ea
                            self.insn.l.create_from_insn(insnl)
                            self.insn.opcode = opcodes[self.insn.opcode]
                            self.blk_changed = True
                            eas.append(self.insn.ea)

            if self.blk_changed:
                self.mark_dirty(self.blk)
        if eas:
            print_to_log("Optimization 1 (Test 80h): %s" % hex_eas(eas))

    def find_test80ea(self, ea):
        for i in range(2):
            mnem = idc.GetDisasm(ea)
            # print("%X" % ea, mnem)
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea):
                # for op in insn.ops:
                #     print(op.n, op.type)
                #     if op.type == ida_ua.o_imm:
                #         print(op.value)
                if mnem.startswith("test") and insn.Op2.type == ida_ua.o_imm and insn.Op2.value == 0x80:
                    # print("%X" % ea)
                    return ea
            ea = idc.prev_head(ea)


def set_enums(cfunc: cfunc_t):
    if cfunc.maturity < CMAT_CASTED:
        return 0
    if is_func_lib(cfunc.entry_ea):
        return 0
    # First pass: bitwise negate
    vstr = Visitor1a(cfunc)
    vstr.apply_to(cfunc.body, None)
    if vstr.ea_lst:
        print_to_log("Optimization 1 bitwise negate: %s" % hex_eas(vstr.ea_lst))
    # Second pass: change to enum
    vstr = Visitor1b(cfunc)
    vstr.apply_to(cfunc.body, None)
    if vstr.ea_lst:
        print_to_log("Optimization 1 set enums: %s" % hex_eas(vstr.ea_lst))

    # nfs = restore_user_numforms(cfunc.entry_ea)
    # for locator, nf in nfs.items():
    #     print("%X %d" % (locator.ea, locator.opnum))
    #     debug_print_numform(nf)
    # for locator, nf in cfunc.numforms.items():
    #     print("%X %d" % (locator.ea, locator.opnum))
    #     debug_print_numform(nf)


class Visitor1(cfunc_parentee_t):
    def __init__(self, cfunc):
        self.ea_lst = []
        super().__init__(cfunc)

    def _get_macro_type(self, expr: cexpr_t, take_all=False):
        if expr.op == cot_num and (not expr.n.nf.is_enum() or take_all):
            if parent_expr := self.parents.back().cexpr:
                if blogexpr := self._get_parent_bool_logic(expr):
                    if blogexpr.x.op == cot_memref:
                        if blogexpr.x.m == 0:
                            if blogexpr.x.x.op == cot_idx:
                                if blogexpr.x.x.x.op == cot_obj:
                                    if blogexpr.x.x.x.obj_ea == 0x64C6A0:
                                        return 'MACRO_CIV2_CIV_FLAGS'
                            elif blogexpr.x.x.op == cot_obj:
                                if blogexpr.x.x.obj_ea == 0x64BC60:
                                    return 'MACRO_CIV2_SCN_FLAGS'
                                elif blogexpr.x.x.obj_ea == 0x655AE8:
                                    return 'MACRO_CIV2_CUSTOM_FEATURES'
                        elif blogexpr.x.m == 2:
                            if blogexpr.x.x.op == cot_obj:
                                if blogexpr.x.x.obj_ea == 0x655AE8:
                                    return 'MACRO_CIV2_OPTIONS'
                        elif blogexpr.x.m == 4:
                            if blogexpr.x.x.op == cot_idx:
                                if blogexpr.x.x.x.op == cot_obj:
                                    if blogexpr.x.x.x.obj_ea == 0x6560F0:
                                        return 'MACRO_CIV2_UNIT_ATTRIBUTES'
                                    elif blogexpr.x.x.x.obj_ea == 0x64F340:
                                        return 'MACRO_CIV2_CITY_ATTRIBUTES'
                                    elif blogexpr.x.x.x.obj_ea == 0x64B1B8:
                                        return 'MACRO_CIV2_UNIT_ABILITIES'
                        elif blogexpr.x.m == 8:
                            if blogexpr.x.x.op == cot_obj and blogexpr.x.x.obj_ea == 0x655AE8:
                                return 'MACRO_CIV2_MAP_FLAGS'
                    elif blogexpr.x.op == cot_idx:
                        if blogexpr.x.x.op == cot_memref and blogexpr.x.x.m == 32:
                            if blogexpr.x.x.x.op == cot_idx:
                                if blogexpr.x.x.x.x.op == cot_obj and blogexpr.x.x.x.x.obj_ea == 0x64C6A0:
                                    return 'MACRO_CIV2_TREATY'
                elif parent_expr.op in [cot_idx]:
                    if parent_expr.x.op == cot_memref:
                        if parent_expr.x.m == 160:
                            if parent_expr.x.x.op == cot_obj and parent_expr.x.x.obj_ea == 0x6A6528:
                                return 'MACRO_CIV2_RESOURCES'
                        elif parent_expr.x.m in [54, 154]:
                            if parent_expr.x.x.op == cot_obj and parent_expr.x.x.obj_ea == 0x655AE8:
                                return 'MACRO_CIV2_TECH'
                        elif parent_expr.x.m == 216:
                            if parent_expr.x.x.op == cot_idx:
                                if parent_expr.x.x.x.op == cot_obj and parent_expr.x.x.x.obj_ea == 0x64C6A0:
                                    return 'MACRO_CIV2_UNIT_TYPE'
                        elif parent_expr.x.m == 980:
                            if parent_expr.x.x.op == cot_idx:
                                if parent_expr.x.x.x.op == cot_obj and parent_expr.x.x.x.obj_ea == 0x64C6A0:
                                    return 'MACRO_CIV2_GOVERNMENT'
                    elif parent_expr.x.op == cot_obj:
                        if parent_expr.x.obj_ea == 0x64B1B8:
                            return 'MACRO_CIV2_UNIT_TYPE'
                        elif parent_expr.x.obj_ea == 0x64C488:
                            return 'MACRO_CIV2_IMPROVEMENT'
                elif parent_expr.op == cot_call:
                    if parent_expr.x.op == cot_obj and parent_expr.x.obj_ea in [0x4019A6, 0x403990]:
                        if parent_expr.a[2].ea == expr.ea:
                            return 'MACRO_CIV2_TREATY'

        return None

    def _get_parent_bool_logic(self, expr):
        parents_size = self.parents.size()
        if pexpr := self.parents.back().cexpr:
            if pexpr.op == cot_bnot:
                pexpr = self.parents.at(parents_size - 2).cexpr
            if pexpr and pexpr.op in [cot_band, cot_asgbor, cot_asgband, cot_asgxor]:
                return pexpr
        return None


class Visitor1a(Visitor1):
    def visit_expr(self, expr: cexpr_t):
        # if expr.op == cot_num:
        #     nf = expr.n.nf
        #     print(text_expr(expr))
        #     debug_print_numform(nf)
        if macro_type := self._get_macro_type(expr, True):
            #print("%X" % expr.ea, macro_type)
            original_value, inverted_value = self._need_bitwise_negate(expr)
            if inverted_value:
                nf = expr.n.nf
                #print("%X: bitwise negate %X to %X" %(expr.ea, original_value, inverted_value))
                #debug_print_numform(nf)
                #return 0
                self.ea_lst.append(expr.ea)
                expr.put_number(self.func, inverted_value, ord(expr.n.nf.org_nbytes))
                nf.flags = ida_bytes.hex_flag()
                nf.props = chr(ord(nf.props) | NF_BITNOT | NF_BINVDONE | NF_VALID)
                nexpr = ida_hexrays.cexpr_t(cot_bnot, cexpr_t(expr))
                nexpr.type = expr.type
                expr.replace_by(nexpr)
                self.recalc_parent_types()
                ol = operand_locator_t(expr.ea, ord(nf.opnum))
                nfs = self.func.numforms
                if ol in nfs:
                    del nfs[ol]
                nfs[ol] = nf
                self.func.save_user_numforms()
        return 0

    def _need_bitwise_negate(self, expr: cexpr_t):
        if parent_expr := self.parents.back().cexpr:
            if parent_expr.op != cot_bnot:
                nbytes = ord(expr.n.nf.org_nbytes)
                mask = (1 << (nbytes * 8)) - 1
                original_value = expr.numval() & mask
                inverted_value = (~original_value) & mask
                #print("%X to %X, type_size=%d, mask=%X" % (original_value, inverted_value, nbytes, mask))
                #debug_print_numform(expr.n.nf)
                if bin(original_value).count('1') > bin(inverted_value).count('1'):
                    return original_value, inverted_value
        return None, None


class Visitor1b(Visitor1):
    def visit_expr(self, expr: cexpr_t):
        if macro_type := self._get_macro_type(expr):
            if expr.ea == 0xFFFFFFFF:
                #print(hex(self.parents.back().cexpr.ea))
                expr.ea = self.parents.back().cexpr.ea
            if expr.ea == 0xFFFFFFFF:
                return 0
            self.ea_lst.append(expr.ea)
            # numfmt = ida_hexrays.number_format_t()
            # numfmt.flags = ida_bytes.enum_flag()
            # numfmt.serial = 0
            # numfmt.type_name = macro_type
            #
            # lnid = ida_hexrays.operand_locator_t(expr.ea, expr.opnum)
            #
            # ida_hexrays.save_user_numfmt(lnid, numfmt)

            nf = expr.n.nf
            nf.flags = ida_bytes.enum_flag()
            nf.serial = 0
            nf.props = chr(ord(nf.props) | NF_VALID)
            nf.type_name = macro_type
            # expr.type.get_named_type(idaapi.cvar.idati, macro_type, ida_typeinf.BTF_ENUM)
            expr.type = create_typedef(macro_type)

            ol = operand_locator_t(expr.ea, ord(nf.opnum))
            nfs = self.func.numforms
            if ol in nfs:
                del nfs[ol]
            nfs[ol] = nf
            self.func.save_user_numforms()

        # if expr.op == cot_num and expr.n.nf.is_enum():
        #     print(text_expr(expr), "parents:", len(self.parents))
        #     print('  ', text_expr(self.parents.back()))
        #     print('    ', text_expr(self.parents.back().back()))

        #nf = expr.n.nf
        #print("flags=%X opnum=%X props=%X serial=%X org_nbytes=%X : %s" % (nf.flags, ord(nf.opnum), ord(nf.props), nf.serial, ord(nf.org_nbytes), text_expr(expr)))
        return 0


def fix_casts(cfunc: cfunc_t):
    if cfunc.maturity < CMAT_CASTED:
        return 0
    if is_func_lib(cfunc.entry_ea):
        return 0
    vstr = Visitor1c(cfunc)
    vstr.apply_to(cfunc.body, None)
    if vstr.ea_lst:
        print_to_log("Optimization 1 (Test 80h): removed casts %s" % hex_eas(vstr.ea_lst))


class Visitor1c(cfunc_parentee_t):
    def __init__(self, cfunc):
        self.ea_lst = []
        super().__init__(cfunc)

    def visit_expr(self, expr: cexpr_t):
        if expr.op == cot_num:
            t = expr.type._print()
            if t.startswith('MACRO_CIV2_'):
                if self.parents:
                    parent_expr = self.parents.back().cexpr
                    #print(text_expr(self.parents.back().cexpr))
                    # print(self.parents.front())
                    # top_parent = self.parents.front()
                    # if top_parent.cexpr:
                    #     root_node = top_parent.cexpr  # Корневое выражение
                    # elif top_parent.cinsn:
                    #     root_node = top_parent.cinsn
                    if parent_expr.op == cot_cast:
                        self.ea_lst.append(expr.ea)
                        #print(text_expr(parent_expr))
                        parent_expr.replace_by(expr)
                        #expr.cleanup()
                        #self.recalc_parent_types()
                        #print(text_expr(root_node))
                        return 1
        return 0


def debug_print_numform(nf: number_format_t):
    print("flags=%X opnum=%X props=%X serial=%X org_nbytes=%X" % (nf.flags, ord(nf.opnum), ord(nf.props), nf.serial, ord(nf.org_nbytes)))
