import ida_allins
import ida_auto
import ida_range
import ida_segment
import ida_tryblks
import ida_ua
import idautils
import ida_funcs
import ida_idaapi
import ida_frame
# import ida_bytes
import ida_name
import idc

import lib

ida_idaapi.require("lib")


def print_funcs_with_chunks():
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        for funcea in idautils.Functions(seg.start_ea, seg.end_ea):
            if not lib.func_is_lib(funcea):
                func = ida_funcs.get_func(funcea)
                if func.tailqty > 0:
                    print("%X" % funcea, func.tailqty, ida_funcs.get_func_name(funcea))
                # fii = ida_funcs.func_item_iterator_t()
                # insn = ida_ua.insn_t()


def fix_CxxFrameHandler_xrefs_names():
    ea = 0x005F1E90  # ___CxxFrameHandler
    for ref in idautils.CodeRefsTo(ea, 1):
        func = ida_funcs.get_func(ref)
        caller_name = ida_funcs.get_func_name(ref)

        prev_insn = idc.prev_head(ref)
        prev_name = ida_name.get_name(prev_insn)
        print("%X %s <- %X %s" % (prev_insn, prev_name, func.start_ea, caller_name))
        ida_name.set_name(prev_insn, '', 0)
        new_name = "SEH_%X" % func.start_ea
        ida_name.set_name(prev_insn, new_name, ida_name.SN_LOCAL)
        #print(f"  Called from {caller_name} at {hex(ref)}")
        #print(f"  Stack pointer delta (spd): {hex(spd) if spd is not None else 'unknown'}")


def fix_CxxFrameHandler_stkpnts():
    fix = True
    debug = True
    single_ea = 0x4E2803

    ea = 0x005F1E90  # ___CxxFrameHandler
    for ref in idautils.CodeRefsTo(ea, 1):
        func = ida_funcs.get_func(ref)
        if single_ea and func.start_ea != single_ea:
            continue
        caller_name = ida_funcs.get_func_name(ref)
        prev_insn = idc.prev_head(ref)
        next_insn = idc.next_head(ref)
        spd = ida_frame.get_sp_delta(func, next_insn)
        print("%X %X <- %X %s" % (ref, spd, func.start_ea, caller_name))

        #fix_tryblocks(func)

        tryblks = ida_tryblks.tryblks_t()
        fr = ida_range.range_t(func.start_ea, func.end_ea)
        ida_tryblks.get_tryblks(tryblks, fr)
        ceas = []
        for tryblk in tryblks:
            if tryblk.is_cpp() and tryblk.size() == 1:
                catches: ida_tryblks.catchvec_t = tryblk.cpp()
                if catches.size() == 1 and catches.at(0).size() == 1:
                    cea = catches.at(0).at(0).start_ea
                    ceas.append(cea)
        ceas.sort()
        after_retns = find_after_retn_upwards(ref, ceas[0])
        after_retns.pop(0)
        ceas = sorted(set(ceas + after_retns))

        stkpnts = {}
        for idx, cea in enumerate(ceas):
            d = 0 if idx else -4
            stkpnts[cea] = d
        stkpnts[prev_insn] = 4
        stkpnts[next_insn] = 0
        leave_addr = find_leave_after_ref(ref)
        if leave_addr:
            sp = ida_frame.get_spd(func, leave_addr + 1)
            spd = ida_frame.get_sp_delta(func, leave_addr + 1)
            stkpnts[leave_addr + 1] = spd - sp

        loceas = find_call_jump_loc_upwards(ref, func.start_ea)
        for locea in loceas:
            next_locea = idc.next_head(locea)
            if next_locea not in stkpnts:
                stkpnts[next_locea] = 0

        stkpnts = dict(sorted(stkpnts.items()))

        if debug:
            print("  points:")
            for p in func.points:
                spd = ida_frame.get_sp_delta(func, p.ea)
                print("%X %X %X" % (p.ea, p.spd, spd))
            print("  ceas:")
            for cea in ceas:
                sp = ida_frame.get_spd(func, cea)
                spd = ida_frame.get_sp_delta(func, cea)
                print("%X %X %X" % (cea, sp, spd))
            for tryblk in tryblks:
                debug_print_tryblock(tryblk)
            print("loceas")
            for locea in loceas:
                next_locea = idc.next_head(locea)
                sp = ida_frame.get_spd(func, next_locea)
                spd = ida_frame.get_sp_delta(func, next_locea)
                print("%X %X %X %s" % (next_locea, sp, spd, next_locea in stkpnts))
            print("stkpnts:")
            for stkpnt_ea, stkpnt_delta in stkpnts.items():
                print("%X %X" % (stkpnt_ea, stkpnt_delta))

        if fix:
            for stkpnt_ea, stkpnt_delta in stkpnts.items():
                ida_frame.add_user_stkpnt(stkpnt_ea, stkpnt_delta)
                if debug:
                    print("add_user_stkpnt %X %X" % (stkpnt_ea, stkpnt_delta))
            if debug:
                print("reanalyze_function %X" % func.start_ea)
            func.flags &= ~ida_funcs.FUNC_SP_READY
            ida_funcs.update_func(func)
            ida_funcs.reanalyze_function(func)
            ida_auto.auto_wait()


def fix_tryblocks(func: ida_funcs.func_t):
    tryblks = ida_tryblks.tryblks_t()
    fr = ida_range.range_t(func.start_ea, func.end_ea)
    ida_tryblks.get_tryblks(tryblks, fr)
    modified = []
    for tryblk in tryblks:
        if tryblk.is_cpp() and tryblk.size() == 1:
            catches: ida_tryblks.catchvec_t = tryblk.cpp()
            if catches.size() == 1 and catches.at(0).size() == 1:
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, tryblk.at(0).end_ea):
                    if insn.itype == ida_allins.NN_mov:
                        if insn.Op1.type == ida_ua.o_displ and insn.Op1.phrase == 5 and idc.get_operand_value(insn.ea, 0) == 0xFFFFFFFC:
                            # Found  mov [ebp+var_4]
                            print("%X, %d, %d, %X" % (insn.ea, insn.Op1.type, insn.Op1.phrase, idc.get_operand_value(insn.ea, 0)))
                            next_ea = insn.ea + insn.size
                            next_insn = ida_ua.insn_t()
                            if ida_ua.decode_insn(next_insn, next_ea) and next_insn.itype == ida_allins.NN_call:
                                call_ea = next_insn.Op1.addr
                                if func.start_ea <= call_ea < func.end_ea:
                                    #print("%X, %d, %d, %d, %X" % (next_insn.ea, next_insn.itype, next_insn.Op1.type, next_insn.Op1.phrase, idc.get_operand_value(next_insn.ea, 0)))
                                    if catches.at(0).at(0).start_ea != next_insn.Op1.addr:
                                        modified.append((catches.at(0).at(0).start_ea, next_insn.Op1.addr))
                                        catches.at(0).at(0).start_ea = next_insn.Op1.addr
    if modified:
        for a, b in modified:
            print("Fixed cleanup from %X to %X" % (a, b))
        ida_tryblks.del_tryblks(fr)
        for tryblk in tryblks:
            ida_tryblks.add_tryblk(tryblk)

def print_names():
    for ea, n in idautils.Names():
        print("%X %s" % (ea, n))


def debug_print_tryblock(tryblk: ida_tryblks.tryblk_t):
    print("tryblk.get_kind():", tryblk.get_kind())
    for r in tryblk:
        print("  %X : %X" % (r.start_ea, r.end_ea))
    if tryblk.is_cpp():
        for catch in tryblk.cpp():  # catch_t(try_handler_t) in catchvec_t
            print("  catch: obj:%d, type_id:%d, disp:%d, fpreg:%d" % (catch.obj, catch.type_id, catch.disp, catch.fpreg))
            for r in catch:
                print("    %X : %X" % (r.start_ea, r.end_ea))


def find_leave_after_ref(ref):
    # expected_addr = ref + 18
    current_ea = ref

    # print(f"Searching for 'leave' starting from {hex(ref)}...")

    # Проходим 6 инструкций вперед
    for i in range(1, 7):
        # Переходим к следующей инструкции
        current_ea = idc.next_head(current_ea)

        # Получаем мнемонику (текст команды)
        mnemonic = idc.print_insn_mnem(current_ea)

        if mnemonic == "leave":
            # print(f"  [+] Found 'leave' at {hex(current_ea)} (Step {i})")

            # # Проверка на конкретное смещение +18
            # if current_ea == expected_addr:
            #     print(f"  [!] Match! It is exactly at ref + 0x18")
            # else:
            #     print(f"  [-] Note: Found at {hex(current_ea)}, but expected {hex(expected_addr)}")
            return current_ea

    # print("  [-] 'leave' not found within 6 instructions.")
    return None


def find_after_retn_upwards(from_ea, limit_ea):
    """
    Ищет все 'retn' (0xC3) от start_ea вверх до limit_ea.
    """
    found_retns = []
    current_ea = idc.prev_head(from_ea)

    #print(f"Scanning upwards for 'retn' from {hex(start_ea)} to {hex(limit_ea)}...")

    while current_ea >= limit_ea and current_ea != idc.BADADDR:
        # Проверяем опкод (0xC3 для retn)
        if idc.get_wide_byte(current_ea) == 0xC3:
            # Дополнительная проверка мнемоники для надежности
            if idc.print_insn_mnem(current_ea) == "retn":
                #print(f"  [+] Found 'retn' at {hex(current_ea)}")
                found_retns.append(current_ea + 1)

        current_ea = idc.prev_head(current_ea)

    return found_retns


def find_call_jump_loc_upwards(from_ea, limit_ea):
    found_eas = []
    current_ea = idc.prev_head(from_ea)
    while current_ea >= limit_ea and current_ea != idc.BADADDR:
        mnem = idc.GetDisasm(current_ea)
        #print(mnem)
        if mnem.startswith("call    loc_") or mnem.startswith("jmp     loc_"):
            found_eas.append(current_ea)
        current_ea = idc.prev_head(current_ea)
    return found_eas


if __name__ == '__main__':
    # print_funcs_with_chunks()

    # fix_CxxFrameHandler_xrefs_names()

    fix_CxxFrameHandler_stkpnts()

    # print_names()
