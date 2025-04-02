import ida_idp
import ida_kernwin
import ida_nalt
import ida_typeinf


def main():
    funcea = ida_kernwin.get_screen_ea()
    unspoil(funcea)
    ida_kernwin.refresh_idaview_anyway()
    return
    print(hex(funcea))

    tinfo = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(tinfo, funcea)
    function_details = ida_typeinf.func_type_data_t()
    tinfo.get_func_details(function_details)
    print("Len = %d" % len(function_details.spoiled))
    for s in function_details.spoiled:
        print(ida_idp.get_reg_name(s.reg, s.size))

    print("Flags = %d" % function_details.flags)
    function_details.flags = function_details.flags | 1
    # function_details.flags = 257
    print("Flags = %d" % function_details.flags)
    r = ida_idp.reg_info_t()
    # r.reg = 8
    # r.size = 4
    # function_details.spoiled.grow(r)
    # print(len(function_details.spoiled))
    # tinfo.create_func(function_details)
    # idaapi.apply_tinfo(funcea, tinfo, idaapi.TINFO_DEFINITE)


def unspoil(funcea):
    ti = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(ti, funcea)
    ftd = ida_typeinf.func_type_data_t()
    ti.get_func_details(ftd)
    ftd.flags = ftd.flags | ida_typeinf.FTI_SPOILED
    ftd.spoiled.clear()
    ti.create_func(ftd)
    ida_typeinf.apply_tinfo(funcea, ti, ida_typeinf.TINFO_DEFINITE)


if __name__ == '__main__':
    main()
