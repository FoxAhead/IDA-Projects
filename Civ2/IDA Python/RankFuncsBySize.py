import ida_funcs
import ida_idaapi
import ida_segment
import idautils
import idc

import lib

ida_idaapi.require("lib")


def main():
    d = {}
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        for funcea in idautils.Functions(seg.start_ea, seg.end_ea):
            if not lib.func_is_lib(funcea):
                func = ida_funcs.get_func(funcea)
                d[func.start_ea] = func.end_ea - func.start_ea
    l = sorted(d.items(), key=lambda item: item[1], reverse=True)
    print("Pos  Addr   Size Name")
    for idx, (ea, s) in enumerate(l[:100]):
        print("%.3d. %.6X %.4X %s" % (idx + 1, ea, s, idc.get_func_name(ea)))


if __name__ == '__main__':
    main()
