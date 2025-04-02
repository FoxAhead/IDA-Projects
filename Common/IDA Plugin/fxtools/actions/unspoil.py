import ida_hexrays
import ida_kernwin
import ida_nalt
import ida_typeinf


def run(ctx):
    vu = ida_hexrays.get_widget_vdui(ctx.widget)
    ti = ida_typeinf.tinfo_t()
    if not vu.cfunc.get_func_type(ti):
        return
    ftd = ida_typeinf.func_type_data_t()
    ti.get_func_details(ftd)
    ftd.flags = ftd.flags | ida_typeinf.FTI_SPOILED
    ftd.spoiled.clear()
    ti.create_func(ftd)
    ida_typeinf.apply_tinfo(vu.cfunc.entry_ea, ti, ida_typeinf.TINFO_DEFINITE)
    vu.refresh_view(True)
