import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import networkx as nx


def run(ctx):
    current_address = ida_kernwin.get_screen_ea()
    if current_address == ida_idaapi.BADADDR:
        ida_kernwin.warning("Could not open Microcode Explorer (bad cursor address)")
        return
    func = ida_funcs.get_func(current_address)
    if not func:
        return False
    mba = get_microcode(func, ida_hexrays.MMAT_GLBOPT3)
    G = nx.DiGraph()
    blk = mba.blocks
    while blk:
        for pred in list(blk.predset):
            G.add_edge(pred, blk.serial)
        blk = blk.nextb
    fname = r"D:\graph_%.X.graphml" % mba.entry_ea
    nx.write_graphml_lxml(G, fname)
    print("Graph exported to: %s" % fname)


def get_microcode(func, maturity):
    """
    Return the mba_t of the given function at the specified maturity.
    """
    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    ml = ida_hexrays.mlist_t()
    ida_hexrays.mark_cfunc_dirty(func.start_ea)
    mba = ida_hexrays.gen_microcode(mbr, hf, ml, ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_ALL_BLKS, maturity)
    if not mba:
        print("0x%08X: %s" % (hf.errea, hf.desc()))
        return None
    return mba
