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

    matlist = [
        [str(ida_hexrays.MMAT_LOCOPT), 'MMAT_LOCOPT'],
        [str(ida_hexrays.MMAT_CALLS), 'MMAT_CALLS'],
        [str(ida_hexrays.MMAT_GLBOPT1), 'MMAT_GLBOPT1'],
        [str(ida_hexrays.MMAT_GLBOPT2), 'MMAT_GLBOPT2'],
        [str(ida_hexrays.MMAT_GLBOPT3), 'MMAT_GLBOPT3'],
        [str(ida_hexrays.MMAT_LVARS), 'MMAT_LVARS'],
    ]
    print(matlist)
    chooser = MaturityChoose(matlist)
    chooser.deflt = 4
    level = chooser.Show(modal=True)
    if level <= 0:
        print("Canceled")
        return
    mba = get_microcode(func, int(matlist[level][0]))
    G = nx.DiGraph()
    blk = mba.blocks
    while blk:
        for pred in list(blk.predset):
            G.add_edge(pred, blk.serial)
        blk = blk.nextb
    fname = r"D:\graph_%.X.graphml" % mba.entry_ea
    nx.write_graphml_lxml(G, fname)
    print("Graph for %s exported to: %s" % (matlist[level][1], fname))


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


class MaturityChoose(ida_kernwin.Choose):

    def __init__(self, items):
        ida_kernwin.Choose.__init__(
            self,
            "Select maturity level",
            [
                ["Level", ida_kernwin.Choose.CHCOL_DEC | 10],
                ["Maturity", ida_kernwin.Choose.CHCOL_PLAIN | 60],
            ],
            icon=-1, y1=-2,
            flags=ida_kernwin.Choose.CH_MODAL | ida_kernwin.Choose.CH_NOIDB)
        self.items = items

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)
