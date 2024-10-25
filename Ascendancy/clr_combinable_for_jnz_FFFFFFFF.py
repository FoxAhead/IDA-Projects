"""
summary: various decompiler hooks

description:
  Shows how to hook to many notifications sent by the decompiler.

  This plugin doesn't really accomplish anything: it just prints
  the parameters.

  Also, the list of notifications handled below, isn't exhaustive.
  Please investigate `ida_hexrays.Hexrays_Hooks` for a full list.
"""
from __future__ import print_function

import ida_idaapi
import ida_typeinf
import ida_hexrays

class vds_hooks_t(ida_hexrays.Hexrays_Hooks):
    def _log(self, msg):
        print("### %s" % msg)
        return 0

    def combine(self, blk, insn):
        buf = insn.dstr()
        #if "0x100000000.8" in buf:
        #if "jz     [ds.2:(ebx.4{2}+#0x10C.4)].4, #0.4, @4" in buf:
        if ("jnz " in buf) and ("0xFFFFFFFF.4" in buf):
            #vp = ida_hexrays.vd_printer_t()
            #blk._print(vp)
            #print("FOUND")
            #print("INS=%s" % insn.dstr())
            insn.clr_combinable()
            return self._log("clr_combinable: insn=%s" % (buf))
            return 0
        else:
            return 0

vds_hooks = vds_hooks_t()
vds_hooks.hook()

