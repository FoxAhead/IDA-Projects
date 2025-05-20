import ida_bytes
import ida_kernwin
from ida_hexrays import *
from utils import *

import lib

ida_idaapi.require("lib")


def main():
    ida_kernwin.msg_clear()
    mba = lib.get_current_microcode(MMAT_PREOPTIMIZED)
    Opt().run(mba)


class Opt:

    def run(self, mba: mba_t):
        self.mba = mba
        for blk in all_blocks_in_mba(self.mba):
            if self.find_pattern1(blk):
                print(blk.serial)

    def find_pattern1(self, blk: mblock_t):
        insn = blk.head
        if insn:
            b = ida_bytes.get_bytes(insn.ea, 25)
            if b is not None:
                s = b.hex().upper()
                if s == '8A0688073C0074108A460183C60288470183C7023C0075E85F':
                    return True
        return False


if __name__ == '__main__':
    main()
