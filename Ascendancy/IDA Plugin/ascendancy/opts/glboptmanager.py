import os

from ascendancy.utils import *


class GlbOptManager(object):
    iteration = 0
    opts = {}
    print_to_files = False

    @classmethod
    def clear(cls):
        cls.iteration = 0
        cls.opts.clear()

    @classmethod
    def register(cls, glbopt):
        cls.opts[glbopt.num] = glbopt

    @classmethod
    def run(cls, mba):
        cls.iteration = cls.iteration + 1
        results = {}
        cls.print_result(mba)
        rr = True
        for num, opt in cls.opts.items():
            if not opt.delayed or rr:
                r = opt.run(mba)
                results[num] = r
                rr = rr and r
                cls.print_result(mba, num, r)
        # print("Iteration %d" % cls.iteration)
        # print(results)
        if cls.iteration > 15:
            print(results)
            print("!!!WARNING!!!: break infinite loop in GLBOPT!")
            print_to_log(results)
            print_to_log("!!!WARNING!!!: break infinite loop in GLBOPT!")
            rr = True
        return rr

    @classmethod
    def print_result(cls, mba, num=0, r=None, serials=None):
        return
        if r:
            return
        if not serials:
            blocks = all_blocks_in_mba(mba)
        else:
            blocks = [mba.get_mblock(serial) for serial in serials]
        header = "Iteration %d%s" % (cls.iteration, " - GlbOpt %d" % num if num else "")
        if cls.print_to_files:
            vp = BlockPrinter()
            for blk in blocks:
                # print_blk(blk)
                blk._print(vp)
            filepath = r"GlbOptManagerDump\%.X-%d-%d.txt" % (mba.entry_ea, cls.iteration, num)
            filedir = os.path.dirname(filepath)
            os.makedirs(filedir, exist_ok=True)
            files = os.listdir(filedir)
            # for file in files:
            #    if file.startswith("%.X" % mba.entry_ea):
            #        #print("remove: %s" % os.path.join(filedir, file))
            #        os.remove(os.path.join(filedir, file))
            with open(filepath, "w") as f:
                f.write(header + "\n")
                f.write(vp.get_block_mc())
        else:
            print(header)
            for blk in blocks:
                print_blk(blk)


class BlockPrinter(vd_printer_t):
    def __init__(self):
        vd_printer_t.__init__(self)
        self.block_ins = []

    def get_block_mc(self):
        return "\n".join(self.block_ins)

    def _print(self, indent, line):
        s = "".join([c if 0x20 <= ord(c) <= 0x7e else "" for c in line])
        # s = s.replace(" (", "(")
        # s = s.replace(" )", ")")
        # s = s.replace(" [", "[")
        # s = s.replace(" ]", "]")
        # s = s.replace(" ,", ",")
        self.block_ins.append(s)
        return 1
