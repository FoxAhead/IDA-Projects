import os

from ascendancy.utils import *


class GlbOptManager(object):
    iteration = 0
    opts = {}
    dump_to_files = False

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
                LoopManager.init(mba)
                r = opt.run(mba)
                results[num] = r
                rr = rr and r
                cls.print_result(mba, num, r)
        if cls.iteration > 15:
            print(results)
            print("!!!WARNING!!!: break infinite loop in GLBOPT!")
            print_to_log(results)
            print_to_log("!!!WARNING!!!: break infinite loop in GLBOPT!")
            rr = True
        if rr:
            cls.dump_to_files = False
        return rr

    @classmethod
    def print_result(cls, mba, num=0, r=None, serials=None):
        if not cls.dump_to_files:
            return
        if r:
            return
        if not serials:
            blocks = all_blocks_in_mba(mba)
        else:
            blocks = [mba.get_mblock(serial) for serial in serials]
        header = "Iteration %d%s" % (cls.iteration, " - GlbOpt %d" % num if num else "")
        if cls.dump_to_files:
            filepath = r"GlbOptManager.dmp\%.X-%.2d-%d.txt" % (mba.entry_ea, cls.iteration, num)
            filedir = os.path.dirname(filepath)
            os.makedirs(filedir, exist_ok=True)
            if num == 0 and cls.iteration == 1:
                files = os.listdir(filedir)
                for file in files:
                    if file.startswith("%.X" % mba.entry_ea):
                        # print("remove: %s" % os.path.join(filedir, file))
                        os.remove(os.path.join(filedir, file))
            block_texts = []
            for blk in blocks:
                vp = BlockPrinter()
                blk._print(vp)
                block_texts.append(vp.get_block_mc())
            with open(filepath, "w") as f:
                f.write(header + "\n")
                f.write("\n\n".join(block_texts))
        else:
            print(header)
            for blk in blocks:
                print_blk(blk)


class BlockPrinter(vd_printer_t):
    def __init__(self):
        vd_printer_t.__init__(self)
        self.block_ins = []

    def get_block_mc(self):
        if self.block_ins:
            return "\n".join(self.block_ins)
        else:
            return ""

    def _print(self, indent, line):
        s = "".join([c if 0x20 <= ord(c) <= 0x7e else "" for c in line])
        # s = s.replace(" (", "(")
        # s = s.replace(" )", ")")
        # s = s.replace(" [", "[")
        # s = s.replace(" ]", "]")
        # s = s.replace(" ,", ",")
        if s:
            self.block_ins.append(s)
        return 1
