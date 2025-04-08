from ascendancy.util import *


class GlbOptManager(object):
    iteration = 0
    opts = {}

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
        #print("Iteration %d" % cls.iteration)
        #print(results)
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
        print("After %d: %s" % (num, r))
        if not serials:
            blocks = all_blocks_in_mba(mba)
        else:
            blocks = [mba.get_mblock(serial) for serial in serials]
        for blk in blocks:
            print_blk(blk)
