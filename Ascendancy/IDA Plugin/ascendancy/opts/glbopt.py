from ascendancy.utils import *
from abc import ABC, abstractmethod


class GlbOpt(ABC):

    def __init__(self, num, desc="", delayed=False):
        self.active = True
        self.mba: mba_t = None
        self.say_hello = True
        self.num = num
        self.desc = desc
        self.delayed = delayed
        self.err_code = MERR_OK

    def run(self, mba: mba_t):
        self.mba = mba
        self.say_hello = True
        self.err_code = MERR_OK
        self._init()
        if not is_func_lib(mba.entry_ea) and self.active:
            LoopManager.init(mba)
            self._run()
        return self.err_code == MERR_OK

    @abstractmethod
    def _run(self):
        pass

    @abstractmethod
    def _init(self):
        pass

    def print_to_log(self, s):
        self.hello()
        print_to_log(s)

    def hello(self):
        if self.say_hello:
            self.say_hello = False
            print_to_log("Optimization %d (%s)" % (self.num, self.desc))

    def mark_dirty(self, blk: mblock_t, verify=True):
        blk.mark_lists_dirty()
        self.err_code = MERR_LOOP
        if verify:
            try:
                self.mba.verify(True)
            except RuntimeError as e:
                print("Error in opt%d (blk=%d): %s" % (self.num, blk.serial, e))
                print_blk(blk)
                # print_mba(self.mba)
                raise e
