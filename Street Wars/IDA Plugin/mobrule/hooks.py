import inspect

import ida_hexrays
from mobrule.opts import *
from mobrule.utils import *


class HxeHooks(ida_hexrays.Hexrays_Hooks):

    def func_printed(self, cfunc):
        opt1.run(cfunc)  # Static comments
        return 0
