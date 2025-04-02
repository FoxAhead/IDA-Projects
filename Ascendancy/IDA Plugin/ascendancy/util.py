import time
from typing import List

import networkx as nx
from ida_hexrays import *
import ida_pro
import ida_lines
import idc
from dataclasses import dataclass, field

LogMessages = []


def text_expr(expr):
    return "%.8X: (%s) %s" % (expr.ea, get_ctype_name(expr._op), get_expr_name(expr))


def text_insn(insn, blk=None):
    if blk is None:
        return "%.8X: %s" % (insn.ea if insn else 0, insn.dstr() if insn else None)
    else:
        return "%.8X: %d. %s" % (insn.ea if insn else 0, blk.serial, insn.dstr() if insn else None)


def get_expr_name(expr):
    name = expr.print1(None)
    name = ida_lines.tag_remove(name)
    name = ida_pro.str2user(name)
    return name


def print_insn(insn):
    print_to_log(text_insn(insn))


def print_insns(insns):
    for insn in insns:
        print_insn(insn)


def collect_insns_up(insn, lst):
    """
    Collects group of instructions from the same address
    """
    lst.clear()
    if insn:
        ea = insn.ea
        while insn and insn.ea == ea:
            lst.append(insn)
            insn = insn.prev
    return len(lst)


def collect_insns_down(insn, lst):
    lst.clear()
    if insn:
        ea = insn.ea
        while insn and insn.ea == ea:
            lst.append(insn)
            insn = insn.next
    return len(lst)


def print_expr(expr):
    print_to_log(text_expr)


def print_to_log(msg):
    LogMessages.append(msg)


def is_func_lib(ea):
    function_flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)
    if function_flags & idc.FUNC_LIB:
        return True
    return False


def is_insn_mov_ds_seg(insn):
    if insn and insn.opcode == m_mov and insn.l.is_reg() and insn.l.r == 104 and insn.d.is_reg() and insn.d.r == 84:
        return True
    return False


def print_mba(mba):
    vp = vd_printer_t()
    mba._print(vp)


def print_blk(blk):
    vp = vd_printer_t()
    blk._print(vp)


def is_blk_jumps_to(blk, serial):
    if blk and (j_insn := blk.tail) and is_mcode_jcond(j_insn.opcode) and j_insn.d.b == serial:
        return j_insn
    return None


def is_inside_loop(mba, blk):
    # 16161
    if insn := is_blk_jumps_to(blk, blk.serial):
        return insn
    # 54554
    if insn := is_blk_jumps_to(blk, blk.serial - 1):
        return insn
    # 54533-5454E
    if insn := is_blk_jumps_to(blk.nextb, blk.serial):
        return insn
    # 1AE54, 1AE96-1AEA2
    if (insn := blk.tail) and is_mcode_jcond(insn.opcode):
        dest_blk = mba.get_mblock(insn.d.b)
        if insn2 := is_blk_jumps_to(dest_blk, blk.serial):
            if blk.serial < dest_blk.serial:
                return insn
            else:
                return insn2

    return None


def rotate(l, n):
    return l[n:] + l[:n]


##################################################

@dataclass
class SimpleLoop:
    # mba: mba_t
    entry: mblock_t = None
    blocks: List[mblock_t] = field(default_factory=list)

    def __str__(self):
        serial = self.entry.serial if self.entry else "None"
        return "Entry: %s, Serials: %s" % (serial, self.key())

    def __repr__(self):
        return self.__str__()

    def serials(self):
        # s = []
        # for blk in self.blocks:
        #    s.append(blk.serial)
        return [blk.serial for blk in self.blocks]

    def key(self):
        return str(self.serials())

    def __contains__(self, item):
        if type(item) == mblock_t:
            return item.serial in self.serials()
        elif type(item) == int:
            return item in self.serials()
        else:
            return False


@dataclass
class SingleLoop:
    entry: int = -1
    serials: List[int] = field(default_factory=list)

    def __str__(self):
        return "Entry: %s, Serials: %s" % (self.entry, self.serials)

    def __repr__(self):
        return self.__str__()

    def __contains__(self, item):
        if type(item) == mblock_t:
            return item.serial in self.serials
        elif type(item) == int:
            return item in self.serials
        else:
            return False

    def entry_block(self, mba):
        return mba.get_mblock(self.entry)

    def blocks(self, mba):
        for serial in self.serials:
            yield mba.get_mblock(serial)


@dataclass
class LoopsGroup:
    entry: int = -1
    loops: List[SingleLoop] = field(default_factory=list)

    def __contains__(self, item):
        if type(item) == mblock_t:
            return any(item.serial in loop for loop in self.loops)
        elif type(item) == int:
            return any(item in loop for loop in self.loops)
        else:
            return False

    def all_serials(self):
        u = set()
        for loop in self.loops:
            u = u | set(loop.serials)
        return list(u)

    def entry_block(self, mba):
        return mba.get_mblock(self.entry)

    def all_loops_blocks(self, mba):
        for serial in self.all_serials():
            yield mba.get_mblock(serial)

    def all_loops_blocks_insns(self, mba):
        for blk in self.all_loops_blocks(mba):
            insn = blk.head
            while insn:
                yield blk, insn
                insn = insn.next

    def begin(self):
        u = set()
        for loop in self.loops:
            u.add(loop.serials[0])
        if len(u) == 1:
            return list(u)[0]

    def end(self):
        u = set()
        for loop in self.loops:
            u.add(loop.serials[-1])
        if len(u) == 1:
            return list(u)[0]

    def all_loops_contain_block(self, item):
        if type(item) == mblock_t:
            return all(item.serial in loop for loop in self.loops)
        elif type(item) == int:
            return all(item in loop for loop in self.loops)
        else:
            return False


def blk_is_simple_loop(mba, blk, loop):
    """
    Example 1:
        2. INBOUND: [1, 2] OUTBOUND: [3, 2]
            entry  = 1
            blocks = [2]
    Example 2:
        2. INBOUND: [3] OUTBOUND: [3]
        3. INBOUND: [1, 2] OUTBOUND: [4, 2]
            entry  = 1
            blocks = [2, 3]
    Example 3:
        10. INBOUND: [9, 15] OUTBOUND: [11, 15]
        15. INBOUND: [10] OUTBOUND: [16, 10]
            entry  = 9
            blocks = [10, 15]
    """
    p = set(blk.predset)
    i = p & set(blk.succset)
    e = p - i
    if len(i) == 1 and len(e) <= 1 and (next_blk := mba.get_mblock(list(i)[0])) and blk.serial not in loop.serials():
        if not loop.entry and len(e) == 1:
            loop.entry = mba.get_mblock(list(e)[0])
        if loop.entry:
            loop.blocks.append(blk)
        return blk_is_simple_loop(mba, next_blk, loop)
    elif len(loop.blocks) in [1, 2]:
        return True
    else:
        loop.entry = None
        loop.blocks.clear()
        return False


def is_insn_j(insn):
    return is_mcode_jcond(insn.opcode) or insn.opcode == m_goto


def find_last_blk_insn_not_jump(blk):
    insn = blk.tail
    if insn and is_insn_j(insn):
        insn = insn.prev
    return insn


class InsnBuilder(object):

    def __init__(self, ea, opcode, size=4):
        self.size = size
        self._insn = minsn_t(ea)
        self._insn.opcode = opcode
        self.opn = 1
        # print("InsnBuilder __init__: %s" % text_insn(self._insn))

    def _op(self):
        if self.opn == 1:
            # print("InsnBuilder._op(): l")
            op = self._insn.l
            if self._insn.opcode in [m_mov]:
                self.opn = self.opn + 1
        elif self.opn == 2:
            # print("InsnBuilder._op(): r")
            op = self._insn.r
        elif self.opn == 3:
            # print("InsnBuilder._op(): d")
            op = self._insn.d
        else:
            return None
        self.opn = self.opn + 1
        # print("InsnBuilder._op(): %d" % self.opn)
        return op

    def n(self, n):
        # print("InsnBuilder n: %s" % n)
        self._op().make_number(n, self.size)
        # print("InsnBuilder n: %s" % text_insn(self._insn))
        return self

    def r(self, r):
        # print("InsnBuilder r: %s" % r)
        self._op().make_reg(r, self.size)
        # print("InsnBuilder r: %s" % text_insn(self._insn))
        return self

    def i(self, i):
        self._op().create_from_insn(i)
        # print("InsnBuilder i: %s" % text_insn(self._insn))
        return self

    def S(self, mba, off):
        self._op().make_stkvar(mba, off)
        return self

    def insn(self):
        # print("self.opn = %d" % self.opn)
        if self.opn == 3:
            self.r(mr_none)
        if self.opn != 4:
            return None
        # print("InsnBuilder: %s" % text_insn(self._insn))
        return self._insn


class LoopManager(object):
    entry_ea = 0
    cycles = []
    all_serials_of_cycles = None
    loops = []
    groups = []

    @classmethod
    def init(cls, mba):
        # print("LoopManager.init: %X %X" % (cls.entry_ea, mba.entry_ea))
        if cls.entry_ea != mba.entry_ea:
            cls.build_cycles(mba)
            cls.build_loops(mba)
        # cls.print_loops_groups()
        # print(cls.all_serials_of_cycles)

    @classmethod
    def build_cycles(cls, mba):
        # t1 = time.time()
        # print("LoopManager.build_cycles begin")
        cls.entry_ea = mba.entry_ea
        cls.cycles.clear()
        G = nx.DiGraph()
        blk = mba.blocks
        while blk:
            for pred in list(blk.predset):
                G.add_edge(pred, blk.serial)
            blk = blk.nextb
        # nx.write_graphml_lxml(G, r"D:\graph_%.X.graphml" % cls.entry_ea)
        cls.cycles = list(nx.simple_cycles(G))
        cls.all_serials_of_cycles = set([serial for cycle in cls.cycles for serial in cycle])
        # print("LoopManager.build_cycles end")
        # print(cls.cycles)
        # print("LoopManager.build_cycles = %.3f" % (time.time() - t1))

    @classmethod
    def build_loops(cls, mba):
        # t1 = time.time()
        # print("build_loops")
        cls.loops.clear()
        blk = mba.blocks
        while blk:
            serial = blk.serial
            if not cls.serial_in_cycles(serial):
                for succ in list(blk.succset):
                    for cycle in cls.cycles:
                        if succ in cycle:
                            while cycle[0] != succ:
                                cycle = rotate(cycle, 1)
                            # print("%d -> %s" % (serial, cycle))
                            cls.loops.append(SingleLoop(serial, cycle))
            blk = blk.nextb
        cls.build_loops_groups(mba)
        # print("LoopManager.build_loops = %.3f" % (time.time() - t1))

    @classmethod
    def build_loops_groups(cls, mba):
        # t1 = time.time()
        cls.groups.clear()
        d = {}
        for loop in cls.loops:
            if loop.entry not in d:
                d[loop.entry] = LoopsGroup(loop.entry)
            d[loop.entry].loops.append(loop)
        cls.groups = list(d.values())
        # print("LoopManager.build_loops_groups = %.3f" % (time.time() - t1))

    @classmethod
    def print_loops_groups(cls):
        for group in cls.groups:
            print("Group: %s - %s" % (group.entry, group.all_serials()))

    @classmethod
    def serial_in_cycles(cls, serial):
        # print(serial, [serial in cycle for cycle in cls.cycles])
        # return any(serial in cycle for cycle in cls.cycles)
        return serial in cls.all_serials_of_cycles


def var_as_key(op):
    if op.t == mop_r:
        return "r-%d" % op.r
    elif op.t == mop_S:
        return "S-%d" % op.s.off
    else:
        return op.dstr()
