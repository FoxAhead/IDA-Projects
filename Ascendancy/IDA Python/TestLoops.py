from dataclasses import dataclass, field
from typing import List, Set

import ida_hexrays
import ida_kernwin
import networkx as nx
from ida_hexrays import *


def main():
    ida_kernwin.msg_clear()

    current_address = ida_kernwin.get_screen_ea()
    if current_address == ida_idaapi.BADADDR:
        ida_kernwin.warning("Could not open Microcode Explorer (bad cursor address)")
        return
    func = ida_funcs.get_func(current_address)
    if not func:
        return False
    mba = get_microcode(func, ida_hexrays.MMAT_GLBOPT2)
    LoopManager2.init(mba)

    test2(mba).run2()
    return

    # LoopManager2.print_groups(True)
    for group in LoopManager2.all_groups():
        print(group.title())
        # print(group.all_serials)
        # for entry in group.entry_blocks(mba):
        #    test1(group.all_loops_blocks(mba))


class test2:

    def __init__(self, mba):
        self.mba = mba
        self.visited = set()
        self.chains = []

    def run2(self):
        g = LoopManager2.g.copy()
        rem = []
        for serial in g:
            if LoopManager2.serial_in_cycles(serial):
                rem.append(serial)
        g.remove_nodes_from(rem)
        rem = []
        for serial in g:
            if len(list(g.in_edges(serial))) > 1:
                for r in list(g.in_edges(serial)):
                    rem.append(r)
        g.remove_edges_from(rem)
        for serial in g.nodes:
            if len(list(g.in_edges(serial))) == 0:
                print(serial)


        fname = r"D:\graph_%.X_cut.graphml" % self.mba.entry_ea
        nx.write_graphml_lxml(g, fname)
        print("Graph exported to: %s" % fname)


    def run(self):
        self.visited.clear()
        self.chains.clear()
        blk = self.mba.blocks
        while blk:
            if blk.serial not in self.visited:
                if blk_can_be_start(blk):
                    chain = []
                    self.construct_chain(blk, chain)
                    if chain:
                        self.chains.append(chain)
                        print(chain)
                    else:
                        print(blk.serial)
            blk = blk.nextb

    def construct_chain(self, blk, chain):
        if blk.serial in self.visited:
            return
        self.visited.add(blk.serial)
        if len(chain) == 0 and blk_can_be_start(blk) or blk_can_be_finish(blk):
            chain.append(blk.serial)
            if blk.nsucc() == 1:
                succ_blk = self.mba.get_mblock(blk.succ(0))
                self.construct_chain(succ_blk, chain)


def blk_can_be_start(blk):
    return blk.nsucc() == 1 and not LoopManager2.serial_in_cycles(blk.serial)


def blk_can_be_finish(blk):
    return blk.npred() < 2 and not LoopManager2.serial_in_cycles(blk.serial)


def all_succ_blocks(mba: mba_t, blk: mblock_t):
    for succ in list(blk.succset):
        yield mba.get_mblock(succ)


def test1(blocks):
    for blk in blocks:
        print(blk.serial)


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


class LoopManager2(object):
    entry_ea = 0
    qty = 0
    all_serials_of_cycles = set()  # All serials that belong to the cycles. Not entry blocks.
    groups = []  # List of toplevel LoopsGroups (contains entry block and list of SingleLoops)
    g: nx.DiGraph = None

    @classmethod
    def init(cls, mba):
        # print("LoopManager.init: %X %X" % (cls.entry_ea, mba.entry_ea))
        if cls.entry_ea != mba.entry_ea or cls.qty != mba.qty:
            cls.build_groups(mba)
            # cls.print_loops_groups()
        # print(cls.all_serials_of_cycles)

    @classmethod
    def build_groups(cls, mba):
        # t1 = time.time()
        cls.entry_ea = mba.entry_ea
        cls.qty = mba.qty
        cls.all_serials_of_cycles.clear()
        cls.groups.clear()
        cls.g = cls.mba_to_graph(mba)
        cls.build_groups_recursive(cls.g)
        # print("LoopManager.build_groups = %.3f" % (time.time() - t1))

    @classmethod
    def mba_to_graph(cls, mba):
        g = nx.DiGraph()
        blk = mba.blocks
        while blk:
            for pred in list(blk.predset):
                g.add_edge(pred, blk.serial)
            blk = blk.nextb
        return g

    @classmethod
    def build_groups_recursive(cls, g, parent=None, entry_filter=None):
        d = {}  # Dict[entry, LoopsGroup]
        level = parent.level + 1 if parent else 0
        cycles = list(nx.simple_cycles(g))
        all_serials_of_cycles = set([serial for cycle in cycles for serial in cycle])
        for serial in g.nodes:
            # Get block out of any cycle - candidate for entry-block
            if serial not in all_serials_of_cycles and (not entry_filter or serial in entry_filter):
                entry = serial
                # And test it's successors if they are in any cycle
                for succ in list(g.successors(entry)):
                    for cycle in cycles:
                        if succ in cycle:
                            begin = succ
                            # This block should become begin-block, put it infront of the list
                            while cycle[0] != begin:
                                cycle = rotate(cycle, 1)
                            d.setdefault(begin, LoopsGroup(level, parent)).add_loop(SingleLoop(entry, cycle))
        cls.all_serials_of_cycles.update(all_serials_of_cycles)
        for group in d.values():
            if parent:
                parent.children.append(group)
            else:
                cls.groups.append(group)
            g1 = g.copy()
            if group.end is not None:
                # Cut the edge from end to begin
                g1.remove_edge(group.end, group.begin)
                # And repeat cycle search for new graph
                cls.build_groups_recursive(g1, group, group.all_serials)

    @classmethod
    def print_groups(cls, detailed=False):
        for group in cls.groups:
            if detailed:
                print(repr(group))
            else:
                print(group)

    @classmethod
    def serial_in_cycles(cls, serial):
        """
        Does serial participate in any loop?
        """
        return serial in cls.all_serials_of_cycles

    @classmethod
    def all_groups(cls, parent=None):
        if parent is None:
            for group in cls.groups:
                yield from cls.all_groups(group)
        else:
            yield parent
            for child in parent.children:
                yield from cls.all_groups(child)


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
    # TODO: 46480 - one loops group [25..24] have several entries: 21 and 23
    level: int = -1
    parent: "LoopsGroup" = None
    entries: Set[int] = field(default_factory=set)
    loops: List[SingleLoop] = field(default_factory=list)
    dirty: bool = True
    children: List["LoopsGroup"] = field(default_factory=list)

    def __contains__(self, item):
        if type(item) == mblock_t:
            return item.serial in self.all_serials
        elif type(item) == int:
            return item in self.all_serials
        else:
            return False

    def __str__(self):
        s = self.title()
        for child in self.children:
            s = s + "\n" + str(child)
        return s

    def __repr__(self):
        s = self.title()
        s = s + "\n%s  All:    %s" % (self.indent(), self.all_serials)
        s = s + "\n%s  Common: %s" % (self.indent(), self.common_serials)
        for idx, loop in enumerate(self.loops):
            s = s + "\n%s  %s%s" % (self.indent(), "        " if idx else "Loops:  ", loop.serials)
        for child in self.children:
            s = s + "\n" + repr(child)
        return s

    def title(self):
        return "%sGroup %s -> [%d..%s]" % (self.indent(), self.entries, self.begin, self.end)

    def indent(self):
        return ".." * self.level

    def add_loop(self, loop):
        self.dirty = True
        self.entries.add(loop.entry)
        self.loops.append(loop)

    def __calculate(self):
        if self.dirty:
            self.__common_serials = set.intersection(*map(set, [loop.serials for loop in self.loops]))
            self.__all_serials = set.union(*map(set, [loop.serials for loop in self.loops]))
            u1 = set()
            u2 = set()
            for loop in self.loops:
                u1.add(loop.serials[0])
                u2.add(loop.serials[-1])
            self.__begin = list(u1)[0] if len(u1) == 1 else None
            self.__end = list(u2)[0] if len(u2) == 1 else None
            self.dirty = False

    @property
    def common_serials(self):
        self.__calculate()
        return self.__common_serials

    @property
    def all_serials(self):
        self.__calculate()
        return self.__all_serials

    @property
    def begin(self):
        self.__calculate()
        return self.__begin

    @property
    def end(self):
        self.__calculate()
        return self.__end

    def entry_blocks(self, mba):
        for entry in self.entries:
            yield mba.get_mblock(entry)

    def begin_block(self, mba):
        return None if self.begin is None else mba.get_mblock(self.begin)

    def end_block(self, mba):
        return None if self.end is None else mba.get_mblock(self.end)

    def all_loops_blocks(self, mba):
        for serial in self.all_serials:
            yield mba.get_mblock(serial)

    def all_loops_blocks_insns(self, mba):
        for blk in self.all_loops_blocks(mba):
            insn = blk.head
            while insn:
                yield blk, insn
                insn = insn.next

    def all_loops_contain_block(self, item):
        if type(item) == mblock_t:
            return item.serial in self.common_serials
        elif type(item) == int:
            return item in self.common_serials
        else:
            return False


def rotate(l, n):
    return l[n:] + l[:n]


if __name__ == '__main__':
    main()
