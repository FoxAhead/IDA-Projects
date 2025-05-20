from dataclasses import dataclass
from typing import Dict

import ida_kernwin
from ida_hexrays import *
from utils import *
import lib

ida_idaapi.require("lib")


def main():
    ida_kernwin.msg_clear()
    mba = lib.get_current_microcode(MMAT_GLBOPT2)
    Opt().run(mba)


class Opt:

    def run(self, mba: mba_t):
        self.mba = mba
        self.visited: Dict[int, BlockInfo] = {}
        for reg in [8]:
            self.run_with_reg(reg)
            for serial, blk_info in self.visited.items():
                print(serial)
                for item in blk_info.items:
                    s = "" if item.insn is None else "insn=" + text_insn(item.insn, item.blk)
                    print("  id=%d  type=%d  offset=%X  %s" % (item.id, item.type, item.get_offset(), s))
                    print("    prev:", [i.id for i in item.prev])
                    print("    next:", [i.id for i in item.next])
        # root_item = self.visited[0].items[0]
        # self.visited_items = set()
        # self.traverse_items(root_item)

    def traverse_items(self, item):
        if item.id in self.visited_items:
            return
        self.visited_items.add(item.id)
        for i in item.next:
            self.traverse_items(i)

    def run_with_reg(self, reg):
        self.reg_op = mop_t(reg, 4)
        mreg_name = get_mreg_name(reg, 4).upper()
        print("reg %d (%s)" % (reg, mreg_name))
        self.visited.clear()
        self.process_block_recursive(self.mba.blocks)

    def process_block_recursive(self, blk: mblock_t, inb_item: "ChainItem" = None):
        print(blk.serial)
        if blk.serial in self.visited:
            blk_info = self.visited[blk.serial]
            first_item = blk_info.items[0]
            bad_chain = False
            if blk.type != BLT_STOP:
                for item in first_item.prev:
                    if inb_item.get_type() > 0 and item.get_type() > 0:
                        if item.get_offset() == inb_item.get_offset():
                            continue
                    elif item.get_type() == inb_item.get_type():
                        continue
                    bad_chain = True
                    break
            join_chain_items(first_item, inb_item)
            if bad_chain:
                print("destroy_chain blk=%d, item=%d" % (blk.serial, first_item.id))
                self.destroy_chain(first_item)
            return
        else:
            blk_info = BlockInfo()
            self.visited[blk.serial] = blk_info
        # MBA Entry block
        if blk.serial == 0:
            if is_op_defined_in_block(blk, self.reg_op):
                # print("maybdef", blk.maybdef.reg.dstr())
                curr_item = blk_info.add_item(ChainItem(1))
            else:
                curr_item = blk_info.add_item(ChainItem(0))
        else:
            curr_item = inb_item
        # Iterate block instructions
        for insn in all_insns_in_block(blk):
            if is_op_defined_in_insn(blk, self.reg_op, insn):
                if not is_insn_addsub_op(insn, self.reg_op):
                    # Finalize
                    if curr_item.is_defined():
                        new_item = blk_info.add_item(ChainItem(0))
                        curr_item = join_chain_items(new_item, curr_item)
                    # Definition
                    new_item = blk_info.add_item(ChainItem(1, blk, insn))
                    curr_item = join_chain_items(new_item, curr_item)
                elif curr_item.is_defined():
                    # Add/Sub
                    new_item = blk_info.add_item(ChainItem(2, blk, insn))
                    new_item.offset = curr_item.get_offset() + get_value_from_addsub(insn)
                    curr_item = join_chain_items(new_item, curr_item)
            elif curr_item.is_defined() and curr_item.get_offset() > 0:
                vstr = find_op_uses_in_insn(blk, insn, self.reg_op, VisitorSimpleSearchUses(blk, self.reg_op.size, {mop_r}))
                if len(vstr.uses) > 0:
                    new_item = blk_info.add_item(ChainItem(3, blk, insn))
                    new_item.offset = curr_item.get_offset()
                    new_item.uses = vstr.uses
                    curr_item = join_chain_items(new_item, curr_item)
        # If no items in this block, add join item
        if len(blk_info.items) == 0:
            first_item = blk_info.add_item(ChainItem(-1))
            curr_item = join_chain_items(first_item, curr_item)
        # Process block succesors
        for succ_blk in all_succ_blocks(self.mba, blk):
            self.process_block_recursive(succ_blk, curr_item)

    def destroy_chain(self, item: "ChainItem"):
        # return
        self.marked = set()
        self.mark_initial(item)
        print("marked initial", self.marked)

    def mark_initial(self, item):
        if item.id in self.marked:
            return
        item.type = 0
        item.insn = None
        item.offset = 0
        self.marked.add(item.id)
        for i in item.next:
            if i.type != 1:
                self.mark_initial(i)
        for i in item.prev:
            if i.type != 0:
                self.mark_initial(i)


global_id = 0


@dataclass
class ChainItem:
    type: int = 0  # -1 - join item, 0 - Initial (searching for definition), 1 - Definition, 2 - Add/Sub , 3 - Use
    blk: mblock_t = None
    insn: minsn_t = None
    offset: int = 0
    uses: List["OpUse"] = field(default_factory=list)
    prev: List["ChainItem"] = field(default_factory=list)
    next: List["ChainItem"] = field(default_factory=list)

    def __post_init__(self):
        global global_id
        self.id = global_id
        global_id += 1

    def is_defined(self):
        item = self.get_non_join(self, set())
        # item = self
        return item.type > 0

    def get_offset(self):
        item = self.get_non_join(self, set())
        return item.offset

    def get_type(self):
        item = self.get_non_join(self, set())
        return item.type

    def get_non_join(self, item, visited):
        if item.id in visited:
            return None
        visited.add(item.id)
        if item.type == -1:
            for i in item.prev:
                r = self.get_non_join(i, visited)
                if r is not None:
                    return r
        else:
            return item


@dataclass
class BlockInfo:
    inb: List[ChainItem] = field(default_factory=list)
    items: List[ChainItem] = field(default_factory=list)

    def add_item(self, item):
        self.items.append(item)
        return item


def join_chain_items(new_item: ChainItem, prev_item: ChainItem):
    # print("join_chain_items", new_item.id, prev_item.id)
    new_item.prev.append(prev_item)
    prev_item.next.append(new_item)
    return new_item


def is_insn_addsub_op(insn, op):
    return insn.opcode in [m_add, m_sub] and insn.l == op and insn.d == insn.l


def get_value_from_addsub(insn):
    return insn.r.unsigned_value() if insn.opcode == m_add else - insn.r.unsigned_value()


if __name__ == '__main__':
    main()
