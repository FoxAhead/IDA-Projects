"""
summary: Optimization 11

description:

    Fix ADD and SUB to EAX to absolute offset to temporary kreg kr00

    Change this:
1. 1 add    eax.4, #0xBE.4, eax.4{1}              ; 00015EE5
1. 2 call   $__wcpp_2_ctor_array__ <fast:"void *array" eax.4{1},"unsigned int count" #0x64.4,"rt_type_sig_clss *sig" &($stru_959D8).4>.0 ; 00015EEA
1. 3 add    eax.4{1}, #0x4B0.4, eax.4{2}          ; 00015EF9
1. 4 call   $__wcpp_2_ctor_array__ <fast:"void *array" eax.4{2},"unsigned int count" #0x64.4,"rt_type_sig_clss *sig" &($stru_95A3C).4>.0 ; 00015EFE
1. 5 add    eax.4{2}, #0xFA0.4, eax.4{3}          ; 00015F0D
1. 6 call   $__wcpp_2_ctor_array__ <fast:"void *array" eax.4{3},"unsigned int count" #0x64.4,"rt_type_sig_clss *sig" &($stru_959D8).4>.0 ; 00015F12
1. 7 add    eax.4{3}, #0x7FC.4, eax.4{4}          ; 00015F17
1. 8 stx    #0.4, ds.2{5}, eax.4{4}               ; 00015F1C
1. 9 add    eax.4{4}, #0x14.4, eax.4{6}           ; 00015F22
1.10 stx    #0.4, ds.2{5}, (eax.4{6}-#0x10.4)     ; 00015F25
1.11 stx    #0.4, ds.2{5}, (eax.4{6}-#0xC.4)      ; 00015F2C
1.12 stx    #0.4, ds.2{5}, (eax.4{6}+#4.4)        ; 00015F33
1.13 stx    #0.4, ds.2{5}, (eax.4{6}+#8.4)        ; 00015F3A
1.14 stx    #0.4, ds.2{5}, eax.4{6}               ; 00015F41
    to:
1. 1 call   $__wcpp_2_ctor_array__ <fast:"void *array" (eax.4+#0xBE.4),"unsigned int count" #0x64.4,"rt_type_sig_clss *sig" &($stru_959D8).4>.0 ; 00015EEA
1. 2 call   $__wcpp_2_ctor_array__ <fast:"void *array" (eax.4+#0x56E.4),"unsigned int count" #0x64.4,"rt_type_sig_clss *sig" &($stru_95A3C).4>.0 ; 00015EFE
1. 3 call   $__wcpp_2_ctor_array__ <fast:"void *array" (eax.4+#0x150E.4),"unsigned int count" #0x64.4,"rt_type_sig_clss *sig" &($stru_959D8).4>.0 ; 00015F12
1. 4 stx    #0.4, ds.2{5}, (eax.4+#0x1D0A.4)      ; 00015F1C
1. 5 stx    #0.4, ds.2{5}, (eax.4+#0x1D0E.4)      ; 00015F25
1. 6 stx    #0.4, ds.2{5}, (eax.4+#0x1D12.4)      ; 00015F2C
1. 7 stx    #0.4, ds.2{5}, (eax.4+#0x1D22.4)      ; 00015F33
1. 8 stx    #0.4, ds.2{5}, (eax.4+#0x1D26.4)      ; 00015F3A
1. 9 stx    #0.4, ds.2{5}, (eax.4+#0x1D1E.4)      ; 00015F41

    etc...

    Some functions need to be set to return void and __spoils<>

    Test:
        1DE64
        15ED4

        48B40
        1B4F0
        16120 - Do not optimize inside loop
        46CAC - Do not optimize inside loop
        54448 - Optimize before loop 00054554
        4CDF8 - Wrong optimization (4D612 - removed). Should rewrite using flow-graph
        17E88 - TODO - Switch statement. add op used after 2-way brach, so have to keep multi inbound edges to keep connection
                TODO - If it is not EAX, then don't create item at STOP-BLOCK

"""
import dataclasses

from ascendancy.opts import GlbOpt
from ascendancy.utils import *


class Opt(GlbOpt):

    def __init__(self):
        super().__init__(11, "Propagate offsets")
        # self.g: nx.DiGraph = None

    def _init(self):
        self.visited: Dict[int, BlockInfo] = {}

    def _run(self):
        ChainItem.global_id = 0
        for reg in [mr_first, 12, 16, 20, REG_ESI]:
            self.run_with_reg(reg)

    # def traverse_items(self, item):
    #     if item.id in self.visited_items:
    #         return
    #     self.visited_items.add(item.id)
    #     for i in item.next:
    #         self.traverse_items(i)

    def debug_print_items(self):
        for serial, blk_info in self.visited.items():
            print("blk=%d" % serial)
            for item in blk_info.items:
                print("id=%.4d, type=%d, blk=%d, insn=%s, offset=%d" % (item.id, item.type, item.blk.serial if item.blk else -1, text_insn(item.insn), item.offset))
                print("  prev: %s" % [i.id for i in item.prev])
                print("  next: %s" % [i.id for i in item.next])

    def run_with_reg(self, reg):
        self.reg_op = mop_t(reg, 4)
        mreg_name = get_mreg_name(reg, 4).upper()
        #print("reg %d (%s)" % (reg, mreg_name))
        self.visited.clear()
        self.process_block_recursive(self.mba.blocks)
        #self.debug_print_items()
        for serial, blk_info in self.visited.items():
            #print(serial)
            for item in blk_info.items:
                if item.type == 2:
                    self.print_to_log("  %s  make_nop (off=0x%X): %s:" % (mreg_name, item.offset, text_insn(item.insn)))
                    item.blk.make_nop(item.insn)
                    self.mark_dirty(item.blk)
                elif item.type == 3:
                    for use in item.uses:
                        insnn = InsnBuilder(use.topins.ea, m_add, 4).n(item.offset).r(reg).r(reg).insn()
                        use.op.create_from_insn(insnn)
                        self.print_to_log("  %s    create_from_insn: %s %s" % (mreg_name, hex_addr(use.topins.ea), use.op.dstr()))
                        self.mark_dirty(item.blk)

    def process_block_recursive(self, blk: mblock_t, inb_item: "ChainItem" = None):
        if blk.type == BLT_STOP:
            return
        #print("process_block_recursive", blk.serial)
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
                #print("destroy_chain blk=%d, item=%d" % (blk.serial, first_item.id))
                #self.debug_print_items()
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
            #print(text_insn(insn))
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
        #self.marked = set()
        self.marked = []
        self.mark_initial_recursive(item)
        #print("marked initial", self.marked)

    def mark_initial_recursive(self, item):
        if item.id in self.marked:
            return
        item.type = 0
        item.insn = None
        item.offset = 0
        #self.marked.add(item.id)
        self.marked.append(item.id)
        for i in item.next:
            if i.type != 1:
                self.mark_initial_recursive(i)
        for i in item.prev:
            if i.type != 0:
                self.mark_initial_recursive(i)


# class Opt2(GlbOpt):
#
#     def __init__(self):
#         super().__init__(11, "Propagate offsets")
#         self.g: nx.DiGraph = None
#
#     def _init(self):
#         self.roots = []
#
#     def _run(self):
#         self.build_trees()
#         for reg in [mr_first, 12, 16, 20]:
#             self.reg_op = mop_t(reg, 4)
#             self.def_blocks = []  # DefinitionBlock()
#             self.run_with_reg2()
#
#     def build_trees(self):
#         self.g = LoopManager.g.copy()
#         # Remove all cycle blocks
#         rem = []
#         for serial in self.g:
#             if LoopManager.serial_in_cycles(serial):
#                 rem.append(serial)
#         self.g.remove_nodes_from(rem)
#         # Remove inbound edges from the node if there are more than one
#         rem = []
#         for serial in self.g:
#             if len(list(self.g.in_edges(serial))) > 1:
#                 for r in list(self.g.in_edges(serial)):
#                     rem.append(r)
#         self.g.remove_edges_from(rem)
#         # No we left with simple directional trees with one entry
#         for serial in self.g:
#             if len(list(self.g.in_edges(serial))) == 0:
#                 # Collect all such roots
#                 self.roots.append(serial)
#
#     def run_with_reg3(self):
#         for root in self.roots:
#             self.search_in_block_recursive2(root, OptPlan())
#
#     def search_in_block_recursive2(self, serial, in_offset, in_defined):
#         blk = self.mba.get_mblock(serial)
#         if serial in self.visited:
#             blk_info = self.visited[serial]
#             if blk_info.in_offset != in_offset or blk_info.in_defined != in_defined:
#                 return False
#         else:
#             blk_info = OptPlan(in_defined, in_offset)
#             self.visited[serial] = blk_info
#
#     def run_with_reg2(self):
#         for root in self.roots:
#             self.search_in_block_recursive(root, OptPlan())
#         for def_block in self.def_blocks:
#             if def_block.uses > 0:
#                 # print_mba(mba)
#                 reg = self.reg_op.r
#                 mreg_name = get_mreg_name(self.reg_op.r, self.reg_op.size).upper()
#                 self.print_to_log("  Start from %.8X (reg=%s):" % (def_block.ea, mreg_name))
#                 for addsub in def_block.addsubs:
#                     blk = addsub.blk
#                     insn = addsub.insn
#                     off = addsub.off
#                     ea = insn.ea
#                     self.print_to_log("  %s  make_nop (off=0x%X): %s:" % (mreg_name, off, text_insn(insn)))
#                     blk.make_nop(insn)
#                     # if prev_insn := insn.prev:  # Trying to fix combinable here (opt1)
#                     #    prev_insn.clr_combinable()
#                     self.mark_dirty(blk)
#                     insnn = minsn_t(ea)
#                     insnn.opcode = m_add
#                     insnn.l.make_reg(reg, 4)
#                     insnn.r.make_number(off, 4)
#                     insnn.d.make_reg(reg, 4)
#                     for op in addsub.useops:
#                         insnn.ea = op.topins.ea
#                         self.print_to_log("  %s    create_from_insn: %s:" % (mreg_name, text_insn(insnn)))
#                         op.op.create_from_insn(insnn)
#                         self.mark_dirty(blk)
#
#     def search_in_block_recursive(self, serial, in_plan):
#         # print("search_in_block_recursive", serial)
#         blk = self.mba.get_mblock(serial)
#         plan = dataclasses.replace(in_plan)
#         if serial == 0:
#             plan.defined = is_op_defined_in_block(blk, self.reg_op)
#             plan.offset = 0
#             self.def_blocks.append(DefinitionBlock())
#         for insn in all_insns_in_block(blk):
#             # print("defined=%s, insn=%s" % (plan.defined, text_insn(insn)))
#             if is_op_defined_in_insn(blk, self.reg_op, insn) and not is_insn_addsub_op(insn, self.reg_op):
#                 # print("First def: %.8X: %s" % (insn.ea, insn.dstr()))
#                 plan.defined = True
#                 plan.offset = 0
#                 self.def_blocks.append(DefinitionBlock(ea=insn.ea))
#             elif plan.defined:
#                 if is_insn_addsub_op(insn, self.reg_op):
#                     plan.offset += insn.r.unsigned_value() if insn.opcode == m_add else - insn.r.unsigned_value()
#                     # print("  Offset eax: %.8X: %X" % (insn.ea, plan.offset))
#                     self.def_blocks[-1].addsubs.append(AddSubOperation(blk=blk, insn=insn, off=plan.offset))
#                 elif len(self.def_blocks[-1].addsubs) > 0:
#                     # print("    Search uses: %.8X: %s" % (insn.ea, insn.dstr()))
#                     vstr = find_op_uses_in_insn(blk, insn, self.reg_op, VisitorSimpleSearchUses(blk, self.reg_op.size, {mop_r}))
#                     for use in vstr.uses:
#                         # print("      Use: %s" % op["op"].dstr())
#                         self.def_blocks[-1].addsubs[-1].useops.append(use)
#                         self.def_blocks[-1].uses += 1
#         for succ in list(self.g.successors(serial)):
#             self.search_in_block_recursive(succ, plan)
#
#     def run_with_reg(self, reg):
#         self.mba.for_all_topinsns(vstr := Visitor11a(reg))
#         for def_block in vstr.def_blocks:
#             if def_block["uses"] > 0:
#                 # print_mba(mba)
#                 print_to_log("Optimization 11 start from %.8X (reg=%d):" % (def_block["ea"], reg))
#                 for addsub in def_block["addsubs"]:
#                     blk = addsub["blk"]
#                     insn = addsub["insn"]
#                     off = addsub["off"]
#                     ea = insn.ea
#                     print_to_log("  %.2d  make_nop (off=0x%X): %s:" % (reg, off, text_insn(insn)))
#                     blk.make_nop(insn)
#                     # if prev_insn := insn.prev:  # Trying to fix combinable here (opt1)
#                     #    prev_insn.clr_combinable()
#                     self.mark_dirty(blk)
#                     insnn = minsn_t(ea)
#                     insnn.opcode = m_add
#                     insnn.l.make_reg(reg, 4)
#                     insnn.r.make_number(off, 4)
#                     insnn.d.make_reg(reg, 4)
#                     for op in addsub["useops"]:
#                         insnn.ea = op["topins"].ea
#                         print_to_log("  %.2d    create_from_insn: %s:" % (reg, text_insn(insnn)))
#                         op["op"].create_from_insn(insnn)
#                         self.mark_dirty(blk)


# def is_reg_defined_here(blk, ml, insn):
#     # _def = blk.build_def_list(insn, MAY_ACCESS | FULL_XDSU)
#     _def = blk.build_def_list(insn, MUST_ACCESS)
#     return _def.includes(ml)


def is_insn_addsub_op(insn, op):
    return insn.opcode in {m_add, m_sub} and insn.r.t == mop_n and insn.l == op and insn.d == insn.l


# def get_reg_addsub_off(insn, reg):
#     # print("get_reg_addsub_off %d" % reg)
#     if insn.opcode in [m_add, m_sub] and insn.l.is_reg(reg, 4) and insn.r.t == mop_n and insn.d.is_reg(reg, 4):
#         sign = 1 if insn.opcode == m_add else -1
#         return sign * insn.r.unsigned_value()
#     else:
#         return 0


# class Visitor11a(minsn_visitor_t):
#
#     def __init__(self, reg):
#         minsn_visitor_t.__init__(self)
#         self.reg = reg
#         self.insn_def = None  # First definition
#         self.off = 0
#         self.ul_reg = mlist_t(reg, 4)
#         self.def_blocks = []
#         self.inside_loop = False
#
#     def visit_minsn(self):
#         # self.inside_loop = bool(is_inside_loop(self.mba, self.blk))
#         self.inside_loop = LoopManager.serial_in_cycles(self.blk.serial)
#         insn = self.curins
#         # print("curins = %s, inside_loop = %s" % (text_insn(self.curins), self.inside_loop))
#         if not self.insn_def and not self.inside_loop:
#             if is_reg_defined_here(self.blk, self.ul_reg, insn):
#                 # print("First def: %.8X: %s" % (insn.ea, insn.dstr()))
#                 self.insn_def = insn
#                 self.off = 0
#                 self.def_blocks.append({"ea": insn.ea, "uses": 0, "addsubs": []})
#         if (off := get_reg_addsub_off(insn, self.reg)) != 0:
#             if not self.inside_loop:
#                 self.off = self.off + off
#                 # print("  Offset eax: %.8X: %X" % (insn.ea, self.off))
#                 self.def_blocks[-1]["addsubs"].append({"blk": self.blk, "insn": insn, "off": self.off, "useops": []})
#         elif self.insn_def and len(self.def_blocks[-1]["addsubs"]) > 0:
#             if not self.inside_loop:
#                 # print("    Search uses: %.8X: %s" % (insn.ea, insn.dstr()))
#                 self.blk.for_all_uses(self.ul_reg, insn, insn.next, vstr_uses := Visitor11b())
#                 for op in vstr_uses.ops:
#                     # print("      Use: %s" % op["op"].dstr())
#                     self.def_blocks[-1]["addsubs"][-1]["useops"].append(op)
#                     self.def_blocks[-1]["uses"] = self.def_blocks[-1]["uses"] + 1
#             if (insn != self.insn_def) and is_reg_defined_here(self.blk, self.ul_reg, insn):
#                 self.insn_def = None
#         return 0


# class Visitor11b(mlist_mop_visitor_t):
#
#     def __init__(self):
#         mlist_mop_visitor_t.__init__(self)
#         self.ops = []
#
#     def visit_mop(self, op):
#         if op.t == mop_r and op.size == 4:
#             self.ops.append({"op": op, "topins": self.topins})
#         return 0


@dataclass
class AddSubOperation:
    blk: mblock_t
    insn: minsn_t
    off: int
    useops: List[mop_t] = field(default_factory=list)


@dataclass
class DefinitionBlock:
    ea: int = 0
    uses: int = 0
    addsubs: List[AddSubOperation] = field(default_factory=list)


@dataclass
class OptPlan:
    defined: bool = False
    offset: int = 0
    def_block: DefinitionBlock = None


global_item_id = 0


@dataclass
class ChainItem:
    type: int = 0  # -1 - join item, 0 - Initial (searching for definition), 1 - Definition, 2 - Add/Sub , 3 - Use
    blk: mblock_t = None
    insn: minsn_t = None
    offset: int = 0
    uses: List["OpUse"] = field(default_factory=list)
    prev: List["ChainItem"] = field(default_factory=list)
    next: List["ChainItem"] = field(default_factory=list)
    global_id = 0

    def __post_init__(self):
        global global_item_id
        self.id = ChainItem.global_id
        ChainItem.global_id += 1
        #print("ChainItem(%d, %s)" % (self.type, text_insn(self.insn)))

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

    def add_item(self, item: ChainItem):
        #print("BlockInfo.add_item")
        self.items.append(item)
        return item


def join_chain_items(new_item: ChainItem, prev_item: ChainItem):
    # print("join_chain_items", new_item.id, prev_item.id)
    new_item.prev.append(prev_item)
    prev_item.next.append(new_item)
    return new_item


def get_value_from_addsub(insn):
    return insn.r.unsigned_value() if insn.opcode == m_add else - insn.r.unsigned_value()
