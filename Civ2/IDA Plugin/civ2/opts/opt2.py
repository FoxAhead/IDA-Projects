"""
summary: Optimization 2

description:

    Replace JUMPOUT with code from exit block

    Test:
        418870 - Simple
        4183D0 - Complex
        4F3E70 - Cleanup with several blocks
        4EB80A - Multiple calls to cleanup
        4EC3FE - Fix incorrect catch ranges

"""
import ida_allins
import ida_struct
import ida_pro
import ida_tryblks
import idaapi

from civ2.opts import GlbOpt
import ida_frame
import ida_kernwin
from civ2.utils import *
import ida_ua


class Opt:
    def __init__(self):
        self.cleanups = {}  # Dict[cleanup_ea, [from_blk.serial, from_insn.ea]]
        self.cleanups2 = {}  # Dict[cleanup_ea, dtr_call_ea]

    def collect_eh_info(self, mba, fc, reachable_blocks):
        if is_func_lib(mba.entry_ea):
            return
        func = idaapi.get_func(mba.entry_ea)
        #debug_print_tryblocks(func)
        #debug_change_tryblocks(func)
        #debug_print_tryblocks(func)
        fix_tryblocks(func)

        tryblks = ida_tryblks.tryblks_t()
        rng = ida_range.range_t(func.start_ea, func.end_ea)
        ida_tryblks.get_tryblks(tryblks, rng)
        blk_idx_map = {}

        for i in range(fc.size()):
            blk_idx_map[fc[i].start_ea] = i

        for tryblk in tryblks:
            if tryblk.is_cpp():
                for catch in tryblk.cpp():  # catch_t(try_handler_t) in catchvec_t
                    for r in catch:
                        self.cleanups[r.start_ea] = []
                        blks = [blk_idx_map[r.start_ea]]
                        while len(blks):
                            block_idx = blks.pop()
                            if not reachable_blocks.has(block_idx):
                                reachable_blocks.add(block_idx)
                                for i in range(fc.nsucc(block_idx)):
                                    blks.append(fc.succ(block_idx, i))

    def collect_cleanup_calls(self, mba):
        for call in self.cleanups.values():
            call.clear()
        cfgs = {0: [6, 3], 1: [2, 1]}  # Dict[Maturity, [number of insns in call, index of push insn]]
        cfg = cfgs.get(mba.maturity, [-1, -1])
        for blk in all_blocks_in_mba(mba):
            insns = []
            if collect_insns_up(blk.tail, insns) == cfg[0]:
                insn = insns[0]
                if insn and insn.opcode == m_goto and insn.l.t == mop_v:
                    if (call := self.cleanups.get(insn.l.g)) is not None:
                        insn = insns[cfg[1]]
                        if insn and insn.opcode == m_push and insn.l.t == mop_n:
                            ret_ea = insn.l.unsigned_value()
                            if ret_ea == insns[0].ea + 5:
                                call.append((blk, insns[0].ea))
        # print(self.cleanups)

    def dump_stkpnts(self, pfn):
        "dump function stack points"
        print("Function has %d stack points" % pfn.pntqty)
        for i in range(pfn.pntqty):
            pnt = pfn.points[i]
            print("  stkpnt %i @%08X: %x" % (i, pnt.ea, pnt.spd))

    def spds(self, mba):
        func = idaapi.get_func(mba.entry_ea)
        self.dump_stkpnts(func)
        return
        for blk in all_blocks_in_mba(mba):
            if blk.start in self.cleanups:
                print("%d: %x" % (blk.serial, blk.start))
                for insn in all_insns_in_block(blk):
                    sp = ida_frame.get_spd(func, insn.ea)
                    print(sp, text_insn(insn))
                    r = ida_frame.add_auto_stkpnt(func, insn.ea, 0)
                    sp = ida_frame.get_spd(func, insn.ea)
                    print(r, sp, text_insn(insn))

    def keep_blocks(self, mba):
        for blk in all_blocks_in_mba(mba):
            insns = []
            if collect_insns_up(blk.tail, insns) == 6:
                insn = insns[0]
                if insn and insn.opcode == m_goto and insn.l.t == mop_v:
                    if (call := self.cleanups.get(insn.l.g)) is not None:
                        insn = insns[3]
                        if insn and insn.opcode == m_push and insn.l.t == mop_n:
                            ret_ea = insn.l.unsigned_value()
                            if ret_ea == insns[0].ea + 5:
                                call.append(blk.serial)
        for blk in all_blocks_in_mba(mba):
            for call in self.cleanups.get(blk.start, []):
                from_blk = mba.get_mblock(call)
                from_blk.flags |= MBL_KEEP
                blk.flags |= MBL_KEEP

    def find_cleanup_ret(self, blk: mblock_t):
        ret_insn = None
        ret_blk = blk.nextb
        while ret_blk and ret_blk.start not in self.cleanups:
            if ret_blk.head and ret_blk.head.opcode == m_ret:
                ret_insn = ret_blk.head
                break
            ret_blk = ret_blk.nextb
        return ret_blk, ret_insn

    def run_make_goto_back(self, mba):
        eas = []
        self.collect_cleanup_calls(mba)
        for blk in all_blocks_in_mba(mba):
            # if blk.start in self.cleanups:
            #     self.cleanups2[blk.tail.ea] = blk.start
            for from_blk_serial, from_insn_ea in self.cleanups.get(blk.start, []):
                eas.append(blk.start)
                from_blk = mba.get_mblock(from_blk_serial)
                ret_blk, ret_insn = self.find_cleanup_ret(blk)
                if ret_insn:
                    ret_insn.opcode = m_goto
                    ret_insn.l.make_blkref(from_blk.nextb.serial)
                    ret_blk.mark_lists_dirty()
        if eas:
            print_to_log("Optimization 2 restored CLEANUPS: " + ", ".join("%.6X" % ea for ea in eas))
        #print_mba(mba)

    def collect_all_cleanup_insns(self, first_cleanup_blk: mblock_t):
        insns = []
        cleanup_blk = first_cleanup_blk
        while cleanup_blk and (cleanup_blk.start not in self.cleanups or cleanup_blk.start == first_cleanup_blk.start):
            if cleanup_blk.head and cleanup_blk.head.opcode == m_ret:
                break
            for insn in all_insns_in_block(cleanup_blk):
                insns.append(insn)
            cleanup_blk = cleanup_blk.nextb
        return insns

    def run_copy_cleanup_insns(self, mba):
        eas = set()
        self.collect_cleanup_calls(mba)
        for blk in all_blocks_in_mba(mba):
            for call_blk_serial, call_insn_ea in self.cleanups.get(blk.start, []):
                call_blk = mba.get_mblock(call_blk_serial)
                insns = []
                collect_insns_up(call_blk.tail, insns)
                for insn in insns:
                    call_blk.make_nop(insn)
                insns = self.collect_all_cleanup_insns(blk)
                for insn in insns:
                    insnn = minsn_t(insn)
                    # insnn.setaddr(tail.ea)
                    call_blk.insert_into_block(insnn, call_blk.tail)
                call_blk.mark_lists_dirty()
                call_blk.make_lists_ready()
                eas.add(blk.start)
        if eas:
            print_to_log("Optimization 2 restored CLEANUPS: " + ", ".join("%.6X" % ea for ea in eas))

    def run_copy_cleanup_blocks(self, mba):
        eas = set()
        self.collect_cleanup_calls(mba)
        for blk in all_blocks_in_mba(mba):
            for call_blk, call_insn_ea in self.cleanups.get(blk.start, []):
                # call_blk = mba.get_mblock(call_blk_serial)
                insns = []
                collect_insns_up(call_blk.tail, insns)
                for insn in insns:
                    call_blk.make_nop(insn)
                call_blk.mark_lists_dirty()
                call_blk.make_lists_ready()
                cleanup_blk = blk
                insert_before_blk = call_blk.nextb
                while cleanup_blk and (cleanup_blk.start not in self.cleanups or cleanup_blk.start == blk.start):
                    if cleanup_blk.head and cleanup_blk.head.opcode == m_ret:
                        break
                    # print("copy_block %d %d" % (cleanup_blk.serial, insert_before_blk.serial))
                    new_blk = mba.copy_block(cleanup_blk, insert_before_blk.serial, CPBLK_FAST)
                    new_blk.mark_lists_dirty()
                    new_blk.make_lists_ready()
                    cleanup_blk = cleanup_blk.nextb
                eas.add(blk.start)
        if eas:
            self.delete_all_var4(mba)
            mba.mark_chains_dirty()
            print_to_log("Optimization 2 restored CLEANUPS: " + ", ".join("%.6X" % ea for ea in eas))

    def delete_all_var4(self, mba):
        for blk in all_blocks_in_mba(mba):
            for insn in all_insns_in_block(blk):
                if insn and insn.opcode == m_mov and insn.l.t == mop_n and insn.d.t == mop_S:
                    member = insn.d.get_stkvar(None)
                    if idaapi.get_member_name(member.id) == 'var_4':
                        # print("nop %s" % text_insn(insn))
                        blk.make_nop(insn)
                        blk.mark_lists_dirty()

    def run_change_eas(self, mba):
        r = 0
        for blk in all_blocks_in_mba(mba):
            for insn in all_insns_in_block(blk):
                print("Before:", text_insn(insn))
                if cleanup_blk_start := self.cleanups2.get(insn.ea):
                    for from_blk_serial, from_insn_ea in self.cleanups.get(cleanup_blk_start, []):
                        print("Change %x to %x" % (insn.ea, from_insn_ea))
                        insn.setaddr(from_insn_ea)
                        print(text_insn(insn))
                        blk.mark_lists_dirty()
                        r = 1
        return r

    def run_mmat_calls(self, mba):
        for blk in all_blocks_in_mba(mba):
            for call in self.cleanups.get(blk.start, []):
                from_blk = mba.get_mblock(call)
                tail = from_blk.tail
                insns = []
                collect_insns_up(from_blk.tail, insns)
                for insn in insns:
                    from_blk.make_nop(insn)
                for insn in all_insns_in_block(blk):
                    insnn = minsn_t(insn)
                    insnn.setaddr(tail.ea)
                    from_blk.insert_into_block(insnn, from_blk.tail)
                from_blk.mark_lists_dirty()
                from_blk.make_lists_ready()

    def run1(self, mba):
        for blk in all_blocks_in_mba(mba):
            insns = []
            if collect_insns_up(blk.tail, insns) == 6:
                insn = insns[0]
                if insn and insn.opcode == m_goto and insn.l.t == mop_v:
                    if (call := self.cleanups.get(insn.l.g)) is not None:
                        insn = insns[3]
                        if insn and insn.opcode == m_push and insn.l.t == mop_n:
                            ret_ea = insn.l.unsigned_value()
                            if ret_ea == insns[0].ea + 5:
                                call.append(blk.serial)
        for blk in all_blocks_in_mba(mba):
            for call in self.cleanups.get(blk.start, []):
                from_blk = mba.get_mblock(call)
                tail = from_blk.tail
                insns = []
                collect_insns_up(from_blk.tail, insns)
                for insn in insns:
                    from_blk.make_nop(insn)
                for insn in all_insns_in_block(blk):
                    insnn = minsn_t(insn)
                    #insnn.setaddr(mba.alloc_fict_ea(insn.ea))
                    #insnn.setaddr(tail_ea)
                    from_blk.insert_into_block(insnn, from_blk.tail)
                if from_blk.serial == 21:
                    insnn = InsnBuilder(0x41863C, m_push).r(REG_EAX).insn()
                    from_blk.insert_into_block(insnn, tail)
                    insnn = InsnBuilder(0x418641, m_push).r(REG_EAX).insn()
                    from_blk.insert_into_block(insnn, tail)
                from_blk.mark_lists_dirty()
                from_blk.make_lists_ready()

        if len(self.cleanups.keys()):
            print_to_log("Optimization 2 restored CLEANUPS: " + ", ".join("%.6X" % ea for ea in self.cleanups.keys()))

    def run2(self, mba):
        for blk in all_blocks_in_mba(mba):
            insns = []
            if collect_insns_up(blk.tail, insns) == 2:
                insn = insns[0]
                if insn and insn.opcode == m_goto and insn.l.t == mop_b:
                    if (call := self.cleanups.get(mba.get_mblock(insn.l.b).start)) is not None:
                        insn = insns[1]
                        if insn and insn.opcode == m_mov and insn.l.t == mop_n:
                            ret_ea = insn.l.unsigned_value()
                            if ret_ea == insns[0].ea + 5:
                                call.append(blk.serial)
        for blk in all_blocks_in_mba(mba):
            for call in self.cleanups.get(blk.start, []):
                from_blk = mba.get_mblock(call)
                tail_ea = from_blk.tail.ea
                insns = []
                collect_insns_up(from_blk.tail, insns)
                for insn in insns:
                    from_blk.make_nop(insn)
                for insn in all_insns_in_block(blk):
                    insnn = minsn_t(insn)
                    #insnn.ea = tail_ea
                    from_blk.insert_into_block(insnn, from_blk.tail)
                from_blk.mark_lists_dirty()
                from_blk.make_lists_ready()

        if len(self.cleanups.keys()):
            print_to_log("Optimization 2 restored CLEANUPS: " + ", ".join("%.6X" % ea for ea in self.cleanups.keys()))

    def run(self, mba):
        for blk in all_blocks_in_mba(mba):
            insns = []
            insn = blk.tail
            if insn and insn.opcode == m_goto and insn.l.t == mop_v:
                if (call := self.cleanups.get(insn.l.g)) is not None:
                    insns.append(insn)
                    insn = insn.prev
                    if insn and insn.opcode == m_push and insn.l.t == mop_n:
                        ret_ea = insn.l.unsigned_value()
                        if ret_ea == insns[0].ea + 5:
                            insns.append(insn)
                            insn = insn.prev
                            if insn and insn.opcode == m_mov and insn.l.t == mop_n and insn.d.t == mop_S:
                                member = insn.d.get_stkvar(None)
                                if idaapi.get_member_name(member.id) == 'var_4':
                                    call.append(blk.serial)
        for blk in all_blocks_in_mba(mba):
            for call in self.cleanups.get(blk.start, []):
                from_blk = mba.get_mblock(call)
                tail_ea = from_blk.tail.ea
                from_blk.make_nop(from_blk.tail)
                #from_blk.make_nop(from_blk.tail.prev)
                for insn in all_insns_in_block(blk):
                    insnn = minsn_t(insn)
                    #insnn.ea = mba.alloc_fict_ea(insn.ea)
                    insnn.ea = tail_ea
                    from_blk.insert_into_block(insnn, from_blk.tail)
                    #blk.make_nop(insn)
                    #blk.mark_lists_dirty()
                #blk.nextb.make_nop(blk.nextb.head)
                #blk.nextb.mark_lists_dirty()
                insnn = InsnBuilder(from_blk.nextb.head.ea, m_add).r(REG_ESP).n(4).r(REG_ESP).insn()
                #print(text_insn(insnn))
                from_blk.nextb.insert_into_block(insnn, None)
                from_blk.mark_lists_dirty()
                #from_blk.make_lists_ready()
                from_blk.nextb.mark_lists_dirty()
                #from_blk.nextb.make_lists_ready()
                # print_blk(from_blk)
                # try:
                #     mba.verify(True)
                # except RuntimeError as e:
                #     print("Error in blk %d: %s" % (from_blk.serial, e))
                #     print_blk(from_blk)
                #     print("mustbdef", from_blk.mustbdef.dstr())
                #     print("maybdef", from_blk.maybdef.dstr())
                #     # print_mba(self.mba)
                #     raise e

        if len(self.cleanups.keys()):
            print_to_log("Optimization 2 restored CLEANUPS: " + ", ".join("%.6X" % ea for ea in self.cleanups.keys()))


def run(mba):
    if is_func_lib(mba.entry_ea):
        return 0
    if Fix2a(mba):
        return 1

    return 0


def gather_seh_info(mba, fc, reachable_blocks):
    seh_list = []
    func = idaapi.get_func(mba.entry_ea)

    tbks = ida_tryblks.tryblks_t()
    r = ida_range.range_t(func.start_ea, func.end_ea)
    ida_tryblks.get_tryblks(tbks, r)
    blk_idx_map = {}

    for i in range(fc.size()):
        blk_idx_map[fc[i].start_ea] = i
        print("%d: %.8X" % (i, fc[i].start_ea))

    for idx, tryblock in enumerate(tbks):
        print(tryblock.get_kind(), tryblock.level)
        for r in tryblock:
            print("%.8X:%.8X" % (r.start_ea, r.end_ea))
        if tryblock.is_seh():
            seh = tryblock.seh()
            print("seh.disp: %d" % seh.disp)
            print("seh.fpreg: %d" % seh.fpreg)
            print("seh.filter:", list(seh.filter))
            print("seh.seh_code: %x" % seh.seh_code)
            for eh in tryblock.seh():
                print(eh.start_ea)
        elif tryblock.is_cpp():
            cpps = tryblock.cpp()
            for cpp in cpps:
                print("cpp.disp: %d" % cpp.disp)
                print("cpp.fpreg: %d" % cpp.fpreg)
                print("cpp.obj:", cpp.obj)
                print("cpp.type_id", cpp.type_id)
                for r in cpp:
                    print("%.8X:%.8X" % (r.start_ea, r.end_ea))
                    blocks = [blk_idx_map[r.start_ea]]
                    while len(blocks):
                        block_idx = blocks.pop()
                        if not reachable_blocks.has(block_idx):
                            print(f'restore unreferenced block #{block_idx}')
                            reachable_blocks.add(block_idx)
                            for i in range(fc.nsucc(block_idx)):
                                blocks.append(fc.succ(block_idx, i))

        # # skip block 0 (it covers the function itself)
        # # skip cpp seh
        # if not idx or not tryblock.is_seh():
        #     continue
        # # TODO: should consider nested SEH case
        # # TODO: could contain multiple ranges (nested case?), should check if len > 1
        # # finally block?
        # rge = tryblock[0]
        # try_start = rge.start_ea
        # try_end = rge.end_ea
        #
        # if try_start in self.banned_set:
        #     print(f'ignore try block @ {hex(try_start)}')
        #     continue
        #
        # eh_start_list = []
        # for eh in tryblock.seh():
        #     # since some unreachable catch blocks are never included in the microcode block list,
        #     # we have to restore all blocks reachable from the catch block in bitmap
        #
        #     # initialize the list with catch block index
        #     blocks = [blk_idx_map[eh.start_ea]]
        #
        #     # traverse all blocks from catch block
        #     while len(blocks):
        #         block_idx = blocks.pop()
        #         if not reachable_blocks.has(block_idx):
        #             # info(f'restore unreferenced block #{block_idx}')
        #             reachable_blocks.add(block_idx)
        #             # push all successors into list
        #             for i in range(fc.nsucc(block_idx)):
        #                 blocks.append(fc.succ(block_idx, i))
        #
        #     eh_start_list.append(eh.start_ea)
        #
        # # print(f'try block #{idx}')
        # # print(f'range: [{hex(try_start)}, {hex(try_end)}) -> {[hex(i) for i in eh_start_list]}')
        #
        # # NOTE: currently support only one catch block
        # # also, it looks like msvc only accept one __except block?
        # if len(eh_start_list) != 0:
        #     seh_list.append((try_start, try_end, eh_start_list[0]))


def check_lst(lst):
    # Check that toea is unique
    if lst:
        ea = -1
        for (insn, op, fromea, toea) in lst:
            if ea == -1:
                ea = toea
            elif ea != toea:
                return False
        return True
    return False


def Fix2b(mba):
    for blk in all_blocks_in_mba(mba):
        insns = []
        insn = blk.tail
        if insn and insn.opcode == m_goto and insn.l.t == mop_v:
            toea = insn.l.g
            insns.append(insn)
            insn = insn.prev
            if insn and insn.opcode == m_push and insn.l.t == mop_n:
                ret_ea = insn.l.unsigned_value()
                if ret_ea == insns[0].ea + 5:
                    insns.append(insn)
                    insn = insn.prev
                    if insn and insn.opcode == m_mov and insn.l.t == mop_n and insn.d.t == mop_S:
                        member = insn.d.get_stkvar(None)
                        var_name = idaapi.get_member_name(member.id)
                        if var_name == 'var_4':
                            print_to_log("Optimization 2 removed JUMPOUT: jump from %.8X to %.8X" % (insns[0].ea, toea))
                            for insn in insns:
                                blk.make_nop(insn)
                                blk.mark_lists_dirty()


def Fix2a(mba):
    for blk in all_blocks_in_mba(mba):
        # if blk.serial == 8:
        #     sea = 0x004188CA
        #     eea = 0x004188D3
        #     insns = []
        #     if collect_exit_insns(sea, insns):
        #         print_insns(insns)

        # w = ida_kernwin.warning
        # hf = hexrays_failure_t()
        # mbr = mba_ranges_t(None)
        # mbr.ranges.push_back(ida_range.range_t(sea, eea))
        # mba2 = gen_microcode(mbr, hf, None, DECOMP_ALL_BLKS, mba.maturity)
        # if mba2:
        #     print("Successfully generated microcode for 0x%08x..0x%08x\n" % (sea, eea))
        #     print_mba(mba2)
        # else:
        #     w("0x%08x: %d %s" % (hf.errea, hf.code, hf.desc()))

        for insn in all_insns_in_block(blk):
            #    print(text_insn(insn))
            if insn.opcode == m_push and insn.ea == 0x004188C0:
                blk.make_nop(insn)
                blk.mark_lists_dirty()
            if insn.opcode == m_goto and insn.ea == 0x004188C0:
                insn.opcode = m_call
                blk.mark_lists_dirty()
        #     insn.l.make_blkref(6)
        #     blk.mark_lists_dirty()
    print_mba(mba)


def Fix2(mba):
    #print_mba(mba)
    mba.for_all_topinsns(vstr := Visitor2(mba.entry_ea))
    if check_lst(vstr.lst):
        print("Found jump to external %.8X" % vstr.toea)
        return False
        insns = []
        if collect_exit_insns(vstr.toea, insns):
            # print_insns(insns)
            blk = mba.insert_block(mba.qty - 1)
            # blk.start = vstr.ea
            # blk.end = insns[-1].ea + 1
            blk.flags = MBL_PROP | MBL_COMB | MBL_PUSH
            # blk.flags = MBL_FAKE | MBL_PUSH
            # insnn = minsn_t(mba.alloc_fict_ea(vstr.ea))
            # insnn = minsn_t(0x361B6)
            # insnn.opcode = m_nop
            # blk.insert_into_block(insnn, None)
            prev = None
            for insn in insns:
                insn.ea = mba.alloc_fict_ea(mba.entry_ea)
                # insn.ea = 0x361B6
                # print("fictea: %.8X" % fictea)
                blk.insert_into_block(insn, prev)
                # print("map_fict_ea: %.8X to %.8X" % (insn.ea, mba.map_fict_ea(insn.ea)))
                prev = insn
            blk.start = insns[0].ea
            # blk.end = insns[-1].ea + 1 # Should be FFFFFFFF ! This way we avoid INTERR(50870); // block outside of function boundaries
            blk.maxbsp = - vstr.sp
            blk.mark_lists_dirty()
            # blk.make_lists_ready()
            for (insn, op, fromea, toea) in vstr.lst:
                print_to_log("Optimization 9 replaced JUMPOUT: jump from %.8X to %.8X" % (fromea, toea))
                op.g = insns[0].ea
            # mba.mbr.ranges.push_back(ida_range.range_t(blk.start, blk.end))

            # print_mba(mba)
            # print("ranges.empty:", mba.mbr.ranges.empty())
            # print("ranges size:", mba.mbr.ranges.size())
            mba.verify(True)
            # print("Verified")
            return True
    return False


# Finds JUMPOUTs
class Visitor2(minsn_visitor_t):
    def __init__(self, entry_ea):
        self.lst = []
        self.toea = 0
        self.sp = 0
        self.entry_ea = entry_ea
        minsn_visitor_t.__init__(self)

    def visit_minsn(self):
        insn = self.topins
        if insn.opcode == m_jcnd and insn.d.t == mop_v:
            op = insn.d
        elif insn.opcode == m_goto and insn.l.t == mop_v:
            op = insn.l
        else:
            # print(text_insn(insn))
            return 0
        func = ida_funcs.get_func(op.g)
        toea = op.g
        print(text_insn(insn))
        print("op.g: %.8X" % op.g)
        print("func.start_ea: %.8X" % func.start_ea)
        if self.entry_ea != func.start_ea:
            #print("Found %s" % text_insn(insn))
            self.toea = toea
            self.sp = ida_frame.get_spd(func, toea)
            self.lst.append((insn, op, insn.ea, toea))
        return 0


def collect_exit_insns(ea, lst):
    func = ida_funcs.get_func(ea)
    fii = ida_funcs.func_item_iterator_t()
    insn = ida_ua.insn_t()
    i = 0
    ok = fii.set(func, ea)
    endea = 0
    while ok and i < 10:
        ea = fii.current()
        ida_ua.decode_insn(insn, ea)
        s = ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS)
        print(s)
        ops = s.split()
        l = len(ops)
        if l == 3 and ops[0] == "mov" and insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_reg:
            insnn = minsn_t(ea)
            insnn.opcode = m_mov
            ops[1] = ops[1].replace(',', '')
            ri = ida_idp.reg_info_t()
            # print(ops[1])
            if not ida_idp.parse_reg_name(ri, ops[1]):
                return False
            insnn.l.make_reg(reg2mreg(ri.reg), ri.size)
            # print(ops[2])
            if not ida_idp.parse_reg_name(ri, ops[2]):
                return False
            insnn.d.make_reg(reg2mreg(ri.reg), ri.size)
            # print_insn(insnn)
            lst.append(insnn)
        elif l == 3 and ops[0] == "add" and ops[1] == "esp,":
            # print(insn.Op1.reg, reg2mreg(insn.Op1.reg), insn.Op2.value)
            insnn = minsn_t(ea)
            insnn.opcode = m_add
            insnn.l.make_reg(24, 4)
            insnn.r.make_number(insn.Op2.value, 4)
            insnn.d.make_reg(24, 4)
            lst.append(insnn)
        elif l == 2 and ops[0] == "pop":
            # print(insn.Op1.reg, reg2mreg(insn.Op1.reg))
            insnn = minsn_t(ea)
            insnn.opcode = m_pop
            insnn.d.make_reg(reg2mreg(insn.Op1.reg), 4)
            lst.append(insnn)
        elif l == 1 and ops[0] == "retn":
            # print("FOUND RET")
            insnn = minsn_t(ea)
            insnn.opcode = m_ret
            lst.append(insnn)
            endea = ea + 1
            break
        else:
            break
        # print("get_spd", ida_frame.get_effective_spd(func, ea))
        i = i + 1
        ok = fii.next_code()
    if endea > 0:
        return True
    return False


# class Opt(GlbOpt):
#     def __init__(self):
#         super().__init__(2, "Opt2")
#
#     def _init(self):
#         pass
#
#     def _run(self):
#         for blk in all_blocks_in_mba(self.mba):
#             if blk.serial == 3:
#                 blk.start = 0x004188CA
#                 blk.end = 0x004188D2
#                 blk.flags = blk.flags | MBL_KEEP
#         #print_mba(self.mba)

def debug_print_tryblocks(func: idaapi.func_t):
    tryblks = ida_tryblks.tryblks_t()
    rng = ida_range.range_t(func.start_ea, func.end_ea)
    ida_tryblks.get_tryblks(tryblks, rng)
    for tryblk in tryblks:
        debug_print_tryblock(tryblk)


def debug_change_tryblocks(func: idaapi.func_t):
    print("debug_change_tryblocks")
    tryblks = ida_tryblks.tryblks_t()
    rng = ida_range.range_t(func.start_ea, func.end_ea)
    #ida_tryblks.del_tryblks(rng)
    ida_tryblks.get_tryblks(tryblks, rng)
    modified = False
    for tryblk in tryblks:
        if tryblk.is_cpp():
            catches: ida_tryblks.catchvec_t = tryblk.cpp()
            #catch: ida_tryblks.catch_t
            for catch in catches:  # catch_t(try_handler_t(rangevec_t)) in catchvec_t
                if tryblk.at(0).start_ea == 0x4ED140 and catch.at(0).start_ea != 0x4EEEFF:
                    catch.pop_back()
                    catch.push_back(ida_range.range_t(0x4EEEFF, 0xFFFFFFFF))
                    modified = True
                if tryblk.at(0).start_ea == 0x4EE071 and catch.at(0).start_ea != 0x4EEEF3:
                    catch.pop_back()
                    catch.push_back(ida_range.range_t(0x4EEEF3, 0xFFFFFFFF))
                    modified = True
    if modified:
        print("Modified")
        ida_tryblks.del_tryblks(rng)
        for tryblk in tryblks:
            ida_tryblks.add_tryblk(tryblk)


def debug_print_tryblock(tryblk: ida_tryblks.tryblk_t):
    print("tryblk.get_kind():", tryblk.get_kind())
    for r in tryblk:
        print("  %X : %X" % (r.start_ea, r.end_ea))
    if tryblk.is_cpp():
        for catch in tryblk.cpp():  # catch_t(try_handler_t) in catchvec_t
            print("  catch: obj:%d, type_id:%d, disp:%d, fpreg:%d" % (catch.obj, catch.type_id, catch.disp, catch.fpreg))
            for r in catch:
                print("    %X : %X" % (r.start_ea, r.end_ea))


def fix_tryblocks(func: idaapi.func_t):
    tryblks = ida_tryblks.tryblks_t()
    fr = ida_range.range_t(func.start_ea, func.end_ea)
    ida_tryblks.get_tryblks(tryblks, fr)
    modified = []
    for tryblk in tryblks:
        if tryblk.is_cpp() and tryblk.size() == 1:
            catches: ida_tryblks.catchvec_t = tryblk.cpp()
            if catches.size() == 1 and catches.at(0).size() == 1:
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, tryblk.at(0).end_ea):
                    if insn.itype == ida_allins.NN_mov:
                        if insn.Op1.type == ida_ua.o_displ and insn.Op1.phrase == 5 and idc.get_operand_value(insn.ea, 0) == 0xFFFFFFFC:
                            #print("%X, %d, %d, %X" % (insn.ea, insn.Op1.type, insn.Op1.phrase, idc.get_operand_value(insn.ea, 0)))
                            next_ea = insn.ea + insn.size
                            next_insn = ida_ua.insn_t()
                            if ida_ua.decode_insn(next_insn, next_ea) and next_insn.itype == ida_allins.NN_call:
                                call_ea = next_insn.Op1.addr
                                if func.start_ea <= call_ea < func.end_ea:
                                    #print("%X, %d, %d, %d, %X" % (next_insn.ea, next_insn.itype, next_insn.Op1.type, next_insn.Op1.phrase, idc.get_operand_value(next_insn.ea, 0)))
                                    if catches.at(0).at(0).start_ea != next_insn.Op1.addr:
                                        modified.append((catches.at(0).at(0).start_ea, next_insn.Op1.addr))
                                        catches.at(0).at(0).start_ea = next_insn.Op1.addr
    if modified:
        for a, b in modified:
            print("Fixed cleanup from %X to %X" % (a, b))
        ida_tryblks.del_tryblks(fr)
        for tryblk in tryblks:
            ida_tryblks.add_tryblk(tryblk)
