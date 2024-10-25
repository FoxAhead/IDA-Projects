"""
summary: Optimization 9

description:

    Replace JUMPOUT with code from exit block

    Exit block example 1:
00036045 018 83 C4 04                     add     esp, 4
00036048 014 5F                           pop     edi
00036049 010 5E                           pop     esi
0003604A 00C 5A                           pop     edx
0003604B 008 59                           pop     ecx
0003604C 004 5B                           pop     ebx
0003604D 000 C3                           retn

    Exit block example 2:
000341FF 02C 89 E8                        mov     eax, ebp
00034201 02C 83 C4 14                     add     esp, 14h
00034204 018 5D                           pop     ebp
00034205 014 5F                           pop     edi
00034206 010 5E                           pop     esi
00034207 00C 5A                           pop     edx
00034208 008 59                           pop     ecx
00034209 004 5B                           pop     ebx
0003420A 000 C3                           retn

    Test:
        36020
        3420C - Multiple jumpouts and different exit block

"""
import ida_frame
import ida_kernwin
from ida_hexrays import *
from ascendancy.util import *
import ida_ua
import ida_allins
import ascendancy.opts.opt7


def run(mba):
    if is_func_lib(mba.entry_ea):
        return 0
    if Fix9b(mba):
        # print("run7")
        # ascendancy.opts.opt7.run(mba)
        return 1
    return 0


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


def Fix9b(mba):
    # print_mba(mba)
    mba.for_all_topinsns(vstr := Visitor9b(mba.entry_ea))
    if check_lst(vstr.lst):
        # print("Found jump to external %.8X" % vstr.toea)
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
class Visitor9b(minsn_visitor_t):
    lst = []
    toea = 0
    sp = 0

    def __init__(self, entry_ea):
        self.lst.clear()
        toea = 0
        sp = 0
        self.entry_ea = entry_ea
        minsn_visitor_t.__init__(self)

    def visit_minsn(self):
        insn = self.topins
        if insn.opcode == m_jcnd and insn.d.t == mop_v:
            op = insn.d
        elif insn.opcode == m_goto and insn.l.t == mop_v:
            op = insn.l
        else:
            return 0
        func = ida_funcs.get_func(op.g)
        toea = op.g
        if self.entry_ea != func.start_ea:
            self.toea = toea
            self.sp = ida_frame.get_spd(func, toea)
            self.lst.append((insn, op, insn.ea, toea))
        return 0


def Fix9(mba):
    blk = mba.blocks
    while blk:
        # print("BLK %d %.8X %.8X" % (blk.serial, blk.start, blk.end))
        if blk.type == BLT_XTRN:
            if (blk1 := blk.prevb) and blk1.flags & MBL_FAKE and blk1.type == BLT_1WAY:
                if (blk2 := blk.nextb) and blk2.flags & MBL_FAKE and blk2.type == BLT_STOP:
                    print("FOUND BLT_XTRN %d %.8X %.8X" % (blk.serial, blk.start, blk.end))
                    insns = []
                    if collect_exit_insns(blk.start, insns):
                        # print_insns(insns)
                        blk1.succset[0] = blk2.serial
                        mba.remove_block(blk)
                        blk1.flags = MBL_PROP | MBL_COMB | MBL_PUSH
                        blk2 = blk1.nextb
                        blk2.predset.append(blk1.serial)
                        prev = None
                        for insn in insns:
                            blk1.insert_into_block(insn, prev)
                            prev = insn
                        # print(blk14.npred())
                        # print(blk14.nsucc())
                        # insnn = minsn_t(blk13.start)
                        # insnn.opcode = m_nop
                        # blk13.insert_into_block(insnn, None)

                        # insnn = minsn_t(blk13.start)
                        # insnn.opcode = m_ret
                        # blk13.insert_into_block(insnn, None)

                        # insnn = minsn_t(blk1.start)
                        # insnn.opcode = m_pop
                        # insnn.d.make_reg(36, 4)
                        # blk1.insert_into_block(insnn, None)
                        #
                        # insnn = minsn_t(blk1.start)
                        # insnn.opcode = m_pop
                        # insnn.d.make_reg(32, 4)
                        # blk1.insert_into_block(insnn, None)
                        #
                        # insnn = minsn_t(blk1.start)
                        # insnn.opcode = m_add
                        # insnn.l.make_reg(24, 4)
                        # insnn.r.make_number(4, 4)
                        # insnn.d.make_reg(24, 4)
                        # blk1.insert_into_block(insnn, None)
                        #
                        blk1.mark_lists_dirty()

                        # generate_micro(blk.start, endea)
                        return True

        blk = blk.nextb

    return False


def generate_micro(sea, eea):
    print("Generating microcode for 0x%08x..0x%08x\n" % (sea, eea))
    w = ida_kernwin.warning
    hf = hexrays_failure_t()
    mbr = mba_ranges_t()
    mbr.ranges.push_back(ida_range.range_t(sea, eea))
    mba = gen_microcode(mbr, hf, None, DECOMP_WARNINGS | DECOMP_NO_CACHE, MMAT_LOCOPT)
    if mba:
        print("Successfully generated microcode for 0x%08x..0x%08x\n" % (sea, eea))
        vp = vd_printer_t()
        mba._print(vp)
    else:
        w("0x%08x: %s" % (hf.errea, hf.str))


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
        # print(s)
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
