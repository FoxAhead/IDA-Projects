"""
summary: various decompiler hooks

description:
  Shows how to hook to many notifications sent by the decompiler.

  This plugin doesn't really accomplish anything: it just prints
  the parameters.

  Also, the list of notifications handled below, isn't exhaustive.
  Please investigate `ida_hexrays.Hexrays_Hooks` for a full list.
"""
from ida_hexrays import *
import ida_idaapi

class subinsn_optimizer_t(minsn_visitor_t):
    cnt = 0
    def __init__(self):
        minsn_visitor_t.__init__(self)
    def visit_minsn(self):      # for each instruction...
        ins = self.curins       # take a reference to the current instruction
        #if ins.opcode == m_jnz:
        print("INSN_OPTIMIZER_T: INSN: %s" % ins.dstr())
        return 0 # continue traversal

class insn_optimizer_t(optinsn_t):
    def __init__(self):
        optinsn_t.__init__(self)
    def func(self, blk, ins, optflags):
        print("INSN_OPTIMIZER_T: blk=%s, ins=%s, optflags=%s" % (blk.serial, ins, optflags))
        opt = subinsn_optimizer_t()
        ins.for_all_insns(opt)
        if ins.opcode == m_stx and ins.l.is_equal_to(0) and ins.d.d.l.t == mop_d:
            print("INSN: %s" % ins.dstr())
            vp = vd_printer_t()
            blk.mba._print(vp)
            blk5 = blk.mba.get_mblock(5)
            blk5.make_nop(blk5.head)
                
            #ins.clr_combinable()
        #if ins.opcode == m_jnz:
        #    print("INSN: %s" % ins.dstr())
        #opt = subinsn_optimizer_t()
        #ins.for_all_insns(opt)
        #if opt.cnt != 0:                # if we modified microcode,
        #    blk.mba.verify(True)        # run the verifier
        #return opt.cnt                  # report the number of changes
        return 0

class block_optimizer_t(optblock_t):
    def func(self, blk):
        if self.handle123(blk):
            return 1
        return 0

    def handle123(self, blk):
        print("BLOCK_OPTIMIZER_T: %s" % blk.serial)
        #mgoto = blk.tail
        #if not mgoto or mgoto.opcode != ida_hexrays.m_goto:
        #    return False
        #
        #visited = []
        #t0 = mgoto.l.b
        #i = t0
        #mba = blk.mba
        #
        ## follow the goto chain
        #while True:
        #    if i in visited:
        #        return False
        #    visited.append(i)
        #    b = mba.get_mblock(i)
        #    m2 = ida_hexrays.getf_reginsn(b.head)
        #    if not m2 or m2.opcode != ida_hexrays.m_goto:
        #        break
        #    i = m2.l.b
        #
        #if i == t0:
        #    return False # not a chain
        #
        ## all ok, found a goto chain
        #mgoto.l.b = i # jump directly to the end of the chain
        #
        ## fix the successor/predecessor lists
        #blk.succset[0] = i
        #mba.get_mblock(i).predset.add(blk.serial)
        #mba.get_mblock(t0).predset._del(blk.serial)
        #
        ## since we changed the control flow graph, invalidate the use/def chains.
        ## stricly speaking it is not really necessary in our plugin because
        ## we did not move around any microcode operands.
        #mba.mark_chains_dirty()
        #
        ## it is a good idea to verify microcode after each change
        ## however, it may be time consuming, so comment it out eventually
        #mba.verify(True);
        #return True


optimizeri = insn_optimizer_t()
optimizeri.install()

optimizerb = block_optimizer_t()
optimizerb.install()
