ea1 = 0x006560F0;
lst = []

for off in range(0x00, 0x1F):
    ea = ea1 + off
    for ref in DataRefsTo(ea):
        lst.append(ref)

lst = sorted(lst)

for ref in lst:
    buf = GetManyBytes(ref, ItemSize(ref))
    #print "0x%08X"%ref, "0x"+''.join('%02X' % ord(c) for c in buf )
    off = buf.find('\x60\x65\x00')
    if off == -1:
        off = buf.find('\x61\x65\x00')
    off = off - 1
    #print "0x%08X"%(ref+off), off, "0x"+''.join('%02X' % ord(c) for c in buf )
    print "0x%08X"%(ref+off)
    #print "0x%08X"%ref, GetFuncOffset(ref), "0x"+''.join('%02X' % ord(c) for c in buf )
    #di = DecodeInstruction(ref)
    #print "0x%08X"%ref, "0x%08X"%di.Op1.addr, "0x%08X"%di.Op2.addr, "0x%08X"%di.Op3.addr
    #print "0x%08X"%ref, "0x%08X"%GetOperandValue(ref,1)
        


#for off in range(0x00, 0x1F):
#    ea = ea1 + off
#    #print "# DataRefsTo "+"0x%08X"%ea
#    for ref in DataRefsTo(ea):
#        buf = idc.GetManyBytes(ref, ItemSize(ref))
#        #print "0x%08X"%ref, "0x"+''.join('%02X' % ord(c) for c in buf )
#        print "0x%08X"%ref, GetFuncOffset(ref), "0x"+''.join('%02X' % ord(c) for c in buf )
        
    
#for xref in XrefsTo(ea1, 0):
#    print xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to)
