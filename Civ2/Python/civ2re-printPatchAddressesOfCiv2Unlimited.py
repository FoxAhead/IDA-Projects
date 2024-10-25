funcea = 0x00403B1C

for eai in FuncItems(funcea):
    if Byte(eai) == 0xB8:
        #buf = idc.GetManyBytes(eai+1, 4)
        #print "0x%08X"%eai, "0x%08X"%Dword(eai+1)
        print "0x%08X"%Dword(eai+1)
        #print "0x%08X"%eai, GetDisasm(eai)