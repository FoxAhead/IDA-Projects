# kind of slow to loop through all the functions and instructions but it works 
# flaw: only defined functions will be traversed.this. 
for funcea in Functions( SegStart( here() ), SegEnd( here() ) ):
    if len(list(FuncItems(funcea))) == 1:
        for eai in FuncItems(funcea):
            print "%X"%eai, GetDisasm(eai)
            #if GetMnem(eai) == "jmp" or GetMnem(eai) == "call":
            # if GetDisasm(eai)[-2:-1] == "+" and GetDisasm(eai)[-1:].isdigit():
                # print "Broken Instruction: %X"%eai, GetDisasm(eai)
                # code_addr = GetOperandValue(eai, 0) 
                # fix_addr = code_addr -1 
                # MakeUnkn(fix_addr,1)
                # MakeCode(code_addr)