import idc, idautils
for funcea in Functions( SegStart( here() ), SegEnd( here() ) ):
    level = 0
    for eai in FuncItems(funcea):
        if level == 0:
            if GetDisasm(eai) == "push    ebp":
                level += 1
            else:
                break
        elif level == 1:
            if GetDisasm(eai) == "mov     ebp, esp":
                level += 1
            else:
                break
        elif level == 2:
            if GetDisasm(eai) == "push    0FFFFFFFFh":
                level += 1
                print "%X"%funcea, GetFunctionName(funcea)
                frame = idc.GetFrame(funcea)
                for frame_member in idautils.StructMembers(frame):
                    member_offset, member_name, _ = frame_member
                    if member_name == ' s':
                        base = member_offset
                for frame_member in idautils.StructMembers(frame):
                    member_offset, member_name, _ = frame_member
                    if (member_offset - base) == -4:
                        print member_offset, member_name
                        set_member_name(frame, member_offset, "EHState")
            else:
                break
        #disasm = GetDisasm(eai)
            
        
        #print "%X"%eai, GetDisasm(eai)
            #if GetMnem(eai) == "jmp" or GetMnem(eai) == "call":
            # if GetDisasm(eai)[-2:-1] == "+" and GetDisasm(eai)[-1:].isdigit():
                # print "Broken Instruction: %X"%eai, GetDisasm(eai)
                # code_addr = GetOperandValue(eai, 0) 
                # fix_addr = code_addr -1 
                # MakeUnkn(fix_addr,1)
                # MakeCode(code_addr)