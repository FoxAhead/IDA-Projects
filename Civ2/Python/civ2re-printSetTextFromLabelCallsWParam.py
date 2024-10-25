funcea = 0x00401BF4; # j_Q_SetTextFromLabel_sub_40BC10

for ref in CodeRefsTo(funcea, 1):
    previ = prev_head(ref)
    #if GetMnem(previ) = "push":
        
    #print "0x%08X"%ref, "0x%08X"%previ
    print "0x%08X"%ref, GetDisasm(previ)
    