from idautils import *
from idaapi import *
from idc import *

for segea in Segments():
#    for funcea in Functions(segea, SegEnd(segea)):
    for funcea in Functions(segea, get_segm_end(segea)):
        if funcea < 0x5F1B80\
        and funcea != 0x403A49\
        and funcea != 0x55ADD0\
        and not 0x5BB1D2 <= funcea <= 0x5BB3BE\
        and not 0x5EDC2E <= funcea <= 0x5EDC46\
        and not 0x5EF2C2 <= funcea <= 0x5EF310\
        and funcea != 0x5EFDAE:
            functionName = get_func_name(funcea)
            functionFlags = get_func_attr(funcea, FUNCATTR_FLAGS)
#            if functionFlags & FUNC_LIB:
#                if functionFlags & FUNC_HIDDEN:
#            if functionFlags & FUNC_NORET:
            if not functionName.startswith("Q_")\
            and not functionName.startswith("j_Q_")\
            and not functionName.startswith("lib_")\
            and not functionName.startswith("j_lib_")\
            and not functionName.startswith("sub_"):
                #print("{0:0>16b}".format(functionFlags), "%X"%funcea, functionName)
                set_name(funcea, "")
