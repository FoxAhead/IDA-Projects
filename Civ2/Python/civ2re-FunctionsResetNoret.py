from idautils import *
from idaapi import *
from idc import *

for segea in Segments():
    for funcea in Functions(segea, get_segm_end(segea)):
        if funcea < 0x5F1B80\
        and funcea != 0x403A49\
        and funcea != 0x55ADD0:
            functionName = get_func_name(funcea)
            functionFlags = get_func_attr(funcea, FUNCATTR_FLAGS)
            if functionFlags & FUNC_NORET:
                functionFlags &= ~FUNC_NORET;
                set_func_attr(funcea, FUNCATTR_FLAGS, functionFlags)
