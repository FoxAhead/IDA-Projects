from idautils import *
from idaapi import *
from idc import *

for segea in Segments():
#    for funcea in Functions(segea, SegEnd(segea)):
    for funcea in Functions(segea, get_segm_end(segea)):
        if funcea < 0x5F1B80:
            functionName = get_func_name(funcea)
            functionFlags = get_func_attr(funcea, FUNCATTR_FLAGS)
#            if functionFlags & FUNC_LIB:
#                if functionFlags & FUNC_HIDDEN:
#            if functionFlags & FUNC_NORET:
            print("{0:0>16b}".format(functionFlags), "%X"%funcea, functionName)

