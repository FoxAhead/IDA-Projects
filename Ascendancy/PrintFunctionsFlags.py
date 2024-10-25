from idautils import *
from idaapi import *
from idc import *

for segea in Segments():
    for funcea in Functions(segea, get_segm_end(segea)):
        functionName = get_func_name(funcea)
        functionFlags = get_func_attr(funcea, FUNCATTR_FLAGS)
        print("{0:0>16b}".format(functionFlags), "%X"%funcea, functionName)
