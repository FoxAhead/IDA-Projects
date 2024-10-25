from idautils import *
from idaapi import *
from idc import *

for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        functionName = GetFunctionName(funcea)
        functionFlags = GetFunctionFlags(funcea)
        if functionName.startswith("sub_") and not (functionFlags & FUNC_THUNK):
            functionName = "Z_" + functionName
            MakeName(funcea, functionName)

            