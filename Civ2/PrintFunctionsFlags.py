from idautils import *
from idaapi import *
from idc import *

for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        functionName = GetFunctionName(funcea)
        functionFlags = GetFunctionFlags(funcea)
        print "{0:0>16b}".format(functionFlags), "%X"%funcea, functionName
