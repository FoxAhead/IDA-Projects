from idautils import *
from idaapi import *
from idc import *
import ida_typeinf
import ida_nalt

for segea in Segments():
    for funcea in Functions(segea, get_segm_end(segea)):
    #for funcea in Functions(0x66CBF, 0x74CB6):
        functionName = get_func_name(funcea)
        
        tinfo = ida_typeinf.tinfo_t()
        ida_nalt.get_tinfo(tinfo, funcea)
        
        #function_details = idaapi.func_type_data_t()
        #
        #tinfo.get_func_details(function_details)
        
        print(functionName, tinfo)
        #functionFlags = get_func_attr(funcea, FUNCATTR_FLAGS)
        #print("{0:0>16b}".format(functionFlags), "%X"%funcea, functionName)
