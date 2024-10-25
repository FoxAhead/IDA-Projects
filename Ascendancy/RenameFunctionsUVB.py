from idautils import *
from idaapi import *
from idc import *
import ida_typeinf
import ida_nalt

#for segea in Segments():
    #for funcea in Functions(segea, get_segm_end(segea)):
for funcea in Functions(0x74BF0, 0x76CB4):
    functionName = get_func_name(funcea)
    if not functionName.startswith("UVB_"):
        newFunctionName = "UVB_" + functionName
        set_name(funcea, newFunctionName)
    #tinfo = ida_typeinf.tinfo_t()
    #ida_nalt.get_tinfo(tinfo, funcea)
    
    #function_details = idaapi.func_type_data_t()
    #
    #tinfo.get_func_details(function_details)
    
        print("%.8X, %s, %s" % (funcea, functionName, newFunctionName))
    #functionFlags = get_func_attr(funcea, FUNCATTR_FLAGS)
    #print("{0:0>16b}".format(functionFlags), "%X"%funcea, functionName)
    #else:
    #    functionFlags = get_func_attr(funcea, FUNCATTR_FLAGS)
    #    functionFlags = functionFlags | FUNC_LIB
    #    set_func_attr(funcea, FUNCATTR_FLAGS, functionFlags)
            
