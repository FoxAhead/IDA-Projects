from idautils import *
from idaapi import *
from idc import *

for funcea in Functions(0x5BE08, 0x82730+1):
    functionName = get_func_name(funcea)
    functionFlags = get_func_attr(funcea, FUNCATTR_FLAGS)
    functionFlags = functionFlags | FUNC_LIB
    set_func_attr(funcea, FUNCATTR_FLAGS, functionFlags)
    print("%.8X, %s" % (funcea, functionName))
