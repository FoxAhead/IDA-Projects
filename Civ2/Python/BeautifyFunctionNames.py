from idautils import *
from idaapi import *
from idc import *

import lib

require("lib")


def get_first_part_by_type_name(type_name):
    first_part = type_name[2:]
    if first_part.startswith('ControlInfo'):
        if first_part != 'ControlInfo':
            first_part = first_part[11:]
    return first_part


def main():
    funcs = []
    for segea in Segments():
        for funcea in Functions(segea, get_segm_end(segea)):
            if lib.func_is_named(funcea):
                funcs.append(lib.get_function_info(funcea))
    funcs.sort(key=lambda x: x.name)
    n = 0
    for func in funcs:
        if func.cc == CM_CC_THISCALL:
            arg0 = func.arguments[0]
            type_name = arg0.pointed_type if arg0.is_ptr else arg0.type
            if lib.is_custom_type(type_name):
                a, sep, b = func.name.partition('_')
                # print('0x%X %s' % (func.address, func.name))
                first_part = get_first_part_by_type_name(arg0.type)
                if first_part != a:
                    print('0x%X %s' % (func.address, func.name), a, b, type_name, first_part)
                    new_name = first_part + '_' + b
                    n = n + 1


    print('Total %d functions' % n)


if __name__ == '__main__':
    main()
