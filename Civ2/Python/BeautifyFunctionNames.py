from idautils import *
from idaapi import *
from idc import *

import lib

require("lib")


def get_first_part_by_type_name(type_name):
    full_first_part = type_name[2:]
    first_part = full_first_part
    if first_part == 'DialogWindow':
        first_part = 'Dlg'
    # elif first_part.endswith('Window'):
    #    first_part = first_part.replace('Window', 'Win')
    elif first_part.startswith('ControlInfo'):
        if first_part != 'ControlInfo':
            first_part = first_part[11:]
    return full_first_part, first_part


def rename_func(func, new_full_name):
    set_name(func.address, new_full_name)
    set_name(func.jaddress, '', SN_AUTO)
    set_func_name_if_jumpfunc(func_t(func.jaddress), None)


def beautify(rename=False):
    funcs = []
    for segea in Segments():
        for funcea in Functions(segea, get_segm_end(segea)):
            if lib.func_is_named(funcea):
                funcs.append(lib.get_function_info(funcea))
    funcs.sort(key=lambda x: x.name)
    lib.analyze_crefs(funcs, True)
    n = 0
    out_lines = []
    for func in funcs:
        if func.cc == CM_CC_THISCALL:
            arg0 = func.arguments[0]
            type_name = arg0.pointed_type if arg0.is_ptr else arg0.type
            if lib.is_custom_type(type_name):
                a, sep, b = func.name.partition('_')
                if b == '':
                    a, b = b, a
                # print('0x%X %s' % (func.address, func.name))
                full_first_part, first_part = get_first_part_by_type_name(type_name)
                if first_part != a:
                    # second_part = b.replace(first_part, '')
                    second_part = b.replace(full_first_part, '')
                    if second_part == b:
                        second_part = b.replace(first_part, '')
                    new_name = first_part + '_' + second_part
                    new_full_name = 'Q_%s_sub_%X' % (new_name, func.address)
                    # print('0x%X %s:' % (func.address, func.name), a, b, type_name, first_part, second_part, new_name)
                    if a != '':
                        print('!!!!!')
                    out_line = f'0x{func.address:X} {func.full_name:<55} {new_full_name}'
                    print(out_line)
                    out_lines.append(out_line + '\n')

                    if rename:
                        rename_func(func, new_full_name)

                    n = n + 1
    if rename:
        with open('BeautifyFunctionNames.log', 'w') as f:
            f.writelines(out_lines)

    print('Total %d functions' % n)


def main():
    msg_clear()
    beautify(False)


if __name__ == '__main__':
    main()
