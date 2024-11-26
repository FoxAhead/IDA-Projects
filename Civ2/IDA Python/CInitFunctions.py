from idautils import *
from idaapi import *
import lib

require('lib')


def rename_static_root():
    for ea in range(0x624000, 0x6245A8, 4):
        funcea = ida_bytes.get_dword(ea)
        if funcea and (func_name := get_func_name(funcea)) and not lib.func_is_lib(funcea):
            set_name(funcea, '')
            new_name = 'Q_Static_' + get_func_name(funcea)
            set_name(funcea, new_name)
            idc.set_func_cmt(funcea, '', True)
            print('0x%06X: 0x%06X' % (ea, funcea), func_name, new_name)


def main():
    msg_clear()
#    rename_static_root()
    for segea in Segments():
        for funcea in Functions(segea, idc.get_segm_end(segea)):
            for ref in CodeRefsTo(funcea, 1):
                func_name = get_func_name(ref)
                if func_name and func_name.startswith('Q_Static_'):
                    print(func_name, get_func_name(funcea))
                    idc.set_func_cmt(funcea, '', True)


if __name__ == '__main__':
    main()
