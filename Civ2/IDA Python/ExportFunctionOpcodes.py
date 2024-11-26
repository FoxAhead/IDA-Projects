import ida_funcs
import ida_kernwin
import idc
from ida_idaapi import require

import lib
from ExportFunctionsToDelphi import convert_func, pascal_declaration_intf, get_pascal_declaration

require("lib")
require("ExportFunctionsToDelphi")


def output_func_bytes(pfn, width, remove_prologue=True):
    print('asm')
    nb = 4
    d = 'DQ' if nb == 8 else 'DD' if nb == 4 else 'DW' if nb == 2 else 'DB'
    s1 = '    ' + d + '    '

    length = pfn.end_ea - pfn.start_ea
    buf = idc.get_bytes(pfn.start_ea, length)
    if remove_prologue and length > 2 and buf[0:3] == b'\x55\x8B\xEC':
        buf = buf[3:]
    elements = (len(buf) + nb - 1) // nb
    buf = buf.ljust(elements * nb, b'\xCC')

    n1 = (width - len(s1) + 2) // 11
    #print(n1)
    rows = - (elements // -n1)
    #print(rows)
    n2 = -(elements // -rows)
    #print(n2)

    lines = [buf[i:i + n2 * nb] for i in range(0, len(buf), n2 * nb)]
    for line in lines:
        s = s1 + ', '.join(['$' + bytes(reversed(line[j: j + nb])).hex().upper() for j in range(0, len(line), nb)])
        # s = '    DD    ' + ', '.join(['$%0.8X' % int.from_bytes(line[j:j + 4], 'little') for j in range(0, len(line), 4)])
        # lst = line.hex(' ', 4).upper().split()
        # s = '    DB  ' + ', '.join([f'${val}' for val in lst])
        print(s)
    print('end;')


def main():
    ida_kernwin.msg_clear()
    ea = ida_kernwin.get_screen_ea()
    pfn = ida_funcs.get_fchunk(ea)
    if pfn is None:
        print("No function at %08X!" % ea)
        return
    # print("current chunk boundaries: %08X..%08X" % (pfn.start_ea, pfn.end_ea))

    func = lib.get_function_info(pfn.start_ea)
    funcp = convert_func(func)
    pd = get_pascal_declaration(funcp)
    print(pascal_declaration_intf(pd, 1))
    output_func_bytes(pfn, 142, True)


if __name__ == '__main__':
    main()
