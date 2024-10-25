# import idaapi
from idautils import *
from idaapi import *
from idc import *
import ida_typeinf
import ida_nalt
import ida_kernwin
import ida_idp
import re
import dataclasses
from typing import List
import copy
import lib

require("lib")

FILE_NAME_DECLARATION = 'Civ2ProcDeclF.inc'

FILE_NAME_IMPLEMENTATION = 'Civ2ProcImplF.inc'

FILE_NAME_WHITE_LIST = 'Civ2ProcImplF.wl'


@dataclasses.dataclass
class FuncParam:
    var: bool = False
    names: list = dataclasses.field(default_factory=list)
    type: str = ''


def convert_custom_type(type_name):
    if lib.is_custom_type(type_name):
        return type_name[:1] + type_name[2:]
    return type_name


def convert_type(type):
    # if type in ['LPVOID', 'LPCVOID']:
    #    return 'Pointer'
    if type in ['char', 'CHAR', 'const CHAR']:
        return 'char'

    if type == '__int8':
        return 'Shortint'
    if type == '__int16':
        return 'Smallint'
    if type in ['int', '__int32', 'signed int', 'LONG']:
        return 'Integer'

    if type in ['unsigned __int8', 'BYTE', '_BYTE']:
        return 'Byte'
    if type in ['unsigned __int16', 'WORD']:
        return 'Word'
    if type in ['unsigned int', 'unsigned __int32', 'DWORD', '_DWORD', 'size_t', 'UINT_PTR']:
        return 'Cardinal'

    # Better boolean typing combination:
    # C side: BOOL
    # Pascal side: Boolean avoiding direct comparison to True and False
    if type in ['bool', 'BOOL']:
        return 'Boolean'

    if type in ['RECT', 'tagRECT', 'struct tagRECT']:
        return 'TRect'
    if type == 'SMALL_RECT':
        return 'TSmallRect'

    return type


excluded_ptrtypes = ['HWND', 'HGLOBAL', 'HMODULE', 'HMENU', 'HINSTANCE', 'HPALETTE', 'Pointer']


def convert_argument(argument):
    if argument.pos >= 0:
        if argument.name == '':
            # If empty, create automatic names A1, A2, A3...
            argument.name = 'A%d' % (argument.pos + 1)
        elif argument.name[0] == 'a':
            # Remove first small 'a' letter
            new_name = argument.name[1:]
            if not new_name.isnumeric():
                argument.name = new_name
        elif argument.name[0] == 'n' and argument.name[1].isupper():
            # Remove first small 'n' letter followed by second capital letter
            argument.name = argument.name[1:]
        argument.name = argument.name[0].upper() + argument.name[1:]
    argument.custom_type = lib.is_custom_type(argument.type)
    new_type = convert_type(argument.type)
    type_changed = (argument.type != new_type)
    argument.type = convert_custom_type(new_type)
    if argument.is_ptr:
        argument.pointed_type = convert_type(argument.pointed_type)
        if not type_changed:
            if argument.pointed_type == 'char':
                argument.type = 'PChar'
            elif argument.pointed_type == 'Byte':
                argument.type = 'PByte'
            elif argument.pointed_type == 'TRect':
                argument.type = 'PRect'
            elif argument.pointed_type == 'TSmallRect':
                argument.type = 'PSmallRect'
            elif argument.pointed_type in ['void', 'const void']:
                argument.type = 'Pointer'
            elif ')' in argument.pointed_type:
                argument.type = 'Pointer'
            elif argument.custom_type and argument.pointed_type.startswith('T_'):
                argument.type = 'P_' + argument.pointed_type[2:]
            elif argument.type not in excluded_ptrtypes:
                argument.type = '^' + argument.pointed_type
        argument.pointed_type = convert_custom_type(argument.pointed_type)
    argument.type = convert_custom_type(argument.type)


def convert_func(funcc):
    # funcp = dataclasses.replace(funcc)
    funcp = copy.deepcopy(funcc)
    convert_argument(funcp.ret)
    for argument in funcp.arguments:
        convert_argument(argument)
    return funcp


def argument_is_var(argument):
    return argument.is_ptr and argument.pointed_type in ['Cardinal', 'Integer', 'Byte']


def pascal_declaration_intf(funcp):
    cc = 'stdcall' if funcp.cc in [CM_CC_THISCALL, CM_CC_STDCALL] else 'cdecl'
    params = []
    param = None
    for argument in funcp.arguments:
        name = 'This' if argument.pos == 0 and funcp.cc == CM_CC_THISCALL else argument.name
        var = argument_is_var(argument)
        type = argument.pointed_type if var else argument.type

        if param and param.var == var and param.type == type:
            param.names.append(name)
        else:
            params.append(FuncParam(var, [name], type))
            param = params[-1]

    param_strs = []
    for param in params:
        param_str = '%s%s: %s' % ('var ' if param.var else '', ', '.join(param.names), param.type)
        param_strs.append(param_str)

    if params_str := '; '.join(param_strs):
        params_str = '(' + params_str + ')'
    if funcp.ret.type == 'void':
        s = '%s: procedure%s; %s;' % (funcp.name, params_str, cc)
    else:
        s = '%s: function%s: %s; %s;' % (funcp.name, params_str, funcp.ret.type, cc)
    return s


def pascal_declaration_impl(funcp, m=0):
    cast = 'PThisCall' if funcp.cc == CM_CC_THISCALL else 'Pointer'
    address = funcp.jaddress if funcp.jaddress else funcp.address
    s = '@%s := %s($%08X);' % (funcp.name.ljust(m), cast, address)
    return s


def analyze_duplicates(funcs):
    prevfunc = None
    dup = False
    for func in funcs:
        if prevfunc and prevfunc.name == func.name:
            if not dup:
                print('0x%X' % prevfunc.address, prevfunc.name)
            print('0x%X' % func.address, func.name)
            dup = True
        else:
            dup = False
        prevfunc = func


def analyze_crefs(funcs, recreate=False):
    for func in funcs:
        # if func.address != 0x004E989A:
        #    continue
        # print('0x%X %s'%(func.address, func.name))
        nj = 0
        n = 0
        for ref in CodeRefsTo(func.address, 1):
            function_flags = get_func_flags(ref)
            if function_flags != -1:
                if function_flags & FUNC_THUNK:
                    nj = nj + 1
                    func.jaddress = ref
                else:
                    n = n + 1
            # print("  called from %s(0x%x)0x%x" % (get_func_name(ref), ref, function_flags))
        if nj == 1 and n > 0 or nj > 1:
            print("!!!!!")
        # print(n, nj)
        if nj == 1:
            jfunc = lib.get_function_info(func.jaddress)
            if func.tinfo_str != jfunc.tinfo_str:
                print('0x%X %s' % (func.address, func.tinfo_str))
                print('0x%X %s' % (jfunc.address, jfunc.tinfo_str))
                if recreate:
                    lib.recreate_tinfo(jfunc.address)
                print()


def get_max_name_length(funcs):
    m = 0
    for func in funcs:
        if len(func.name) > m:
            m = len(func.name)
    return m


def get_whitelist_eas(file_name):
    eas = []
    with open(file_name, 'r') as file:
        while line := file.readline():
            if match := re.search(r'\$([0-9a-fA-F]{6,8})', line):
                eas.append(int(match[1], 16))
    return eas


def generate_pascal_declarations(funcs):
    eas = get_whitelist_eas('%s' % FILE_NAME_WHITE_LIST)
    i = 0
    m = get_max_name_length(funcs)
    with open('%s' % FILE_NAME_DECLARATION, 'w') as file1, open('%s' % FILE_NAME_IMPLEMENTATION, 'w') as file2:
        s = '// This file is generated automatically. Do not change it.\n'
        file1.write(s)
        file2.write(s)
        for func in funcs:
            # if func.address not in [0x46AD85]:
            #    continue
            if func.address in eas or func.jaddress in eas:
                i = i + 1
                funcp = convert_func(func)
                file1.write(pascal_declaration_intf(funcp) + '\n')
                file2.write(pascal_declaration_impl(funcp, m) + '\n')

                # print('@%s := Pointer(0x%X);'%(func.name, func.address))
                # print('0x%X'%funcp.address)
                # print(funcp.name)
                # print(func.tinfo_str)
                # print(func.ret)
                # print(func.arguments)
                # print(funcp.ret)
                # print(funcp.arguments)
                # print('0x%X'%funcp.cc)
                # print(pascal_declaration(funcp))
                # print()
    return i


def need_that_func(ea):
    if ea in [0x005F2470, 0x005F23C0]:
        return True
    return lib.func_is_named(ea)


def main():
    funcs = []
    for segea in Segments():
        for funcea in Functions(segea, get_segm_end(segea)):
            if need_that_func(funcea):
                funcs.append(lib.get_function_info(funcea))

    funcs.sort(key=lambda x: x.name)

    # analyze_duplicates(funcs)

    analyze_crefs(funcs, True)

    i = generate_pascal_declarations(funcs)

    print('Done. Exported %d functions out of %d.' % (i, len(funcs)))


if __name__ == '__main__':
    main()
