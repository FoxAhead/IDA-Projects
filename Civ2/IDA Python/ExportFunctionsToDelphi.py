# import idaapi
from idautils import *
from idaapi import *
from idc import *
import dataclasses
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


@dataclasses.dataclass
class PascalDeclaration:
    name: str = ''
    params: str = ''
    result: str = ''
    cc: int = 0
    address: int = 0
    jaddress: int = 0


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
    argument.ptr_by_asterisk = argument.type.endswith('*')
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
            elif argument.pointed_type == 'Word':
                argument.type = 'PWord'
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
    return argument.is_ptr and argument.ptr_by_asterisk and argument.pointed_type in ['Cardinal', 'Integer', 'Byte']


def get_pascal_declaration(funcp):
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

    pd = PascalDeclaration()
    pd.name = funcp.name
    pd.params = params_str
    pd.result = '' if funcp.ret.type == 'void' else funcp.ret.type
    pd.cc = funcp.cc
    pd.address = funcp.address
    pd.jaddress = funcp.jaddress
    return pd


def pascal_declaration_intf(pd, mode=0):
    cc = 'stdcall' if pd.cc in [CM_CC_THISCALL, CM_CC_STDCALL] else 'cdecl'
    if mode == 0:
        if pd.result:
            s = '%s: function%s: %s; %s;' % (pd.name, pd.params, pd.result, cc)
        else:
            s = '%s: procedure%s; %s;' % (pd.name, pd.params, cc)
        return s
    else:
        if pd.result:
            s = 'function %s%s: %s; %s;' % (pd.name, pd.params, pd.result, cc)
        else:
            s = 'procedure %s%s; %s;' % (pd.name, pd.params, cc)
        return s


def pascal_declaration_impl(pd, m=0):
    cast = 'PThisCall' if pd.cc == CM_CC_THISCALL else 'Pointer'
    address = pd.jaddress if pd.jaddress else pd.address
    s = '@%s := %s($%08X);' % (pd.name.ljust(m), cast, address)
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


def get_whitelist_eas(file_name):
    eas = []
    with open(file_name, 'r') as file:
        while line := file.readline():
            if match := re.search(r'\$([0-9a-fA-F]{6,8})', line):
                eas.append(int(match[1], 16))
    return eas


def generate_pascal_declarations(funcs, internal=False):
    eas = get_whitelist_eas('%s' % FILE_NAME_WHITE_LIST)
    pds = []
    for func in funcs:
        if func.address in eas or func.jaddress in eas:
            funcp = convert_func(func)
            pd = get_pascal_declaration(funcp)
            pds.append(pd)
            if internal and pd.jaddress:
                _pd = copy.deepcopy(pd)
                _pd.name = '_' + _pd.name
                _pd.jaddress = 0
                pds.append(_pd)

    m = max(len(func.name) for func in funcs)
    thiscalls = 0
    with open('%s' % FILE_NAME_DECLARATION, 'w') as file1, open('%s' % FILE_NAME_IMPLEMENTATION, 'w') as file2:
        s = '// This file is generated automatically. Do not change it.\n'
        file1.write(s)
        file2.write(s)
        for pd in pds:
            file1.write(pascal_declaration_intf(pd) + '\n')
            file2.write(pascal_declaration_impl(pd, m) + '\n')
            if pd.cc == CM_CC_THISCALL:
                thiscalls = thiscalls + 1

    return len(pds), thiscalls


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

    lib.analyze_crefs(funcs, True)

    i, j = generate_pascal_declarations(funcs)

    print('Done. Exported %d functions out of %d. (%d ThisCalls)' % (i, len(funcs), j))


if __name__ == '__main__':
    main()
