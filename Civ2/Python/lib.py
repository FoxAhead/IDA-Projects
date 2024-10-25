from idc import *
import dataclasses


@dataclasses.dataclass
class FuncArgument:
    pos: int = 0
    type: str = ''
    name: str = ''
    is_ptr: bool = False
    pointed_type: str = ''
    custom_type: bool = False


@dataclasses.dataclass
class FuncInfo:
    address: int = 0
    name: str = ''
    cc: int = 0
    tinfo_str: str = ''
    ret: FuncArgument = dataclasses.field(default_factory=FuncArgument)
    arguments: list = dataclasses.field(default_factory=list)
    jaddress: int = 0


def get_function_info(funcea):
    tinfo = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(tinfo, funcea)
    function_details = ida_typeinf.func_type_data_t()
    tinfo.get_func_details(function_details)

    if tinfo.empty():
        print('EMPTY')
        recreate_tinfo(funcea)
    #        if guess_tinfo(tinfo, funcea):
    #            apply_tinfo(funcea, tinfo, 0)
    if tinfo.is_void():
        print('VOID')

    get_rettype = tinfo.get_rettype()
    ret = FuncArgument(-1, str(get_rettype), '', get_rettype.is_ptr(), get_rettype.get_pointed_object().dstr())
    name = get_clean_name(get_func_name(funcea))
    if func_is_crt(funcea):
        name = 'Crt_' + name
    func = FuncInfo(funcea, name, function_details.cc & ida_typeinf.CM_CC_MASK, str(tinfo), ret)

    for i in range(function_details.size()):
        argument_type = ida_typeinf.print_tinfo('', 0, 0, PRTYPE_1LINE, function_details[i].type, '', '')
        argument_name = function_details[i].name
        func.arguments.append(FuncArgument(i, argument_type, argument_name, function_details[i].type.is_ptr(), function_details[i].type.get_pointed_object().dstr()))

    return func


def func_is_crt(ea):
    return ea >= 0x5F1B80


def func_is_lib(ea):
    return func_is_crt(ea) \
           or ea == 0x403A49 \
           or ea == 0x55ADD0 \
           or 0x5BB1D2 <= ea <= 0x5BB3BE \
           or 0x5EDC2E <= ea <= 0x5EDC46 \
           or 0x5EF2C2 <= ea <= 0x5EF310 \
           or ea == 0x5EFDAE


def func_is_named(ea):
    if func_is_lib(ea):
        return False
    if get_func_name(ea).startswith('sub_'):
        return False
    return not (get_func_flags(ea) & FUNC_THUNK)


def get_clean_name(function_name):
    if match := re.search(r'Q_(\w+)_sub_[0-9a-fA-F]{6}', function_name):
        return match[1]
    if demangled := demangle_name(function_name, get_inf_attr(INF_SHORT_DN)):
        if match := re.search(r'^([\w\s]+)\(?', demangled):
            name = match[1]
            if ' ' in name:
                name = name.title().replace(' ', '')
            return name
    return function_name


def is_custom_type(type_name):
    return type_name.startswith('T_') or type_name.startswith('P_')


def recreate_tinfo(funcea):
    tinfo = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(tinfo, funcea)
    if ida_typeinf.guess_tinfo(tinfo, funcea):
        ida_typeinf.apply_tinfo(funcea, tinfo, 0)
        print('Recreated 0x%X' % funcea)
