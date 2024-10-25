import idc
import ida_typeinf
import ida_kernwin
import ida_nalt
import idaapi
import ida_idp


def run(ea):
    print(hex(ea))
    # func_id = extract_function_id(ea)
    func_name = idc.get_func_name(ea)
    # print(func_id)
    print(func_name)
    return_type, arguments, argument_names = get_function_info(ea)
    #print(return_type)
    #print(arguments)
    #print(argument_names)

def extract_function_id(func):
    comment = idc.get_cmt(func, True)
    return comment[5:]


def get_function_info(func):
    tinfo = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(tinfo, func)
    function_details = idaapi.func_type_data_t()
    tinfo.get_func_details(function_details)

    for _ in function_details.spoiled:
        print(_.reg)
    return_type = tinfo.get_rettype().dstr()

    arguments = ""
    argument_names = ""
    for i in range(function_details.size()):
        if i != 0:
            arguments = arguments + ", "
            argument_names = argument_names + ", "

        argument_name = function_details[i].name
        if argument_name == "this":
            argument_name = "apThis"

        arguments = arguments + "{} {}".format(ida_typeinf.print_tinfo('', 0, 0, idc.PRTYPE_1LINE, function_details[i].type, '', ''), argument_name)
        argument_names = argument_names + argument_name

    return return_type, arguments, argument_names


run(ida_kernwin.get_screen_ea())
