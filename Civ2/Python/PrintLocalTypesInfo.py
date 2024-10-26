from venv import logger
from idautils import *
from idaapi import *
import lib

require("lib")


def get_ordinal(tinfo):
    while tinfo.is_ptr() or tinfo.is_array():
        tinfo.remove_ptr_or_array()
    if tinfo.is_udt():
        return tinfo.get_ordinal()
    elif tinfo.is_enum():
        return tinfo.get_ordinal()
    elif tinfo.is_typeref():
        typeref_ordinal = tinfo.get_ordinal()
        if typeref_ordinal:
            typeref_tinfo = lib.get_tinfo_by_ordinal(typeref_ordinal)
            if typeref_tinfo is None:
                logger.warn("You have dependencies of deleted %s type", tinfo.dstr())
                return 0

            if typeref_tinfo.is_typeref() or typeref_tinfo.is_udt() or typeref_tinfo.is_ptr():
                return typeref_ordinal
    return 0


def get_members_ordinals(tinfo):
    ordinals = []
    if tinfo.is_udt():
        udt_data = udt_type_data_t()
        tinfo.get_udt_details(udt_data)
        for udt_member in udt_data:
            if udt_member.type.is_array():
                array_data = array_type_data_t()
                udt_member.type.get_array_details(array_data)
                print('%04X' % (udt_member.offset // 8), udt_member.name, udt_member.type, array_data.elem_type,
                      array_data.nelems, sep=', ')
            else:
                print('%04X' % (udt_member.offset // 8), udt_member.name, udt_member.type, sep=', ')
            ordinal = get_ordinal(udt_member.type)
            if ordinal:
                ordinals.append(ordinal)
    return ordinals


def main():
    for ordinal in range(1, idc.get_ordinal_qty()):
        name = idc.get_numbered_type_name(ordinal)
        if name.startswith('T_'):
            print(name)
            local_tinfo = lib.get_tinfo_by_ordinal(ordinal)
            members_ordinals = get_members_ordinals(local_tinfo)
            # print(members_ordinals)


if __name__ == "__main__":
    main()
