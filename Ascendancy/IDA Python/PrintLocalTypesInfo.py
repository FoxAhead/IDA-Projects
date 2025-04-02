import yaml
from venv import logger
from idautils import *
from idaapi import *
import lib

require("lib")

TYPE_TO_KSY = {
    'uint8_t': 'u1',
    'uint16pippip_t': 'u2',
    'uint32_t': 'u4',
    'uint64_t': 'u8',

    'int8_t': 's1',
    'int16_t': 's2',
    'int32_t': 's4',
    'int64_t': 's8',

    'char': 's1',
    'short': 's2',
    'int': 's4',
    'uint': 'u4',
    'long': 's8',
    'float': 'f4',
    'double': 'f8',

    'BYTE': 's1',
    'WORD': 's2',
    'LONG': 's4',
    'UBYTE': 'u2',
    'UWORD': 'u4',
    'ULONG': 'u4',

    '__s32': 's4',
    '__s64': 's8',
}


def camel_to_snake(name):
    if type(name) != str:
        return name
    pattern = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
    name = pattern.sub('_', name).lower()
    return name
    # return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()


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


def iterate_members(tinfo, name, r):
    if tinfo.is_udt():
        r2 = []
        udt_data = udt_type_data_t()
        tinfo.get_udt_details(udt_data)
        for udt_member in udt_data:
            if udt_member.type.is_array():
                array_data = array_type_data_t()
                udt_member.type.get_array_details(array_data)
                # print('%04X' % (udt_member.offset // 8), udt_member.name, udt_member.type, array_data.elem_type, array_data.nelems, sep=', ')
                t = str(array_data.elem_type)
                t1 = TYPE_TO_KSY.get(t, t)
                if t == 'char' and array_data.nelems > 10:
                    h = {'id': udt_member.name, 'type': 'str', 'size': array_data.nelems, 'encoding': 'ASCII', 'terminator': 0}
                elif t1 == 's1':
                    h = {'id': udt_member.name, 'size': array_data.nelems}
                else:
                    h = {'id': udt_member.name, 'type': t1, 'repeat': 'expr', 'repeat-expr': array_data.nelems}
            else:
                # print('%04X' % (udt_member.offset // 8), udt_member.name, udt_member.type, sep=', ')
                t = str(udt_member.type)
                h = {'id': udt_member.name, 'type': TYPE_TO_KSY.get(t, t)}
            h = {k2: camel_to_snake(v) for k2, v in h.items()}
            r2.append(h)
        r[name] = {'seq': r2}
        # ordinal = get_ordinal(udt_member.type)
        # if ordinal:
        #    ordinals.append(ordinal)


def do_with_one_ordinal(ordinal, r):
    name = camel_to_snake(idc.get_numbered_type_name(ordinal))
    if name and name.startswith('t_'):
        local_tinfo = lib.get_tinfo_by_ordinal(ordinal)
        iterate_members(local_tinfo, name, r)
    elif name and name.startswith('macro_'):
        local_tinfo = lib.get_tinfo_by_ordinal(ordinal)
        if local_tinfo.is_enum():
            enum_data = enum_type_data_t()
            local_tinfo.get_enum_details(enum_data)
            for enum_member in enum_data:
                print(enum_member.name, enum_member.value)


def main():
    r = {}
    # for ordinal in range(1, idc.get_ordinal_qty()):
    #    do_with_one_ordinal(ordinal)
    do_with_one_ordinal(192, r)
    if r:
        print(yaml.dump({'types': r}, sort_keys=False))


if __name__ == "__main__":
    main()
