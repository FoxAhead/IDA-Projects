import yaml
from venv import logger
from idautils import *
from idaapi import *
from fxtools import lib

TYPE_TO_KSY = {
    'uint8_t': 'u1',
    'uint16pippip_t': 'u2',
    'uint32_t': 'u4',
    'uint64_t': 'u8',

    '__int8': 's1',
    '__int16': 's2',
    '__int32': 's4',

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
    'UBYTE': 'u1',
    'UWORD': 'u2',
    'ULONG': 'u4',

    '__s32': 's4',
    '__s64': 's8',

    'void *': 's4',
}

NEED_ENUM = {
    't_planet': {
        'size': 'macro_ascend_planet_size',
        'type': 'macro_ascend_planet_type',
    }
}


def needed_enum(type_name, field_name):
    try:
        print(type_name, field_name)
        enum_name = NEED_ENUM[type_name][field_name]
        print('Yes')
        return enum_name
    except KeyError:
        print('No')
        pass


def kaitaize_name(name):
    if type(name) != str:
        return name
    name = name.lstrip('_')
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


def iterate_members(tinfo, name, dt, de):
    r2 = []
    h = {}
    if tinfo.is_udt():
        udt_data = udt_type_data_t()
        tinfo.get_udt_details(udt_data)
        for udt_member in udt_data:
            if udt_member.type.is_array():
                array_data = array_type_data_t()
                udt_member.type.get_array_details(array_data)
                # print('%04X' % (udt_member.offset // 8), udt_member.name, udt_member.type, array_data.elem_type, array_data.nelems, sep=', ')
                if array_data.elem_type.is_ptr():
                    t = 'void *'
                else:
                    t = str(array_data.elem_type)
                t1 = TYPE_TO_KSY.get(t, t)
                if t == 'char' and array_data.nelems > 10:
                    h = {'id': udt_member.name, 'type': 'str', 'size': array_data.nelems, 'encoding': 'ASCII', 'terminator': 0}
                elif t1 == 's1':
                    h = {'id': udt_member.name, 'size': array_data.nelems}
                else:
                    h = {'id': udt_member.name, 'type': t1, 'repeat': 'expr', 'repeat-expr': array_data.nelems}
            else:
                if udt_member.type.is_union() or udt_member.type.is_ptr():
                    t = 'void *'
                else:
                    t = str(udt_member.type)
                h = {'id': udt_member.name, 'type': TYPE_TO_KSY.get(t, t)}
                if enum_name := needed_enum(name, udt_member.name):
                    h['enum'] = enum_name
            h = {k2: kaitaize_name(v) for k2, v in h.items()}
            r2.append(h)
        dt[name] = {'seq': r2}
    elif tinfo.is_enum():
        enum_data = enum_type_data_t()
        tinfo.get_enum_details(enum_data)
        for enum_member in enum_data:
            h[enum_member.value] = kaitaize_name(enum_member.name)
        de[name] = h


def do_with_one_ordinal(ordinal, dt, de):
    name = kaitaize_name(idc.get_numbered_type_name(ordinal))
    if name:
        local_tinfo = lib.get_tinfo_by_ordinal(ordinal)
        iterate_members(local_tinfo, name, dt, de)


def local_type_to_kaitai(ctx):
    dt = {}
    de = {}
    for sel in ctx.chooser_selection:
        ordinal = sel + 1
        do_with_one_ordinal(ordinal, dt, de)
    if dt:
        print(yaml.dump({'types': dt}, sort_keys=False, Dumper=IndentDumper))
    if de:
        print(yaml.dump({'enums': de}))


class IndentDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(IndentDumper, self).increase_indent(flow, False)
