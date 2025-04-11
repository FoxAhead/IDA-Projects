from dataclasses import dataclass
import idaapi
import ida_kernwin
import ida_hexrays
import ida_typeinf


class ActionArray:
    def __init__(self):
        w = None
        self.vu = None
        w = ida_kernwin.get_current_widget()
        if ida_kernwin.get_widget_type(w) == ida_kernwin.BWN_PSEUDOCODE:
            self.vu = ida_hexrays.get_widget_vdui(w)

    def get_arr_memb_info(self):
        #     e0
        #   e1  e2
        # e3
        # Starting from e1 - selected item
        if self.vu:
            vu = self.vu
            ami = ArrMembInfo()
            if not (vu and vu.get_current_item(ida_hexrays.USE_KEYBOARD) and vu.item.is_citem()):
                ida_kernwin.warning("Please position the cursor on a union member")
                return None
            e1 = vu.item.e
            if e1.op not in {ida_hexrays.cot_memref, ida_hexrays.cot_memptr}:
                ida_kernwin.warning("e1 is not cot_memref nor cot_memptr")
                return None
            e0 = vu.cfunc.body.find_parent_of(e1)
            if e0.op == ida_hexrays.cot_idx:
                e2 = e0.cexpr.y
                if e2.op == ida_hexrays.cot_add:
                    e2 = e2.cexpr.y
                if e2.op != ida_hexrays.cot_num:
                    ida_kernwin.warning("e0 is cot_idx and e2 is not cot_num")
                    return None
                ami.idx = e2.get_const_value()
            e3 = e1.cexpr.x
            if e1.op == ida_hexrays.cot_memref:
                if e3.op not in {ida_hexrays.cot_obj, ida_hexrays.cot_memref, ida_hexrays.cot_var, ida_hexrays.cot_idx}:
                    ida_kernwin.warning("e3 is not in {cot_obj, cot_memref, cot_var, cot_idx}")
                    return None
            if e3.op == ida_hexrays.cot_idx:
                e3 = e3.x
            # if e1.op == ida_hexrays.cot_memptr:
            #    if e3.op != ida_hexrays.cot_var:
            #        ida_kernwin.warning("e3 is not cot_var")
            #        return None
            e3type = e3.type
            while e3type.is_ptr() or e3type.is_array():
                e3type.remove_ptr_or_array()
            if not e3type.is_udt():
                ida_kernwin.warning("e3 is not udt")
                return None
            ami.udt_member = idaapi.udt_member_t()
            ami.offset = e1.m
            ami.udt_member.offset = ami.offset * 8
            if e3type.find_udt_member(ami.udt_member, idaapi.STRMEM_OFFSET) == -1:
                ida_kernwin.warning("udt_member not found")
                return None
            if ami.udt_member.type.is_array():
                array_data = ida_typeinf.array_type_data_t()
                ami.udt_member.type.get_array_details(array_data)
                ami.array_elem_type = array_data.elem_type
                ami.array_nelems = array_data.nelems
            else:
                ami.array_elem_type = ami.udt_member.type
                ami.array_nelems = 1
            ami.array_elem_size = ami.array_elem_type.get_size()
            ami.struct_tinfo = e3type
            ami.ordinal = ami.struct_tinfo.get_ordinal()
            ami.struct_name = ami.struct_tinfo.dstr()
            ami.udt_data = idaapi.udt_type_data_t()
            e3type.get_udt_details(ami.udt_data)

            return ami

    def split_array(self):
        if ami := self.get_arr_memb_info():
            creator = Creator(ami.array_elem_type, ami.offset, ami.array_nelems)
            creator.create_udt_member(ami.idx, ami.udt_member.name)
            creator.create_udt_member(creator.nelems)
            self.apply(ami, creator.udt_members)

    def extract_element(self):
        if ami := self.get_arr_memb_info():
            creator = Creator(ami.array_elem_type, ami.offset, ami.array_nelems)
            creator.create_udt_member(ami.idx, ami.udt_member.name)
            creator.create_udt_member(1)
            creator.create_udt_member(creator.nelems)
            self.apply(ami, creator.udt_members)

    def convert_to(self, btype):
        if ami := self.get_arr_memb_info():
            new_array_elem_type = ida_typeinf.tinfo_t(btype)
            new_array_elem_size = new_array_elem_type.get_size()
            if new_array_elem_size == ami.array_elem_size:
                ida_kernwin.warning("new_array_elem_size == array_elem_size ")
                return
            size = ami.array_elem_size * ami.array_nelems
            (new_array_nelems, remainder) = divmod(size, new_array_elem_size)
            print('new_array_nelems=%d, remainder=%d, type=%s' % (new_array_nelems, remainder, new_array_elem_type))
            if (new_array_nelems == 0) or (remainder != 0):
                ida_kernwin.warning("Can't convert")
                return
            creator = Creator(new_array_elem_type, ami.offset, new_array_nelems)
            creator.create_udt_member(new_array_nelems, ami.udt_member.name)
            self.apply(ami, creator.udt_members, 0)

    def apply(self, ami, udt_members, low=1):
        if len(udt_members) > low:
            iterator = ami.udt_data.find(ami.udt_member)
            iterator = ami.udt_data.erase(iterator)
            for udt_member in reversed(udt_members):
                iterator = ami.udt_data.insert(iterator, udt_member)
            ami.struct_tinfo.create_udt(ami.udt_data, idaapi.BTF_STRUCT)
            ami.struct_tinfo.set_numbered_type(idaapi.cvar.idati, ami.ordinal, idaapi.BTF_STRUCT, ami.struct_name)
            self.vu.refresh_view(True)
        else:
            print('No changes to apply')


@dataclass
class ArrMembInfo:
    idx: int = 0
    offset: int = 0
    struct_tinfo: ida_typeinf.tinfo_t = None
    struct_name: str = ''
    ordinal: int = 0
    udt_member: ida_typeinf.udt_member_t() = None
    udt_data: ida_typeinf.udt_type_data_t() = None
    array_elem_type: ida_typeinf.tinfo_t = None
    array_nelems: int = 0
    array_elem_size: int = 0


@dataclass
class Creator:
    elem_type: ida_typeinf.tinfo_t
    offset: int = 0
    nelems: int = 0
    elem_size: int = 0
    udt_members = []

    def __post_init__(self):
        """
        Holds new members, info about current offset and available nelems
        """
        self.elem_size = self.elem_type.get_size()
        self.udt_members.clear()

    def create_udt_member(self, num, name=''):
        """
        Append new udt_member_t shifting offset and reducing avalaible nelems.
        Only if num > 0

        :param num: Number of elements to allocate.
        :type num: int
        :param name: Name of the member, by default Unknown_X
        :type name: str
        """
        udt_member = idaapi.udt_member_t()
        if name == '':
            udt_member.name = "Unknown_{0:X}".format(self.offset)
        else:
            udt_member.name = name
        udt_member.offset = self.offset * 8
        size = self.elem_size * num
        udt_member.size = size * 8
        print('create_udt_member: offset=%x, num=%d, size=%d, name=%s' % (self.offset, num, size, udt_member.name))

        if num == 1:
            udt_member.type = self.elem_type
        else:
            array_data = idaapi.array_type_data_t()
            array_data.base = 0
            array_data.elem_type = self.elem_type
            array_data.nelems = num
            tmp_tinfo = idaapi.tinfo_t()
            tmp_tinfo.create_array(array_data)
            udt_member.type = tmp_tinfo
        if num > 0:
            self.offset = self.offset + size
            self.nelems = self.nelems - num
            self.udt_members.append(udt_member)


def print_udt_data(udt_data):
    for udt_member in udt_data:
        if udt_member.type.is_array():
            array_data = idaapi.array_type_data_t()
            udt_member.type.get_array_details(array_data)
            print('%04X' % (udt_member.offset // 8), udt_member.name, udt_member.type, array_data.elem_type,
                  array_data.nelems, sep=', ')
        else:
            print('%04X' % (udt_member.offset // 8), udt_member.name, udt_member.type, sep=', ')
