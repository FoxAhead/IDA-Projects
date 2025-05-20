import idc
from idautils import Segments, Functions, XrefsTo


def main():
    d = {}
    for segea in Segments():
        for funcea in Functions(segea, idc.get_segm_end(segea)):
            if not is_func_lib(funcea):
                xs = list(XrefsTo(funcea))
                d[funcea] = len(xs)
    l = sorted(d.items(), key=lambda item: item[1], reverse=True)
    for idx, (ea, xs) in enumerate(l[:50]):
        print("%.2d. %.8X %s: %d" % (idx + 1, ea, idc.get_func_name(ea), xs))


def is_func_lib(ea):
    function_flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)
    if function_flags & idc.FUNC_LIB:
        return True
    return False


if __name__ == '__main__':
    main()
