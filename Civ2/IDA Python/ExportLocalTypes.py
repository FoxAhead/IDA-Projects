from idautils import *
from idaapi import *
import lib

require("lib")


def main():
    ordinals = []
    for ordinal in range(1, idc.get_ordinal_qty()):
        name = idc.get_numbered_type_name(ordinal)
        if name.startswith('T_'):
            ordinals.append(ordinal)
    with open('Civ2Types.h', 'w') as f:
        f.write(idc.print_decls(','.join(map(str, ordinals)), 0))
    print('Exported %d local types' % len(ordinals))


if __name__ == '__main__':
    main()
