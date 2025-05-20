import datetime
import ida_kernwin
from ida_hexrays import *


def compare_lists(ml1: mlist_t, ml2: mlist_t):
    print("ml1=%s" % ml1.dstr())
    print("ml2=%s" % ml2.dstr())
    r = ml1.includes(ml2)
    print("  ml1.includes(ml2)=%s" % r)
    r = ml1.has_common(ml2)
    print("  ml1.has_common(ml2)=%s" % r)


def main():
    ida_kernwin.msg_clear()
    print(datetime.datetime.now())

    ml1 = mlist_t()
    ml2 = mlist_t()
    ml1.add(10, 2)
    ml2.add(8, 2)
    ml2.add(12, 2)

    compare_lists(ml1, ml2)
    compare_lists(ml2, ml1)


if __name__ == '__main__':
    main()
