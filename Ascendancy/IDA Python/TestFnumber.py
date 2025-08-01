import ida_kernwin
from ida_hexrays import fnumber_t
from ida_ieee import fpvalue_t, EONE


def main():
    ida_kernwin.msg_clear()

    fnum = fpvalue_t()
    #fnum.from_12bytes(bytes(EONE))
    fnum = fpvalue_t(EONE)
    print(fnum)

    #fpc = fnumber_t(EONE)
    # fpc.nbytes = 10
    # #fpc.fnum.from_uint64(10)
    # fpc.fnum._set_float(2)
    # print(fpc.fnum)
    # print(fpc._print())
    # print(fpc.nbytes)

    # fpv = fpvalue_t()
    # fpv.fadd(1.0)


if __name__ == '__main__':
    main()