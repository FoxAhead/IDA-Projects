import idautils


def main():
    ea = 0x00034368

    for xref in idautils.XrefsTo(ea):
        print("%X"%xref.frm, xref.to, xref.iscode, xref.type, xref.user)

if __name__ == '__main__':
    main()