#include <idc.idc>

static doFind()
{
  auto start;
  start = 0;
  while (1)
  {
    start = FindBinary(start + 1, SEARCH_DOWN + SEARCH_NEXT, "64 A1 00 00 00 00");
    if (start == BADADDR)
      break;
    Message("0x%08X\n", start);
    Message(GetDisasm(start-2)+"\n");
    Message(GetDisasm(start-1)+"\n");
    Message(GetDisasm(start)+"\n");
  }
}

static main(void)
{
  doFind();
}
