#include <idc.idc>

static doFind()
{
  auto start, a, b;
  start = 0x005F10B6;
  a = 0x005F1172;
  b = 0x005F1183;

  //MakeUnkn(a, 1);
  //MakeCode(a);
  //MakeFunction(a, BADADDR);
  
  if (AppendFchunk(start, a, b))
    Message("Success");

}

static main(void)
{
  doFind();
}


