#include <idc.idc>

static doFind()
{
  auto start, a, b, c, d, answer, i, j;
  start = 0x005F10B6;
  a = 0x005F10B6;
  b = 0x005F115C;
  c = 0x005F1172;
  d = 0x005F1183;

  //delete_all_segments();
  //return;
  //MakeUnkn(a, 3);
  //MakeCode(a);
  //DelExtLnA(0x00005F10E2, 10);
  //AnalyseArea(start, d);
  //MakeFunction(a, b);
  //MakeFunction(0x005F1168, 0x005F1172);
  //AppendFchunk(start, c, d);
  //SetFunctionCmt(b, form("ABCDEFG %08X", start), 1);  
  Message("\nComments:\n\n");
  for (i = a; i < b; i++)
  {
    answer = Comment(i);
    //answer = RptCmt(i);
    /*for (j = -3000; j < 3000; j++)
    {
      //answer = LineA(i, j);
      answer = LineB(i, j);
      if (answer != "")
        Message("%08X:%d: %s\n", i, j, answer);
        //Message("%08X: %s\n", i, answer);
    }*/
    Message("%08X: %s\n", i, answer);
  }

}

static main(void)
{
  doFind();
}


