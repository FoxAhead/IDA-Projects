struct T_MSWindow
{
  T_GraphicsInfo GraphicsInfo;
  MACRO_CIV2_MSSTYLE MSStyle;
  int CaptionHeight;
  int Border;
  int ResizeBorderWidth;
  POINT ClientTopLeft;
  SIZE ClientSize;
  char Title[132];
  int Unknown_1B8[10];
  int Unknown_1E0;
  int Unknown_1E4;
  int Unknown_1E8;
  int Unknown_1EC[4];
  int WinButtonCount;
  T_WinButton WinButtons[6];
  LPVOID WinButtonProc;
  RECT RectDrawPort;
  RECT RectClient;
  P_FontInfo FontInfo1;
  P_FontInfo FontInfo2;
  P_FontInfo FontInfo3;
};
struct T_GraphicsInfo
{
  T_DrawPort DrawPort;
  T_WindowInfo WindowInfo;
  __int8 Unknown5[3];
  void (__cdecl *UpdateProc)();
};
struct T_DrawPort
{
  void **_Proc;
  int Width;
  int Height;
  int BmWidth4;
  int BmWidth4u;
  RECT ClientRectangle;
  RECT WindowRectangle;
  LPBYTE pBmp;
  int *RowsOffset;
  LONG PrevPaletteID;
  P_DrawInfo DrawInfo;
  int ColorDepth;
};
struct T_DrawInfo
{
  HGLOBAL hDrawInfo;
  HDC DeviceContext;
  HGDIOBJ Unknown1;
  HBITMAP hBmp;
  HGDIOBJ ReplacedObject;
  int IsTopDownDIB;
  int Width;
  int Height;
  int bmWidth4;
  LPVOID pBmp;
};
struct T_WindowInfo
{
  T_WindowInfo1 WindowInfo1;
  P_ControlInfo ControlInfo;
  P_ControlInfoButton ButtonInfoOK;
  P_ControlInfoButton ButtonInfoCancel;
  BYTE _AutoFocus;
};
struct T_WindowInfo1
{
  int Style;
  P_Palette Palette;
  P_WindowStructure WindowStructure;
  int Unknown_0C;
  T_WindowProcs WindowProcs;
  P_MenuBar MenuBar;
  POINT MinTrackSize;
  POINT MaxTrackSize;
  DWORD PopupActive;
  int Unknown_90;
  int Unknown_94;
  LPVOID ProcMenuExec;
  int Unknown_9C;
  int Unknown_A0;
  LPVOID WaitProc;
  int LButtonDown;
  int RButtonDown;
  int HScrollPos;
  int VScrollPos;
};
struct T_WindowStructure
{
  HGLOBAL hMem;
  HWND HWindow;
  HDC DeviceContext;
  int Unknown_0C;
  int Unknown_10;
  HBRUSH hBrush;
  HPALETTE hPal;
  HCURSOR Cursor;
  HICON Icon;
  P_DrawPort DrawPortBG;
  int Unknown_28;
  P_DrawPort DrawPort;
  int Moveable;
  int Sizeable;
  int CaptionHeight;
  int ResizeBorderWidth;
  int Unknown_40;
  int Unknown_44;
  int Style;
};

