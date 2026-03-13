struct T_FIL;
struct T_FilEntryInfo;
struct T_FILIndexEntry;
struct T_OPPN;
struct T_House;
struct T_REGN;
struct T_FontChars;
struct T_Type14;
struct T_SpriteFrameHeader;
struct T_Type15;
struct T_ColorPalette;

typedef T_OPPN *P_OPPN;

struct __unaligned T_Type02
{
  int Unknown_0;
  char Unknown_1[36];
};

struct __unaligned T_Team
{
  int Unknown_0;
  int Unknown_4;
  P_OPPN Unknown_8;
  P_OPPN Unknown_C;
  char Unknown_10[8];
  int Money;
  int Unknown_1C;
  int Resources[3];
  int Unknown_21[9];
  int Unknown_50;
  char Unknown_54[12];
  int Unknown_60;
  int Unknown_64;
  int Unknown_68;
  int Unknown_6C;
  int Unknown_70;
  int Unknown_74;
  int Due;
  int Unknown_7C;
  int Unknown_80;
  int Unknown_84[2];
  int Unknown_8C;
  int Unknown_90;
  int Unknown_94[741];
  int Unknown_C28[10];
  char Unknown_C50[28];
  int Unknown_C6C[21];
  int Unknown_CC0[46];
  T_Type02 t02[4];
  char Unknown_E18[60];
};

struct __unaligned T_TeamData
{
  T_Team team[5];
  char a[3668];
};

typedef T_House *P_House;

typedef T_REGN *P_REGN;

struct T_OPPN
{
  P_OPPN Next;
  P_OPPN prev;
  P_OPPN orignext;
  P_OPPN origprev;
  int nextchar;
  int prevchar;
  int nextfixer;
  int prevfixer;
  int nextworker;
  int prevworker;
  int nextgangster;
  int prevgangster;
  int nextundes;
  int prevundes;
  int nextteam;
  int prevteam;
  int nextbrazier;
  int prevbrazier;
  P_OPPN destOppn;
  int aggressor;
  int numaggressors;
  P_House destSite;
  P_House currSite;
  int owner;
  P_House targetSite;
  P_OPPN targetOppn;
  P_OPPN leader;
  int worker;
  int id;
  int flags;
  int flags2;
  int oppntype;
  int teamno;
  int oppnmesstoken;
  int tool;
  int experience;
  int birthdate;
  int task;
  int taskcount;
  int action;
  int subaction;
  int repSubaction;
  int subcount;
  int activity;
  int activitycount;
  int DestnX;
  int DestnY;
  int saDestX;
  int saDestY;
  WORD NextDestX;
  WORD NextDestY;
  int subactionList;
  int subactionLoop;
  int fetchNext;
  int newSubaction;
  int stopRange;
  int count_misc_angle;
  int movespeed;
  int slowmovespeed;
  int intellicount;
  char *infostr;
  int blkxpos;
  int blkypos;
  int forename;
  int surname;
  int lasttime;
  int objcarried;
  int numcarried;
  int cadettype_oldtentype_actioncode_policeindex_offset;
  int aivar;
  P_OPPN savdestOppn;
  P_House savdestSite;
  P_OPPN savtargetOppn;
  P_House savtargetSite;
  int savsubactionLoop;
  int savtask;
  int savtaskcount;
  int savDestnX;
  int savDestnY;
  int savstopRange;
  WORD savNextDestX;
  WORD savNextDestY;
  P_OPPN (__cdecl *main_prg)(P_OPPN);
  void (__cdecl *destructor_prg)(P_OPPN, int);
  int xpos;
  int ypos;
  int xadjust;
  int yadjust;
  int zadjust;
  int htk;
  int scalevolume;
  int force;
  int gfx;
  int scrnx;
  int scrny;
  int frameno;
  int teamremap;
  int specialaction;
  __int16 *seq_ptr;
  __int16 *seq_start;
  int seq_repeats;
  int seq_reploop;
  int mov_ptr;
  int mov_start;
  int mov_repeats;
  int mov_reploop;
  int direction;
  int invisibility;
  int lastrecoiltime;
  P_REGN pRegion;
  int groups;
  char sqf_waiting;
  char sqf_interrupted;
  char sqf_noresponse;
  char sqf_noflip;
  char sqf_noint;
  char sqf_lives;
  char sqf_move;
  char sqf_update;
  char sqf_inhouse;
  char sqf_newcaps;
  char sqf_recoil;
  char sqf_hostile;
  char sqf_gp0;
  char sqf_selected;
  char sqf_trigger;
  char sqf_active;
  char sqf_destmoved;
  char recoildirn;
  char unused2;
  char unused3;
};

struct __unaligned T_House
{
  P_House Next;
  P_House Prev;
  int Unknown_8[21];
  int Unknown_5C;
  int Unknown_60;
  int Unknown_64[40];
  int Unknown_104[4];
  int Unknown_114[4];
  int Unknown_124[48];
};

struct T_REGN
{
  int X;
  int Y;
  int Width;
  int Height;
};

typedef T_TeamData *P_TeamData;

typedef T_Team *P_Team;

typedef T_FontChars *P_FontChars;

typedef T_ColorPalette *P_ColorPalette;

struct __unaligned T_Font
{
  P_FontChars pChars;
  P_ColorPalette pPalette;
  int spacing1;
  int Unknown_C;
  int Unknown_10;
  int Height;
  int RLE;
  int Unknown_1C;
  int Unknown_20;
  __int16 Unknown_24;
  __int16 Unknown_26;
  __int16 Unknown_28;
  __int16 Unknown_2A;
  __int16 Unknown_2C;
  __int16 Unknown_2E;
  __int16 averageCharWidth;
  __int16 Unknown_32;
  __int16 Unknown_34;
  __int16 Unknown_36;
  __int16 halfAverageCharWidth;
  __int16 Unknown_3A;
  int initialized;
};

typedef T_SpriteFrameHeader *P_SpriteFrameHeader;

struct __unaligned T_FontChars
{
  P_SpriteFrameHeader pSpriteFrame[145];
};

struct __unaligned T_ColorPalette
{
  WORD Color[256];
};

/* 226 */
struct __unaligned T_SpriteFrameHeader
{
  __int16 offsetX;
  __int16 offsetY;
  __int16 width;
  __int16 height;
  BYTE data[];
};

typedef T_Type02 *P_Type02;

typedef T_Font *P_Font;

struct __unaligned T_Type04
{
  int Unknown_0;
  int Unknown_4;
  int Unknown_8;
  char *Unknown_C;
  int Unknown_10;
};

typedef T_Type04 *P_Type04;

struct __unaligned T_Type05
{
  P_Team Unknown_0;
  P_Team Unknown_4;
  P_Team Unknown_8;
  P_Team Unknown_C;
  int Unknown_10;
  int Unknown_14;
};

typedef T_Type05 *P_Type05;

struct __unaligned T_Mouse
{
  void *Unknown_0;
  int isInitialized;
  int CheckedButtonState;
  int CheckedButtonCounter;
  int Unknown_10;
  int Unknown_14;
  int Unknown_18;
  int Unknown_1C;
  int Unknown_20;
  int Unknown_24;
  int Unknown_28;
  int Unknown_2C;
  int Unknown_30;
  int Unknown_34;
  int Unknown_38;
  int Unknown_3C;
  int isHidden;
  int Unknown_44;
  int Unknown_48[4];
  int Unknown_58;
  int width;
  int height;
  int maskRowSize;
  WORD *backupBuffer;
  int screenX;
  int screenY;
  BYTE *maskData;
  int CommandCode;
  int Unknown_7C;
  int Unknown_80[2];
  int Unknown_88;
  void *Unknown_8C;
  void *Unknown_90;
};

typedef T_Mouse *P_Mouse;

struct __unaligned T_Localization
{
  char *pTextLang;
  char *pSfxLang;
  char ThousandsSeparator;
  char MoneySign;
  __int16 Unknown_2;
  char *pTextPleaseInsertCD;
  int Unknown_8;
};

typedef T_Localization *P_Localization;

struct __unaligned T_GameHeader
{
  int Unknown_0;
  char GameName[32];
  int Money;
  int Unknown_28;
  int Unknown_2C;
  int GameDays;
  int Unknown_34;
  char VersionDate[32];
};

typedef T_GameHeader *P_GameHeader;

struct __unaligned T_FileBuffer
{
  int Unknown_0;
  char FileFullName[128];
  char *bufferPointer;
  int fileSize;
  int bufferAllocatedSize;
  void *currentDataPointer;
  int currentOffset;
  int Unknown_98;
  int keyStartPosition;
  char *valuePointer;
  char *valueStartOffset;
  int Unknown_A8;
};

typedef T_FileBuffer *P_FileBuffer;

typedef T_FILIndexEntry *P_FILIndexEntry;

typedef T_FilEntryInfo *P_FilEntryInfo;

typedef T_FIL *P_FIL;

struct __unaligned T_FilEntryInfo
{
  P_FIL pFIL;
  int Offset;
  int _Size;
  P_FILIndexEntry pIndexEntry;
};

struct __unaligned T_FIL
{
  P_FILIndexEntry pIndexEntries;
  P_FilEntryInfo pEntryInfo;
  int indexEntriesNum;
  int Unknown_C;
  int Unknown_10;
  FILE *Stream;
  HANDLE hFile;
  HANDLE hObject;
  P_FilEntryInfo pCurrentEntryInfo;
  T_FilEntryInfo T08[];
};

struct __unaligned T_FILIndexEntry
{
  char FileName[13];
  int Offset;
};

struct __unaligned T_SpriteSetHeader
{
  int Num;
  int Offsets[1];
};

typedef T_SpriteSetHeader *P_SpriteSetHeader;

struct __unaligned T_SpriteSet
{
  P_SpriteSetHeader pSpriteHeader;
  int SpritesNum;
  int bIsSHD;
  int Unknown_C;
  P_ColorPalette pPalette;
};

typedef T_SpriteSet *P_SpriteSet;

struct __unaligned T_Resources
{
  char *Name;
  int SpriteNumberStatus;
  int SpriteNumber;
  int Unknown_C;
  int Unknown_10;
  int Unknown_14;
};

typedef T_Resources *P_Resources;

struct __unaligned T_Type07
{
  int Offset;
  char *FieldName;
};

typedef T_Type07 *P_Type07;

struct __unaligned T_Character
{
  char *KeyName;
  char *Unknown_4;
  int Unknown[2];
  int Unknown_10;
  int Unknown_14[9];
  void *DESTR_Kill_func;
  int Unknown_3C;
  int Initial_HTK;
  int Num_Lives;
  int Power_Multiplier;
  int Initial_No;
  int Trainer_No;
  int Max_Num_Allowed;
  int SlowDown_Energy;
  int Strike_Energy;
  int Fast_Speed;
  int Slow_Speed;
  int Flee_Speed;
  int Min_Recoil_Rate;
  int Initial_Experience;
  int Reset_Experience;
  int Experience_incr;
  int Enemy_experience;
  int Aggressor_Count;
  int Unknown_84[7];
};

typedef T_Character *P_Character;

struct __unaligned T_Type08
{
  void *Func;
  char *FuncName;
};

typedef T_Type08 *P_Type08;

struct __unaligned T_HouseBuffer
{
  int Unknown[10];
  T_House House[320];
};

typedef T_HouseBuffer *P_HouseBuffer;

struct __unaligned T_Type09
{
  int Unknown_0;
  int Unknown_4;
  int Unknown_8;
  int Unknown_C[3];
  int Unknown_18;
  int Unknown_1C;
  int _FrameNo;
};

typedef T_Type09 *P_Type09;

struct __unaligned T_Product
{
  char *Name;
  int Unknown[7];
  int Unknown_20;
  int Unknown_24[14];
  int Cost_Manuf;
  int WorkNeeded;
  int Multiple_Made;
  int Max_In_Stock;
  int Equip_Cost;
  int Usage_Chng;
  int Unknown_74;
};

typedef T_Product *P_Product;

struct __unaligned T_Type10
{
  __int16 Unknown_0[];
};

typedef T_Type10 *P_Type10;

struct __unaligned T_Mode
{
  int Unknown_0;
  int Unknown_4;
  int Unknown_8;
  int Unknown_C;
  void (__stdcall *Proc)();
  int Unknown_14;
  int Unknown_18;
  int Unknown_1C;
  int Unknown_20;
  int Unknown_24;
  char *ProcName;
};

typedef T_Mode *P_Mode;

typedef T_Type14 *P_Type14;

typedef T_Type15 *P_Type15;

struct __unaligned T_Type13
{
  P_Type14 spriteEntries;
  P_Type15 boundingBox;
};

struct __unaligned T_Type14
{
  int spriteFrameId;
  int posX;
  int posY;
  int Unknown_C;
};

struct __unaligned T_Type15
{
  int left;
  int top;
  int width;
  int height;
};

typedef T_Type13 *P_Type13;

struct __unaligned T_ScreenBuffers
{
  BYTE ScreenBuffer1[359424];
  WORD ScreenBuffer2[832][616];
  WORD PrimarySurfaceBuffer[800][600];
};

typedef T_ScreenBuffers *P_ScreenBuffers;

struct __unaligned T_Command
{
  int id;
  char *Name;
  int Unknown_8;
};

typedef T_Command *P_Command;

enum MACRO_MR_COMMANDS
{
  MR_COMMAND_ADVANCESYNC = 0x342,
  MR_COMMAND_PLACEHOUSE = 0x28F,
  MR_COMMAND_REPAIR = 0x22D,
  MR_COMMAND_REPAIRFENCE = 0x22E,
  MR_COMMAND_AUTOREPAIR = 0x22A,
  MR_COMMAND_KILLHOUSE = 0x22B,
  MR_COMMAND_REMOVEOBJECT = 0x34E,
  MR_COMMAND_SUPPLYLOAN = 0x2A5,
  MR_COMMAND_REPAYLOAN = 0x2A6,
  MR_COMMAND_BUYTOOL = 0x25B,
  MR_COMMAND_WRKR2FIXER = 0x2BB,
  MR_COMMAND_UPGRADE = 0x23E,
  MR_COMMAND_BUYTENANT = 0x276,
  MR_COMMAND_CHANGECHILDTYP = 0x240,
  MR_COMMAND_TENANT2WORKER = 0x2BE,
  MR_COMMAND_WORKER2TENANT = 0x2BD,
  MR_COMMAND_COMMANDUNDES = 0x245,
  MR_COMMAND_ABORTTASK = 0x247,
  MR_COMMAND_WAKETENANT = 0x24E,
  MR_COMMAND_SETBRIBE = 0x24F,
  MR_COMMAND_PAYBRIBE = 0x24D,
  MR_COMMAND_ADJUSTSPEED = 0x20B,
  MR_COMMAND_FLEE = 0x229,
  MR_COMMAND_MOVE = 0x228,
  MR_COMMAND_RETURNHOME = 0x22F,
  MR_COMMAND_WAIT = 0x227,
  MR_COMMAND_ATTACKHOUSE = 0x226,
  MR_COMMAND_ATTACK = 0x225,
  MR_COMMAND_TAKEOVER = 0x231,
  MR_COMMAND_GOPICKUP = 0x231,
  MR_COMMAND_TARGETUNDES = 0x34A,
  MR_COMMAND_MOVEUNDES = 0x34B,
  MR_COMMAND_GROUPTEAM = 0x2B9,
  MR_COMMAND_REQPULLOUT = 0x343,
  MR_COMMAND_CONFIRMPULLOUT = 0x344,
  MR_COMMAND_KILLNODE = 0x345,
  MR_COMMAND_MAINPAUSE = 0x20E,
  MR_COMMAND_CHANGESERVER = 0x346,
  MR_COMMAND_SIGNALREADY = 0x347,
  MR_COMMAND_SETVIEW = 0x348,
  MR_COMMAND_CHANGETEAM = 0x349,
  MR_COMMAND_SELLHOUSE = 0x244,
  MR_COMMAND_PLACEOBJECT = 0x297,
  MR_COMMAND_BUYWORKER = 0x2BF,
  MR_COMMAND_ADDCADETS = 0x34C,
  MR_COMMAND_SENDMESSAGE = 0x28C,
  MR_COMMAND_SETCHEAT = 0x34D,
  MR_COMMAND_WORLDRADARBUY = 0x2C1,
  MR_COMMAND_PAYTAX = 0x2B1,
  MR_COMMAND_MANUFACTURE = 0x34F,
  MR_COMMAND_STOPMANUFACTUR = 0x350,
  MR_COMMAND_ENDGAMEFORPLAY = 0x351,
  MR_COMMAND_IGNORECOMPLAIN = 0x352,
  MR_COMMAND_OUTOFSYNC = 0x353,
  MR_COMMAND_NEWTEAM = 0x354,
  MR_COMMAND_UNKNOWN = 0xFFFFFFFF,
};

struct __unaligned T_TeamDefinition
{
  int TextBufferIndex;
  char *Name;
  int Unknown_8;
  int Color1;
  int Color2;
  int Unknown_14[10];
  int Act;
  int Comp;
  int Unknown_44[9];
};

typedef T_TeamDefinition *P_TeamDefinition;

enum MACRO_MR_MODES
{
  MR_MODE_START_GAME = 0x0,
  MR_MODE_SCROLL_MAP = 0x1,
  MR_MODE_EXIT_GAME = 0x2,
  MR_MODE_END_GAME = 0x3,
  MR_MODE_NET_GAME = 0x4,
  MR_MODE_START_MISSION = 0x5,
  MR_MODE_SAVE_START = 0x6,
  MR_MODE_RE_START_MISSION = 0x7,
  MR_MODE_AUTO_LOAD = 0x8,
  MR_MODE_ESTATE_AGENT = 0x9,
  MR_MODE_WORLD_RADAR = 0xA,
  MR_MODE_CITY_HALL = 0xB,
  MR_MODE_VIEW_MISSIONS = 0xC,
  MR_MODE_MESSAGES = 0xD,
  MR_MODE_VIEW_TENANTS = 0xE,
  MR_MODE_ALL_MEN = 0xF,
  MR_MODE_POLICE = 0x10,
  MR_MODE_PRISON = 0x11,
  MR_MODE_HOMEBASE = 0x12,
  MR_MODE_HOUSE_DATA = 0x13,
  MR_MODE_SITE_DATA = 0x14,
  MR_MODE_RESOURCE = 0x15,
  MR_MODE_FACTORY = 0x16,
  MR_MODE_EDIT_GADGETS = 0x17,
  MR_MODE_ASSIGN_TENANT = 0x18,
  MR_MODE_TOOL_DATA = 0x19,
  MR_MODE_UNDES_ABODES = 0x1A,
  MR_MODE_UTILITY = 0x1B,
  MR_MODE_SHOW_END_GAME = 0x1C,
  MR_MODE_MAIN_MENU = 0x1D,
  MR_MODE_CHANGE_OPTS = 0x1E,
  MR_MODE_TO_IN_GAME_OPTS = 0x1F,
  MR_MODE_IN_GAME_OPTS = 0x20,
  MR_MODE_FROM_IN_GAME_OPTS = 0x21,
  MR_MODE_BRIEFING = 0x22,
  MR_MODE_BRIEFING2 = 0x23,
  MR_MODE_MAP_INTRO = 0x24,
  MR_MODE_LEVEL_COMPLETE = 0x25,
  MR_MODE_LOAD_GAME = 0x26,
  MR_MODE_SAVE_GAME = 0x27,
  MR_MODE_SHOW_DEMO = 0x28,
  MR_MODE_INTRO_TEXT = 0x29,
  MR_MODE_EXIT2DOS = 0x2A,
  MR_MODE_SHOW_TITLE = 0x2B,
};

enum MACRO_MR_CHARACTERS
{
  MR_CHARACTER_WORKER = 0x0,
  MR_CHARACTER_FIXER = 0x1,
  MR_CHARACTER_GANGSTER = 0x2,
  MR_CHARACTER_COUSIN = 0x3,
  MR_CHARACTER_TENANT_M = 0x4,
  MR_CHARACTER_TENANT_F = 0x5,
  MR_CHARACTER_CHILD1 = 0x6,
  MR_CHARACTER_CHILD2 = 0x7,
  MR_CHARACTER_CHILD3 = 0x8,
  MR_CHARACTER_BRUTO = 0x9,
  MR_CHARACTER_PRIEST = 0xA,
  MR_CHARACTER_SABOT = 0xB,
  MR_CHARACTER_GHOST = 0xC,
  MR_CHARACTER_HOODS = 0xD,
  MR_CHARACTER_HOOKER = 0xE,
  MR_CHARACTER_ZOMBIE = 0xF,
  MR_CHARACTER_POLICE = 0x10,
  MR_CHARACTER_COCKROACH = 0x11,
  MR_CHARACTER_DOG = 0x12,
  MR_CHARACTER_DELIVERY = 0x13,
  MR_CHARACTER_TENANT_M2 = 0x14,
  MR_CHARACTER_TENANT_F2 = 0x15,
  MR_CHARACTER_BRAZIER = 0x16,
  MR_CHARACTER_BOMB = 0x17,
  MR_CHARACTER_WASTER = 0x18,
  MR_CHARACTER_BEACON = 0x19,
  MR_CHARACTER_BRIBE = 0x1A,
  MR_CHARACTER_DUMMY = 0x1B,
};

