// 
// typedef          char       CHAR;
// typedef          short      SHORT;
// typedef          long       LONG;  // 1
// typedef unsigned char       BYTE;
// typedef unsigned short      WORD;
// typedef unsigned long       DWORD; // 2
//
// typedef          int        INT;   // 1
// typedef unsigned int        UINT;  // 2
//

#pragma pack(push, 1)

// Size = 0x14
struct T_UnitType
{
  LONG dword_64B1B8;
  LONG dword_64B1BC;
  BYTE byte_64B1C0;
  BYTE byte_64B1C1;
  BYTE byte_64B1C2;
  BYTE byte_64B1C3;
  BYTE byte_64B1C4;
  BYTE byte_64B1C5;
  BYTE byte_64B1C6;
  BYTE byte_64B1C7;
  BYTE byte_64B1C8;
  BYTE byte_64B1C9;
  BYTE Role;
  BYTE byte_64B1CB;
};

// Address = 0x64B1B8
typedef T_UnitType T_UnitTypes[62];

// Size = 0x594
struct T_Civ
{
  BYTE Unknown1;
  BYTE Unknown2;
  LONG Gold;
  BYTE Unknown3;
  BYTE Unknown4;
  WORD Beakers;
  BYTE Unknown5[11];
  BYTE Government;
  BYTE Unknown6[1406];
};

// Address = 0x64C6A0
// Size = 0x594 * 0x8 = 0x2CA0
typedef T_Civ T_Civs[8];

// Size = 0x58
struct T_City
{
  WORD X;
  WORD Y;
  BYTE byte_64F344;
  BYTE unk_64F345;
  BYTE byte_64F346;
  BYTE byte_64F347;
  BYTE Owner;
  BYTE Size;
  BYTE Founder;
  BYTE TurnsCaptured;
  BYTE byte_64F34C;
  BYTE RevealedSize[9];
  LONG dword_64F356;
  WORD word_64F35A;
  WORD word_64F35C;
  WORD word_64F35E;
  BYTE Name[16];
  LONG dword_64F370;
  BYTE byte_64F374[5];
  BYTE byte_64F379;
  BYTE byte_64F37A;
  BYTE byte_64F37B;
  BYTE byte_64F37C[2];
  BYTE byte_64F37E;
  BYTE byte_64F37F[2];
  BYTE byte_64F381;
  BYTE byte_64F382[2];
  WORD word_64F384;
  WORD word_64F386[2];
  WORD word_64F38A;
  WORD word_64F38C;
  WORD word_64F38E;
  BYTE byte_64F390;
  BYTE byte_64F391;
  BYTE byte_64F392;
  BYTE byte_64F393;
  LONG ID;
};

// Address = 0x64F340
// Size = 0x58 * 0x100 = 0x5800
typedef T_City T_Cities[0x100];

// Size = 0x30
struct T_Leader
{
  BYTE Attack;
  BYTE Expand;
  BYTE Civilize;
  BYTE Female;
  BYTE byte_6554FC;
  BYTE CitiesBuilt;
  WORD Color;
  WORD Style;
  WORD word_655502;
  WORD word_655504;
  WORD word_655506;
  WORD word_655508;
  WORD word_65550A;
  WORD word_65550C[14];
};

// Address = 0x6554F8
// Size = 0x30 * 0x15 = 0x3F0
typedef T_Leader T_Leaders[0x15];

// Address = 0x655AE8
struct TGameParameters
{
  WORD word_655AE8;
  LONG dword_655AEA;
  WORD word_655AEE;
  WORD MapFlags;
  WORD word_655AF2;
  WORD word_655AF4;
  WORD word_655AF6;
  WORD Turn;
  WORD Year;
  WORD word_655AFC;
  WORD word_655AFE;
  WORD word_655B00;
  BYTE PlayerTribeNumber;
  BYTE byte_655B03;
  BYTE byte_655B04;
  BYTE byte_655B05;
  BYTE byte_655B06;
  BYTE byte_655B07;
  BYTE DifficultyLevel;
  BYTE BarbarianActivity;
  BYTE TribesLeftInPlay;
  BYTE HumanPlayers;
  BYTE byte_655B0C;
  BYTE byte_655B0D;
  BYTE byte_655B0E;
  BYTE byte_655B0F;
  WORD word_655B10;
  WORD word_655B12;
  WORD word_655B14;
  WORD TotalUnits;
  WORD TotalCities;
  WORD word_655B1A;
  WORD word_655B1C;
  BYTE byte_655B1E[34];
  BYTE byte_655B40;
  BYTE byte_655B41[3];
  BYTE byte_655B44;
};

// Size = 0x20
struct T_Unit
{
  WORD X;
  WORD Y;
  WORD Attributes;
  BYTE UnitType;
  BYTE CivIndex;
  BYTE MovePoints;
  BYTE field_9;
  BYTE field_A;
  BYTE MoveDirection;
  BYTE field_C;
  BYTE Counter;
  BYTE field_E;
  BYTE Orders;
  BYTE HomeCity;
  BYTE field_11;
  WORD GotoX;
  WORD GotoY;
  WORD PrevInStack;
  WORD NextInStack;
  LONG ID;
  WORD field_1E;
};

// Address = 0x6560F0
typedef T_Unit T_Units[2048];

#pragma pack(pop)

