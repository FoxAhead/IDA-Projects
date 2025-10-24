#include <stdio.h>
#pragma pack(1)


// Definitions

typedef signed char         BYTE;
typedef signed long int     LONG;
typedef signed short int    WORD;
typedef unsigned char       UBYTE;
typedef unsigned long int   ULONG;
typedef unsigned short int  UWORD;
typedef int BOOL;


// Types

typedef struct {
  //T_WndA2 super;
  //P_Wnd10LB pPlayerDipListBox;
  //P_Wnd10LB pAlienDipListBox;
  //P_Wnd02COSW pCosWnd;
  int Unknown_B7;
  WORD Unknown_BB;
  WORD Unknown_BD;
  WORD Unknown_BF;
  WORD Unknown_C1;
} T_Wnd21NW;

typedef T_Wnd21NW *P_Wnd21NW;

typedef struct {
  UBYTE index;
  UBYTE species;
  UBYTE colorSet;
  BOOL extinct;
  BYTE ability;
  int daysAfterAbilityUse;
  int Unknown_1A2[2];
  WORD shipPatience;
  WORD attitudes[7];
  BYTE treaties[7];
  WORD negPlayerTurns;
  WORD declareWar;
  WORD acceptPeace;
  WORD proposePeace;
  WORD breakAlliance;
  WORD acceptAlliance;
  WORD proposeAlliance;
  WORD startAttitude;
  WORD bioPeriod;
  WORD bioMaxpositve;
  WORD bioMaxnegative;
  float bioSinX;
  float bioSinHalfX;
  float bioSinTwiceX;
  char Unknown_1E9;
  int Unknown_1EA;
} T_Race;

typedef struct {
  int day;
  WORD _combatSearchIndex;
  T_Race races[7];
  WORD racesNum;
  BYTE atmosphere;
} T_Game;

#pragma pack(1)

// Glabals 

T_Game  V_Game;
int     V_PlayerRaceIndex;
BYTE    byte_968DD;

// Implementation

void Q_Wnd21NW_sub_32658(P_Wnd21NW pNegWnd)
{
  WORD i; // dx
  WORD Unknown_C1; // ax
  
  for ( i = 0; i < V_Game.racesNum; ++i )
  {
    if ( i != V_PlayerRaceIndex && i != byte_968DD && V_Game.races[i].extinct != 0xFFFFFFFF && V_Game.races[V_PlayerRaceIndex].treaties[i] )
    {
      if ( V_Game.races[byte_968DD].treaties[i] )
      {
        Unknown_C1 = pNegWnd->Unknown_C1;
        pNegWnd->Unknown_C1 = Unknown_C1 + 1;
        //word_96842[Unknown_C1] = i;
      }
    }
  }
};


// Main

void main()
{
  T_Wnd21NW NegWnd;
  
  byte_968DD = 1;
  Q_Wnd21NW_sub_32658(&NegWnd);
};

