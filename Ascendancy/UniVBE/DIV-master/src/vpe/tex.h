/*****************************************************************************
 *                                                                           *
 *                           TEXTURE FILE STUFF                              *
 *                                                                           *
 *                   ------------------------------------                    *
 *                  |      Virtual Presence Engine       |                   *
 *****************************************************************************/

struct PicInfo {        // Information about a picture
  int    code;          // Codigo dentro del fpg
  SHORT  Width, Height; // Dimensions of a pic
  SHORT  InsX, InsY;    // Insertion point
  SHORT  Used;          // Used counter
  SHORT  Width2;        // log2 Width
  BYTE  *Raw;           // Pointer to data
  int    fpg;
};

struct TexCon {                   // Texture control
  struct PicInfo *pPic;           // Pointer to current picture
  BYTE   IsMirror;                // Mirror flag
  BYTE   reserved_1[3];           // To keep the alignment
  struct PicInfo *pic_render[10]; // Pointer to current picture
  int    IsMirror_render[10];     // Mirror flag
};

