
# This file was generated by the SOM Compiler.
# FileName: wpfntpal.sc.
# Generated using:
#     SOM Precompiler spc: 1.22
#     SOM Emitter emitcsc: 1.10

/*
 *  Module Header
 * 
 *  Module Name: WPFNTPAL
 * 
 *  OS/2 Presentation Manager Workplace class definitions
 * 
 *  Copyright (c) International Business Machines Corporation 1991, 1992
 * 
 */

#include "wppalet.sc"

class: WPFontPalette, 
    external stem = wpfon, local, external prefix = fon_, 
    classprefix = fonM_, major version = 1, minor version = 2, 
    file stem = wpfntpal;


parent class: WPPalette;


release order:
    wpGetFattrsFromPsz;


passthru: C.h, after;

   #define CCHFONTNAME   80

      /* Fontpot structure */

      typedef struct _FONTPOT
      {
         CELL        cell;     /* Size of the data that follows */
         FATTRS      fAttrs;   /* fattrs from WinFontDlg/wpfattrsfrompsz */
         CHAR        szFont[CCHFONTNAME+1];
      } FONTPOT;
      typedef FONTPOT *PFONTPOT;

endpassthru;
methods:


    override wpPaintCell;

    -- From WPPalette

    override wpEditCell;

    -- From WPPalette

    override wpSetupCell;

    -- From WPPalette

    override wpDragCell;

    -- From WPPalette

    override wpclsQueryEditString, class;

    -- From WPPalette

    override wpQueryPaletteHelp;

    -- From WPPalette

    override wpSetup;

    -- From WPObject

    override wpMenuItemHelpSelected;

    -- From WPObject

    override wpclsQueryTitle, class;

    -- From WPObject

    override wpclsQueryIconData, class;

    -- From WPObject

    override wpclsQueryStyle, class;

    -- From WPObject

    override wpclsQueryDefaultHelp, class;

    -- From WPObject

