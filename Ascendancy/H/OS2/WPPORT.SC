
# This file was generated by the SOM Compiler.
# FileName: ..\..\sc\wpport.sc.
# Generated using:
#     SOM Precompiler spc: 1.22
#     SOM Emitter emitcsc: 1.10

/*
 *  Module Header
 * 
 *  Module Name: WPPORT
 * 
 *  OS/2 Presentation Manager Workplace class definitions
 * 
 *  Copyright (c) International Business Machines Corporation 1991, 1992
 * 
 */

#include "wptrans.sc"

class: PORT, 
    external stem = port, local, external prefix = port_, 
    classprefix = portM_, major version = 1, minor version = 1, 
    file stem = wpport;


parent class: WPTransient;


release order:
    prtGetPortInfo, prtSetPortInfo, prtSettings, 
    prtGetDeviceObject, prtSetPortDiscardhwndDlg, prtSetPortInstallhwndDlg, 
    prtPrintPort, prtSetIcon, prtChangePort;

methods:


    override wpInitData;

    -- From WPObject

    override wpUnInitData;

    -- From WPObject

    override somDumpSelfInt;

    -- From SOMObject

    override wpQueryTitle;

    -- From WPObject

    override wpclsQueryTitle, class;

    -- From WPObject

    override wpQueryIcon;

    -- From WPObject

    override wpclsQueryIcon, class;

    -- From WPObject

    override wpFilterPopupMenu;

    -- From WPObject

    override wpFree;

    -- From WPObject

    override wpModifyPopupMenu;

    -- From WPObject

    override wpMenuItemSelected;

    -- From WPObject

    override wpMenuItemHelpSelected;

    -- From WPObject

    override wpclsQueryDefaultHelp, class;

    -- From WPObject

    override wpclsQueryDefaultView, class;

    -- From WPObject

    override wpOpen;

    -- From WPObject

    override wpDrop;

    -- From WPObject

    override wpDragOver;

    -- From WPObject

    override wpCnrSetEmphasis;

    -- From WPObject

    override wpclsQueryStyle, class;

    -- From WPObject

