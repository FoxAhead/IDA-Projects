/****************************************************************************
*
*			The SuperVGA Kit - UniVBE Software Development Kit
*
*				 	Copyright (C) 1994 SciTech Software.
*							All rights reserved.
*
* Filename:		$RCSfile: svtestw.cpp $
* Version:		$Revision: 1.1 $
* Author:		Kendall Bennett
*
* Language:     Borland C++ 4.5/OWL 2.0
* Environment:	Windows 3.1
*
* Description:	Windows based test program for the SuperVGA Kit. This version
*				uses DISPDIB.DLL to switch the system to full screen VGA
*				mode, and then performs full screen VESA VBE graphics.
*
*               It also plays the SOUND.WAV file using the Windows
*               Multimedia API from the current directory. You can replace
*               this with any .WAV file you like to play that instead.
*
*               Written using Borland C++ 4.5 and OWL 2.0
*
* $Id: svtestw.cpp 1.1 1995/02/06 16:28:15 kjb release $
*
****************************************************************************/

#include <owl\owlpch.h>
#include <owl\applicat.h>
#include <owl\framewin.h>
#include <owl\dialog.h>
#include <owl\dc.h>
#include <owl\checkbox.h>
#include <owl\edit.h>
#include <stdio.h>
#include <string.h>
#include <mmsystem.h>
#include "svtestw.h"
#include "vesavbe.h"
#include "svga.h"
#include "windirec.h"

#define	MAX_MODES	15
#define	MAX_STR		100

extern "C" bool doTest(ushort mode,bool widedac,bool doPalette,bool doVirtual,
	bool doRetrace,int maxProgram);

#include "version.c"

//-------------------------------------------------------------------------//

void _cdecl VBE_fatalError(char *msg)
{
	MessageBox(NULL, msg, "FATAL: VESAVBE.C", MB_ICONEXCLAMATION);
	exit(1);
}

HWND	hwndEvent;

extern "C" void SV_resetGS(void);

// Check if a key or mouse click is waiting in Windows message queue.
extern "C" int KeyHit(void)
{
	MSG	msg;

	while (PeekMessage(&msg, hwndEvent, 0, 0, PM_NOREMOVE)) {
		switch (msg.message) {
			case WM_KEYDOWN:
			case WM_LBUTTONDOWN:
            case WM_RBUTTONDOWN:
				SV_resetGS();
				return TRUE;
			}
		GetMessage(&msg, hwndEvent, 0, 0);
		}
	SV_resetGS();
	return FALSE;
}

// Get a key from Windows message queue. If a mouse click is found, we
// return an 'Enter' keystroke. 
extern "C" int GetChar(void)
{
	MSG msg;

	while (1) {
		GetMessage(&msg, hwndEvent, 0, 0);
		switch (msg.message) {
			case WM_KEYDOWN:
				SV_resetGS();
				return msg.wParam;
			case WM_LBUTTONDOWN:
			case WM_RBUTTONDOWN:
				SV_resetGS();
				return 0xD;
			}
		}
}

//-------------------------------------------------------------------------//

void CenterWindow(TWindow *center, TWindow *parent, BOOL repaint)
{
	TRect	RectParent;
	TRect	RectCenter;
	TWindow	desktop(GetDesktopWindow());
	int		CenterX, CenterY, Height, Width;

	if (parent == NULL) parent = &desktop;
	parent->GetWindowRect(RectParent);
	center->GetWindowRect(RectCenter);

	Width = (RectCenter.right - RectCenter.left);
	Height = (RectCenter.bottom - RectCenter.top);
	CenterX = ((RectParent.right - RectParent.left) - Width) / 2;
	CenterY = ((RectParent.bottom - RectParent.top) - Height) / 2;

	if ((CenterX < 0) || (CenterY < 0)) {
		// The Center Window is smaller than the parent window.

		if (parent != &desktop) {
			// If the parent window is not the desktop use the desktop size.
			CenterX = (GetSystemMetrics(SM_CXSCREEN) - Width) / 2;
			CenterY = (GetSystemMetrics(SM_CYSCREEN) - Height) / 2;
			}

		CenterX = (CenterX < 0) ? 0: CenterX;
		CenterY = (CenterY < 0) ? 0: CenterY;
		}
	else {
		CenterX += RectParent.left;
		CenterY += RectParent.top;
		}

	// Copy the values into RectCenter.
	RectCenter.left = CenterX;
	RectCenter.right = CenterX + Width;
	RectCenter.top = CenterY;
	RectCenter.bottom = CenterY + Height;

	// Move the window to the new location
	center->MoveWindow(RectCenter, repaint);
}

//--------------------------------------------------------------------------//

class SVGAInfoDialog : public TDialog {
public:
			SVGAInfoDialog(TWindow* parent, int resId, TModule* module)
				: TDialog(parent, resId, module) {};

			// Override dialog box virtuals
			void SetupWindow();
	};

void SVGAInfoDialog::SetupWindow()
{
	char		buf[MAX_STR];
    VBE_vgaInfo	vgaInfo;

	TStatic *oemString = new TStatic(this,IDC_OEMSTRING,MAX_STR);
	TStatic *vbeVersion = new TStatic(this,IDC_VBEVERSION,MAX_STR);
	TStatic *vbeMemory = new TStatic(this,IDC_VBEMEMORY,MAX_STR);
	TStatic *oemSoftwareRev = new TStatic(this,IDC_OEMSOFTWAREREV,MAX_STR);
	TStatic *oemVendorName = new TStatic(this,IDC_OEMVENDORNAME,MAX_STR);
	TStatic *oemProductName = new TStatic(this,IDC_OEMPRODUCTNAME,MAX_STR);
	TStatic *oemProductRev = new TStatic(this,IDC_OEMPRODUCTREV,MAX_STR);
	TStatic *have8BitDAC = new TStatic(this,IDC_8BITDAC,MAX_STR);
	TStatic *haveLinearBuffer = new TStatic(this,IDC_LINEARBUFFER,MAX_STR);
	TDialog::SetupWindow();
	CenterWindow(this, NULL, FALSE);

    VBE_detect(&vgaInfo);
	oemString->SetText(vgaInfo.OemStringPtr);
    sprintf(buf,"%d.%d", vgaInfo.VESAVersion >> 8, vgaInfo.VESAVersion & 0xFF);
	vbeVersion->SetText(buf);
	sprintf(buf,"%d Kb", vgaInfo.TotalMemory * 64);
	vbeMemory->SetText(buf);
    if (vgaInfo.VESAVersion >= 0x200) {
		sprintf(buf,"0x%04X", vgaInfo.OemSoftwareRev);
		oemSoftwareRev->SetText(buf);
		oemVendorName->SetText(vgaInfo.OemVendorNamePtr);
		oemProductName->SetText(vgaInfo.OemProductNamePtr);
		oemProductRev->SetText(vgaInfo.OemProductRevPtr);
		haveLinearBuffer->SetText("No");
		}
	else {
		oemSoftwareRev->SetText("N/A");
		oemVendorName->SetText("N/A");
		oemProductName->SetText("N/A");
		oemProductRev->SetText("N/A");
		haveLinearBuffer->SetText("No");
		}
 	have8BitDAC->SetText((capabilities & vbe8BitDAC) ? "Yes" : "No");
}

//--------------------------------------------------------------------------//

struct TransferBuf {
	BOOL			mode4Bit;
	BOOL			mode8Bit;
	BOOL			mode15Bit;
	BOOL			mode16Bit;
	BOOL			mode24Bit;
	BOOL			mode32Bit;
	BOOL			useLinear;
	BOOL			doPalette;
	BOOL			doVirtual;
	BOOL			doRetrace;
	TListBoxData	modes;
	ushort			modeNums[MAX_MODES];

	// Construct the default options
	TransferBuf();

	// Build the list of available video mode
	void RefreshModeList();

	// Get mode number for list box selection
	ushort GetModeNum();
	};

TransferBuf::TransferBuf()
{
	mode4Bit = true;
	mode8Bit = false;
	mode15Bit = false;
	mode16Bit = false;
	mode24Bit = false;
	mode32Bit = false;
	useLinear = (linearAddr != 0);
	doPalette = true;
	doVirtual = true;
	doRetrace = true;
	RefreshModeList();
}

void TransferBuf::RefreshModeList()
{
	char			buf[MAX_STR];
	int				bits,i;
	ushort			*m,mode;
	VBE_modeInfo	mi;

	if (mode4Bit)		bits = 4;
	else if (mode8Bit)	bits = 8;
	else if (mode15Bit)	bits = 15;
	else if (mode16Bit)	bits = 16;
	else if (mode24Bit)	bits = 24;
	else if (mode32Bit)	bits = 32;

	modes.Clear();
    modes.Select(0);
	for (m = modeList, i = 0; *m != 0xFFFF; m++) {
		if (!VBE_getModeInfo(*m,&mi))
			continue;
		if (mi.BitsPerPixel != bits)
			continue;
		if ((mode = SV_getModeName(buf,&mi,*m,useLinear)) == 0)
			continue;
		modes.AddString(buf);
		modeNums[i++] = mode;
		}
}

ushort TransferBuf::GetModeNum()
{
	if (modes.GetSelCount() == 0)
		return 0;
	return modeNums[modes.GetSelIndices()[0]]; 
}

//--------------------------------------------------------------------------//

class MainDialog : public TDialog {
protected:
	TCheckBox				*useLinear;
	TransferBuf				t;
    char					soundName[255];
    TOpenSaveDialog::TData	*FileData;

			// Display the SuperVGA Information dialog box
			void CmSVGAInfo()	{ SVGAInfoDialog(this, IDD_SVGAINFO, NULL).Execute(); };

			// Test the selected video mode
            void CmTestMode();

			// Refresh the list of available modes
			void RefreshModes();

public:
			MainDialog(TWindow* parent, int resId, TModule* module);
            ~MainDialog();

			// Override dialog box virtuals
			void SetupWindow();

	DECLARE_RESPONSE_TABLE(MainDialog);
	};

DEFINE_RESPONSE_TABLE1(MainDialog, TDialog)
	EV_COMMAND(IDC_TESTMODE, CmTestMode),
	EV_COMMAND(IDC_SVGAINFO, CmSVGAInfo),
	EV_CHILD_NOTIFY(IDC_4BIT, BN_CLICKED, RefreshModes),
	EV_CHILD_NOTIFY(IDC_8BIT, BN_CLICKED, RefreshModes),
	EV_CHILD_NOTIFY(IDC_15BIT, BN_CLICKED, RefreshModes),
	EV_CHILD_NOTIFY(IDC_16BIT, BN_CLICKED, RefreshModes),
	EV_CHILD_NOTIFY(IDC_24BIT, BN_CLICKED, RefreshModes),
	EV_CHILD_NOTIFY(IDC_32BIT, BN_CLICKED, RefreshModes),
	EV_CHILD_NOTIFY(IDC_USELINEAR, BN_CLICKED, RefreshModes),
	EV_LBN_DBLCLK(IDC_MODELIST, CmTestMode),
END_RESPONSE_TABLE;

MainDialog::MainDialog(TWindow* parent, int resId, TModule* module)
	: TDialog(parent, resId, module)
{
	FileData  = new TOpenSaveDialog::TData(OFN_HIDEREADONLY|OFN_FILEMUSTEXIST,
										"Wave Files (*.WAV)|*.wav|", 0, "",
										"WAV");
	strcpy(soundName,"sound.wav");
	new TRadioButton(this, IDC_4BIT);
	new TRadioButton(this, IDC_8BIT);
	new TRadioButton(this, IDC_15BIT);
	new TRadioButton(this, IDC_16BIT);
	new TRadioButton(this, IDC_24BIT);
	new TRadioButton(this, IDC_32BIT);
	useLinear = new TCheckBox(this, IDC_USELINEAR);
	new TCheckBox(this, IDC_DOPALETTE);
	new TCheckBox(this, IDC_DOVIRTUAL);
	new TCheckBox(this, IDC_DORETRACE);
	new TListBox(this, IDC_MODELIST);
	SetTransferBuffer(&t);
}

MainDialog::~MainDialog()
{
	delete FileData;
}

void MainDialog::SetupWindow()
{
	char	buf[MAX_STR];
    char	format[MAX_STR];
	TStatic	*version = new TStatic(this, IDC_VERSIONSTR, MAX_STR);
	TStatic	*copyright = new TStatic(this, IDC_COPYRIGHTSTR, MAX_STR);
	TDialog::SetupWindow();
	CenterWindow(this, NULL, FALSE);
	version->GetText(format,MAX_STR);
    sprintf(buf,format,release_major,release_minor,release_date);
    version->SetText(buf);
	copyright->SetText(copyright_str);
	useLinear->EnableWindow(linearAddr != 0);
}

void MainDialog::CmTestMode()
{
	TransferData(tdGetData);
	if (t.modes.GetSelCount() != 0) {
		hwndEvent = WIN_startFullScreen(FALSE);
		sndPlaySound(soundName, SND_ASYNC | SND_LOOP);
		doTest(t.GetModeNum(),(capabilities & vbe8BitDAC),t.doPalette,
				t.doVirtual,t.doRetrace,256);
		sndPlaySound(NULL, NULL);
		WIN_restoreGDI();
		}
}

void MainDialog::RefreshModes()
{
	TransferData(tdGetData);
	t.RefreshModeList();
	TransferData(tdSetData);
}

//--------------------------------------------------------------------------//

class SVTestApp : public TApplication {
public:
			SVTestApp(char far* name)
				: TApplication(name) { EnableCtl3d(TRUE); };

			// Overload InitInstance as we dont have a MainWindow
			void InitInstance() {};
	};

//-------------------------------------------------------------------------//

int OwlMain(int, char*[])
{
	SVTestApp *app = new SVTestApp("SuperVGA Kit for Windows");
	app->Start();
	if (SV_init() < 0x102)
		TDialog(0, IDD_NOTDETECTED, app).Execute();
	else MainDialog(0, IDD_MAINDLG, app).Execute();
	delete app;
	return 0;
}

