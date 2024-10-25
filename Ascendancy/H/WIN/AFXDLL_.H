// Microsoft Foundation Classes C++ library.
// Copyright (C) 1992-1993 Microsoft Corporation,
// All rights reserved.

// This source code is only intended as a supplement to the
// Microsoft Foundation Classes Reference and Microsoft
// QuickHelp and/or WinHelp documentation provided with the library.
// See these sources for detailed information regarding the
// Microsoft Foundation Classes product.

// afxdll_.h - extensions to AFXWIN.H used for the 'AFXDLL' version
// This file contains MFC library implementation details as well
//   as APIs for writing MFC Extension DLLs.
// Please refer to Technical Note 033 (TN033) for more details.

/////////////////////////////////////////////////////////////////////////////

#ifndef _AFXDLL
#error illegal file inclusion
#endif

#undef AFXAPP_DATA
#define AFXAPP_DATA     AFXAPI_DATA

/////////////////////////////////////////////////////////////////////////////

// get best fitting resource
HINSTANCE AFXDLL_EXPORT AFXAPI AfxFindResourceHandle(LPCSTR lpszName, LPCSTR lpszType);

/////////////////////////////////////////////////////////////////////////////
// CDynLinkLibrary - for implementation of MFC Extension DLLs

struct AFX_EXTENSION_MODULE
{
	HMODULE hModule;
	CRuntimeClass* pFirstSharedClass;
};

// Call in DLL's LibMain
void AFXDLL_EXPORT AFXAPI AfxInitExtensionModule(AFX_EXTENSION_MODULE& state, HMODULE hMod);

// there is one CDynLinkLibrary in each client application using an
//   MFC Extension DLL

class AFX_CLASS_EXPORT CDynLinkLibrary : public CCmdTarget
{
	DECLARE_DYNAMIC(CDynLinkLibrary)
public:

// Constructor
	CDynLinkLibrary(AFX_EXTENSION_MODULE& state);

// Attributes
	HMODULE m_hModule;
	HMODULE m_hResource;                // for shared resources
	CRuntimeClass* m_pFirstSharedClass; // for shared CRuntimeClasses

// Implementation
public:
	CDynLinkLibrary* m_pNextDLL;        // simple singly linked list
	virtual ~CDynLinkLibrary();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif //_DEBUG
};

/////////////////////////////////////////////////////////////////////////////
// Diagnostic support (exported by App, used by MFC250D.DLL)

class COleDebugMalloc;

#ifdef _DEBUG
//WARNING: Do not change this structure since AFXDLL.ASM depends on
//  the specific structure layout and size
struct AFX_APPDEBUG
{
	// Trace output
	void (CALLBACK* lpfnTraceV)(LPCSTR lpszFormat, const void FAR* lpArgs);

	// Assert failure reporting
	void (CALLBACK* lpfnAssertFailed)(LPCSTR lpszFileName, int nLine);

	BOOL appTraceEnabled;
	int appTraceFlags;

	// state for current memory allocation ('bAllocObj' used for free as well)
	LPCSTR  lpszAllocFileName;          // source file name (NULL => unknown)
	UINT    nAllocLine;                 // source line number
	BOOL    bAllocObj;                  // allocating CObject derived object
	BOOL    bMemoryTracking;            // tracking on

	// state for OLE debug allocations
	COleDebugMalloc* appDebugMalloc;    // OLE 2.0 debug allocator
};
#define _AfxGetAppDebug()   (_AfxGetAppData()->pAppDebug)
#define afxTraceEnabled     (_AfxGetAppDebug()->appTraceEnabled)
#define afxTraceFlags       (_AfxGetAppDebug()->appTraceFlags)
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// App specific data for _AFXDLL version

class CHandleMap;       // not NEAR in _AFXDLL version
struct AFX_VBSTATE;     // VB State
struct AFX_FRSTATE;     // Find/Replace state (for CEditView)
struct AFX_OLESTATE;    // OLE State

//WARNING: Do not change this structure since the assembler DLL init
//  the specific structure layout and size
struct AFX_APPDATA  // starts at SS:0010
{
	WORD    cbSize;             // size of this structure
	WORD    wVersion;           // 0x0250 for MFC 250

#ifdef _DEBUG
	AFX_APPDEBUG BASED_STACK* pAppDebug;
	UINT    wReserved;
#else
	DWORD   dwReserved;
#endif
	DWORD   dwReserved2;
	DWORD   dwReserved3;

	FARPROC lpfnVBApiEntry;                             // must be at SS:0020

	// App provided/exported memory allocation interface etc
	void (CALLBACK* lpfnAppAbort)();                    // SS:0024
	FARPROC (CALLBACK* lpfnAppSetNewHandler)(FARPROC);  // SS:0028
	void* (CALLBACK* lpfnAppAlloc)(size_t nBytes);      // SS:002C
	void (CALLBACK* lpfnAppFree)(void*);                // SS:0030
	void* (CALLBACK* lpfnAppReAlloc)(void* pOld, size_t nSize); // SS:0034

	DWORD   dwReserved4;        // SS:0038
	DWORD   dwReserved5;        // SS:0040

	// app state
	CWinApp* appCurrentWinApp;
	HINSTANCE appCurrentInstanceHandle;
	HINSTANCE appCurrentResourceHandle;
	AFX_EXCEPTION_CONTEXT appExceptionContext;
	const char* appCurrentAppName;
	DWORD appTempMapLock;

	// internal App initialization and state
	HBRUSH appDlgBkBrush;
	COLORREF appDlgTextClr;
	HHOOK appHHookOldMsgFilter;
	HHOOK appHHookOldCbtFilter;
	BOOL appUserAbort;              // for printing and other app modal states

	// splitter window state (used in winsplit.cpp)
	HCURSOR hcurSplitLast;
	HCURSOR hcurSplitDestroy;
	UINT    idcSplitPrimaryLast;

	// linkage to shared resources/classes
	CDynLinkLibrary* pFirstDLL;     // order is important for resource loads
	CRuntimeClass* pFirstAppClass;  // CRuntimeClass support
	CFrameWnd* appFirstFrameWnd;    // first frame window for this app

  // sub-system state storage

	// handle maps
	CHandleMap* appMapHGDIOBJ;
	CHandleMap* appMapHDC;
	CHandleMap* appMapHMENU;
	CHandleMap* appMapHWND;

	AFX_VBSTATE FAR* appVBState;
	AFX_FRSTATE FAR* appLastFRState;
	AFX_OLESTATE FAR* appOleState;

	WORD appWaitForDataSource;      // semaphore for async database access
	BOOL bDBExtensionDLL;
};
#define _AfxGetAppData()        ((AFX_APPDATA BASED_STACK*)0x10)

#define afxTempMapLock      (_AfxGetAppData()->appTempMapLock)

// Extra Initialization
extern "C" int PASCAL AFXDLL_EXPORT
AfxWinMain(HINSTANCE, HINSTANCE, LPSTR, int);

#undef AFXAPP_DATA
#define AFXAPP_DATA     NEAR

/////////////////////////////////////////////////////////////////////////////
