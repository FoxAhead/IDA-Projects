// Microsoft Foundation Classes C++ library.
// Copyright (C) 1992-1993 Microsoft Corporation,
// All rights reserved.

// This source code is only intended as a supplement to the
// Microsoft Foundation Classes Reference and Microsoft
// QuickHelp and/or WinHelp documentation provided with the library.
// See these sources for detailed information regarding the
// Microsoft Foundation Classes product.

// Do not include this file directly (included by AFXWIN.H)

/////////////////////////////////////////////////////////////////////////////
// Standard Dialog Data Exchange routines

// simple text operations
void AFXDLL_EXPORT AFXAPI DDX_Text(CDataExchange* pDX, int nIDC, BYTE& value);
void AFXDLL_EXPORT AFXAPI DDX_Text(CDataExchange* pDX, int nIDC, int& value);
void AFXDLL_EXPORT AFXAPI DDX_Text(CDataExchange* pDX, int nIDC, UINT& value);
void AFXDLL_EXPORT AFXAPI DDX_Text(CDataExchange* pDX, int nIDC, long& value);
void AFXDLL_EXPORT AFXAPI DDX_Text(CDataExchange* pDX, int nIDC, DWORD& value);
void AFXDLL_EXPORT AFXAPI DDX_Text(CDataExchange* pDX, int nIDC, CString& value);
void AFXDLL_EXPORT AFXAPI DDX_Text(CDataExchange* pDX, int nIDC, float& value);
void AFXDLL_EXPORT AFXAPI DDX_Text(CDataExchange* pDX, int nIDC, double& value);

// special control types
void AFXDLL_EXPORT AFXAPI DDX_Check(CDataExchange* pDX, int nIDC, int& value);
void AFXDLL_EXPORT AFXAPI DDX_Radio(CDataExchange* pDX, int nIDC, int& value);
void AFXDLL_EXPORT AFXAPI DDX_LBString(CDataExchange* pDX, int nIDC, CString& value);
void AFXDLL_EXPORT AFXAPI DDX_CBString(CDataExchange* pDX, int nIDC, CString& value);
void AFXDLL_EXPORT AFXAPI DDX_LBIndex(CDataExchange* pDX, int nIDC, int& index);
void AFXDLL_EXPORT AFXAPI DDX_CBIndex(CDataExchange* pDX, int nIDC, int& index);
#if (WINVER >= 0x030a)
void AFXDLL_EXPORT AFXAPI DDX_LBStringExact(CDataExchange* pDX, int nIDC, CString& value);
void AFXDLL_EXPORT AFXAPI DDX_CBStringExact(CDataExchange* pDX, int nIDC, CString& value);
#endif

// for getting access to the actual controls
void AFXDLL_EXPORT AFXAPI DDX_Control(CDataExchange* pDX, int nIDC, CWnd& rControl);

/////////////////////////////////////////////////////////////////////////////
// Standard Dialog Data Validation routines

// range - value must be >= minVal and <= maxVal
// NOTE: you will require casts for 'minVal' and 'maxVal' to use the
//   UINT, DWORD or float types
void AFXDLL_EXPORT AFXAPI DDV_MinMaxByte(CDataExchange* pDX, BYTE value, BYTE minVal, BYTE maxVal);
void AFXDLL_EXPORT AFXAPI DDV_MinMaxInt(CDataExchange* pDX, int value, int minVal, int maxVal);
void AFXDLL_EXPORT AFXAPI DDV_MinMaxLong(CDataExchange* pDX, long value, long minVal, long maxVal);
void AFXDLL_EXPORT AFXAPI DDV_MinMaxUInt(CDataExchange* pDX, UINT value, UINT minVal, UINT maxVal);
void AFXDLL_EXPORT AFXAPI DDV_MinMaxDWord(CDataExchange* pDX, DWORD value, DWORD minVal, DWORD maxVal);
void AFXDLL_EXPORT AFXAPI DDV_MinMaxFloat(CDataExchange* pDX, float const& value, float minVal, float maxVal);
void AFXDLL_EXPORT AFXAPI DDV_MinMaxDouble(CDataExchange* pDX, double const& value, double minVal, double maxVal);

// number of characters
void AFXDLL_EXPORT AFXAPI DDV_MaxChars(CDataExchange* pDX, CString const& value, int nChars);

/////////////////////////////////////////////////////////////////////////////
