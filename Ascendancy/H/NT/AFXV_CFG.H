#ifndef _AFXV_CFG_H
#define _AFXV_CFG_H

#ifdef __WATCOMC__

#define _PORTABLE
#define _X86_

#undef  AFXAPI_DATA
#define AFXAPI_DATA
#undef  AFX_STACK_DATA
#define AFX_STACK_DATA
#undef  BASED_CODE
#define BASED_CODE
#undef  BASED_DEBUG
#define BASED_DEBUG
#undef  BASED_STACK
#define BASED_STACK

#define AFXAPI_DATA_TYPE

#undef AFX_CORE1_SEG
#undef AFX_CORE2_SEG
#undef AFX_CORE3_SEG
#undef AFX_AUX_SEG  
#undef AFX_COLL_SEG 
#undef AFX_COLL2_SEG
#undef AFX_OLE_SEG  
#undef AFX_INIT_SEG 
#undef AFX_PRINT_SEG
#undef AFX_DBG1_SEG 
#undef AFX_DBG2_SEG 

struct CBlockHeader;
struct CPlex;

#endif

#endif
