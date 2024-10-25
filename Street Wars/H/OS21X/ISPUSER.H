/*********************************************************************\
*                                                                      
* Module Name: ISPUSER.H                                               
*                                                                      
* OS/2 Dialog Manager message constants and type definitions for       
* user controls and user exits.                                        
*                                                                      
* (c) Copyright IBM Corporation, 1989. All rights reserved.            
*                                                                      
\**********************************************************************/

#ifndef ISPUSER_H
#define ISPUSER_H

/**********************************************************************/
/* Application-defined messages should be begin at DM_USER to avoid   */
/* conflict with DM-defined messages.                                 */
/**********************************************************************/
 
#define DM_USER                            WM_USER+0x1000
 
#define CM_MESSAGE_BASE                    WM_USER+0x800
 
/**********************************************************************/
/*  DM messages common to User Controls and User Exits                */
/**********************************************************************/
 
#define CM_FREE_CTL_RESOURCES             (CM_MESSAGE_BASE+0x0000)
#define CM_MEM_ALLOC                      (CM_MESSAGE_BASE+0x0001)
#define CM_MEM_FREE                       (CM_MESSAGE_BASE+0x0002)
#define CM_MEM_REALLOC                    (CM_MESSAGE_BASE+0x0003)
#define CM_QUERY_CTL_HDL                  (CM_MESSAGE_BASE+0x0004)
#define CM_QUERY_USER_INST_PTR            (CM_MESSAGE_BASE+0x0005)
#define CM_SET_USER_INST_PTR              (CM_MESSAGE_BASE+0x0006)
#define CM_UPDATE_CONTROL                 (CM_MESSAGE_BASE+0x0007)
 
/**********************************************************************/
/*  DM User Control Messages                                          */
/**********************************************************************/
 
#define CM_INIT_USER_CONTROL              (CM_MESSAGE_BASE+0x0008)
#define CM_PANEL_ENTERED                  (CM_MESSAGE_BASE+0x0009)
#define CM_END_DISPLAY                    (CM_MESSAGE_BASE+0x000A)
#define CM_GET_UC_PARM_AND_TEXT           (CM_MESSAGE_BASE+0x000B)
#define CM_NO_FOCUS_USER_CONTROL          (CM_MESSAGE_BASE+0x000C)
#define CM_YES_FOCUS_USER_CONTROL         (CM_MESSAGE_BASE+0x000D)
#define CM_SET_MIN_MAX_SIZE               (CM_MESSAGE_BASE+0x000E)
 
/**********************************************************************/
/*  DM User Action Exit Messages                                      */
/**********************************************************************/
 
#define CM_DO_ACTION                      (CM_MESSAGE_BASE+0x000F)
#define CM_INIT_USER_ACTION               (CM_MESSAGE_BASE+0x0010)
 
/**********************************************************************/
/*  DM User Check Exit Messages                                       */
/**********************************************************************/
 
#define CM_DO_CHECK                       (CM_MESSAGE_BASE+0x0011)
#define CM_INIT_USER_CHECK                (CM_MESSAGE_BASE+0x0012)
 
/**********************************************************************/
/*  DM User Command Action Exit Messages                              */
/**********************************************************************/
 
#define CM_DO_CMD_ACTION                  (CM_MESSAGE_BASE+0x0013)
#define CM_INIT_USER_CMD_ACTION           (CM_MESSAGE_BASE+0x0014)
 
/**********************************************************************/
/*  DM User Translate Exit Messages                                   */
/**********************************************************************/
 
#define CM_DO_XLATE                       (CM_MESSAGE_BASE+0x0015)
#define CM_INIT_USER_XLATE                (CM_MESSAGE_BASE+0x0016)
 
/**********************************************************************/
/*  DM User Variable Exit Messages                                    */
/**********************************************************************/
 
#define CM_INIT_USER_VARIABLE             (CM_MESSAGE_BASE+0x0017)
#define CM_QUERY_VARIABLE_VALUE           (CM_MESSAGE_BASE+0x0018)
#define CM_SET_VARIABLE_VALUE             (CM_MESSAGE_BASE+0x0019)
 
 
#define CCTL_INPUT                        1
#define CCTL_OUTPUT                       2
 
/**********************************************************************/
/* These constants are provided to make is easy for the writer of a   */
/* user control or user exit to register their class.                 */
/*                                                                    */
/* The style constants provided as class styles for the application's */
/* user control/exit window class.  They should "or" in any of their  */
/* own class styles.  Currently these are null because DM doesn't     */
/* require user controls/exits to have a particular window style, but */
/* these can be changed in the future if that requirement arises.     */
/*                                                                    */
/* The extra bytes constants should be used so that user controls/    */
/* exits have extra window words for the pointer to their instance    */
/* data.  Any extra bytes the application wants to use must be after  */
/* the first 4 in the extra window words, as these are reserved by    */
/* DM.  Remember the UserInstancePtr in the user control/exit         */
/* instance data can be used to point to application specific data.   */
/**********************************************************************/
 
#define CCTL_UC_CLASS_STYLE    0x00000000L          /* User control   */
#define CCTL_UA_CLASS_STYLE    0x00000000L          /* Action         */
#define CCTL_UK_CLASS_STYLE    0x00000000L          /* Check          */
#define CCTL_UM_CLASS_STYLE    0x00000000L          /* Command action */
#define CCTL_UX_CLASS_STYLE    0x00000000L          /* Translate      */
#define CCTL_UV_CLASS_STYLE    0x00000000L          /* Variable access*/
 
#define CCTL_UC_EXTRA_BYTES    4                    /* User control   */
#define CCTL_UA_EXTRA_BYTES    4                    /* Action         */
#define CCTL_UK_EXTRA_BYTES    4                    /* Check          */
#define CCTL_UM_EXTRA_BYTES    4                    /* Command action */
#define CCTL_UX_EXTRA_BYTES    4                    /* Translate      */
#define CCTL_UV_EXTRA_BYTES    4                    /* Variable access*/
 
 
typedef struct
{
  ULONG ReturnCode;
  USHORT MessageParmSize;
} cmDefaultMessageParm,       far *cmDefaultMessageParmPtr,
  cmFreeCtlResourcesParm,     far *cmFreeCtlResourcesParmPtr,
  cmInitUserControlParm,      far *cmInitUserControlParmPtr,
  cmInitUserVariableParm,     far *cmInitUserVariableParmPtr,
  cmNoFocusUserControlParm,   far *cmNoFocusUserControlParmPtr,
  cmYesFocusUserControlParm,  far *cmYesFocusUserControlParmPtr,
  cmPanelEnteredParm,         far *cmPanelEnteredParmPtr,
  cmQueryUserInstPtrParm,     far *cmQueryUserInstPtrParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  USHORT ByteCount;
} cmMemAllocParm, far *cmMemAllocParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  PVOID  MemoryPtr;
} cmMemFreeParm, far *cmMemFreeParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  USHORT NewByteCount;
  PVOID  SourcePtr;
} cmMemReallocParm, far *cmMemReallocParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  PSZ    Name;
} cmQueryCtlHdlParm, far *cmQueryCtlHdlParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  PVOID  UserInstancePtr;
} cmSetUserInstPtrParm, far *cmSetUserInstPtrParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  BOOL   SetInitialState;
} cmUpdateControlParm, far *cmUpdateControlParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  ULONG  DisplayReasonCode;
  BOOL   MsgOnInvalidField;
} cmEndDisplayParm, far *cmEndDisplayParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  PSZ    ReturnControlTextPtr;
  PSZ    ReturnControlPrmdataPtr;
} cmGetUCParmAndTextParm, far *cmGetUCParmAndTextParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  USHORT MinWidth;
  USHORT MaxWidth;
  USHORT MinDepth;
  USHORT MaxDepth;
} cmSetMinMaxSizeParm, far *cmSetMinMaxSizeParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  PSZ    ActionParmPtr;
} cmDoActionParm, far *cmDoActionParmPtr;
 
typedef struct
{
  ULONG   ReturnCode;
  USHORT  MessageParmSize;
  PSZ     ActionParmPtr;
} cmInitUserActionParm, far *cmInitUserActionParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  PSZ    CheckValuePtr;
  PSZ    CheckParm1Ptr;
  PSZ    CheckParm2Ptr;
} cmDoCheckParm, far *cmDoCheckParmPtr;
 
typedef struct
{
  ULONG   ReturnCode;
  USHORT  MessageParmSize;
  PSZ     CheckParm1Ptr;
  PSZ     CheckParm2Ptr;
} cmInitUserCheckParm, far *cmInitUserCheckParmPtr;
 
typedef struct
{
   ULONG  ReturnCode;
   USHORT MessageParmSize;
   PSZ    CmdParmPtr;
   PSZ    CmdActionParmPtr;
} cmDoCmdActionParm, far *cmDoCmdActionParmPtr;
 
typedef struct
{
  ULONG   ReturnCode;
  USHORT  MessageParmSize;
  PSZ     CmdActionParmPtr;
} cmInitUserCmdActionParm, far *cmInitUserCmdActionParmPtr;
 
typedef struct
{
  ULONG   ReturnCode;
  USHORT  MessageParmSize;
  USHORT  Direction;
  USHORT  XlateBufferLen;
  PSZ     XlateBufferPtr;
  PSZ     XlateParmPtr;
  BOOL    Continue;
} cmDoXlateParm, far *cmDoXlateParmPtr;
 
typedef struct
{
  ULONG   ReturnCode;
  USHORT  MessageParmSize;
  USHORT  XlateBufferLen;
  PSZ     XlateParmPtr;
} cmInitUserXlateParm, far *cmInitUserXlateParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  PSZ    VnamePtr;
  PSZ    ReturnBufferPtr;
  USHORT ReturnBufferLength;
  USHORT Subscript;
} cmQueryVariableValueParm, far *cmQueryVariableValueParmPtr;
 
typedef struct
{
  ULONG  ReturnCode;
  USHORT MessageParmSize;
  PSZ    VnamePtr;
  PSZ    BufferPtr;
  USHORT Subscript;
} cmSetVariableValueParm, far *cmSetVariableValueParmPtr;
 

#endif
