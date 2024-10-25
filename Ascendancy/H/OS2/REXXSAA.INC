;**********************************************************************
; Module Name: REXXSAA.H
;
; REXX Common Definitions File
;
; @Copyright  1989, 1991 IBM Corporation
; Licensed Materials - Property of IBM
;
; *********************************************************************
;
;   #define:              To include:
;
;   INCL_REXXSAA          Complete Rexx support
;   INCL_RXSUBCOM         Rexx subcommand handler support
;   INCL_RXSHV            Rexx shared variable pool support
;   INCL_RXFUNC           Rexx external function support
;   INCL_RXSYSEXIT        Rexx system exit support
;   INCL_RXMACRO          Rexx macro space support
;   INCL_RXARI            Rexx asynchronous Trace/Halt support
;
;********************************************************************  
ifndef REXXSAA_INCLUDED
REXXSAA_INCLUDED	EQU	1

;  XLATON   
ifndef OS2_INCLUDED
INCLUDE os2.INC
endif
;********************************************************************  
;                                                                      
;                             Common                                   
;                                                                      
;********************************************************************  
;  This section defines return codes and constants that are the        
;  same for both 16-bit and 32-bit REXX calls.                         
ifdef INCL_REXXSAA
INCL_RXSUBCOM	EQU	1

INCL_RXSHV	EQU	1

INCL_RXFUNC	EQU	1

INCL_RXSYSEXIT	EQU	1

INCL_RXMACRO	EQU	1

INCL_RXARI	EQU	1

endif ;  INCL_REXXSAA   
;***    Structure for external interface string (RXSTRING)   

RXSTRING	STRUC
rxstr_strlength	DD	?           ;    length of string           
rxstr_strptr	DB	SIZE PCH DUP (?)              ;    pointer to string          
RXSTRING	ENDS
RXAUTOBUFLEN	EQU	256 
;***    Structure for system exit block (RXSYSEXIT) 32-bit   

RXSYSEXIT	STRUC
syse_sysexit_name	DB	SIZE PSZ DUP (?)                 ;  subcom enviro for sysexit    
syse_sysexit_code	DD	?                 ;  sysexit function code        
RXSYSEXIT	ENDS
;*** Call type codes for use on interpreter startup                    
RXCOMMAND	EQU	0               ;  Program called as Command    
RXSUBROUTINE	EQU	1               ;  Program called as Subroutin  
RXFUNCTION	EQU	2               ;  Program called as Function   
;***    Subcommand Interface defines  
ifdef INCL_RXSUBCOM
;***    Drop Authority for RXSUBCOM interface   
RXSUBCOM_DROPPABLE	EQU	00H      ;  handler to be dropped by all  
RXSUBCOM_NONDROP	EQU	01H      ;  process with same PID as the  
                                      ;  registrant may drop environ   
;***    Return Codes from RXSUBCOM interface   
RXSUBCOM_ISREG	EQU	01H      ;  Subcommand is registered      
RXSUBCOM_ERROR	EQU	01H      ;  Subcommand Ended in Error     
RXSUBCOM_FAILURE	EQU	02H      ;  Subcommand Ended in Failure   
RXSUBCOM_BADENTRY	EQU	1001      ;  Invalid Entry Conditions      
RXSUBCOM_NOEMEM	EQU	1002      ;  Insuff stor to complete req   
RXSUBCOM_BADTYPE	EQU	1003      ;  Bad registration type.        
RXSUBCOM_NOTINIT	EQU	1004      ;  API system not initialized.   
RXSUBCOM_OK	EQU	0        ;  Function Complete             
RXSUBCOM_DUP	EQU	10        ;  Duplicate Environment Name-   
                                      ;  but Registration Completed    
RXSUBCOM_MAXREG	EQU	20        ;  Cannot register more          
                                      ;  handlers                      
RXSUBCOM_NOTREG	EQU	30        ;  Name Not Registered           
RXSUBCOM_NOCANDROP	EQU	40        ;  Name not droppable            
RXSUBCOM_LOADERR	EQU	50        ;  Could not load function       
RXSUBCOM_NOPROC	EQU	127        ;  RXSUBCOM routine - not found  
endif ;  INCL_RXSUBCOM for defines   
;***    Shared Variable Pool Interface defines   
ifdef INCL_RXSHV
;***    Function Codes for Variable Pool Interface (shvcode)   
RXSHV_SET	EQU	00H        ;  Set var from given value      
RXSHV_FETCH	EQU	01H        ;  Copy value of var to buffer   
RXSHV_DROPV	EQU	02H        ;  Drop variable                 
RXSHV_SYSET	EQU	03H        ;  Symbolic name Set variable    
RXSHV_SYFET	EQU	04H        ;  Symbolic name Fetch variable  
RXSHV_SYDRO	EQU	05H        ;  Symbolic name Drop variable   
RXSHV_NEXTV	EQU	06H        ;  Fetch "next" variable         
RXSHV_PRIV	EQU	07H        ;  Fetch private information     
RXSHV_EXIT	EQU	08H        ;  Set function exit value       
;***    Return Codes for Variable Pool Interface   
RXSHV_NOAVL	EQU	144        ;  Interface not available       
;***    Return Code Flags for Variable Pool Interface (shvret)   
RXSHV_OK	EQU	00H        ;  Execution was OK              
RXSHV_NEWV	EQU	01H        ;  Variable did not exist        
RXSHV_LVAR	EQU	02H        ;  Last var trans via SHVNEXTV   
RXSHV_TRUNC	EQU	04H        ;  Truncation occurred-Fetch     
RXSHV_BADN	EQU	08H        ;  Invalid variable name         
RXSHV_MEMFL	EQU	10H        ;  Out of memory failure         
RXSHV_BADF	EQU	80H        ;  Invalid funct code (shvcode)  
;***    Structure of Shared Variable Request Block (SHVBLOCK)   

SHVBLOCK	STRUC
shvb_shvnext	DW	?       ;  pointer to the next block     
shvb_shvname	DB	SIZE RXSTRING DUP (?)       ;  Pointer to the name buffer    
shvb_shvvalue	DB	SIZE RXSTRING DUP (?)      ;  Pointer to the value buffer   
shvb_shvnamelen	DD	?    ;  Length of the name value      
shvb_shvvaluelen	DD	?   ;  Length of the fetch value     
shvb_shvcode	DB	?       ;  Function code for this block  
shvb_shvret	DB	?        ;  Individual Return Code Flags  
SHVBLOCK	ENDS
endif ;  INCL_RXSHV for defines   
;***    External Function Interface   
ifdef INCL_RXFUNC
;***    Registration Type Identifiers for Available Function Table   
RXFUNC_DYNALINK	EQU	1         ;  Function Available in DLL    
RXFUNC_CALLENTRY	EQU	2         ;  Registered as mem entry pt.  
;***    Return Codes from RxFunction interface   
RXFUNC_OK	EQU	0         ;  REXX-API Call Successful     
RXFUNC_DEFINED	EQU	10         ;  Function Defined in AFT      
RXFUNC_NOMEM	EQU	20         ;  Not Enough Mem to Add        
RXFUNC_NOTREG	EQU	30         ;  Funct Not Registered in AFT  
RXFUNC_MODNOTFND	EQU	40         ;  Funct Dll Module Not Found   
RXFUNC_ENTNOTFND	EQU	50         ;  Funct Entry Point Not Found  
RXFUNC_NOTINIT	EQU	60         ;  API not initialized          
RXFUNC_BADTYPE	EQU	70         ;  Bad function type            
endif ;  INCL_RXFUNC for defines   
;***   System Exits defines   
ifdef INCL_RXSYSEXIT
;***    Drop Authority for Rexx Exit interface   
RXEXIT_DROPPABLE	EQU	00H      ;  handler to be dropped by all  
RXEXIT_NONDROP	EQU	01H      ;  process with same PID as the  
                                      ;  registrant may drop environ   
;***    Exit return actions   
RXEXIT_HANDLED	EQU	0         ;  Exit handled exit event       
RXEXIT_NOT_HANDLED	EQU	1         ;  Exit passes on exit event     
RXEXIT_RAISE_ERROR	EQU	(-1 )     ;  Exit handler error occurred   
;***    Return Codes from RXEXIT interface   
RXEXIT_ISREG	EQU	01H      ;  Exit is registered            
RXEXIT_ERROR	EQU	01H      ;  Exit Ended in Error           
RXEXIT_FAILURE	EQU	02H      ;  Exit Ended in Failure         
RXEXIT_BADENTRY	EQU	1001      ;  Invalid Entry Conditions      
RXEXIT_NOEMEM	EQU	1002      ;  Insuff stor to complete req   
RXEXIT_BADTYPE	EQU	1003      ;  Bad registration type.        
RXEXIT_NOTINIT	EQU	1004      ;  API system not initialized.   
RXEXIT_OK	EQU	0        ;  Function Complete             
RXEXIT_DUP	EQU	10        ;  Duplicate Exit Name-          
                                      ;  but Registration Completed    
RXEXIT_MAXREG	EQU	20        ;  Cannot register more          
                                      ;  handlers                      
RXEXIT_NOTREG	EQU	30        ;  Name Not Registered           
RXEXIT_NOCANDROP	EQU	40        ;  Name not droppable            
RXEXIT_LOADERR	EQU	50        ;  Could not load function       
RXEXIT_NOPROC	EQU	127        ;  RXEXIT routine - not found    
;  System Exit function and sub-function definitions   
RXENDLST	EQU	0                  ;  End of exit list.             
RXFNC	EQU	2                     ;  Process external functions.   
RXFNCCAL	EQU	1                  ;  subcode value.                
RXCMD	EQU	3                     ;  Process host commands.        
RXCMDHST	EQU	1                  ;  subcode value.                
RXMSQ	EQU	4                     ;  Manipulate queue.             
RXMSQPLL	EQU	1                  ;  Pull a line from queue        
RXMSQPSH	EQU	2                  ;  Place a line on queue         
RXMSQSIZ	EQU	3                  ;  Return num of lines on queue  
RXMSQNAM	EQU	20                 ;  Set active queue name         
RXSIO	EQU	5                     ;  Session I/O.                  
RXSIOSAY	EQU	1                  ;  SAY a line to STDOUT          
RXSIOTRC	EQU	2                  ;  Trace output                  
RXSIOTRD	EQU	3                  ;  Read from char stream         
RXSIODTR	EQU	4                  ;  DEBUG read from char stream   
RXSIOTLL	EQU	5                  ;  Return linelength(N/A OS/2)   
RXHLT	EQU	7                     ;  Halt processing.              
RXHLTCLR	EQU	1                  ;  Clear HALT indicator          
RXHLTTST	EQU	2                  ;  Test HALT indicator           
RXTRC	EQU	8                     ;  Test ext trace indicator.     
RXTRCTST	EQU	1                  ;  subcode value.                
RXINI	EQU	9                     ;  Initialization processing.    
RXINIEXT	EQU	1                  ;  subcode value.                
RXTER	EQU	10                     ;  Termination processing.       
RXTEREXT	EQU	1                  ;  subcode value.                
RXNOOFEXITS	EQU	11                 ;  1 + largest exit number.      
endif ;  INCL_RXSYSEXIT for defines   
;***    Asynchronous Request Interface defines   
ifdef INCL_RXARI
;***    Return Codes from Asynchronous Request interface   
RXARI_OK	EQU	0   ;  Interface completed           
RXARI_NOT_FOUND	EQU	1   ;  Target program not found      
RXARI_PROCESSING_ERROR	EQU	2   ;  Error processing request      
endif ;  INCL_RXARI for defines   
;***    Macro Space Interface defines   
ifdef INCL_RXMACRO
;***    Registration Search Order Flags   
RXMACRO_SEARCH_BEFORE	EQU	1   ;  Beginning of search order    
RXMACRO_SEARCH_AFTER	EQU	2   ;  End of search order          
;***    Return Codes from RxMacroSpace interface   
RXMACRO_OK	EQU	0   ;  Macro interface completed     
RXMACRO_NO_STORAGE	EQU	1   ;  Not Enough Storage Available  
RXMACRO_NOT_FOUND	EQU	2   ;  Requested function not found  
RXMACRO_EXTENSION_REQUIRED	EQU	3   ;  File ext required for save    
RXMACRO_ALREADY_EXISTS	EQU	4   ;  Macro functions exist         
RXMACRO_FILE_ERROR	EQU	5   ;  File I/O error in save/load   
RXMACRO_SIGNATURE_ERROR	EQU	6   ;  Incorrect format for load     
RXMACRO_SOURCE_NOT_FOUND	EQU	7   ;  Requested cannot be found     
RXMACRO_INVALID_POSITION	EQU	8   ;  Invalid search order pos      
RXMACRO_NOT_INIT	EQU	9   ;  API not initialized           
endif ;  INCL_RXMACRO for defines   
;********************************************************************  
;                                                                      
;                             32-bit                                   
;                                                                      
;********************************************************************  
;***    Subcommand Interface   
ifdef INCL_RXSUBCOM
endif ;  INCL_RXSUBCOM   
;***    Shared Variable Pool Interface   
ifdef INCL_RXSHV
endif ;  INCL_RXSHV   
;***    External Function Interface   
ifdef INCL_RXFUNC
endif ;  INCL_RXFUNC   
;***   System Exits   
ifdef INCL_RXSYSEXIT
;***    Subfunction RXFNCCAL - External Function Calls   

RXFNC_FLAGS	STRUC
	fl_fs	DB  ?
RXFNC_FLAGS	ENDS
fl_rxfferr	EQU	01h
fl_rxffnfnd	EQU	02h
fl_rxffsub	EQU	04h

RXFNCCAL_PARM	STRUC
fnc_rxfnc_flags	DB	SIZE RXFNC_FLAGS DUP (?)     ;  function flags               
fnc_rxfnc_name	DB	SIZE PUCHAR DUP (?)       ;  Pointer to function name.    
fnc_rxfnc_namel	DW	?      ;  Length of function name.     
fnc_rxfnc_que	DB	SIZE PUCHAR DUP (?)        ;  Current queue name.          
fnc_rxfnc_quel	DW	?       ;  Length of queue name.        
fnc_rxfnc_argc	DW	?       ;  Number of args in list.      
fnc_rxfnc_argv	DW	?       ;  Pointer to argument list.    
fnc_rxfnc_retc	DB	SIZE RXSTRING DUP (?)       ;  Return value.                
RXFNCCAL_PARM	ENDS
;***    Subfunction RXCMDHST -- Process Host Commands       

RXCMD_FLAGS	STRUC
	fl_fs	DB  ?
RXCMD_FLAGS	ENDS
fl_rxfcfail	EQU	01h
fl_rxfcerr	EQU	02h

RXCMDHST_PARM	STRUC
rx_rxcmd_flags	DB	SIZE RXCMD_FLAGS DUP (?)      ;  error/failure flags          
rx_rxcmd_address	DB	SIZE PUCHAR DUP (?)    ;  Pointer to address name.     
rx_rxcmd_addressl	DW	?   ;  Length of address name.      
rx_rxcmd_dll	DB	SIZE PUCHAR DUP (?)        ;  dll name for command.        
rx_rxcmd_dll_len	DW	?    ;  Length of dll name.          
rx_rxcmd_command	DB	SIZE RXSTRING DUP (?)    ;  The command string.          
rx_rxcmd_retc	DB	SIZE RXSTRING DUP (?)       ;  Pointer to return buffer     
RXCMDHST_PARM	ENDS
;***     Subfunction RXMSQPLL -- Pull Entry from Queue   

RXMSQPLL_PARM	STRUC
pll_rxmsq_retc	DB	SIZE RXSTRING DUP (?)       ;  Pointer to dequeued entry    
                                       ;  buffer.  User allocated.     
RXMSQPLL_PARM	ENDS
;***    Subfunction RXMSQPSH -- Push Entry on Queue   

RXMSQ_FLAGS	STRUC
	fl_fs	DB  ?
RXMSQ_FLAGS	ENDS
fl_rxfmlifo	EQU	01h

RXMSQPSH_PARM	STRUC
psh_rxmsq_flags	DB	SIZE RXMSQ_FLAGS DUP (?)      ;  LIFO/FIFO flag               
psh_rxmsq_value	DB	SIZE RXSTRING DUP (?)      ;  The entry to be pushed.      
RXMSQPSH_PARM	ENDS
;***    Subfunction RXMSQSIZ -- Return the Current Queue Size   

RXMSQSIZ_PARM	STRUC
siz_rxmsq_size	DD	?       ;  Number of Lines in Queue     
RXMSQSIZ_PARM	ENDS
;***    Subfunction RXMSQNAM -- Set Current Queue Name   

RXMSQNAM_PARM	STRUC
nam_rxmsq_name	DB	SIZE RXSTRING DUP (?)       ;  RXSTRING containing          
                                       ;  queue name.                  
RXMSQNAM_PARM	ENDS
;***    Subfunction RXSIOSAY -- Perform SAY Clause   

RXSIOSAY_PARM	STRUC
say_rxsio_string	DB	SIZE RXSTRING DUP (?)     ;  String to display.           
RXSIOSAY_PARM	ENDS
;***    Subfunction RXSIOTRC -- Write Trace Output   

RXSIOTRC_PARM	STRUC
trcparm_rxsio_string	DB	SIZE RXSTRING DUP (?)     ;  Trace line to display.       
RXSIOTRC_PARM	ENDS
;***    Subfunction RXSIOTRD -- Read Input from the Terminal   

RXSIOTRD_PARM	STRUC
trd_rxsiotrd_retc	DB	SIZE RXSTRING DUP (?)    ;  RXSTRING for output.         
RXSIOTRD_PARM	ENDS
;***    Subfunction RXSIODTR -- Read Debug Input from the Terminal   

RXSIODTR_PARM	STRUC
dtr_rxsiodtr_retc	DB	SIZE RXSTRING DUP (?)    ;  RXSTRING for output.         
RXSIODTR_PARM	ENDS
;***    Subfunction RXHSTTST -- Test for HALT Condition   

RXHLT_FLAGS	STRUC
	fl_fs	DW  ?
RXHLT_FLAGS	ENDS
fl_rxfhhalt	EQU	01h

RXHLTTST_PARM	STRUC
tst_rxhlt_flags	DB	SIZE RXHLT_FLAGS DUP (?)            ;  Set if HALT occurred         
RXHLTTST_PARM	ENDS
;***    Subfunction RXTRCTST -- Test for TRACE Condition   

RXTRC_FLAGS	STRUC
	fl_fs	DW  ?
RXTRC_FLAGS	ENDS
fl_rxftrace	EQU	01h

RXTRCTST_PARM	STRUC
tst_rxtrc_flags	DB	SIZE RXTRC_FLAGS DUP (?)            ;  Set to run external trace    
RXTRCTST_PARM	ENDS
endif ;  INCL_RXSYSEXIT   
;***    Asynchronous Request Interface   
ifdef INCL_RXARI
endif ;  INCL_RXARI   
;***    Macro Space Interface   
ifdef INCL_RXMACRO
endif ;  INCL_RXMACRO   
endif ;  REXXSAA_INCLUDED   
