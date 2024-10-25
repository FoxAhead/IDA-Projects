ifdef __IBMC__
ifndef __CHKHDR__
endif
endif
ifndef __OS2_H__
__OS2_H__	EQU	1

OS2_INCLUDED	EQU	1

INCLUDE os2def.INC
ifndef INCL_NOBASEAPI
INCLUDE bse.INC
endif 
ifndef INCL_NOPMAPI
INCLUDE pm.INC
endif 
endif 
ifdef __IBMC__
ifndef __CHKHDR__
endif
endif
