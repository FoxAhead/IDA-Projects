PROJ	=VSA_DEMO
DEBUG	=0
CC	=qcl
AS	=qcl
CFLAGS_G	= /AL /W1 /Ze 
CFLAGS_D	= /Zd /Od 
CFLAGS_R	= /O /Ol /DNDEBUG 
CFLAGS	=$(CFLAGS_G) $(CFLAGS_R)
AFLAGS_G	= /Cx /W1 /P1 
AFLAGS_D	= /Zi 
AFLAGS_R	= /DNDEBUG 
AFLAGS	=$(AFLAGS_G) $(AFLAGS_R)
LFLAGS_G	= /CP:0xfff /NOI /SE:0x80 /ST:0x2710 
LFLAGS_D	= 
LFLAGS_R	= 
LFLAGS	=$(LFLAGS_G) $(LFLAGS_R)
RUNFLAGS	=
OBJS_EXT = 	
LIBS_EXT = 	vsa256ms.lib 

.asm.obj: ; $(AS) $(AFLAGS) -c $*.asm

all:	$(PROJ).EXE

vsa_demo.obj:	vsa_demo.c $(H)

$(PROJ).EXE:	vsa_demo.obj $(OBJS_EXT)
	echo >NUL @<<$(PROJ).crf
vsa_demo.obj +
$(OBJS_EXT)
$(PROJ).EXE

$(LIBS_EXT);
<<
	qlink $(LFLAGS) @$(PROJ).crf

run: $(PROJ).EXE
	$(PROJ) $(RUNFLAGS)

