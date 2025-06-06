# =========================================================================
# WIN32.MAK - Win32 application master NMAKE definitions file for the
#               Microsoft Win32 SDK for Windows programming samples
# -------------------------------------------------------------------------
# This files should be included at the top of all MAKEFILEs as follows:
#  !include <win32.mak>
# -------------------------------------------------------------------------
#
# Define APPVER = [ 3.51 | 4.0 ] prior to including win32.mak to get
#  build time checking for version dependencies and to mark the executable
#  with version information.
#
# Define TARGETOS = [ WIN95 | WINNT | BOTH ] prior to including win32.mak
#  to get some build time checking for platform dependencies.
#
# Define TARGETLANG = [ LANG_JAPANESE ] prior to including win32.mak to get
#  compile & link flags for building applications to run on Japanese Windows.
#  (This is an optional parameter.  The system locale is the default.)
#
# -------------------------------------------------------------------------
# NMAKE Options
#
# Use the table below to determine the additional options for NMAKE to
# generate various application debugging, profiling and performance tuning
# information.
#
# Application Information Type         Invoke NMAKE
# ----------------------------         ------------
# For No Debugging Info                nmake nodebug=1
# For Working Set Tuner Info           nmake tune=1
# For Call Attributed Profiling Info   nmake profile=1
#
# Note: The three options above are mutually exclusive (you may use only
#       one to compile/link the application).
#
# Note: creating the environment variables NODEBUG, TUNE, and PROFILE is an
#       alternate method to setting these options via the nmake command line.
#
# Additional NMAKE Options             Invoke NMAKE
# ----------------------------         ------------
# For No ANSI NULL Compliance          nmake no_ansi=1
# (ANSI NULL is defined as PVOID 0)
#
# =========================================================================

!IFNDEF _WIN32_MAK_
_WIN32_MAK_ = 1

# -------------------------------------------------------------------------
# Get CPU Type - exit if CPU environment variable is not defined
# -------------------------------------------------------------------------

!IF "$(CPU)" == ""
CPU = i386
!ENDIF

!IF "$(CPU)" != "i386"
!IF "$(CPU)" != "MIPS"
!IF "$(CPU)" != "ALPHA"
!IF "$(CPU)" != "PPC"
!ERROR  Must specify CPU environment variable ( CPU=i386, CPU=MIPS, CPU=ALPHA, CPU=PPC)
!ENDIF
!ENDIF
!ENDIF
!ENDIF


# -------------------------------------------------------------------------
# Get Target Operating System - Default to WINNT
# -------------------------------------------------------------------------
!IFNDEF TARGETOS
TARGETOS = WINNT
!ENDIF

!IF "$(TARGETOS)" != "WINNT"
!IF "$(TARGETOS)" != "WIN95"
!IF "$(TARGETOS)" != "BOTH"
!ERROR Must specify TARGETOS environment variable (BOTH, WIN95, WINNT)
!ENDIF
!ENDIF
!ENDIF


!IFNDEF APPVER
APPVER = 4.0
!ENDIF

!IF "$(APPVER)" != "4.0"
!IF "$(APPVER)" != "3.51"
!ERROR Must specify APPVER environment variable (3.51, 4.0)
!ENDIF
!ENDIF

# binary declarations common to all platforms
cc     = cl
rc     = rc
link   = link
implib = lib
hc     = hcrtf -xn

# for compatibility with older-style makefiles
cvtobj = REM !!! CVTOBJ is no longer necessary - please remove !!!
cvtres = REM !!! CVTRES is no longer necessary - please remove !!!


# -------------------------------------------------------------------------
# Platform Dependent Compile Flags - must be specified after $(cc)
#
# Note: Debug switches are on by default for current release
#
# These switches allow for source level debugging with WinDebug for local
# and global variables.
#
# Both compilers now use the same front end - you must still define either
# _X86_, _MIPS_, _PPC_ or _ALPHA_.  These have replaced the i386, MIPS, and ALPHA
# definitions which are not ANSI compliant.
#
# Common compiler flags:
#   -c   - compile without linking
#   -W3  - Set warning level to level 3
#   -Zi  - generate debugging information
#   -Od  - disable all optimizations
#   -Ox  - use maximum optimizations
#   -Zd  - generate only public symbols and line numbers for debugging
#
# i386 specific compiler flags:
#   -Gz  - stdcall
#
# -------------------------------------------------------------------------

# declarations common to all compiler options
ccommon = -c -W3 -DCRTAPI1=_cdecl -DCRTAPI2=_cdecl -nologo

# for compatibility with old source code, map {try, except, leave, finally}
# to their proper names (i.e. prefaced by "__")
!IFDEF SEHMAP
ccommon = $(ccommon) -FIsehmap.h
!ENDIF

!IF "$(TARGETLANG)" == "LANG_JAPANESE"
ccommon = $(ccommon) -DJAPAN -DDBCS -DFE_IME
!ENDIF

!IF "$(TARGETLANG)" == "LANG_CHINESE"
ccommon = $(ccommon) -DDBCS -DFE_IME
!ENDIF

!IF "$(TARGETLANG)" == "LANG_KOREAN"
ccommon = $(ccommon) -DDBCS -DFE_IME
!ENDIF



!IF "$(CPU)" == "i386"
cflags = $(ccommon) -D_X86_=1
scall  = -Gz
!ELSE
!IF "$(CPU)" == "MIPS"
cflags = $(ccommon) -D_MIPS_=1
!ELSE
!IF "$(CPU)" == "PPC"
cflags = $(ccommon) -D_PPC_=1
!ELSE
!IF "$(CPU)" == "ALPHA"
cflags = $(ccommon) -D_ALPHA_=1
!ENDIF
!ENDIF
!ENDIF
scall  =
!ENDIF

!IF "$(TARGETOS)" == "WINNT"
cflags = $(cflags) -D_WINNT -D_WIN32_WINNT=0x0400
!ELSE
!IF "$(TARGETOS)" == "WIN95"
cflags = $(cflags) -D_WIN95 -D_WIN32_WINDOWS=0x0400
!ENDIF
!ENDIF

# For this release, for all values of APPVER, WINVER is 0x0400
cflags = $(cflags) -DWINVER=0x0400


!IFDEF NODEBUG
cdebug = -Ox
!ELSE
!IFDEF PROFILE
cdebug = -Gh -Zd -Ox
!ELSE
!IFDEF TUNE
cdebug = -Gh -Zd -Ox
!ELSE
cdebug = -Z7 -Od
!ENDIF
!ENDIF
!ENDIF

# -------------------------------------------------------------------------
# Target Module & Subsystem Dependent Compile Defined Variables - must be
#   specified after $(cc)
#
# The following table indicates the various acceptable combinations of
# the C Run-Time libraries LIBC, LIBCMT, and CRTDLL respect to the creation
# of a EXE and/or DLL target object.  The appropriate compiler flag macros
# that should be used for each combination are also listed.
#
#  Link EXE    Create Exe    Link DLL    Create DLL
#    with        Using         with         Using
# ----------------------------------------------------
#  LIBC        CVARS          None        None      *
#  LIBC        CVARS          LIBC        CVARS
#  LIBC        CVARS          LIBCMT      CVARSMT
#  LIBCMT      CVARSMT        None        None      *
#  LIBCMT      CVARSMT        LIBC        CVARS
#  LIBCMT      CVARSMT        LIBCMT      CVARSMT
#  CRTDLL      CVARSDLL       None        None      *
#  CRTDLL      CVARSDLL       LIBC        CVARS
#  CRTDLL      CVARSDLL       LIBCMT      CVARSMT
#  CRTDLL      CVARSDLL       CRTDLL      CVARSDLL  *
#
# * - Denotes the Recommended Configuration
#
# When building single-threaded applications you can link your executable
# with either LIBC, LIBCMT, or CRTDLL, although LIBC will provide the best
# performance.
#
# When building multi-threaded applications, either LIBCMT or CRTDLL can
# be used as the C-Runtime library, as both are multi-thread safe.
#
# Note: Any executable which accesses a DLL linked with CRTDLL.LIB must
#       also link with CRTDLL.LIB instead of LIBC.LIB or LIBCMT.LIB.
#       When using DLLs, it is recommended that all of the modules be
#       linked with CRTDLL.LIB.
#
# Note: The macros of the form xDLL are used when linking the object with
#       the DLL version of the C Run-Time (that is, CRTDLL.LIB).  They are
#       not used when the target object is itself a DLL.
#
# -------------------------------------------------------------------------

!IFDEF NO_ANSI
noansi = -DNULL=0
!ENDIF

# for Windows applications that use the C Run-Time libraries
cvars      = -DWIN32 $(noansi) -D_WIN32
cvarsmt    = $(cvars) -D_MT -MT
cvarsdll   = $(cvars) -D_MT -D_DLL -MD

# for compatibility with older-style makefiles
cvarsmtdll   = $(cvarsmt) -D_DLL

# for POSIX applications
psxvars    = -D_POSIX_

# resource compiler
rcflags = /r
rcvars = -DWIN32 -D_WIN32 -DWINVER=0x0400 $(noansi)

!IF "$(TARGETLANG)" == "LANG_JAPANESE"
rcflags = $(rcflags) /c932
rcvars = $(rcvars) -DJAPAN -DDBCS -DFE_IME
!ENDIF

!IF "$(TARGETLANG)" == "LANG_CHINESE"
rcvars = $(rcvars) -DDBCS -DFE_IME
!ENDIF

!IF "$(TARGETLANG)" == "LANG_KOREAN"
rcvars = $(rcvars) -DDBCS -DFE_IME
!ENDIF



# -------------------------------------------------------------------------
# Platform Dependent Link Flags - must be specified after $(link)
#
# Note: $(DLLENTRY) should be appended to each -entry: flag on the link
#       line.
#
# Note: When creating a DLL that uses C Run-Time functions it is
#       recommended to include the entry point function of the name DllMain
#       in the DLL's source code.  Also, the MAKEFILE should include the
#       -entry:_DllMainCRTStartup$(DLLENTRY) option for the creation of
#       this DLL.  (The C Run-Time entry point _DllMainCRTStartup in turn
#       calls the DLL defined DllMain entry point.)
#
# -------------------------------------------------------------------------

# declarations common to all linker options
lflags  = /NODEFAULTLIB /INCREMENTAL:NO /PDB:NONE /RELEASE /NOLOGO -nowref

# declarations for use on Intel i386, i486, and Pentium systems
!IF "$(CPU)" == "i386"
DLLENTRY = @12
!ENDIF

# declarations for use on self hosted MIPS R4x000 systems
!IF "$(CPU)" == "MIPS"
DLLENTRY =
!ENDIF

# declarations for use on self hosted PowerPC systems
!IF "$(CPU)" == "PPC"
DLLENTRY =
!ENDIF

# declarations for use on self hosted Digital Alpha AXP systems
!IF "$(CPU)" == "ALPHA"
DLLENTRY =
!ENDIF

# -------------------------------------------------------------------------
# Target Module Dependent Link Debug Flags - must be specified after $(link)
#
# These switches allow the inclusion of the necessary symbolic information
# for source level debugging with WinDebug, profiling and/or performance
# tuning.
#
# Note: Debug switches are on by default.
# -------------------------------------------------------------------------

!IFDEF NODEBUG
ldebug = /RELEASE
!ELSE
!IFDEF PROFILE
ldebug = -debug:mapped,partial -debugtype:coff
!ELSE
!IFDEF TUNE
ldebug = -debug:mapped,partial -debugtype:coff
!ELSE
ldebug = -debug:full -debugtype:cv
!ENDIF
!ENDIF
!ENDIF

#Watcom switch for wmain()
ldebug = $(ldebug) -nowref
# for compatibility with older-style makefiles
linkdebug = $(ldebug)

# -------------------------------------------------------------------------
# Subsystem Dependent Link Flags - must be specified after $(link)
#
# These switches allow for source level debugging with WinDebug for local
# and global variables.  They also provide the standard application type and
# entry point declarations.
#
# Note that on x86 screensavers have a WinMain entrypoint, but on RISC
# platforms it is main.  This is a Win95 compatibility issue.
#
# -------------------------------------------------------------------------

# for Windows applications that use the C Run-Time libraries
conlflags = $(lflags) -subsystem:console,$(APPVER)
guilflags = $(lflags) -subsystem:windows,$(APPVER)
dlllflags = $(lflags) -entry:_DllMainCRTStartup$(DLLENTRY) -dll

savlflags = $(lflags) -entry:mainCRTStartup

# for POSIX applications
psxlflags = $(lflags) -subsystem:posix -entry:__PosixProcessStartup

# for compatibility with older-style makefiles
conflags  = $(conlflags)
guiflags  = $(guilflags)
psxflags  = $(psxlflags)

# -------------------------------------------------------------------------
# C Run-Time Target Module Dependent Link Libraries
#
# Below is a table which describes which libraries to use depending on the
# target module type, although the table specifically refers to Graphical
# User Interface apps, the exact same dependencies apply to Console apps.
# That is, you could replace all occurrences of 'GUI' with 'CON' in the
# following:
#
# Desired CRT  Libraries   Desired CRT  Libraries
#   Library     to link      Library     to link
#   for EXE     with EXE     for DLL     with DLL
# ----------------------------------------------------
#   LIBC       GUILIBS       None       None       *
#   LIBC       GUILIBS       LIBC       GUILIBS
#   LIBC       GUILIBS       LIBCMT     GUILIBSMT
#   LIBCMT     GUILIBSMT     None       None       *
#   LIBCMT     GUILIBSMT     LIBC       GUILIBS
#   LIBCMT     GUILIBSMT     LIBCMT     GUILIBSMT
#   CRTDLL     GUILIBSDLL    None       None       *
#   CRTDLL     GUILIBSDLL    LIBC       GUILIBS
#   CRTDLL     GUILIBSDLL    LIBCMT     GUILIBSMT
#   CRTDLL     GUILIBSDLL    CRTDLL     GUILIBSDLL *
#
# * - Recommended Configurations.
#
# Note: Any executable which accesses a DLL linked with CRTDLL.LIB must
#       also link with CRTDLL.LIB instead of LIBC.LIB or LIBCMT.LIB.
#
# Note: For POSIX applications, link with $(psxlibs).
#
# -------------------------------------------------------------------------

# These CRT Libraries assume the use of Microsoft Visual C++.  If you are
# using another Compiler product, change the libc* variable to correspond
# to your import library names.

libc = 
libcmt = 
libcdll = 

# for POSIX applications
psxlibs    = psxdll.lib psxrtl.lib 


# optional profiling and tuning libraries
!IFDEF PROFILE
optlibs =  cap.lib
!ELSE
!IFDEF TUNE
optlibs = wst.lib
!ELSE
optlibs =
!ENDIF
!ENDIF

# if building for Windows NT 4 or greater, switch over to WinSock2
!IF "$(TARGETOS)" == "WINNT"
!IF "$(APPVER)" != "3.51"
winsocklibs = ws2_32.lib mswsock.lib
!ELSE
winsocklibs = wsock32.lib
!ENDIF
!ELSE
winsocklibs = wsock32.lib
!ENDIF


# basic subsystem specific libraries, less the C Run-Time
baselibs   = kernel32.lib $(optlibs) $(winsocklibs) advapi32.lib
winlibs    = $(baselibs) user32.lib gdi32.lib comdlg32.lib winspool.lib

# for Windows applications that use the C Run-Time libraries
conlibs    = $(libc) $(baselibs)
conlibsmt  = $(libcmt) $(baselibs)
conlibsdll = $(libcdll) $(baselibs)
guilibs    = $(libc) $(winlibs)
guilibsmt  = $(libcmt) $(winlibs)
guilibsdll = $(libcdll) $(winlibs)

# for OLE applications
olelibs      = ole32.lib uuid.lib oleaut32.lib $(guilibs)
olelibsmt    = ole32.lib uuid.lib oleaut32.lib $(guilibsmt)
olelibsdll   = ole32.lib uuid.lib oleaut32.lib $(guilibsdll)

# for backward compatibility
ole2libs    = $(olelibs)
ole2libsmt  = $(olelibsmt)
ole2libsdll = $(olelibsdll)

#ENDIF _WIN32_MAK_
!ENDIF 
