#
# OpenWatcom makefile for the SpamFilter OS/2 REXX library.
#

DLLNAME = rxsf
VERSION = 1.0.1
BINPATH = ..\..\imapd
AUTOR = Andrey Vasilkin
COMMENT = REXX interface for SpamFilter and imapd

# DEBUG = 1

DLLFILE = $(BINPATH)\$(DLLNAME).dll
LNKFILE = $(DLLNAME).lnk

SRCS = rxsf.c utils.c
!ifdef DEBUG
SRCS += debug.c
!endif

OBJS = $(SRCS:.c=.obj)

LIBPATH = ..

CFLAGS = -i=..;$(%WATCOM)\H\OS2;$(%WATCOM)\H; -DVERSION="$(VERSION)"
CFLAGS += -bt=os2 -q -d0 -bd -bm
!ifdef DEBUG
CFLAGS += -DDEBUG_FILE="rxsf.dbg"
COMMENT = $(COMMENT) (debug version)
!endif

.extensions:
.extensions: .lib .dll .obj .c

.c: ..\

$(DLLFILE): infCompiling $(OBJS) $(LNKFILE)
  @echo * Link: $@
  @wlink @$(LNKFILE)

$(LNKFILE):
  @%create $@
  @%append $@ SYSTEM os2v2_dll INITINSTANCE TERMINSTANCE
  @%append $@ NAME $(DLLFILE)
  @%append $@ OPTION MANYAUTODATA
  @for %i in ($(OBJS)) do @%append $@ FILE %i
  @%append $@ OPTION QUIET
  @%append $@ OPTION ELIMINATE
!ifdef %osdir
  @$(%osdir)\KLIBC\BIN\date +"OPTION DESCRIPTION '@$#$(AUTOR):$(VERSION)$#@$#$#1$#$# %F %T      $(%HOSTNAME)::ru:RUS:::@@$(COMMENT)'" >>$^@
!else
  @%append $@ OPTION DESCRIPTION '@$#$(AUTOR):$(VERSION)$#@$#$#1$#$#                          $(%HOSTNAME)::ru:RUS:0::@@$(COMMENT)'
!endif
  @%append $@ LIBPATH $(LIBPATH)
  @for %i in ($(LIBS)) do @%append $@ LIB %i
#  @%append $@ OPTION MAP=$*
  @%append $@ EXPORT RXSFLOADFUNCS             .1 = rxsfLoadFuncs
  @%append $@ EXPORT RXSFDROPFUNCS             .2 = rxsfDropFuncs
  @%append $@ EXPORT RXSFOPEN                  .10 = rxsfOpen
  @%append $@ EXPORT RXSFCLOSE                 .11 = rxsfClose
  @%append $@ EXPORT RXSFSEND                  .12 = rxsfSend
  @%append $@ EXPORT RXSFRECV                  .13 = rxsfRecv
  @%append $@ EXPORT RXSFREQUEST               .14 = rxsfRequest
  @%append $@ OPTION ELIMINATE
  @%append $@ OPTION OSNAME='OS/2 and eComStation'

.c.obj:
  @wcc386 $(CFLAGS) $<

infCompiling: .SYMBOLIC
  @echo * Compiling: $(COMMENT) $(VERSION) ...

clean: .SYMBOLIC
  @echo * Clean: $(DLLNAME)
  @if exist *.obj del *.obj
  @if exist *.err del *.err
  @if exist *.map del *.map
  @if exist $(LNKFILE) del $(LNKFILE)
  @if exist $(DLLFILE) del $(DLLFILE)
