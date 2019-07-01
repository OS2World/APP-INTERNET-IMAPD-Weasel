#
# GCC makefile for the SpamFilter OS/2 REXX library.
#

NAME         = rxsf
VERSION      = 1.0.2
DESCRIPTION  = REXX interface for SpamFilter and imapd
AUTOR        = Andrey Vasilkin

# Uncomment next line to make debug version.
#DEBUGCODE = YES

DLLNAME = ..\..\imapd\$(NAME)
DLLFILE = $(DLLNAME).dll
DEFFILE = $(NAME).def
DBGFILE = $(NAME).dbg

# Sources
SRCS = rxsf.c

# Libraries (-Lpath -lname ...)
LIBS =

CC = @gcc

OBJS = $(SRCS:.c=.o)

CFLAGS = -I. -idirafter /@unixroot/usr/include/os2tk45 -Wall -Wno-pointer-sign

LDFLAGS = $(DEFFILE) -Zdll -Zmtd -Zomf

ifneq ($(PUBLICBUILD),YES)
ifeq ($(DEBUGCODE),YES)
SRCS += debug.c
CFLAGS += -DDEBUG_FILE=\"$(DBGFILE)\"
DESCRIPTION += (debug)
endif
endif

all: $(DLLFILE)

$(DLLFILE): $(OBJS) $(DEFFILE)
	$(CC) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)
	@lxlite /CS "$@" >nul

.c.obj: .AUTODEPEND
	$(CC) $(CFLAGS) -c $<

$(DEFFILE):
	@cmd /c %unixroot%\\usr\\libexec\\bin\\date +"DESCRIPTION '@#$(AUTOR):$(VERSION)#@##1## %F               %HOSTNAME%::::::@@$(DESCRIPTION)'" >$@
	@echo EXPORTS >>$@
	@echo  RXSFLOADFUNCS              = rxsfLoadFuncs >>$@
	@echo  RXSFDROPFUNCS              = rxsfDropFuncs >>$@
	@echo  RXSFOPEN                   = rxsfOpen >>$@
	@echo  RXSFCLOSE                  = rxsfClose >>$@
	@echo  RXSFSEND                   = rxsfSend >>$@
	@echo  RXSFRECV                   = rxsfRecv >>$@
	@echo  RXSFREQUEST                = rxsfRequest >>$@

clean:
	@rm -f $(OBJS) $(DEFFILE) $(DBGFILE) $(DLLFILE)
