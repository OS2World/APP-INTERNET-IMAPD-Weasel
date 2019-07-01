#
# GCC makefile
#

NAME         = imapd
VERSION      = 0.1.13
DESCRIPTION  = IMAP4 service for the Weasel mail server
AUTOR        = Andrey Vasilkin

# Uncomment next line to make debug version.
#DEBUGCODE = YES

EXEFILE = ..\imapd\$(NAME).exe
DEFFILE = $(NAME).def
DBGFILE = $(NAME).dbg

# Sources
SRCS = context.c imap.c imapfs.c main.c message.c netserv.c utils.c xmlutils.c \
       wcfg.c cmdsearch.c log.c inifiles.c ctlproto.c piper.c storage.c pop3.c \
       control.c ctlpipe.c

# Libraries (-Lpath -lname ...)
LIBS = -L./lib -llibxml2 -llibcrypto -llibssl -L./libgiconv -l libgiconv

CC = @gcc

OBJS = $(SRCS:.c=.o)

CFLAGS = -I. -I./libgiconv -I /@unixroot/usr/include/libxml2 \
         -march=pentium -msse -O3 -pipe -Wall -Wno-pointer-sign \
         -DVERSION="\"$(VERSION)\""

LDFLAGS = $(DEFFILE) -Zhigh-mem -Zmap

ifneq ($(PUBLICBUILD),YES)
ifeq ($(DEBUGCODE),YES)
SRCS += debug.c
CFLAGS += -DDEBUG_FILE=\"$(DBGFILE)\"
DESCRIPTION += (debug)
endif
endif

all: $(EXEFILE)

$(EXEFILE): $(OBJS) $(DEFFILE)
	$(CC) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)
ifneq ($(DEBUGCODE),YES)
	@lxlite /CS "$@" >nul
endif
	@mapxqs.exe -o $*.xqs $*.map

.c.obj: .AUTODEPEND
	$(CC) $(CFLAGS) -c $<

$(DEFFILE):
	@cmd /c %unixroot%\\usr\\libexec\\bin\\date +"DESCRIPTION '@#$(AUTOR):$(VERSION)#@##1## %F               %HOSTNAME%::::::@@$(DESCRIPTION)'" >>$@

clean:
	@rm -f $(OBJS) $(DEFFILE) $(DBGFILE) $(EXEFILE) ..\imapd\$(NAME).map ..\imapd\$(NAME).xqs
