
                   IMAP4 server for the Weasel mail server.


This is an IMAPD server designed to run in conjunction with the Weasel mail
server.


  Contents
  --------

  1. Installation
  2. Using disk quotas
  3. POP3 service
  4. Encrypted connections
  5. Clients authentication
  6. Command-line options
  7. Local control protocol


1. Installation
---------------

1. Install the following packages needed by IMAPD using either YUM or ANPM:

   libc libgcc1 libxml2 openssl

   If you use YUM, simply type `yum install <package_list>` on the command line
   and press Enter. For ANPM, select "YUM -> Quick install..." from the menu,
   copy the given package list into the entry field and press Enter. The
   packages and all their dependencies will be downloaded and installed
   automatically. Note that if some of these packages are already installed,
   the install command will simply do nothing for them.

2. Copy imapd.exe into the same directory as Weasel. Alternatively, put it into
   any other directory and point Weasel directory (where weasel.ini placed)
   with -p command-line switch.

   You enable IMAP operation by running imapd.exe at the same time that
   weasel.exe is running. Note that you will also have to run the Weasel
   Setup program to tune on IMAP4 and define which users are allowed to use
   IMAP. Default "Max users" value (10) on the IMAP page of Weasel Setup is too
   small. Many IMAP4 clients use multiple simultaneous connections. Increase
   this value to a few hundred or type 0 (unlimited).
   Log record "Maximum connection limit reached (N)" point to the need to
   increase "Max users" value.

3. This step is optional but strongly recommended.

   To fast-tracking incoming messages IMAPD will try to read Weasel detailed
   log from the pipe. Go to Logging page of Weasel Setup and check option
   "pipe". If this pipe is already being used in your system (Weasel supports
   only one connection) you can prevent connection to the Weasel log pipe with
   command-line switch -w Off.

   In order to enable the IMAPD to fast-tracking incoming messages without
   Weasel log pipe the stage 4 filter are used:

   - Copy files imapStage4.cmd and rxsf.dll to your Weasel directory. If you
     use SpamFilter and already have rxsf.dll you can safely replace this file
     with version from the archive.

   - If you use any stage 4 filter (for example MyFilter.cmd):
     open imapStage4.cmd and replace line 
       userFilter = ""
     with
       userFilter = "MyFilter.cmd"

   - Type "imapStage4.cmd" (without the quotation marks) in the
     "Filter 4: after receiving message body" field on the Filters page of
     Weasel Setup.

   Both information sources may be used simultaneously (and it is a good idea).
   In this case notifications from the filter will be rejected while log pipe
   is connected.


IMAPD creates subdirectories "imap" in Weasel user directories. Do not change
contents of these subdirectories outside IMAPD!


2. Using disk quotas
--------------------

IMAPD allows you to control the size of the disk space used to store messages.
This is done using a list of size limits for mail storage, domains and users.

First, you need to install the stage 4 filter script to Weasel even if you plan
to use Weasel log pipe. See "Installation", step 3. Copy file imapd-quotas.xml
into the same directory as Weasel. Follow the comments in imapd-quotas.xml file
to change the defaults, make sure to set value "1" for node "enable" under the
root node.

IMAPD will check imapd-quotas.xml file for updates. It will reload limits
configuration if changes are detected.

Note: Quotas controls only *.MSG files. Quotas do not controls content of the
      forward directory.


3. POP3 service
---------------

It is recommend using build-in POP3 service which allows IMAPD to be quickly
noticed about changes in mailboxes, thus makes it possible to promptly
identify mail storage sizes for disk quotas. Users who use imap4 protocol
can receive instant notifications about deleting messages. A new POP3 service
provides the Secure Socket Layer (SSL and STLS) support. See section
"Command-line options" below, switch -P.


4. Encrypted connections
------------------------

To enable encrypted connections you must have private key and certificate.
See command-line switches -C and -K to specify the appropriate certificate and
key files (default is imapd.crt and imapd.key).

You can create server self-signed certificate/key (self signed, DONT ADD
PASSWORD) with openssl utility:

  >openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout imapd.key
           -out imapd.crt


5. Clients authentication
-------------------------

By default plain-text authentication is disabled on unencrypted connections,
client must use TLS encryption before authenticating or use encrypted login.
You can use command-line switch -e to enable plain-text authentication on
unencrypted connections. It is not recommended to use switch -e on real mail
servers.

Note that if the remote IP is 127.0.0.1 (i.e. the loopback address), the
connection is considered secure and plain-text authentication is allowed.

The form user@domain (or user%domain) may be used for username. That is, the
login name includes a specification of which domain that user is logging into. 


6. Command-line options
-----------------------

  -b  Bind specified address and port to an IMAP4 server.

      For example:

        *             - listen on all addresses and default port 143 for IMAP4
                        or port 110 for POP3.
        192.168.1.1   - listen on the specified address and default port 143
                        for IMAP or port 110 for POP3.
        *:1143        - listen on all addresses and port 1143.
        ssl           - SSL connections on all addresses and default port 993
                        for IMAP4 or 995 for POP3.
        ssl,any:1993  - SSL connections on all addresses and port 1993.

      You can specify the switch -b multiple times.
      By default, the configured value will be used.

  -e  Allow plain-text authentication on unencrypted connections.
      By default plain-text authentication is disabled unless TLS is used.
      Note that if the remote IP is 127.0.0.1 (i.e. the loopback address), the
      connection is considered secure and plain-text authentication is allowed.

  -i  Read configuration data from WEASEL.INI (ignore the default rules) (*).

  -l  Logfile properties: "level[,N[,size]]", where:

        level          - Minimal lightweight logging (0..6).
        N              - Number of logfile rotations to make, 0 means no
                         rotations. When size is 0 or omitted it means how many
                         days to keep history logfiles.
        size[Kb/Mb/Gb] - Maximum size of the logfile. If 0 is specified and
                         N is not 0 then files will be renamed every day as
                           FILENAME-yyyymmdd.EXT,
                         where FILENAME - configured log file name,
                         yyyy - year, mm - month, dd - day of month and EXT -
                         configured log file extension.

      Default is "5,0,0".

  -p  Path to the Weasel directory.
      Default is current directory.

  -s  Send signal to the runned IMAPD and exit.

      List of signals:

      SHUTDOWN      - Disconnect all clients, store state of mailboxes and
                      exit.
      UPDATED       - Reload Weasel configuration if file date/time was changed.
                      IMAPD generates this signal for itself periodically.
      ROTATE        - Logfiles rotation.
      QUOTASUPDATED - Reload mail storage size limits from imapd-quotas.xml if
                      file date/time was changed.
                      IMAPD generates this signal for itself periodically.

  -t  Read configuration data from WEASEL.TNI (ignore the default rules) (*).

  -w  Read Weasel detailed log from pipe to fast-tracking incoming messages.

        Off    or O  - Do not connect to the pipe.
        Quiet  or Q  - Connect to the pipe.
        Screen or S  - Connect to the pipe and print all output to the screen.

      Default is Quiet (read Weasel log from the pipe without screen output).

  -C  Certificate file.
      Default is imapd-cert.pem.

  -K  Private key file.
      Default is imapd-key.pem.

  -P  Start POP3 server. The following parameters b,e,C,K,T will apply to POP3
      server.

  -T  Normal and maximum number of threads to process requests.
      Default is "4,16".

(*) Refer to the Weasel documentation for more information about the default
    rules: "Configuration" / "Weasel.INI or Weasel.TNI?"

Example 1:

  - Listen IMAP4 and POP3 connections on configured in Weasel setup ports (all
    available interfaces).
  - Log level is 4, keep 10 files, when the file size will reach 5 Mb it will
    be renamed.

  >imapd.exe -l 4,10,5Mb -P

Example 2:

  - Listen IMAP4 connections on all local interfaces, default port 143, default
    SSL port 993 and port 1143.
  - Listen POP3 connections on all local interfaces, default port 110 and
    default SSL port 995.
  - Use SSL private key from key.pem file and SSL certificate from cert.pem
    file for both servers.
  - Log level is 6, rename files every day, keep logs for 30 days.

  >imapd.exe -K key.pem -C cert.pem -l 6,30,0 -b * -b ssl -b any:1143 -P -b*
             -bssl -K key.pem -C cert.pem


7. Local control protocol
-------------------------

Local named socket \socket\imapd can be used to control runned IMAPD.
IMAPD uses a lightweight protocol very similar to POP3:

  Commands in consist of a case-insensitive keyword, possibly followed by one
  or more arguments. All commands are terminated by a CRLF pair. Keywords and
  arguments are each separated by a single SPACE character.

  Responses consist of a status indicator followed by additional information.
  All responses are terminated by a CRLF pair. There are two status indicators:
  positive ("+OK") and negative ("-ERR").

  Responses to certain commands are multi-line. In these cases after sending
  the first line of the response and a CRLF, any additional lines (responce
  body) are sent, each terminated by a CRLF pair. When all lines of the
  response have been sent, a final line is sent, consisting of a termination
  octet (decimal code 046, ".") and a CRLF pair.

Refer to examples in .\examples to see how the protocol is used in REXX.
Full commands list for the control protocol:

  NOTIFY delay pathname

    delay    - delay in seconds to process the notificaton (0..9),
    pathname - user home directory or .MSG file full name.

  Informs IMAPD about changes in the user home directory (INBOX), appearance or
  deletion of a .MSG file.


  NWPNOTIFY delay pathname

    delay    - delay in seconds to process the notificaton (0..9),
    pathname - user home directory or .MSG file full name.

  Same as NOTIFY but it will be rejected if the Weasel log pipe currently is
  connected.


  QUERYSTORAGE

  Returns responce with body (POP3 protocol style) - information about all
  storage sizes.


  QUERYSIZE path

    path - user home directory.

  Responce: +OK [MainRootSize DomainSize InboxSize FoldersSize]
  Each "size" item - the total size of ".MSG" files in bytes, slash, limit in
  bytes or "unlimited".


  QUERYFS

  Returns responce with body (POP3 protocol style) - information about open
  user home objects and sessions.
  

  CHKAVAILSPACE object size [notify_to]

     object    - local user email OR full pathname to user home directory OR
                 path relative MailRoot,
     size      - number of bytes/Kb/Mb to add in user home directory,
     notify_to - e-mail, who should be notified by message when limit for
                 object is reached (i.e. (current size + given size) > limit).

  Disk quota check. Possible pesponces:
     +OK no error
     -ERR internal error
     -ERR not found
     -ERR excess

  It will not returns "-ERR excess" if user non-blocked (see imapd-quotas.xml)
  when the limit is exceeded.


  CHKAVAILSIZE object new_msg [notify_to]

     object    - local user email OR full pathname to user home directory OR
                 path relative MailRoot,
     new_msg   - received message file,
     notify_to - e-mail, who should be notified by message (sender of new_msg).

  Same as CHKAVAILSPACE but for size of existing file new_msg.


---
Donations are most welcome!
https://www.arcanoae.com/shop/os2-ports-and-applications-by-andrey-vasilkin/
PayPal: digi@os2.snc.ru

Andrey Vasilkin, 2017
E-mail: digi@os2.snc.ru
