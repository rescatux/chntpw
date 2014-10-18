#
# Makefile for the Offline NT Password Editor
#
#
# Change here to point to the needed OpenSSL libraries & .h files
# See INSTALL for more info.
#

#SSLPATH=/usr/local/ssl
OSSLPATH=/usr
OSSLINC=$(OSSLPATH)/include

CC=gcc

# Force 32 bit
CFLAGS= -DUSEOPENSSL -g -I. -I$(OSSLINC) -Wall -m32 
OSSLLIB=$(OSSLPATH)/lib

# 64 bit if default for compiler setup
#CFLAGS= -DUSEOPENSSL -g -I. -I$(OSSLINC) -Wall
#OSSLLIB=$(OSSLPATH)/lib64


# This is to link with whatever we have, SSL crypto lib we put in static
#LIBS=-L$(OSSLLIB) $(OSSLLIB)/libcrypto.a
LIBS=-L$(OSSLLIB)


all: chntpw chntpw.static cpnt reged reged.static samusrgrp samusrgrp.static sampasswd sampasswd.static

chntpw: chntpw.o ntreg.o edlib.o libsam.o
	$(CC) $(CFLAGS) -o chntpw chntpw.o ntreg.o edlib.o libsam.o $(LIBS)

chntpw.static: chntpw.o ntreg.o edlib.o libsam.o
	$(CC) -static $(CFLAGS) -o chntpw.static chntpw.o ntreg.o edlib.o libsam.o $(LIBS)

cpnt: cpnt.o
	$(CC) $(CFLAGS) -o cpnt cpnt.o $(LIBS)

reged: reged.o ntreg.o edlib.o
	$(CC) $(CFLAGS) -o reged reged.o ntreg.o edlib.o

reged.static: reged.o ntreg.o edlib.o
	$(CC) -static $(CFLAGS) -o reged.static reged.o ntreg.o edlib.o

samusrgrp.static: samusrgrp.o ntreg.o libsam.o
	$(CC) -static $(CFLAGS) -o samusrgrp.static samusrgrp.o ntreg.o libsam.o 

samusrgrp: samusrgrp.o ntreg.o libsam.o
	$(CC) $(CFLAGS) -o samusrgrp samusrgrp.o ntreg.o libsam.o 

sampasswd: sampasswd.o ntreg.o libsam.o
	$(CC) $(CFLAGS) -o sampasswd sampasswd.o ntreg.o libsam.o 

sampasswd.static: sampasswd.o ntreg.o libsam.o
	$(CC) -static $(CFLAGS) -o sampasswd.static sampasswd.o ntreg.o libsam.o 



#ts: ts.o ntreg.o
#	$(CC) $(CFLAGS) -nostdlib -o ts ts.o ntreg.o $(LIBS)

# -Wl,-t

.c.o:
	$(CC) -c $(CFLAGS) $<

clean:
	rm -f *.o chntpw chntpw.static cpnt reged reged.static samusrgrp samusrgrp.static sampasswd sampasswd.static *~

