#
# Makefile for the Offline NT Password Editor
#
#

CC=gcc

# Force 32 bit
CFLAGS= -DUSELIBGCRYPT -I. $(shell libgcrypt-config --cflags) -Wall -m32
OSSLLIB=$(OSSLPATH)/lib

LIBS=$(shell libgcrypt-config --libs)


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

