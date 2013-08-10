/*
 * reged.c - Simple Registry Edit Utility for Windows registry hives.
 *
 * Frontend command line utility which uses registry library to:
 * - Export (parts) of registry hive to .reg file
 * - Import .reg file into registry hive
 * - Do interactive registry edit
 * 
 * Changes:
 * 2011 - may: Trace flags moved here.
 * 2011 - apr: Added options for import and flags for safe modes..
 * 
 *
 *****
 *
 * Copyright (c) 1997-2010 Petter Nordahl-Hagen.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * See file GPL.txt for the full license.
 * 
 *****
 */


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>


#include "ntreg.h"


const char reged_version[] = "reged version 0.1 110511, (c) Petter N Hagen";


/* Global verbosity flag */
int gverbose = 0;

/* Array of loaded hives */
#define MAX_HIVES 10
struct hive *hive[MAX_HIVES+1];
int no_hives = 0;


void usage(void)
{
  printf("\nModes:\n"
         "-x <registryhivefile> <prefixstring> <key> <output.reg>\n"
	 "   Xport. Where <prefixstring> for example is HKEY_LOCAL_MACHINE\\SOFTWARE\n"
	 "   <key> is key to dump (recursively), \\ or \\\\ means all keys in hive\n"
	 "   Only one .reg and one hive file supported at the same time\n"
	 "-I <registryhivefile> <prefixstring> <input.reg>\n"
	 "   Import from .reg file. Where <prefixstring> for example is HKEY_LOCAL_MACHINE\\SOFTWARE\n"
	 "   Only one .reg and one hive file supported at the same time\n"
	 "-e <registryhive> ...\n"
	 "   Interactive edit one or more of registry files\n\n"
	 "Options:\n"
	 "-L : Log changed filenames to /tmp/changed, also auto-saves\n"
	 "-C : Auto-save (commit) changed hives without asking\n"
	 "-N : No allocate mode, only allow edit of existing values with same size\n"
	 "-E : No expand mode, do not expand hive file (safe mode)\n"
	 "-t : Debug trace of allocated blocks\n"
	 "-v : Some more verbose messages\n"
	 );
}


int main(int argc, char **argv)
{
   
  int export = 0, edit = 0, import = 0;
  int d = 0;
  int autocommit = 0, update = 0;
  int logchange = 0, mode = 0, dd = 0;
  int il;
  extern int optind;
  extern char* optarg;
  char *hivename, *prefix, *key, *outputname, *inputname;
  char c;
  char yn[10];
  FILE *ch;
  
  char *options = "vhtxCLeINE";
  
  printf("%s\n",reged_version);
  while((c=getopt(argc,argv,options)) > 0) {
    switch(c) {
    case 'e': edit = 1; break;
    case 'x': export = 1; break;
    case 'I': import = 1; break;
    case 'C': autocommit = 1; break;
    case 'L': logchange = 1; break;
    case 'v': mode |= HMODE_VERBOSE; gverbose = 1; break;
    case 'N': mode |= HMODE_NOALLOC; break;
    case 'E': mode |= HMODE_NOEXPAND; break;
    case 't': mode |= HMODE_TRACE; break;
    case 'h': usage(); exit(0); break;
    default: usage(); exit(1); break;
    }
  }
  if (!export && !edit && !import) {
    usage();
    exit(1);
  }
  if ( import && export ) {
    fprintf(stderr,"Import and export cannot be done at same time\n");
    usage();
    exit(1);
  }
  if (export) { /* Call export. Works only on one hive at a time */
    hivename=argv[optind];
    prefix=argv[optind+1];
    key=argv[optind+2];
    outputname=argv[optind+3];
    if (gverbose) {
      printf("hivename: %s, prefix: %s, key: %s, output: %s\n",hivename,prefix,key,outputname);
    }
    
    if (!hivename || !*hivename || !prefix || !*prefix || !key || !*key || !outputname || !*outputname) {
      usage(); exit(1);
    }
    
    if (!(hive[no_hives] = openHive(hivename,HMODE_RO|mode))) {
      fprintf(stderr,"Unable to open/read hive %s, exiting..\n",hivename);
      exit(1);
    }
    
    export_key(hive[no_hives], 0, key, outputname, prefix);
    
    no_hives++;
    
  }

  if (import) { /* Call import. Works only on one hive at a time */
    hivename=argv[optind];
    prefix=argv[optind+1];
    inputname=argv[optind+2];
    if (gverbose) {
      printf("hivename: %s, prefix: %s\n",hivename,prefix);
    }
    
    if (!hivename || !*hivename || !prefix || !*prefix || !inputname || !*inputname) {
      usage(); exit(1);
    }
    
    if (!(hive[no_hives] = openHive(hivename,HMODE_RW|mode))) {
      fprintf(stderr,"Unable to open/read hive %s, exiting..\n",hivename);
      exit(1);
    }
    
    import_reg(hive[no_hives], inputname, prefix);
    
    no_hives++;
    update = 1;
    if (edit) regedit_interactive(hive, no_hives);
    edit = 0;
    
  }

  if (edit) {  /* Call editor. Rest of arguments are considered hives to load */
    hivename = argv[optind+no_hives];
    do {
      if (!(hive[no_hives] = openHive(hivename,
				      HMODE_RW|mode))) {
	printf("Unable to open/read a hive, exiting..\n");
	exit(1);
      }
      no_hives++;
      hivename = argv[optind+no_hives];
    } while (hivename && *hivename && no_hives < MAX_HIVES);
    regedit_interactive(hive, no_hives);
    update = 1;
  }

  
  if (update) {  /* run for functions that can have changed things */
    printf("\nHives that have changed:\n #  Name\n");
    for (il = 0; il < no_hives; il++) {
      if (hive[il]->state & HMODE_DIRTY) {
	if (!logchange && !autocommit) { 
	  printf("%2d  <%s>",il,hive[il]->filename);
	  if (hive[il]->state & HMODE_DIDEXPAND)
	    printf(" WARNING: File was expanded! Experimental! Use at own risk!\n");
	  printf("\n");
	}
	d = 1;
      }
    }
    if (d) {
      /* Only prompt user if logging of changed files has not been set */
      /* Thus we assume confirmations are done externally if they ask for a list of changes */
      if (!logchange && !autocommit) fmyinput("Commit changes to registry? (y/n) [n] : ",yn,3);
      if (*yn == 'y' || logchange || autocommit) {
	if (logchange) {
	  ch = fopen("/tmp/changed","w");
	}
	for (il = 0; il < no_hives; il++) {
	  if (hive[il]->state & HMODE_DIRTY) {
	    printf("%2d  <%s> - ",il,hive[il]->filename);
	    if (!writeHive(hive[il])) {
	      printf("OK ");
	      if (hive[il]->state & HMODE_DIDEXPAND)
		printf(" WARNING: File was expanded! Experimental! Use at own risk!\n");
	      printf("\n");
	      if (logchange) fprintf(ch,"%s ",hive[il]->filename);
	      dd = 2;
	    }
	  }
	}
	if (logchange) {
	  fprintf(ch,"\n");
	  fclose(ch);
	}
      } else {
	printf("Not written!\n\n");
      }
    } else {
      printf("None!\n\n");
    }
  }
  while (no_hives > 0)
    closeHive(hive[--no_hives]);
  return(dd);
}

