/*
 * samusrgrp.c - SAM database, add or remove user in a group
 * 
 * Command line utility, non-interactive to add or remove a user to/from
 * a local group in the SAM database, list groups with memberships etc
 *
 * When run as:
 *   samusrtogrp - add user to group
 *   samusrfromgrp - remove user from a group
 * or as any other name, option of what to do must be specified
 *
 * Changes:
 * 2013 - aug: cleaned up for release, still some debug & strangeness left
 * 2013 - apr-may: add, remove, list working (more or less)
 * 2012 - oct: First version, never released
 *
 *****
 *
 * Copyright (c) 1997-2014 Petter Nordahl-Hagen.
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
#include <string.h>

#include "ntreg.h"
#include "sam.h"


const char samusrgrp_version[] = "samusrgrp version 0.2 140201, (c) Petter N Hagen";


/* Global verbosity flag */
int gverbose = 0;

/* Array of loaded hives */
#define MAX_HIVES 10
struct hive *hive[MAX_HIVES+1];
int no_hives = 0;

int H_SAM = -1;


/* Print machine SID. Put into here since no better place for now */

void cmd_machinesid(void)
{
  struct sid_binary sid;
  char *sidstr;
 
  if (sam_get_machine_sid(hive[H_SAM], (char *)&sid)) {  
    sidstr = sam_sid_to_string(&sid);
    puts(sidstr);
    FREE(sidstr);
  }
}

/* Get and parse parameters for group changes */

int cmd_usrgrp(char *user, char *grp, int what, int human)
{
  int numgrp;
  int rid = 0;
  char *resolveduser = NULL;
  char *resolvedgroup = NULL;
  char s[200];

  numgrp = strtol(grp, NULL, 0);

  if ((H_SAM < 0) || (!user)) return(1);

  if (*user == '0' && *(user+1) == 'x') sscanf(user,"%i",&rid);
  
  if (!rid) { /* Look up username */
    /* Extract the unnamed value out of the username-key, value is RID  */
    snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\Names\\%s\\@",user);
    rid = get_dword(hive[H_SAM],0,s, TPF_VK_EXACT|TPF_VK_SHORT);
    if (rid == -1) {
      printf("User <%s> not found\n",user);
      return(1);
    }
  }

  /* At this point we have a RID, so get the real username it maps to just to show it */
  resolveduser = sam_get_username(hive[H_SAM], rid);
  if (!resolveduser) return(1);  /* Fails if RID does not exists */

  resolvedgroup = sam_get_groupname(hive[H_SAM], numgrp);
  if (!resolvedgroup) return(1);  /* Fails if GID does not exists */


  if (human) printf("%s user <%s> with RID = %d (0x%0x) %s group <%s> with GID = %d (0x%x)\n",
		    (what == 1 ? "Add" : "Remove"),
		    resolveduser,
		    rid, rid,
		    (what == 1 ? "to" : "from"),
		    resolvedgroup,
		    numgrp, numgrp );

  FREE(resolveduser);
  FREE(resolvedgroup);

  switch (what) {
  case 1: return(!sam_add_user_to_grp(hive[H_SAM] ,rid, numgrp)); break;
  case 2: return(!sam_remove_user_from_grp(hive[H_SAM] ,rid, numgrp)); break;
  }


  return(0);

}

int cmd_usrgrp_sid(char * parsing_sid, char *grp, int what, int human)
{
    long ret;
    int sid_sections = 0;
    int numgrp;
    struct sid_binary * sid;
    ALLOC(sid, sizeof(struct sid_binary), 1);
    memset(sid, 0x00, sizeof(struct sid_binary));
    char * current_sid_ptr = parsing_sid + 2;
    char * current_separator = current_sid_ptr;

    numgrp = strtol(grp, NULL, 0);

    if ( memcmp( parsing_sid, "S-", 2 ) )
    {
        printf("Wrong SID start\n");
        return 0;
    }

    while (current_separator)
    {
        current_separator = strchr(current_sid_ptr, '-');
        if ( current_separator )
            *current_separator = 0;

        ret = atol(current_sid_ptr);
        if ( ret > 0 )
        {
            switch (sid_sections) {
            case 0:
                if ( ret > 255 )
                {
                    fprintf(stderr, "ERROR: SID revision more than 255\n");
                    free(sid);
                    return 0;
                }
                sid->revision   = ret;
                break;
            case 1:
                if ( ret > 255 )
                {
                    fprintf(stderr, "ERROR: SID authority more than 255\n");
                    free(sid);
                    return 0;
                }
                sid->authority  = ret;
                break;
            default:
                if ( ret > 4294967295 )
                {
                    fprintf(stderr, "ERROR: SID section value more than 4294967295\n");
                    free(sid);
                    return 0;
                }
                sid->array[sid->sections]   = ret;
                sid->sections++;
                break;
            }
            current_sid_ptr = current_separator + 1;
            sid_sections++;
            if ( sid_sections > 10 )
            {
                fprintf(stderr, "ERROR: SID sections more than 8\n");
                free(sid);
                return 0;
            }

            if ( ( current_separator == NULL ) && ( sid->sections == 0 ) )
            {
                fprintf(stderr, "ERROR: SID sections less than 1\n");
                free(sid);
                return 0;
            }
        }
        else
        {
            fprintf(stderr, "ERROR: SID section parsing Error\n");
            free(sid);
            return 0;
        }
    }
    switch (what)
    {
        case 1: return( !sam_add_sid_to_grp( hive[H_SAM], sid, numgrp)); break;
        case 2: return( !sam_remove_sid_from_grp( hive[H_SAM], sid, numgrp)); break;
    }

    return 1;
}


void usage(void)
{
  printf(" [-a|-r] [-u <user>|-S <sid>] -g <groupid> <samhive>\n"
	 "Add or remove a (local) user to/from a group\n"
         "Mode:"
	 "   -a = add user to group\n"
         "   -r = remove user from group\n"
	 "   -l = list groups\n"
	 "   -L = list groups and also their members\n"
	 "   -s = Print machine SID\n"
         "Parameters:\n"
         "   <user> can be given as a username or a RID in hex with 0x in front\n"
         "   <group> is the group number, in hex with 0x in front\n"
         "   <sid> is the SID number, in  with 0x in front\n"
         "   Example:\n"
         "   -a -u theboss -g 0x220 -> add user named 'theboss' group hex 220 (administrators)\n"
         "   -a -S S-1-5-21-229-324-890-511 -g 0x220 -> add user SID 'S-1-5-21-229-324-890-511' group hex 221 (users)\n"
         "   -a -u 0x3ea -g 0x221 -> add user with RID (hex) 3ea group hex 221 (users)\n"
         "   -r -u 0x3ff -g 0x220 -> remove user RID 0x3ff from grp 0x220\n"
         "   Usernames with international characters usually fails to be found,\n"
         "   please use RID number instead\n"
	 "   If success, there will be no output, and exit code is 0\n"
         "   Also, success if user already in (or not in if -r) the group\n"
	 "Options:\n"
	 "   -H : Human readable output, else parsable\n"
	 "   -N : No allocate mode, only allow edit of existing values with same size\n"
	 "   -E : No expand mode, do not expand hive file (safe mode)\n"
	 "   -t : Debug trace of allocated blocks\n"
	 "   -v : Some more verbose messages/debug\n"
         "Multi call binary, if program is named:\n"
         "  samusrtogrp -- Assume -a mode: Add a user into a group\n"
	 "  samusrfromgrp -- Assume -r mode: Remove user from a group\n"
	 );
}


int main(int argc, char **argv)
{
   
  extern int optind;
  extern char* optarg;

  int what = 0;
  int add = 0;
  int rem = 0;
  int mode = 0;
  int m = 0;
  int list = 0;
  int human = 0;
  int use_sid = 0;
  int ret, wret, il;
  char *hivename;
  char c;
  char *usr = NULL;
  char *grp = NULL;
  char *sid = NULL;

  char *options = "aru:g:S:vNEthlLHs";
  
  if (!strcmp(argv[0],"samusrtogrp")) what = 1;
  if (!strcmp(argv[0],"samusrfromgrp")) what = 2;
  if (!strcmp(argv[0],"samgrplist")) what = 3;

  while((c=getopt(argc,argv,options)) > 0) {
    switch(c) {
    case 'a': add = 1; m++; break;  /* Add user */
    case 'r': rem = 2; m++; break;  /* Remove user */
    case 'l': list = 1; m++; break; /* List groups */
    case 'L': list = 2; m++; break; /* List groups + members */
    case 's': list = 3; m++; break;  /* Print machine sid */
    case 'u': usr = optarg; break;
    case 'g': grp = optarg; break;
    case 'S': sid = optarg; break;
    case 'H': human = 1; break;
    case 'v': mode |= HMODE_VERBOSE; gverbose = 1; break;
    case 'N': mode |= HMODE_NOALLOC; break;
    case 'E': mode |= HMODE_NOEXPAND; break;
    case 't': mode |= HMODE_TRACE; break;
    case 'h': printf("%s\n%s ",samusrgrp_version,argv[0]); usage(); exit(0); break;
    default: printf("%s\n%s ",samusrgrp_version,argv[0]); usage(); exit(1); break;
    }
  }

  if (m == 0) {
    fprintf(stderr,"%s: ERROR: One of mode -a -r -l -L must be specified\n",argv[0]);
    printf("%s\n%s ",samusrgrp_version,argv[0]);
    usage();
    exit(1);
  }

  if (m > 1) {
    fprintf(stderr,"%s: ERROR: Please select only one of modes -a -r -l -L\n",argv[0]);
    exit(1);
  }

  if ( list == 0 )
  {
      if ( !grp || !*grp )
      {
          fprintf(stderr,"%s: ERROR: -g must be specified with -a or -r.\n",argv[0]);
          exit(1);
      }

      if ( ( sid && usr ) || ( !sid && !usr ) )
      {
          fprintf(stderr,"%s: ERROR: -u or -S must be specified with -a or -r.\n",argv[0]);
          exit(1);
      }

      if ( sid && !*sid )
      {
          fprintf(stderr,"%s: ERROR: SID must be specified with -S.\n",argv[0]);
          exit(1);
      }

      if ( usr && !*usr )
      {
          fprintf(stderr,"%s: ERROR: SID must be specified with -S.\n",argv[0]);
          exit(1);
      }

      if ( sid ) use_sid = 1;
      if ( usr ) use_sid = 0;
  }


  /* Implicit mode parameter overrides mode based on binary name */
  if (add) what = 1;
  if (rem) what = 2;
  if (list) what = 3;

  // printf("add = %d, rem = %d, list = %d, what = %d\n",add,rem,list,what);


  /* Load hives. Only first SAM hive will be used however */

  hivename = argv[optind+no_hives];
  if (!hivename || !*hivename) {
    fprintf(stderr,"%s: ERROR: You must specify a SAM registry hive filename.\n",argv[0]);
    exit(1);
  }
  do {
    if (!(hive[no_hives] = openHive(hivename,
				    HMODE_RW|mode))) {
      fprintf(stderr,"%s: ERROR: Unable to open/read registry hive, cannot continue\n",argv[0]);
      exit(1);
    }
    switch(hive[no_hives]->type) {
    case HTYPE_SAM:      H_SAM = no_hives; break;
      // case HTYPE_SOFTWARE: H_SOF = no_hives; break;
      // case HTYPE_SYSTEM:   H_SYS = no_hives; break;
      // case HTYPE_SECURITY: H_SEC = no_hives; break;
    }
    no_hives++;
    hivename = argv[optind+no_hives];
  } while (hivename && *hivename && no_hives < MAX_HIVES);

  if (H_SAM == -1) {
    fprintf(stderr,"%s: WARNING: Registry hive does not look like SAM!\n"
	    "%s: WARNING: Continuing anyway, may lead to strange messages/failures!\n",argv[0],argv[0]);
    H_SAM = 0;
  }


  /* Do logic  */

  if (list == 3) {
    cmd_machinesid();
    ret = 0;
  } else {
    if (list) {
      sam_list_groups(hive[H_SAM], list - 1, human);
      ret = 0;
    } else {
      if ( use_sid )
        ret = cmd_usrgrp_sid(sid, grp, what, human);
      else
        ret = cmd_usrgrp(usr, grp, what, human);
      if (!ret && human) printf("Success!\n");
    }
  }

  /* write registry hive (if needed) */
  
  wret = 0;
  for (il = 0; il < no_hives; il++) {
    wret |= writeHive(hive[il]);
    if (hive[il]->state & HMODE_DIDEXPAND)
      fprintf(stderr," WARNING: Registry file %s was expanded! Experimental! Use at own risk!\n",hive[il]->filename);  
    while (no_hives > 0)
      closeHive(hive[--no_hives]);
  }
  
  return(ret | wret);
}

