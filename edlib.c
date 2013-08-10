/*
 * edlib.c - Registry edit interactive fuctions.
 * 
 * Point of this is so that interactive registry editor
 * can be accessed from several other programs
 * 
 * 2010-jun: New function from  Aleksander Wojdyga: dpi, decode product ID
 *           Mostly used on \Microsoft\Windows NT\CurrentVersion\DigitalProductId
 *           Now as command in registry editor, but may be moved to chnpw menu later.
 * 2010-apr: Lots of bugfix and other patches from
 *           Frediano Ziglio <freddy77@gmail.com>
 *           His short patch comments:
 *           remove leak
 *           fix default value, bin and quote
 *           support wide char in key
 *           support wide character into value names
 *           fix export for string with embedded end lines
 *           remove some warnings
 *           compute checksum writing
 *
 * 2008-mar: First version. Moved from chntpw.c
 * See HISTORY.txt for more detailed info on history.
 *
 *****
 *
 * Copyright (c) 1997-2011 Petter Nordahl-Hagen.
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
#include <ctype.h>

#include "ntreg.h"

const char edlib_version[] = "edlib version 0.1 110511, (c) Petter N Hagen";

#define ALLOC_DEBUG 0     /* Reg allocation debug hooks */
#define ADDBIN_DEBUG 0     /* Reg expansion debug hooks */

extern char *val_types[REG_MAX+1];

struct cmds {
  char cmd_str[12];
  int  cmd_num;
};

#define MCMD_CD 1
#define MCMD_LS 2
#define MCMD_QUIT 3
#define MCMD_CAT  4
#define MCMD_STRUCT 5
#define MCMD_DEBUG 6
#define MCMD_HELP 7
#define MCMD_EXPORTKEY 8
#define MCMD_HIVE 9
#define MCMD_EDIT 10
#define MCMD_ALLOC 11
#define MCMD_FREE 12
#define MCMD_ADDV 13
#define MCMD_DELV 14
#define MCMD_DELVALL 15
#define MCMD_NEWKEY 16
#define MCMD_DELKEY 17
#define MCMD_CATHEX 18
#define MCMD_RDEL 19
#define MCMD_CK 20
#define MCMD_CAT_DPI 21
#define MCMD_ADDBIN 22

struct cmds maincmds[] = {
 { "cd" , MCMD_CD } ,
 { "ls" , MCMD_LS } ,
 { "dir", MCMD_LS } ,
 { "q"  , MCMD_QUIT } ,
 { "cat", MCMD_CAT } ,
 { "type",MCMD_CAT } ,
 { "st" , MCMD_STRUCT } ,
 { "debug", MCMD_DEBUG } ,
 { "hive", MCMD_HIVE } ,
 { "ed", MCMD_EDIT } ,
#if ALLOC_DEBUG
 { "alloc", MCMD_ALLOC } ,
 { "free", MCMD_FREE } ,
#endif
#if ADDBIN_DEBUG
 { "addbin", MCMD_ADDBIN },
#endif
 { "nv", MCMD_ADDV } ,
 { "dv", MCMD_DELV } ,
 { "delallv", MCMD_DELVALL } ,
 { "nk", MCMD_NEWKEY } ,
 { "dk", MCMD_DELKEY } ,
 { "hex", MCMD_CATHEX } ,
 { "rdel", MCMD_RDEL } ,
 { "ek", MCMD_EXPORTKEY },
 { "ck", MCMD_CK } ,
 { "?", MCMD_HELP } ,
 { "dpi", MCMD_CAT_DPI } ,
 { "", 0 }
};

/* display decoded DigitalProductId
 * nkofs = node
 * path = "DigitalProductId" or some other
 */
void cat_dpi(struct hive *hdesc, int nkofs, char *path)
{
  void *data;
  int len,i,type;

  type = get_val_type(hdesc, nkofs, path, 0);
  if (type == -1) {
    printf("cat_dpi: No such value <%s>\n",path);
    return;
  }

  len = get_val_len(hdesc, nkofs, path, 0);
  if (len < 67) {
    printf("cat_dpi: Value <%s> is too short for decoding\n",path);
    return;
  }

  data = (void *)get_val_data(hdesc, nkofs, path, 0, 0);
  if (!data) {
    printf("cat_dpi: Value <%s> references NULL-pointer (bad boy!)\n",path);
    abort();
    return;
  }

  if (type != REG_BINARY) {
    printf ("Only binary values\n");
    return;
  }

  printf("Value <%s> of type %s, data length %d [0x%x]\n", path,
	 (type < REG_MAX ? val_types[type] : "(unknown)"), len, len);


  char digits[] = {'B','C','D','F','G','H','J','K','M','P','Q','R','T','V','W','X','Y','2','3','4','6','7','8','9'}; 

#define RESULT_LEN 26
  char result[RESULT_LEN];
  memset (result, 0, RESULT_LEN);

#define START_OFFSET 52
#define BUF_LEN 15
  unsigned char buf[BUF_LEN];
  memcpy (buf, data + START_OFFSET, BUF_LEN);

  for (i = RESULT_LEN - 2; i >= 0; i--) {
        unsigned int x = 0;

        int j;
        for (j = BUF_LEN - 1; j >= 0; j--) {
            x = (x << 8) + buf[j];
            buf[j] = x / 24;
            x = x % 24;
        }
        result[i] = digits[x];
  }

  printf ("\nDecoded product ID: [%s]\n", result);
}

/* display (cat) the value,
 * vofs = offset to 'nk' node, paths relative to this (or 0 for root)
 * path = path string to value
 * Does not handle all types yet (does a hexdump instead)
 */
void cat_vk(struct hive *hdesc, int nkofs, char *path, int dohex)
{     
  void *data;
  int len,i,type;
  //  char string[SZ_MAX+1];
  char *string = NULL;
  struct keyval *kv = NULL;

  type = get_val_type(hdesc, nkofs, path, TPF_VK);
  if (type == -1) {
    printf("cat_vk: No such value <%s>\n",path);
    return;
  }

  len = get_val_len(hdesc, nkofs, path, TPF_VK);
  if (!len) {
    printf("cat_vk: Value <%s> has zero length\n",path);
    return;
  }

#if 0
  data = (void *)get_val_data(hdesc, nkofs, path, 0, TPF_VK);
  if (!data) {
    printf("cat_vk: Value <%s> references NULL-pointer (bad boy!)\n",path);
    abort();
    return;
  }
#endif

  kv = get_val2buf(hdesc, NULL, nkofs, path, 0, TPF_VK);

  if (!kv) {
    printf("cat_vk: Value <%s> could not fetch data\n",path);
    abort();
  }
  data = (void *)&(kv->data);


  printf("Value <%s> of type %s, data length %d [0x%x]\n", path,
	 (type < REG_MAX ? val_types[type] : "(unknown)"), len, len);

  if (dohex) type = REG_BINARY;
  switch (type) {
  case REG_SZ:
  case REG_EXPAND_SZ:
  case REG_MULTI_SZ:
    string = string_regw2prog(data, len);
    //    cheap_uni2ascii(data,string,len);
    for (i = 0; i < (len>>1)-1; i++) {
      if (string[i] == 0) string[i] = '\n';
      if (type == REG_SZ) break;
    }
    puts(string);
    FREE(string);
    break;
  case REG_DWORD:
    printf("0x%08x",*(unsigned short *)data);
    break;
  default:
    printf("Don't know how to handle type yet!\n");
  case REG_BINARY:
    hexdump((char *)data, 0, len, 1);
  }
  putchar('\n');
  FREE(kv);

}

/* Edit value: Invoke whatever is needed to edit it
 * based on its type
 */

void edit_val(struct hive *h, int nkofs, char *path)
{
  struct keyval *kv, *newkv;
  int type,len,n,i,in,go, newsize, d = 0, done, insert = 0;
  char inbuf[SZ_MAX+4];
  char origstring[SZ_MAX+4];
  char *newstring;
  char *dbuf;

  type = get_val_type(h, nkofs, path, TPF_VK);
  if (type == -1) {
    printf("Value <%s> not found!\n",path);
    return;
  }

  kv = get_val2buf(h, NULL, nkofs, path, type, TPF_VK);
  if (!kv) {
    printf("Unable to get data of value <%s>\n",path);
    return;
  }
  len = kv->len;

  printf("EDIT: <%s> of type %s with length %d [0x%x]\n", path,
	 (type < REG_MAX ? val_types[type] : "(unknown)"),
	 len, len);

  switch(type) {
  case REG_DWORD:
    printf("DWORD: Old value %d [0x%x], ", kv->data, kv->data);
    fmyinput("enter new value (prepend 0x if hex, empty to keep old value)\n-> ",
	     inbuf, 12);
    if (*inbuf) {
      sscanf(inbuf,"%i",&kv->data);
      d = 1;
    }
    printf("DWORD: New value %d [0x%x], ", kv->data, kv->data);
    break;
  case REG_SZ:
  case REG_EXPAND_SZ:
  case REG_MULTI_SZ:
    newstring = NULL;
    dbuf = (char *)&kv->data;
    cheap_uni2ascii(dbuf,origstring,len);
    n = 0; i = 0;
    while (i < (len>>1)-1) {
      printf("[%2d]: %s\n",n,origstring+i);
      i += strlen(origstring+i) + 1;
      n++;
    }

    printf("\nNow enter new strings, one by one.\n");
    printf("Enter nothing to keep old.\n");
    if (type == REG_MULTI_SZ) {
      printf("'--n' to quit (remove rest of strings)\n");
      printf("'--i' insert new string at this point\n");
      printf("'--q' to quit (leaving remaining strings as is)\n");
      printf("'--Q' to quit and discard all changes\n");
      printf("'--e' for empty string in this position\n");
    }
    n = 0; i = 0; in = 0; go = 0; done = 0;

    /* Now this one is RATHER UGLY :-} */

    while (i < (len>>1)-1 || !done) {

      printf("[%2d]: %s\n",n, insert == 1 ? "[INSERT]" : ((i < (len>>1)-1 ) ? origstring+i : "[NEW]"));
      if (insert) insert++;
      if (!go) fmyinput("-> ",inbuf, 500);
      else *inbuf = 0;
      if (*inbuf && strcmp("--q", inbuf)) {
	if (!strcmp("--n", inbuf) || !strcmp("--Q", inbuf)) { /* Zap rest */
	  i = (len>>1) ; done = 1;
	} else if (strcmp("--i", inbuf)) {  /* Copy out given string */
	  if (!strcmp("--e",inbuf)) *inbuf = '\0';
	  if (newstring) newstring = realloc(newstring, in+strlen(inbuf)+1);
	  else newstring = malloc(in+strlen(inbuf)+1);
	  strcpy(newstring+in, inbuf);
	  in += strlen(inbuf)+1;
	} else {
	  insert = 1;
	}
      } else {  /* Copy out default string */

	if (newstring) newstring = realloc(newstring, in+strlen(origstring+i)+1);
	else newstring = malloc(in + strlen(origstring+i) + 1);
	strcpy(newstring+in, origstring+i);
	in += strlen(origstring+i)+1;

	if (!strcmp("--q", inbuf)) { 
	  go = 1; done = 1;
	  if (!(i < (len>>1)-1 )) {
	    in--;  /* remove last empty if in NEW-mode */
	  }
	}
      }
      
      if (!insert) i += strlen(origstring+i) + 1;
      if (insert != 1) n++;
      if (insert == 2) insert = 0;
      if (type != REG_MULTI_SZ) {
	i = (len<<1);
	done = 1;
      }

    }

    if (strcmp("--Q", inbuf)) {  /* We didn't bail out */
      if (newstring) newstring = realloc(newstring, in+1);
      else newstring = malloc(in+1);
      if (type == REG_MULTI_SZ) {
	in++;
	*(newstring+in) = '\0';  /* Must add null termination */
      }
      ALLOC(newkv,1,(in<<1)+sizeof(int));
      newkv->len = in<<1;
      printf("newkv->len: %d\n",newkv->len);
      cheap_ascii2uni(newstring, (char *)&(newkv->data), in);
      
      d = 1;

      FREE(kv);
      kv = newkv;

    }
    break;

  default:
    printf("Type not handeled (yet), invoking hex editor on data!\n");
  case REG_BINARY:
    fmyinput("New length (ENTER to keep same): ",inbuf,90);
    if (*inbuf) {
      newsize = atoi(inbuf);
      ALLOC(newkv,1,newsize+sizeof(int)+4);
      bzero(newkv,newsize+sizeof(int)+4);
      memcpy(newkv, kv, ((len < newsize) ? (len) : (newsize)) + sizeof(int));
      FREE(kv);
      kv = newkv;
      kv->len = newsize;
    }
    d = debugit((char *)&kv->data, kv->len);
    break;
  }

  if (d) {
    if (!(put_buf2val(h, kv, nkofs, path, type, TPF_VK))) {
      printf("Failed to set value!?\n");
    }
  }
  FREE(kv);
}

/* look up command in array
 */
int parsecmd(char **s, struct cmds *cmd)
{

  int l = 0;

  while ((*s)[l] && ((*s)[l] != ' ')) {
    l++;
  }
  while (cmd->cmd_num) {
    if (!strncmp(*s, cmd->cmd_str, l)) {
      *s += l;
      return(cmd->cmd_num);
    }
    cmd++;
  }
  return(0);
}


/* Lot of people didn't understand the "nv" command.
 * Actually the command should understand the type names too, but.. some later time
 */

void nv_help(void)
{
  int i;

  printf("Command syntax is:\n\n"
	 " nv <type> <valuename>\n\n"
	 "where <type> should be the HEX NUMBER from one of these registry value types:\n\n");

  for (i=0; i < REG_MAX; i++) {
    printf(" %2x : %s\n",i,val_types[i]);
  }
  printf("\nExample:\n nv 4 foobar\n");
  printf("to make a new value named foobar of the type REG_DWORD\n\n");
}


/* Interactive registry editor
 * hive - list of loaded hives (array pointing to hive structs)
 * no_hives - max number of hives loaded
 */

void regedit_interactive(struct hive *hive[], int no_hives)
{
  struct hive *hdesc;
  int cdofs, newofs;
  struct nk_key *cdkey;
  char inbuf[100], *bp, *file, *prefix;
  char path[1000];
  int l, vkofs, nh, i;
  int usehive = 0;
  struct keyval *kv;

#if ALLOC_DEBUG
  int pagestart;
  int freetest;
#endif

  hdesc = hive[usehive];
  cdofs = hdesc->rootofs;

  printf("Simple registry editor. ? for help.\n");

  while (1) {
    cdkey = (struct nk_key *)(hdesc->buffer + cdofs);

    *path = 0;
    get_abs_path(hdesc,cdofs+4, path, 50);

#if ALLOC_DEBUG
    pagestart = find_page_start(hdesc,cdofs);
    printf("find_page_start: 0x%x\n",pagestart);
    freetest = find_free_blk(hdesc,pagestart,10);
    printf("find_free_blk: 0x%x\n",freetest);
#endif
    if (hdesc->state & HMODE_VERBOSE) printf("\n[%0x] %s> ",cdofs,path);
    else printf("\n%s> ",path);
    l = fmyinput("",inbuf,90);
    bp = inbuf;
    skipspace(&bp);
      
    if (l > 0 && *bp) {
      switch(parsecmd(&bp,maincmds)) {
      case MCMD_HELP:
	printf("Simple registry editor:\n");
	printf("hive [<n>]             - list loaded hives or switch to hive numer n\n");
	printf("cd <key>               - change current key\n");
	printf("ls | dir [<key>]       - show subkeys & values,\n");
        printf("cat | type <value>     - show key value\n");
        printf("dpi <value>            - show decoded DigitalProductId value\n");
        printf("hex <value>            - hexdump of value data\n");
	printf("ck [<keyname>]         - Show keys class data, if it has any\n");
	printf("nk <keyname>           - add key\n");
	printf("dk <keyname>           - delete key (must be empty)\n");
	printf("ed <value>             - Edit value\n");
	printf("nv <type#> <valuename> - Add value\n");
	printf("dv <valuename>         - Delete value\n");
	printf("delallv                - Delete all values in current key\n");
	printf("rdel <keyname>         - Recursively delete key & subkeys\n");
	printf("ek <filename> <prefix> <keyname>  - export key to <filename> (Windows .reg file format)\n");
	printf("debug                  - enter buffer hexeditor\n");
        printf("st [<hexaddr>]         - debug function: show struct info\n");
        printf("q                      - quit\n");
        break;

      case MCMD_DELKEY :
	bp++;
	skipspace(&bp);
        del_key(hdesc, cdofs + 4, bp);
	break;
      case MCMD_NEWKEY :
	bp++;
	skipspace(&bp);
        add_key(hdesc, cdofs + 4, bp);
	break;
      case MCMD_DELVALL :
	bp++;
	skipspace(&bp);
        del_allvalues(hdesc, cdofs + 4);
	break;
      case MCMD_DELV :
	bp++;
	skipspace(&bp);
        del_value(hdesc, cdofs + 4, bp, 0);
	break;
      case MCMD_ADDV :
	bp++;
	skipspace(&bp);
	if (!isxdigit(*bp)) {
	  nv_help();
	  break;
        }
	nh = gethex(&bp);
	skipspace(&bp);
	if (!*bp) {
	  nv_help();
	  break;
	}
        add_value(hdesc, cdofs+4, bp, nh);
	break;
#if ALLOC_DEBUG
      case MCMD_FREE :
	bp++;
	skipspace(&bp);
	nh = gethex(&bp);
        free_block(hdesc, nh);
	break;
      case MCMD_ALLOC :
	bp++;
	skipspace(&bp);
	nh = gethex(&bp);
        alloc_block(hdesc, cdofs+4, nh);
	break;
#endif
#if ADDBIN_DEBUG
      case MCMD_ADDBIN :
	bp++;
	skipspace(&bp);
	nh = gethex(&bp);
        add_bin(hdesc, nh);
	break;
#endif
      case MCMD_LS :
	bp++;
	skipspace(&bp);
        nk_ls(hdesc, bp, cdofs+4, 0);
	break;
      case MCMD_CK :
	bp++;
	skipspace(&bp);
        kv = get_class(hdesc, cdofs+4, bp);
	if (kv) {
	  hexdump((char *)&kv->data, 0, kv->len, 1);
	  FREE(kv);
	}
	break;
      case MCMD_RDEL :
	bp++;
	skipspace(&bp);
        rdel_keys(hdesc, bp, cdofs+4);
	break;
      case MCMD_EDIT :
	bp++;
	skipspace(&bp);
        edit_val(hdesc, cdofs+4, bp);
	break;
      case MCMD_HIVE :
	bp++;
	skipspace(&bp);
	if (*bp) {
	  nh = gethex(&bp);
	  if (nh >= 0 && nh < no_hives) {
	    usehive = nh;
	    printf("Switching to hive #%d, named <%s>, size %d [0x%x]\n",
		   usehive, hive[usehive]->filename,
		   hive[usehive]->size,
		   hive[usehive]->size);
	    hdesc = hive[usehive];
	    cdofs = hdesc->rootofs;
	  }
	} else {
	  for (nh = 0; nh < no_hives; nh++) {
	    printf("%c %c %2d %9d 0x%08x <%s>\n", (nh == usehive) ? '*' : ' ',
		   (hive[nh]->state & HMODE_DIRTY) ? 'D' : ' ',
		   nh, 
		   hive[nh]->size,
		   hive[nh]->size, hive[nh]->filename);
	  }
	}
        break;
      case MCMD_CD :
	bp++;
	skipspace(&bp);
	newofs = trav_path(hdesc, cdofs+4,bp,TPF_NK);
        if (newofs) cdofs = newofs;
	else printf("Key %s not found!\n",bp);
	break;
      case MCMD_CAT:
	bp++;
	skipspace(&bp);
	cat_vk(hdesc,cdofs+4,bp,0);
	break;
      case MCMD_CAT_DPI:
	bp++;
	skipspace(&bp);
	cat_dpi (hdesc, cdofs+4, bp);
	break;
      case MCMD_CATHEX:
	bp++;
	skipspace(&bp);
	cat_vk(hdesc,cdofs+4,bp,1);
	break;
      case MCMD_EXPORTKEY :
        bp++;
        skipspace(&bp);
        file = bp;
        i = 0;
        while(*bp != ' ' && (*bp))
        {
           i++;
           bp++;
        }
        file[i] = '\0';
        bp++;
        skipspace(&bp);
        prefix = bp;
        i = 0;
        while(*bp != ' ' && (*bp))
        {
           i++;
           bp++;
        }
        prefix[i] = '\0';
        bp++;
        skipspace(&bp);
        export_key(hdesc, cdofs + 4, bp, file, prefix);
    break;
      case MCMD_STRUCT:
	bp++;
	skipspace(&bp);
	vkofs = cdofs;
	if (*bp) {
	  vkofs = gethex(&bp);
	}
	parse_block(hdesc,vkofs,2);
	break;
      case MCMD_DEBUG:
	if (debugit(hdesc->buffer,hdesc->size)) hdesc->state |= HMODE_DIRTY;
	break;
      case MCMD_QUIT:
        return;
        break;
      default:
	printf("Unknown command: %s, type ? for help\n",bp);
	break;
      }
    }
  }
}
