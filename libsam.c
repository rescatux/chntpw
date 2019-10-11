/*
 * libsam.c - SAM database functions, user and group editing
 *
 * Functions to edit SAM database, like adding and removing
 * users to groups, list users and groups
 * list user data and reset passwords
 * low level SID handling functions
 
 *
 * 2013-aug: Cleaned up a bit for release, still some debug/strange things left
 * 2013-aug: actually having functions doing listings in library is not good, bu
 *           have to do with that for now.
 * 2013-apr-may: Functions for password reset, more group stuff etc
 * 2012-oct: Split off from functions in chntpw.c
 * 2012-jun-oct: Made routines for group handling (add/remove user from group etc)
 *
 * See HISTORY.txt for more detailed info on history.
 *
 *****
 *
 * Copyright (c) 1997-2013 Petter Nordahl-Hagen.
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
 *
 * Some information and ideas taken from pwdump by Jeremy Allison.
 * More info from NTCrack by Jonathan Wilkins.
 * 
 */ 


#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "ntreg.h"
#include "sam.h"

extern int gverbose;  /* Ehm.. must get rid of this some day */

/* Strings for account bits fields */

char *acb_fields[16] = {
   "Disabled" ,
   "Homedir req." ,
   "Passwd not req." ,
   "Temp. duplicate" ,
   "Normal account" ,
   "NMS account" ,
   "Domain trust act." ,
   "Wks trust act." ,
   "Srv trust act" ,
   "Pwd don't expire" ,
   "Auto lockout" ,
   "(unknown 0x08)" ,
   "(unknown 0x10)" ,
   "(unknown 0x20)" ,
   "(unknown 0x40)" ,
   "(unknown 0x80)" ,
};

/* Number of paths we find group info under, needed by some later routines */
#define SAM_NUM_GROUPPATHS 2

/* Paths for group ID list*/

static char *SAM_GRPCPATHS[] = { 
  "\\SAM\\Domains\\Builtin\\Aliases",
  "\\SAM\\Domains\\Account\\Aliases",
  "" };

/* Paths for C (group data) value under group ID %08X */
static char *SAM_GRPCPATHID[] = {
  "\\SAM\\Domains\\Builtin\\Aliases\\%08X\\C",
  "\\SAM\\Domains\\Account\\Aliases\\%08X\\C",
  "" };

/* Paths for users lists of group memberships, machine SID %s , user RID %08x
 * each key contains one default value (no name) with TYPE indicating number of group IDs it contains
 * value contents is then an array of 32 bit group IDs
 */

static char *SAM_GRPMEMBERSPATH[] = {
  "\\SAM\\Domains\\Builtin\\Aliases\\Members\\%s\\%08X",
  "\\SAM\\Domains\\Account\\Aliases\\Members\\%s\\%08X",
  "" };

static char *SAM_GRPSIDPATH[] = {
  "\\SAM\\Domains\\Builtin\\Aliases\\Members\\%s",
  "\\SAM\\Domains\\Account\\Aliases\\Members\\%s",
  "" };



/* Check if hive is SAM, and if it is, extract some
 * global policy information from it, like lockout counts etc
 * show = 1 means also print some more info
 * Returns the number of allowed logins before lockout (locklimit)
 * or -1 if error (not SAM, key not found etc)
 */


int sam_get_lockoutinfo(struct hive *hdesc, int show)
{
  struct accountdb_F *f;
  struct keyval *v;

  if (hdesc->type == HTYPE_SAM) {

    /* Get accoundb F value */
    v = get_val2buf(hdesc, NULL, 0, ACCOUNTDB_F_PATH, REG_BINARY, TPF_VK);
    if (!v) {
      fprintf(stderr,"WARNING: Login counts data not found in SAM\n");
      return (-1);
    }
    
    f = (struct accountdb_F *)&v->data;

    if (show) { 
      printf("\n* SAM policy limits:\n");    
      printf("Failed logins before lockout is: %d\n",f->locklimit);
      printf("Minimum password length        : %d\n",f->minpwlen);
      printf("Password history count         : %d\n",f->minpwlen);
    }

    return(f->locklimit);

  }

  return(-1); /* Not SAM */
  
}



/* Try to decode and possibly change account lockout etc
 * This is \SAM\Domains\Account\Users\<RID>\F
 * It's size seems to always be 0x50.
 * Params: RID - user ID, mode - 0 silent, 1 print info, 2 edit.
 * Returns: ACB bits with high bit set if lockout count is >0
 */

short sam_handle_accountbits(struct hive *hdesc, int rid, int mode)
{

  struct user_F *f;
  char s[200];
  struct keyval *v;
  unsigned short acb;
  int b;
  int max_sam_lock;

  if (hdesc->type != HTYPE_SAM) return(0);

  /* Get users F value */
  snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\%08X\\F",rid);
  v = get_val2buf(hdesc, NULL, 0, s, REG_BINARY, TPF_VK_EXACT);
  if (!v) {
    printf("Cannot find value <%s>\n",s);
    return(0);
  }

  if (v->len < 0x48) {
    printf("handle_F: F value is 0x%x bytes, need >= 0x48, unable to check account flags!\n",v->len);
    FREE(v);
    return(0);
  }

  max_sam_lock = sam_get_lockoutinfo(hdesc, 0);

  f = (struct user_F *)&v->data;
  acb = f->ACB_bits;

  if (mode == 1) {
    printf("Account bits: 0x%04x =\n",acb);


    for (b=0; b < 15; b++) {
      printf("[%s] %-15.15s | ",
	     (acb & (1<<b)) ? "X" : " ", acb_fields[b] );
      if (b%3 == 2) printf("\n");
    }

    printf("\nFailed login count: %u, while max tries is: %u\n",f->failedcnt,max_sam_lock);
    printf("Total  login count: %u\n",f->logins);
  }
    
  if (mode == 2) {  /* MODE = 2, reset to default sane sets of bits and null failed login counter */
    acb |= ACB_PWNOEXP;
    acb &= ~ACB_DISABLED;
    acb &= ~ACB_AUTOLOCK;
    f->ACB_bits = acb;
    f->failedcnt = 0;
    put_buf2val(hdesc, v, 0, s, REG_BINARY,TPF_VK_EXACT);  /* TODO: Check error return */
    printf("Unlocked!\n");
  }
  return (acb | ( (f->failedcnt > 0 && f->failedcnt >= max_sam_lock)<<15 ) | (acb & ACB_AUTOLOCK)<<15 | (acb & ACB_DISABLED)<<15);
}


/***** SID data handling routines **********/


/* Get machines SID as binary (raw data)
 * str = pointer to buffer, first 20 bytes will be filled in
 * returns true if found, else 0
 */

int sam_get_machine_sid(struct hive *hdesc, char *sidbuf)
{

  struct accountdb_V *v;
  struct keyval *kv;
  uint32_t ofs;
  uint32_t len;

  /* Get accoundb V value */
  kv = get_val2buf(hdesc, NULL, 0, ACCOUNTDB_V_PATH, REG_BINARY, TPF_VK);
  if (!kv) {
    fprintf(stderr,"sam_get_machine_sid: Machine SID not found in SAM\n");
    return(0);
  }
  
  //    hexdump(&(kv->data), 0, kv->len,1);
  
  v = (struct accountdb_V *)&kv->data;
  ofs = v->sid_ofs;
  len = v->sid_len + 4;
  ofs += 0x40;
  
  if (len != SID_BIN_LEN) {
    fprintf(stderr,"sam_get_machine_sid: WARNING: SID found, but it has len=%d instead of expected %d bytes\n",len,SID_BIN_LEN);
  }
  
  //    printf("get_machine_sid: adjusted ofs = %x, len = %x (%d)\n",ofs,len,len);
  
  
  memcpy(sidbuf, (char *)v+ofs, len);
  
  // hexdump(sidbuf, 0, len, 1);
  
  return(1);
}

/* Make string out of SID, in S-1-5 authority (NT authority)
 * like S-1-5-21-516312364-151943033-2698651
 * Will allocate return string (which can be of variable lenght)
 * NOTE: caller must free it
 * sidbuf = the SID binary data structure with it's type+counter first
 * 
 * returns str:
 *       6 chars athority prefix (S-1-5-)
 *       4 * 10 digits (the 4 32 bit groups)
 *       3 for the - between the groups
 *       1 for null termination
 *      50 chars
 */
char *sam_sid_to_string(struct sid_binary *sidbuf)
{

  int cnt, i;
  char *str = NULL;

   //   hexdump(sidbuf, 0, 24, 1);


  if (sidbuf->revision != 1) {
    fprintf(stderr,"sam_sid_to_string: DEBUG: first byte unexpected: %d\n",sidbuf->revision);
  }
  
  cnt = sidbuf->sections;
  
  // printf("sid_to_string: DEBUG: sections = %d\n",cnt);

  str = str_dup("S-");
  str = str_catf(str, "%u-%u", sidbuf->revision, sidbuf->authority);

  for (i = 0; i < cnt; i++) {
    str = str_catf(str,"-%u",sidbuf->array[i]);
  }

  // printf("sid_to_string: returning <%s>\n",str);


  return(str);
}





/* Stuff SID binary list into more easily handled arrays
 * sidbuf = binary list buffer (not changed, may point into value structure)
 * size = number of bytes of raw data
 * returns pointer to array, terminated with NULL pointer.
 * Keeps full binary data from each SID
 * All array space is allocated, call sam_free_sid_array() to free it.
 */

struct sid_array *sam_make_sid_array(struct sid_binary *sidbuf, int size)
{

  int num = 0;
  int sidlen;
  struct sid_binary *sb;
  struct sid_array *array;

  CREATE(array, struct sid_array, 1);
  array[0].len = 0;
  array[0].sidptr = NULL;

  while (size > 0) {

    sidlen = sidbuf->sections * 4 + 8;

    // printf("make_sid_array: sidlen = %d\n",sidlen);

    ALLOC(sb, 1, sidlen);
    memcpy(sb, sidbuf, sidlen);
    array[num].len = sidlen;
    array[num].sidptr = sb;
    sidbuf = (void *)sidbuf + sidlen;
    size -= sidlen;
    num++;

    array = realloc(array, (num + 1) * sizeof(struct sid_array));
    array[num].len = 0;
    array[num].sidptr = NULL;

  }


  return(array);

}

/* Free the sid array (from the function above) */

void sam_free_sid_array(struct sid_array *array)
{

  int num = 0;

  while (array[num].sidptr) {
    free(array[num].sidptr);
    num++;
  }

  free(array);
}

/* Compare two SIDs, and return like strcmp */
int sam_sid_cmp(struct sid_binary *s1, struct sid_binary *s2)
{
  int p;

  if (!s1 && !s2) return(0);
  if (!s1) return(-1);
  if (!s2) return(1);

  if (s1->sections < s2->sections) return(-1); /* s1 has shorter len, always smaller */
  if (s1->sections > s2->sections) return(1); /* s1 has longer len, always larger */
  /* Run compare since same length */
  for (p = 0; p < s1->sections; p++) {
    if (s1->array[p] < s2->array[p]) return (-1);
    if (s1->array[p] > s2->array[p]) return (1);
  }
  /* At end. Thus equal */
  return(0);
}






/************** GROUP DATA HANDLING ROUTINES ****************/


/* Get C value of a group ID, searching botg bult-in and user defined
 * hdesc - hive
 * grp - group ID
 * returns pointer to value buffer or NULL if not found
 */

struct keyval *sam_get_grpC(struct hive *hdesc, int grp)
{
  struct keyval *c = NULL;
  int n = 0;
  char g[200];

  /* Try built-in groups first (administrators, user, guests etc) */
  while (*SAM_GRPCPATHID[n] && !c) {
    snprintf(g, 180, SAM_GRPCPATHID[n], grp);
    c = get_val2buf(hdesc, NULL, 0, g, 0, TPF_VK_EXACT);
    n++;
  }

  return(c);
 
}


/* Get list of group members for a group
 * Will get the SID list (as binary) into a buffer that will be allocated
 * according to the neccessary size (based on member count)
 * NOTE: Caller must free the buffer when not needed any more
 * grp = group ID
 * sidarray = pointer to pointer to sid array which will be allocated
 * Returns number of members in the group
 */

int sam_get_grp_members_sid(struct hive *hdesc, int grp, struct sid_array **sarray)
{
  // char groupname[128];

  struct sid_array *marray;
  struct keyval *c = NULL;
  struct group_C *cd;
  // int grpnamoffs, grpnamlen;
  int mofs, mlen;

  c = sam_get_grpC(hdesc, grp);
  if (c) {
    cd = (struct group_C *)&c->data;

    // grpnamoffs = cd->grpname_ofs + 0x34;
    // grpnamlen  = cd->grpname_len;
    
    // cheap_uni2ascii((char *)cd + grpnamoffs, groupname, grpnamlen);
    
    // printf("get_grp_members_sid: group %x named %s has %d members\n",grp,groupname,cd->grp_members);

    mofs = cd->members_ofs;
    mlen = cd->members_len;

    //    printf("get_grp_members_sid: mofs = %x, mlen = %x (%d)\n", mofs,mlen,mlen);
    // printf("get_grp_members_sid: ajusted: mofs = %x, mlen = %x (%d)\n", mofs + 0x34 ,mlen,mlen);

    // hexdump(&c->data, 0, c->len, 1);
    // hexdump(&cd->data[mofs], 0, mlen, 1);

    marray = sam_make_sid_array((struct sid_binary *)&cd->data[mofs], mlen);

    *sarray = marray;
    // sam_free_sid_array(marray);

    free(c);

  } else {
    printf("Group info for %x not found!\n",grp);
    *sarray = NULL;
    return(0);
  }
  
  return(cd->grp_members);

}

/* Put list of group members back into group C structure
 * grp = group ID
 * sidarray = pointer to sid array
 * Returns true if success
 */

int sam_put_grp_members_sid(struct hive *hdesc, int grp, struct sid_array *sarray)
{
  char g[200];
  char groupname[128];

  struct keyval *c = NULL;
  struct group_C *cd;
  int grpnamoffs, grpnamlen;
  int mofs, mlen;
  int sidlen = 0;
  void *sidptr;
  int i, n;
  char *str;

  /* Try built-in groups first (administrators, user, guests etc) */
  n = 0;
  while (*SAM_GRPCPATHID[n] && !c) {
    snprintf(g, 180, SAM_GRPCPATHID[n], grp);
    c = get_val2buf(hdesc, NULL, 0, g, 0, TPF_VK_EXACT);
    n++;
  }

  if (c) {
    cd = (struct group_C *)&c->data;
    
    grpnamoffs = cd->grpname_ofs + 0x34;
    grpnamlen  = cd->grpname_len;
    
    cheap_uni2ascii((char *)cd + grpnamoffs, groupname, grpnamlen);
    
    if (gverbose) printf("put_grp_members_sid: group %x named %s has %d members\n",grp,groupname,cd->grp_members);

    mofs = cd->members_ofs;
    mlen = cd->members_len;

     if (gverbose) printf("put_grp_members_sid: ajusted: mofs = %x, mlen = %x (%d)\n", mofs + 0x34 ,mlen,mlen);

     if (gverbose) hexdump((char *)&(c->data), 0, c->len, 1);

    /* Get total size of new SID data */

    for (i = 0; sarray[i].sidptr; i++) sidlen += sarray[i].len;

    if (gverbose) printf("put_grp_members_sid: new count : %d, new sidlen: %x\n",i,sidlen);

    /* Resize buffer with C structure */
    c = realloc(c, 4 + mofs + sidlen + 0x34); /* offset of SIDs + sids lenght + pointer list at start */
    c->len = 0x34 + mofs + sidlen;

    cd = (struct group_C *)&c->data;
    mofs = cd->members_ofs;
    sidptr = &cd->data[mofs];

    for (i = 0; sarray[i].sidptr; i++) {
      if (gverbose)
      {
          printf("  copying : %d len %x, at %x\n",i,sarray[i].len, (unsigned int)sidptr);
          str = sam_sid_to_string(sarray[i].sidptr);
          printf("  Member # %d = <%s>\n", i, str);
          FREE(str);
      }

      memcpy(sidptr, sarray[i].sidptr, sarray[i].len);
      sidptr += sarray[i].len;
    }

    cd->members_len = sidlen;  /* Update member count in C struct */
    cd->grp_members = i;

    if (gverbose) hexdump((char *)&(c->data), 0, c->len, 1);

    if (!put_buf2val(hdesc, c, 0, g, 0, TPF_VK_EXACT)) {
      fprintf(stderr,"put_grp_members_sid: could not write back group info in value %s\n",g);
      free(c);
      return(0);
    }


    free(c);

  } else {
    printf("Group info for %x not found!\n",grp);
    return(0);
  }
  
  return(1);

}



/* Get group IDs a user is member of
 * rid = user ID
 * returns: since value data is just an array of grp ids (4 bytes each),
 *          just return the keyval structure (size + data)
 * caller must free() keyval
 */

struct keyval *sam_get_user_grpids(struct hive *hdesc, int rid)
{
  char s[200];
  struct sid_binary sid;
  char *sidstr;

  int nk = 0;
  struct keyval *m = NULL;
  struct keyval *result = NULL;
  struct keyval *newresult = NULL;
  int count = 0;
  int size;
  int n;

  if (!rid || (hdesc->type != HTYPE_SAM)) return(NULL);

  if (!sam_get_machine_sid(hdesc, (char *)&sid)) {
    fprintf(stderr,"sam_get_user_grpids: Could not find machine SID\n");
    return(0);
  }

  sidstr = sam_sid_to_string(&sid);

  /* Get member list for user on this machine */

  n = 0;  /* Look up user RID under computer SID under builtin and account path */
  while (*SAM_GRPMEMBERSPATH[n]) {

    snprintf(s, 180, SAM_GRPMEMBERSPATH[n], sidstr, rid);

    if (gverbose) printf("sam_get_user_grpids:  member path: %s\n",s);

    nk = trav_path(hdesc, 0, s, 0);

    if (nk) {   /* Found a key */
 
      /* Now, the TYPE field is the number of groups the user is member of */
      /* Don't we just love the inconsistent use of fields!! */
      nk += 4;
      count = get_val_type(hdesc,nk,"@",TPF_VK_EXACT);
      if (count == -1) {
	printf("sam_get_user_grpids: Cannot find default value <%s\\@>\n",s);
	n++;
	continue;
      }
      
      //  printf("sam_get_user_grpids: User is member of %d groups:\n",count);
  
      /* This is the data size */
      size = get_val_len(hdesc,nk,"@",TPF_VK_EXACT);
      
      /* It should be 4 bytes for each group */
      // if (gverbose) printf("Data size %d bytes.\n",size);
      if (size != count * 4) {
	printf("sam_get_user_grpids: DEBUG: Size is not 4 * count! May not matter anyway. Continuing..\n");
      }
      
      m = get_val2buf(hdesc, NULL, nk, "@", 0, TPF_VK_EXACT);
      if (!m) {
	printf("sam_get_user_grpids: Could not get value data! Giving up.\n");
	FREE(sidstr);
	return(NULL);
      }

      /* At this point we have a value containing member list from this part of the tree */
      /* Just append this one to the earlier ones */

      newresult = reg_valcat(result, m);
      FREE(m);
      FREE(result);
      result = newresult;

    }

    n++;
  }

  FREE(sidstr);

 if (!result) {
   /* This probably means user is not in any group. Seems to be the case
      for a couple of XPs built in support / guest users. So just return */
   if (gverbose) printf("sam_get_user_grpids: Cannot find RID under computer SID <%s>\n",s);
   return(NULL);
 }
 
 // printf(" sam_get_user_grpids done\n");
 return(result);
}

/* Put/set group IDs a user is member of
 * rid = user ID
 * val = keyval structure of data, actual value data is a list
 *       of ints, one per group
 * returns true if successful setting the value
 */

int sam_put_user_grpids(struct hive *hdesc, int rid, struct keyval *val)
{
  char s[200];
  char news[200];
  char ks[12];
  struct nk_key *newkey = NULL;
  struct sid_binary sid;
  char *sidstr;

  int n, grp, pnum;
  int newcount = 0;
  int nk = 0;
  int count = 0;
  struct keyvala *v;
  struct keyvala *new;
  struct keyvala entry;

  /* Pointers to value lists for each group path in use */
  struct keyval *p[SAM_NUM_GROUPPATHS];

  if (!rid || (hdesc->type != HTYPE_SAM)) return(0);

  if (!val) return(0);

#if 0
  if (!val->len) {
    printf("sam_put_user_grpids: zero list len\n");
    //    return(0);
  }
#endif

  v = (struct keyvala *)val;

  if (!sam_get_machine_sid(hdesc, (char *)&sid)) {
    fprintf(stderr,"sam_put_user_grpids: Could not find machine SID\n");
    return(0);
  }
  sidstr = sam_sid_to_string(&sid);

  for (n = 0; n < SAM_NUM_GROUPPATHS; n++) {
    ALLOC(p[n], sizeof(struct keyvala), 1);
    p[n]->len = 0;
    p[n]->data = 0;

  }

  /* Split value list into relevant stuff for each path */
  for (n = 0; n < val->len >> 2; n++) {
    grp = v->data[n];
    for (pnum = 0; pnum < SAM_NUM_GROUPPATHS; pnum++) {
      snprintf(s, 180, SAM_GRPCPATHID[pnum], grp);
      // printf("sam_put_user_grpids: split path: %s\n",s);
      nk = trav_path(hdesc, 0, s, TPF_VK_EXACT);  /* Check if group is in path?? */
      if (nk) {  /* Yup, it is here */
	entry.data[0] = grp;
	entry.len = 4;
	// printf("sam_put_user_grpids: path match for grp ID: %x\n", entry.data[1]);
	new = (struct keyvala *)reg_valcat( p[pnum], (struct keyval *)&entry);
	FREE( p[pnum] );
	p[pnum] = (struct keyval *)new;
      }
    }
  }


  /* Now put the lists into the correct place */

  for (n = 0; n < SAM_NUM_GROUPPATHS; n++) {

    /* Get member list for user on this machine */
    snprintf(s,180,SAM_GRPMEMBERSPATH[n] ,sidstr, rid);
    // printf("sam_put_user_grpids: putting for path: %s\n",s);

    newcount = p[n]->len >> 2;
    
    // printf("--- list for that path has len: %d\n",p[n]->len);
    for (pnum = 0; pnum < p[n]->len >> 2; pnum++) {
      new = (struct keyvala *)p[n];
      // printf("%d : %x\n", pnum, new->data[pnum]);
    }


    /* Find users member list under this path */

    nk = trav_path(hdesc, 0, s, 0);
    if (!nk) {
      /* User is not in any group in this path, see if we need to create key */

      if (gverbose) printf("sam_put_user_grpids: Cannot find path <%s>\n",s);
      if (!newcount) continue; /* Nothing to put there anyway, so just try next path */

      snprintf(news,180,SAM_GRPSIDPATH[n] ,sidstr);
      // snprintf(ks, 180, "%08X", rid);

      // printf("sam_put_user_grpids: creating key <%s> on path <%s>\n",ks,news);

      nk = trav_path(hdesc, 0, news, 0);
     
      newkey = add_key(hdesc, nk+4, ks);
      if (!newkey) {
	fprintf(stderr,"sam_put_user_grpids: ERROR: creating group list key for RID <%08x> under path <%s>\n",rid,news);
	abort();
      }

      nk = trav_path(hdesc, 0, s, 0);

      if (!add_value(hdesc, nk+4, "@", 0)) {
	fprintf(stderr,"sam_put_user_grpids: ERROR: creating group list default value for RID <%08x> under path <%s>\n",rid,news);
	abort();
      }
    }
    
    nk += 4;

    /* Now, the TYPE field is the number of groups the user is member of */
    
    count = get_val_type(hdesc, nk,"@", TPF_VK_EXACT);
    if (count == -1) {
      printf("sam_put_user_grpids: Cannot find value <%s\\@>\n",s);
      return(1);
    }
    
    if (gverbose) printf("sam_put_user_grpids: User was member of %d groups:\n",count);
    
    /* This is the data size */
    /* It should be 4 bytes for each group */
    
    
    if (gverbose) printf("Data size %d bytes.\n",p[n]->len);
    if (p[n]->len != newcount << 2) {
      printf("set_user_grpids: DEBUG: Size is not 4 * count! May not matter anyway. Continuing..\n");
    }
    
    if (gverbose) printf("sam_put_user_grpids: User is NOW member of %d groups:\n",newcount);
    
    if (newcount == 0) {  /* Seems windows removes the key and default subvalue when user not in any group */

      // printf("sam_put_user_grpids: removing user reference for path %s\n",s);
      del_value(hdesc, nk, "@", TPF_VK_EXACT);
      nk = trav_path(hdesc, nk, "..", 0);
      snprintf(s,180, "%08X", rid);
      del_key(hdesc, nk + 4, s);      

    } else { /* Stuff back list into default value */

      set_val_type(hdesc, nk, "@", TPF_VK_EXACT, newcount);
      if (!put_buf2val(hdesc, p[n], nk, "@", 0, TPF_VK_EXACT) ) {
	printf("sam_put_user_grpids: Could not set reg value data!\n");
	return(0);
      }

    }


  } /* for path loop */

  FREE(sidstr);

  for (n = 0; n < SAM_NUM_GROUPPATHS; n++) {
    FREE(p[n]);
  }


  printf("sam_put_user_grpids: success exit\n");
  return(1);


}




/********* GROUP / USER MANIPULATION ROUTINES **************/

/* Add SID to a group
 * SID = any SID
 * grp = group ID
 * return true if success
 */

int sam_add_sid_to_grp(struct hive *hdesc, struct sid_binary * sid, int grp)
{
    struct sid_array *sarray, *narray;
    struct sid_binary *usid = sid;
    int members, newmembers;
    char *str;
    int o, n, hit, c;

    if (!sid || !grp || (hdesc->type !=HTYPE_SAM) ) return(0);

    if (gverbose)
    {
        str = sam_sid_to_string(usid);
        printf("sam_add_sid_to_grp: user SID is <%s>\n", str);
        free(str);
    }

    /* Just add SID to group, SID without RID situation like AD users
     */

    members = sam_get_grp_members_sid(hdesc, grp, &sarray);

    if (!sarray) {
      printf("sam_add_sid_to_grp: group # %x not found!\n",grp);
      return(0);
    }
    if (gverbose)
    {
        printf("add_user_to_grp: grp memberlist BEFORE:\n");

        for (o = 0; sarray[o].sidptr; o++)
        {
            str = sam_sid_to_string(sarray[o].sidptr);
            printf("  Member # %d = <%s>\n", o, str);
            FREE(str);
            }
    }

    newmembers = members + 1;
    ALLOC(narray, sizeof(struct sid_array) * (newmembers + 2), 1);  /* Add one entry size */

    if (gverbose) printf("members = %d\n", members);

    hit = 0;
    for (o = 0, n = 0; o <= members; o++, n++) {
      c = sam_sid_cmp(sarray[o].sidptr, usid);     /* Compare slot with new SID */
      if (gverbose) printf("sam_sid_cmp returns %d\n",c);
      if (c == 0) {
        newmembers--;                   /* Already there, don't change anything */
        hit = 1;
      }
      if (!hit && ((c > 0) || !sarray[o].sidptr)) {              /* Next is higher, insert new SID */
        if (gverbose) printf("  -- add\n");
        narray[n].len = usid->sections * 4 + 8;     /* Hmm */
        narray[n].sidptr = usid;
        n++;
        hit = 1;
      }
      narray[n].len = sarray[o].len;
      narray[n].sidptr = sarray[o].sidptr;
    }

    if (gverbose)
    {
        printf("sam_add_sid_to_grp: grp memberlist AFTER:\n");

        for (o = 0; narray[o].sidptr; o++)
        {
            str = sam_sid_to_string(narray[o].sidptr);
            printf("  Member # %u = <%s>\n", o, str);
           FREE(str);
        }
    }

    if ( !sam_put_grp_members_sid(hdesc, grp, narray) )
    {
        fprintf(stderr,"sam_add_sid_to_grp: failed storing groups user list\n");
        sam_free_sid_array(narray);
        FREE(sarray);
        return(0);
    }
    sam_free_sid_array(narray);
    FREE(sarray);     /* Pointers was copied to narray, and freed above, just free the array here */

    return(1);
}

/* Remove SID from a group
 * SID = any SID
 * grp = group ID
 * return true if success
 */

int sam_remove_sid_from_grp(struct hive *hdesc, struct sid_binary * sid, int grp)
{
    struct sid_array *sarray, *narray;
    struct sid_binary *usid = sid;
    int members, newmembers;
    char *str;
    int o, n, hit, c;

    if (!sid || !grp || (hdesc->type !=HTYPE_SAM) ) return(0);

    members = sam_get_grp_members_sid(hdesc, grp, &sarray);

    if (!sarray) {
      printf("sam_remove_sid_from_grp: group # %x not found!\n",grp);
      return(0);
    }

    /* Remove the user SID from the groups list of members */

    if (gverbose)
    {
        printf("sam_remove_sid_from_grp: grp memberlist BEFORE:\n");
        for (o = 0; sarray[o].sidptr; o++)
        {
            str = sam_sid_to_string(sarray[o].sidptr);
            printf("  Member # %d = <%s>\n", o, str);
            FREE(str);
        }
    }

    newmembers = members;
    ALLOC(narray, sizeof(struct sid_array) * (newmembers + 2), 1);

    if (gverbose) printf("members = %d\n", members);

    hit = 0;
    for (o = 0, n = 0; o <= members; o++, n++) {
      c = sam_sid_cmp(sarray[o].sidptr, usid);     /* Compare slot with new SID */
      if (gverbose) printf("sid_cmp returns %d\n",c);
      if (c == 0) {
        newmembers--;                   /* Found, skip copy and decrease list size */
        hit = 1;
        n--;
      } else {
        narray[n].len = sarray[o].len;        /* Copy entry */
        narray[n].sidptr = sarray[o].sidptr;
      }
    }
    if (!hit) fprintf(stderr, "sam_remove_sid_from_grp: NOTE: user not in groups list of users, may mean user was not member at all. Does not matter, continuing.\n");

    if (gverbose)
    {
        printf("sam_remove_sid_from_grp: grp memberlist AFTER:\n");

        for (o = 0; narray[o].sidptr; o++)
        {
            str = sam_sid_to_string(narray[o].sidptr);
            printf("  Member # %u = <%s>\n", o, str);            
            FREE(str);
        }
    }
    if ( !sam_put_grp_members_sid(hdesc, grp, narray) )
    {
        fprintf(stderr,"sam_remove_sid_from_grp: failed storing groups user list\n");
        sam_free_sid_array(narray);
        FREE(sarray);
        return(0);
    }
    sam_free_sid_array(narray);
    FREE(sarray);     /* Pointers was copied to narray, and freed above, just free the array here */

    return(1);
}

/* Add user to a group
 * rid = user RID
 * grp = group ID
 * return true if success
 */

int sam_add_user_to_grp(struct hive *hdesc, int rid, int grp)
{
  struct keyvala *usrgrplist, *newusrgrplist;
  struct sid_array *sarray, *narray;
  struct sid_binary *usid;
  struct sid_binary msid;
  int members, newmembers;
  char *str;
  int ugcnt;
  int o,n,hit,c;
  unsigned int *og, *ng;
  char s[200];


  if (!rid || !grp || (hdesc->type !=HTYPE_SAM) ) return(0);

  snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\%08X\\V",rid);
  if (!trav_path(hdesc, 0, s, TPF_VK_EXACT)) {
    fprintf(stderr,"sam_add_user_to_grp: user # %x not found!\n",rid);
    return(0);
  }

  /* Build user SID (add RID to machine SID) */

  if (!sam_get_machine_sid(hdesc, (char *)&msid)) {
    fprintf(stderr,"sam_add_user_to_grp: Could not find machine SID\n");
    return(0);
  }

  /* well, and hope that machine SID is always same size here too */
  ALLOC(usid, sizeof(struct sid_binary) +4, 1);

  memcpy(usid, &msid, sizeof(struct sid_binary));

  usid->array[4] = rid; /* Tack RID on at end */
  usid->sections = 5;

  str = sam_sid_to_string(usid);

  if (gverbose) printf("add_user_to_grp: user SID is <%s>\n", str);

  free(str);

  /* With all of the above functions, it should now just be to get
   * the list of groups the user account has listed under it
   * and the list of users the group has listed under it
   */

  usrgrplist = (struct keyvala *)sam_get_user_grpids(hdesc, rid);

  if (!usrgrplist) {
    printf("sam_add_user_to_grp: user # %x WAS IN NO GROUPS!\n",rid);
    /* So make new blank list for it */
    ALLOC(usrgrplist, sizeof(struct keyvala), 1);
    usrgrplist->len = 0;
    usrgrplist->data[0] = 0;
  }
  

  members = sam_get_grp_members_sid(hdesc, grp, &sarray);

  if (!sarray) {
    printf("sam_add_user_to_grp: group # %x not found!\n",grp);
    FREE(usrgrplist);
    return(0);
  }


  /* Add the group to the users list of groups it is member of */
 
  ugcnt = usrgrplist->len >> 2;      /* Count of groups already on user */

  /* Allocate new larger usrgrplist for one more entry */

  ALLOC(newusrgrplist, usrgrplist->len + 4 + 4, 1);
  bzero(newusrgrplist, usrgrplist->len + 4 + 4);      /* for sanity.. */
  newusrgrplist->len = usrgrplist->len + 4;

  og = (unsigned int *)&usrgrplist->data;
  ng = (unsigned int *)&newusrgrplist->data;

  if (gverbose) printf("usrgrplist-len = %d\n", usrgrplist->len);


#if 0   /* If list should be sorted, but seems windows does not do that? */

  /* Copy over users group list, adding in where needed */

  hit = 0;
  for (o = 0, n = 0; o < ugcnt; o++, n++) { 
    printf(":: %d %d : %x\n",o,n,og[o]);
    if (og[o] == grp) {     /* Was already in there, so just don't increase size.. */
      newusrgrplist->len = usrgrplist->len;
      hit = 1;
    }
    if (og[o] > grp && !hit) {
      ng[n++] = grp;     /* Next is higher, so insert out rid */
      hit = 1;
      printf("  -- insert\n");
    }
    ng[n] = og[o];
  }
  printf("n = %d\n",n);
  if (!hit) ng[n] = grp;    /* Insert at end if we run down */

#endif

  /* Copy over users group list, checking if already there */

  hit = 0;
  for (o = 0; o < ugcnt; o++) { 
    if (gverbose) printf(":: %d : %x\n",o,og[o]);
    if (og[o] == grp) {     /* Was already in there, so just don't increase size.. */
      newusrgrplist->len = usrgrplist->len;
      hit = 1;
      if (gverbose) printf("  -- match\n");
    }
    ng[o] = og[o];
  }
  if (gverbose) printf(" - end of list at o = %d\n",o);

  if (!hit) ng[o] = grp;  /* Just stuff new group in at end if not already in list */

  if (gverbose) {
  for (o = 0; o < (newusrgrplist->len >> 2); o++) {
    printf("grp index %d = %08x\n", o, ng[o]);
  }
  }
  /* And then we add the user SID into the groups list of members */

  if (gverbose) {
  printf("add_user_to_grp: grp memberlist BEFORE:\n");

  for (o = 0; sarray[o].sidptr; o++) {
    str = sam_sid_to_string(sarray[o].sidptr);
    printf("  Member # %d = <%s>\n", o, str);
    FREE(str);
  }
  }

  newmembers = members + 1;
  ALLOC(narray, sizeof(struct sid_array) * (newmembers + 2), 1);  /* Add one entry size */
  
  if (gverbose) printf("members = %d\n", members);

  hit = 0;
  for (o = 0, n = 0; o <= members; o++, n++) {
    c = sam_sid_cmp(sarray[o].sidptr, usid);     /* Compare slot with new SID */
    if (gverbose) printf("sam_sid_cmp returns %d\n",c);
    if (c == 0) {
      newmembers--;                   /* Already there, don't change anything */
      hit = 1;
    }
    if (!hit && ((c > 0) || !sarray[o].sidptr)) {              /* Next is higher, insert new SID */
      if (gverbose) printf("  -- add\n");
      narray[n].len = usid->sections * 4 + 8;     /* Hmm */
      narray[n].sidptr = usid;
      n++;
      hit = 1;
    }
    narray[n].len = sarray[o].len;
    narray[n].sidptr = sarray[o].sidptr;
  }
 
  if (gverbose) {
  printf("add_user_to_grp: grp memberlist AFTER:\n");


  for (o = 0; narray[o].sidptr; o++) {
    str = sam_sid_to_string(narray[o].sidptr);
    printf("  Member # %d = <%s>\n", o, str);
    FREE(str);
  }
  }

  /* Write new lists back to registry */
  if (!sam_put_user_grpids(hdesc, rid, (struct keyval *)newusrgrplist)) {
    fprintf(stderr, "add_user_to_grp: failed storing users group list\n");
  } else if (!sam_put_grp_members_sid(hdesc, grp, narray)) {
    fprintf(stderr,"add_user_to_grp: failed storing groups user list\n");
    sam_put_user_grpids(hdesc, rid, (struct keyval *)usrgrplist);      /* Try to roll back */
  }
  
  FREE(usrgrplist);
  FREE(newusrgrplist);
  sam_free_sid_array(narray);
  FREE(sarray);     /* Pointers was copied to narray, and freed above, just free the array here */

  return(1);

}

/* Remove user from a group
 * rid = user RID
 * grp = group ID
 * return true if success
 */

int sam_remove_user_from_grp(struct hive *hdesc, int rid, int grp)
{
  struct keyvala *usrgrplist, *newusrgrplist;
  struct sid_array *sarray, *narray;
  struct sid_binary *usid;
  struct sid_binary msid;
  int members, newmembers;
  char *str;
  int ugcnt;
  int o,n,hit,c;
  unsigned int *og, *ng;



  if (!rid || !grp || (hdesc->type != HTYPE_SAM)) return(0);

  /* Build user SID (add RID to machine SID) */

  if (!sam_get_machine_sid(hdesc, (char *)&msid)) {
    fprintf(stderr,"sam_remove_user_from_grp: Could not find machine SID\n");
    return(0);
  }

  /* well, and hope that machine SID is always same size here too */
  ALLOC(usid, sizeof(struct sid_binary) +4, 1);

  memcpy(usid, &msid, sizeof(struct sid_binary));

  usid->array[4] = rid; /* Tack RID on at end */
  usid->sections = 5;

  if (gverbose) {
    str = sam_sid_to_string(usid);
    printf("remove_user_from_grp: user SID is <%s>\n", str);
    free(str);
  }

  /* With all of the above functions, it should now just be to get
   * the list of groups the user account has listed under it
   * and the list of users the group has listed under it
   */

  usrgrplist = (struct keyvala *)sam_get_user_grpids(hdesc, rid);

  if (!usrgrplist) {
    printf("remove_user_from_grp: user # %x not found!\n",rid);
    return(0);
  }
  

  members = sam_get_grp_members_sid(hdesc, grp, &sarray);

  if (!sarray) {
    printf("remove_user_from_grp: group # %x not found!\n",grp);
    FREE(usrgrplist);
    return(0);
  }


  /* Add the group to the users list of groups it is member of */
 
  ugcnt = usrgrplist->len >> 2;      /* Count of groups already on user */

  /* Allocate same size usrgrplist, since we don't know if we are in there and need to be removed */

  ALLOC(newusrgrplist, usrgrplist->len + 4, 1);
  bzero(newusrgrplist, usrgrplist->len + 4);      /* for sanity.. */
  newusrgrplist->len = usrgrplist->len;

  og = (unsigned int *)&usrgrplist->data;
  ng = (unsigned int *)&newusrgrplist->data;

  if (gverbose) printf("usrgrplist-len = %d\n", usrgrplist->len);


  /* Copy over users group list, if relevant group found, don't copy it over */

  hit = 0;
  for (o = 0; o < ugcnt; o++) { 
    if (gverbose) printf(":: %d : %x\n",o,og[o]);
    if (og[o] == grp) {     /* Group found */
      hit = 1;
      if (gverbose) printf("  -- match\n");
    } else {
      ng[o-hit] = og[o];
    }
  }
  if (gverbose) printf(" - end of list at o = %d\n",o);
  if (hit) {
    newusrgrplist->len -= 4;  /* Decrease size if found */
  } else {
    fprintf(stderr, "remove_user_from_grp: NOTE: group not in users list of groups, may mean user not member at all. Safe. Continuing.\n");
  }


  if (gverbose) {
  for (o = 0; o < (newusrgrplist->len >> 2); o++) {
    printf("grp index %d = %08x\n", o, ng[o]);
  }

  /* Remove the user SID from the groups list of members */

  printf("remove_user_from_grp: grp memberlist BEFORE:\n");

  for (o = 0; sarray[o].sidptr; o++) {
    str = sam_sid_to_string(sarray[o].sidptr);
    printf("  Member # %d = <%s>\n", o, str);
    FREE(str);
  }
  }

  newmembers = members;
  ALLOC(narray, sizeof(struct sid_array) * (newmembers + 2), 1);
  
  if (gverbose) printf("members = %d\n", members);


  hit = 0;
  for (o = 0, n = 0; o <= members; o++, n++) {
    c = sam_sid_cmp(sarray[o].sidptr, usid);     /* Compare slot with new SID */
    if (gverbose) printf("sid_cmp returns %d\n",c);
    if (c == 0) {
      newmembers--;                   /* Found, skip copy and decrease list size */
      hit = 1;
      n--;
    } else {
      narray[n].len = sarray[o].len;        /* Copy entry */
      narray[n].sidptr = sarray[o].sidptr;
    }
  }
  if (!hit) fprintf(stderr, "remove_user_from_grp: NOTE: user not in groups list of users, may mean user was not member at all. Does not matter, continuing.\n");
 
  if (gverbose) {
  printf("remove_user_from_grp: grp memberlist AFTER:\n");
  for (o = 0; narray[o].sidptr; o++) {
    str = sam_sid_to_string(narray[o].sidptr);
    printf("  Member # %d = <%s>\n", o, str);
    FREE(str);
  }
  }

  /* Write new lists back to registry */
  if (!sam_put_user_grpids(hdesc, rid, (struct keyval *)newusrgrplist)) {
    fprintf(stderr, "remove_user_from_grp: failed storing users group list\n");
  } else if (!sam_put_grp_members_sid(hdesc, grp, narray)) {
    fprintf(stderr,"remvoe_user_from_grp: failed storing groups user list\n");
    sam_put_user_grpids(hdesc, rid, (struct keyval *)usrgrplist);      /* Try to roll back */
  }
  
  FREE(usrgrplist);
  FREE(newusrgrplist);
  sam_free_sid_array(narray);
  FREE(sarray);     /* Pointers was copied to narray, and freed above, just free the array here */

  return(1);

}


/* TODO: So.. having listing functions in library.. should better be handled by tools.. */

/* List users membership or check if admin (is in admin group)
 * rid   - users rid
 * check - if 1 just check if admin, do not list
 * returns true if user is admin
 */

int sam_list_user_groups(struct hive *hdesc, int rid, int check)
{
  char groupname[128];
  struct keyval *m = NULL, *c = NULL;
  struct group_C *cd;
  unsigned int *grps;
  int count = 0, isadmin = 0;
  int i, grp, grpnamoffs, grpnamlen;

  if (!rid || (hdesc->type != HTYPE_SAM) ) return(0);

  m = sam_get_user_grpids(hdesc, rid);

  if (!m) return(0);

  grps = (unsigned int *)&m->data;
  count = m->len >> 2;

  for (i = 0; i < count; i++) {
    grp = grps[i];
    if (!check) printf("%08x ",grp);

    if (grp == 0x220) isadmin = 1;

    if (!check) {
      c = sam_get_grpC(hdesc, grp);
      if (c) {
	cd = (struct group_C *)&c->data;
	grpnamoffs = cd->grpname_ofs + 0x34;
	grpnamlen  = cd->grpname_len;
	
	cheap_uni2ascii((char *)cd + grpnamoffs, groupname, grpnamlen);
	
	printf("= %s (which has %d members)\n",groupname,cd->grp_members);

	//	get_grp_members_sid(grp, &sidbuf);

      } else {
	printf("Group info for %x not found!\n",grp);
      }
    }
  }

  free(m);

  return(isadmin);
}




/* List users in SAM file
 * readable - 1 = list in human readable form, 0 = colon-separated, 2 = quiet, no ouput (find admin)
 * return logic:
 * If no users / error: 0
 * If only 0x1f4 (built-in adminsitrator) is admin (or no one at all in admin group), return 0x1f4
 * Else return lowest numbered user that is in admin group
 *
 * Fields ouput in parsable listing (all numbers in hex)
 * rid:username:isadmin:acb:hashlen
 * rid = User RID
 * isadmin = (boolean flag) 1 user is admin, 0 is not
 * acb = ACB account bits
 * hashlen = lenght of password hash, 14 is normal if has passwd, 4 if blank
 */

char SAMdaunPATH[] = "\\SAM\\Domains\\Account\\Users\\Names\\";

int sam_list_users(struct hive *hdesc, int readable)
{
  char s[200];
  struct keyval *v;
  int nkofs /* ,vkofs */ ;
  int rid;
  int count = 0, countri = 0;
  int ntpw_len;

  int admrid = 0x1f4;
  int isadm;

  unsigned short acb;

  struct user_V *vpwd;
  struct ex_data ex;
  
  if (hdesc->type != HTYPE_SAM) return(0);

  nkofs = trav_path(hdesc, 0, SAMdaunPATH, 0);
  if (!nkofs) {
    printf("sam_list_users: Cannot find usernames in registry! (is this a SAM-hive?)\n");
    return(0);
  }

  if (readable == 1) printf("| RID -|---------- Username ------------| Admin? |- Lock? --|\n");

  while ((ex_next_n(hdesc, nkofs+4, &count, &countri, &ex) > 0)) {

    /* Extract the value out of the username-key, value is RID  */
    snprintf(s,180,"%s%s\\@",SAMdaunPATH, ex.name);
    rid = get_dword(hdesc, 0, s, TPF_VK_EXACT|TPF_VK_SHORT);

    /* Now that we have the RID, build the path to, and get the V-value */
    snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\%08X\\V",rid);
    v = get_val2buf(hdesc, NULL, 0, s, REG_BINARY, TPF_VK_EXACT);
    if (!v) {
      printf("Cannot find value <%s>\n",s);
      return(1);
    }
    
    if (v->len < 0xcc) {
      printf("sam_list_users: Value <%s> is too short (only %d bytes) to be a SAM user V-struct!\n",
	     s, v->len);
    } else {

      vpwd = (struct user_V *)&(v->data);
      ntpw_len = vpwd->ntpw_len;

      acb = sam_handle_accountbits(hdesc, rid, 0);
      isadm = sam_list_user_groups(hdesc, rid, 1);

      if (isadm && rid != 0x1f4) {  /* Found an non-built-in administrator */
	if (admrid == 0x1f4) admrid = rid;  /* Prefer anything over built-in one */
	if (rid < admrid) admrid = rid;
      }

      if (readable == 1) {
	printf("| %04x | %-30.30s | %-6s | %-8s |\n",
	       rid, ex.name, ( isadm ? "ADMIN" : "") , (  acb & 0x8000 ? "dis/lock" : (ntpw_len < 16) ? "*BLANK*" : "")  );
      } else if (readable == 0) {
	printf("%04x:%s:%d:%x:%x\n",
	       rid, ex.name, isadm , acb, ntpw_len );
      }
      

      //      change_pw( (char *)&v->data , rid, v->len, (*automode == 'l') ? 2 : 1);

    }
    FREE(v);
    FREE(ex.name);
  }
  return(admrid);
}



/* Get username when we have a RID
 * hdesc - hive
 * rid - just that.. :)
 * returns allocated string with username, caller must free it
 * or NULL if RID not found in local databse
 */

char *sam_get_username(struct hive *hdesc, int rid)
{
  char s[200];
  char *username = NULL;
  int username_offset,username_len;
  struct user_V *v;
  struct keyval *value;
  int vlen;
  char *vp;

  snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\%08X\\V",rid);
  value = get_val2buf(hdesc, NULL, 0, s, REG_BINARY, TPF_VK_EXACT);
  if (!value) {
    printf(" sam_get_username: ERROR: User with RID 0x%x not found, path <%s>\n",rid,s);
    return(NULL);
  }
  
  vlen = value->len;
  if (vlen < 0xcc) {
    printf(" sam_get_username: Value <%s> is too short (only %d bytes) to be a SAM user V-struct!\n",
	   s, vlen);
    FREE(value);
    return(NULL);
  }
  
  v = (struct user_V *)&value->data;
  vp = (char *)&value->data;
  
  username_offset = v->username_ofs;
  username_len    = v->username_len; 

  if(username_len <= 0 || username_len > vlen ||
     username_offset <= 0 || username_offset >= vlen)
    {
      printf(" sam_get_username: Not a legal V struct? (negative struct lengths)\n");
      FREE(value);
      return(0);
    }
  
  /* Offsets in top of struct is relative to end of pointers, adjust */
   username_offset += 0xCC;
   
   ALLOC(username, 2, (username_len >> 1) + 4);
   *username = 0;
   cheap_uni2ascii(vp + username_offset,username,username_len);
   
   if (gverbose) {
     printf("RID     : %04d [%04x]\n",rid,rid);
     printf("Username: %s\n",username);
   }

   FREE(value);
   return(username);

}




/* Get username from SID:
 * Local database if matching machine SID
 * Well known SIDs if in list
 * Else probably domain SID, don't know how to find more info
 *
 * sid = sid to extract RID from
 *
 * returns a string (which must be free()d)  or NULL if not able to resolve
 */

char *sam_get_username_from_sid(struct hive *hdesc, struct sid_binary *sid)
{
  int rid;
  char *str;
  int i;
  struct sid_binary msid;

  struct known_sidentry {
    int val;
    char *name;
  };

  const struct known_sidentry ntauthority_table[] = {
    { 4, "INTERACTIVE" },
    { 11, "Authenticated Users" },
    { 17, "IUSR" }, 
    { 20, "NETWORK SERVICE" },
    { 0, "" }
  };
 

  if (!sid) return(NULL);
  if(sid->sections < 1) return(NULL);

  rid = sid->array[sid->sections-1];

  if (sid->sections != 5) {
    //    fprintf(stderr," WARNING: sam_get_rid_from_sid: Strange size SID, sections = %d, not 5, got rid = %d\n",sid->sections, rid);

    if (sid->sections == 1) {
      if (sid->authority == 5) { /* We only handle S-1-5 (NTAUTHORITY) known names yet */
	str = str_dup("NT AUTHORITY\\");
	for (i = 0; ntauthority_table[i].val; i++) {
	  if (rid == ntauthority_table[i].val) {
	    str = str_cat(str, ntauthority_table[i].name);
	    return(str);
	  }
	  
	}
	
      } else {  /* Not NT AUTHORITY */
	return(sam_sid_to_string(sid));
      }
    } /* sections */
    return(sam_sid_to_string(sid));
  }


  if (sam_get_machine_sid(hdesc, (char *)&msid)) {

    sid->sections--;  /* Don't compare RID part */
    if (!sam_sid_cmp(sid, &msid)) {
      sid->sections++;
      return(sam_get_username(hdesc, rid));  /* Match, find and return local username */
    } else {
      sid->sections++;
      return(sam_sid_to_string(sid)); /* No match with local machine SID, so just return SID string */
    }
    
  }

  /* If we get here we don't have a machine SID, so, well, try to get a local name anyway */
  return(sam_get_username(hdesc, rid));

}


/* List groups in SAM
 * hdesc - the hive
 * listmembers - true = list groups members also, else just group id/name etc
 * human = human readable form (true) or parsable (false)
 *
 * Format of group list:
 *    grpid:grpname:membercount
 * Format of membership list:
 *    grpid:grpname:index:rid:username:usersid
 * where index is just the ordinal number in the groups membership list (starts at 0)
 * grpid and rid is in hex
 */

void sam_list_groups(struct hive *hdesc, int listmembers, int human) {

  struct ex_data ex;
  struct sid_array *sids = NULL;
  int nkofs;
  unsigned int grp;
  int count,countri;
  struct keyval *c = NULL;
  struct group_C *cd;
  int grpnamoffs, grpnamlen, i;
  char groupname[200];
  char *str;
  char *username;
  int pnum = 0;

  if (hdesc->type != HTYPE_SAM) return;

  while (*SAM_GRPCPATHS[pnum]) {

    // printf("  -- grp C list path: %s\n",SAM_GRPCPATHS[pnum]);

    nkofs = trav_path(hdesc, 0, SAM_GRPCPATHS[pnum], 0);
    if (!nkofs) {
      printf(" list_groups: Cannot find group list in registry! (is this a SAM-hive?)\n");
      return;
    }

    /* Pick up all subkeys here, they are local groups */
    count = 0;
    countri = 0;
    while ((ex_next_n(hdesc, nkofs+4, &count, &countri, &ex) > 0)) {
      
      // printf("Group ID %s\n",ex.name);
      sscanf(ex.name,"%x",&grp);
      
      /* Groups keys have a C value, get it and pick up the name etc */
      /* Some other keys also exists (Members, Names at least), but we skip them */
      
      c = get_val2buf(hdesc, NULL, ex.nkoffs+4, "C", 0, TPF_VK_EXACT);
      if (c) {
	cd = (struct group_C *)&c->data;
	grpnamoffs = cd->grpname_ofs + 0x34;
	grpnamlen  = cd->grpname_len;
	
	cheap_uni2ascii((char *)cd + grpnamoffs, groupname, grpnamlen);
	
	if (human) printf("=== Group #%4x : %s\n",grp,groupname);
	else if (!listmembers) printf("%x:%s:%d\n",grp,groupname,cd->grp_members);
	
	if (listmembers) {
	  sam_get_grp_members_sid(hdesc, grp, &sids); 
	  
	  for (i = 0; sids[i].sidptr; i++) {
	    str = sam_sid_to_string(sids[i].sidptr);
	    username = sam_get_username_from_sid(hdesc, sids[i].sidptr);
	    if (human) printf("  %3d | %04x | %-31s | <%s>\n", i, sids[i].sidptr->array[sids[i].sidptr->sections-1], username, str);
	    else printf("%x:%s:%d:%x:%s:%s\n", grp, groupname, i, sids[i].sidptr->array[sids[i].sidptr->sections-1], username, str);
	    
	    FREE(username);
	    FREE(str);
	    
	  }
	  sam_free_sid_array(sids);
	}
      } /* if c */
      
    }
    
    pnum++;
  } /* path loop */
}

/* Get groupname when we have a group ID
 * hdesc - hive
 * grpid - just that.. :)
 * returns allocated string with username, caller must free it
 * or NULL if RID not found in local databse
 */

char *sam_get_groupname(struct hive *hdesc, int grpid)
{

  struct keyval *value = NULL;  
  struct group_C *cd;
  int grpnamoffs;
  int grpnamlen;
  char *groupname = NULL;
  

  value = sam_get_grpC(hdesc, grpid);
  if (!value) {
    printf(" sam_get_groupname: ERROR: Group ID 0x%x not found\n",grpid);
    return(NULL);
  }


  /* Offsets in top of struct is relative to end of pointers, adjust */

  cd = (struct group_C *)&value->data;
  grpnamoffs = cd->grpname_ofs + 0x34;
  grpnamlen  = cd->grpname_len;
  
  ALLOC(groupname, 2, (grpnamlen >> 1) + 4);
  *groupname = 0;
  cheap_uni2ascii((char *)cd + grpnamoffs, groupname, grpnamlen);
  
  // printf("==== Group #%4x : %s\n",grpid,groupname);
  
  FREE(value);
  return(groupname);

}





/* Reset users password
 * hdesc - the HIVE :)
 * rid - the users RID
 *
 * Returns: 0 = OK, 1 = error (for use in exit())
 */
int sam_reset_pw(struct hive *hdesc, int rid)
{
   
   char *vp;
   static char username[128],fullname[128];
   int username_offset,username_len;
   int fullname_offset,fullname_len;
   int ntpw_len,lmpw_len,ntpw_offs,lmpw_offs;
   int vlen;
   struct user_V *v;
   struct keyval *value;
   char s[200];
  
   if (!hdesc || !rid) return(1);

   /* Now that we have the RID, build the path to, and get the V-value */
   snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\%08X\\V",rid);
   value = get_val2buf(hdesc, NULL, 0, s, REG_BINARY, TPF_VK_EXACT);
   if (!value) {
     printf(" sam_reset_pw: ERROR: User with RID 0x%x not found, path <%s>\n",rid,s);
     return(1);
   }
   
   vlen = value->len;
   if (vlen < 0xcc) {
     printf(" sam_reset_pw: Value <%s> is too short (only %d bytes) to be a SAM user V-struct!\n",
	    s, vlen);
     return(1);
   }

   v = (struct user_V *)&value->data;
   vp = (char *)&value->data;
 
   username_offset = v->username_ofs;
   username_len    = v->username_len; 
   fullname_offset = v->fullname_ofs;
   fullname_len    = v->fullname_len;
   lmpw_offs       = v->lmpw_ofs;
   lmpw_len        = v->lmpw_len;
   ntpw_offs       = v->ntpw_ofs;
   ntpw_len        = v->ntpw_len;

   if (gverbose) {
     printf(" lmpw_offs: 0x%x, lmpw_len: %d (0x%x)\n",lmpw_offs,lmpw_len,lmpw_len);
     printf(" ntpw_offs: 0x%x, ntpw_len: %d (0x%x)\n",ntpw_offs,ntpw_len,ntpw_len);
   }

   *username = 0;
   *fullname = 0;
   
   if(username_len <= 0 || username_len > vlen ||
      username_offset <= 0 || username_offset >= vlen ||
      fullname_len < 0 || fullname_len > vlen ||
      lmpw_offs < 0 || lmpw_offs >= vlen)
     {
       printf(" sam_reset_pw: Not a legal V struct? (negative struct lengths)\n");
       FREE(value);
       return(0);
     }

   /* Offsets in top of struct is relative to end of pointers, adjust */
   username_offset += 0xCC;
   fullname_offset += 0xCC;
   ntpw_offs += 0xCC;
   lmpw_offs += 0xCC;
   
   cheap_uni2ascii(vp + username_offset,username,username_len);
   cheap_uni2ascii(vp + fullname_offset,fullname,fullname_len);
   
   if (gverbose) {
     printf("RID     : %04d [%04x]\n",rid,rid);
     printf("Username: %s\n",username);
     printf("fullname: %s\n",fullname);
   }

   /* Setting hash lengths to zero seems to make NT think it is blank
    * However, we probably leak about 40 bytes since I am to lazy to adjust the rest
    * of the V structure.
    */
   v->ntpw_len = 0;
   v->lmpw_len = 0;
      
   if (!(put_buf2val(hdesc, value, 0, s, REG_BINARY, TPF_VK_EXACT))) {
     printf(" reset_pw: Failed to write updated <%s> to registry! Password change not completed!\n",s);
     FREE(value);
     return(1);
   }

   if (gverbose) printf(" reset_pw: Password cleared for user %s\n",username);
   FREE(value);
   return(0);

}


/* Reset password of ALL admin users
 * hdesc - hive
 * list - if true, list some info about users processed
 */

int sam_reset_all_pw(struct hive *hdesc, int list)
{
  char s[200];
  struct keyval *v;
  int nkofs;
  int rid;
  int isadm;
  int count = 0;
  int countri = 0;
  int fail = 0;

  struct ex_data ex;
  
  if (hdesc->type != HTYPE_SAM) return(0);

  nkofs = trav_path(hdesc, 0, SAMdaunPATH, 0);
  if (!nkofs) {
    printf("sam_reset_all_pw: Cannot find usernames in registry! (is this a SAM-hive?)\n");
    return(1);
  }

  while ((ex_next_n(hdesc, nkofs+4, &count, &countri, &ex) > 0)) {

    /* Extract the value out of the username-key, value is RID  */
    snprintf(s,180,"%s%s\\@",SAMdaunPATH, ex.name);
    rid = get_dword(hdesc, 0, s, TPF_VK_EXACT|TPF_VK_SHORT);

    /* Now that we have the RID, build the path to, and get the V-value */
    snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\%08X\\V",rid);
    v = get_val2buf(hdesc, NULL, 0, s, REG_BINARY, TPF_VK_EXACT);
    if (!v) {
      printf("sam_reset_all_pw: Cannot find value <%s>\n",s);
      return(1);
    }
    
    if (v->len < 0xcc) {
      printf("sam_reset_all_pw: Value <%s> is too short (only %d bytes) to be a SAM user V-struct!\n",
	     s, v->len);
    } else {

      isadm = sam_list_user_groups(hdesc, rid, 1);

      if (isadm) {
	if (list) printf("Reset user :%04x:%s\n", rid, ex.name );
	fail |= sam_reset_pw(hdesc, rid);
      }


    }
    FREE(v);
    FREE(ex.name);
  }
  return(fail);
}
