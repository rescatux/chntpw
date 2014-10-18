/*
 * chntpw.c - Offline Password Edit Utility for Windows SAM database
 *
 * This program uses the "ntreg" library to load and access the registry,
 * it's main purpose is to reset password based information.
 * It can also call the registry editor etc
 
 * 2011-apr: Command line options added for hive expansion safe mode
 * 2010-jun: Syskey not visible in menu, but is selectable (2)
 * 2010-apr: Interactive menu adapts to show most relevant
 *           selections based on what is loaded
 * 2008-mar: Minor other tweaks
 * 2008-mar: Interactive reg ed moved out of this file, into edlib.c
 * 2008-mar: 64 bit compatible patch by Mike Doty, via Alon Bar-Lev
 *           http://bugs.gentoo.org/show_bug.cgi?id=185411
 * 2007-sep: Group handling extended, promotion now public
 * 2007-sep: User edit menu, some changes to user info edit
 * 2007-apr-may: Get and display users group memberships
 * 2007-apr: GNU license. Some bugfixes. Cleaned up some output.
 * 2004-aug: More stuff in regedit. Stringinput bugfixes.
 * 2004-jan: Changed some of the verbose/debug stuff
 * 2003-jan: Changed to use more of struct based V + some small stuff
 * 2003-jan: Support in ntreg for adding keys etc. Editor updated.
 * 2002-dec: New option: Specify user using RID
 * 2002-dec: New option: blank the pass (zero hash lengths).
 * 2001-jul: extra blank password logic (when NT or LANMAN hash missing)
 * 2001-jan: patched & changed to use OpenSSL. Thanks to Denis Ducamp
 * 2000-jun: changing passwords regardless of syskey.
 * 2000-jun: syskey disable works on NT4. Not properly on NT5.
 * 2000-jan: Attempt to detect and disable syskey
 * 1999-feb: Now able to browse registry hives. (write support to come)
 * See HISTORY.txt for more detailed info on history.
 *
 *****
 *
 * Copyright (c) 1997-2012 Petter Nordahl-Hagen.
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
 * Information and ideas taken from pwdump by Jeremy Allison.
 *
 * More info from NTCrack by Jonathan Wilkins.
 * 
 */ 

/* TODO: This is getting ugly. Most likely best to split up into different programs
 *       and put commun stuff in library
 */


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <inttypes.h>

/* Define DOCRYPTO in makefile to include cryptostuff to be able to change passwords to
 * a new one.
 * Changing passwords is seems not to be working reliably on XP and newer anyway.
 * When not defined, only reset (nulling) of passwords available.
 */

#ifdef DOCRYPTO
#include <openssl/des.h>
#include <openssl/md4.h>
#endif

#define uchar u_char
#define MD4Init MD4_Init
#define MD4Update MD4_Update
#define MD4Final MD4_Final

#include "ntreg.h"
#include "sam.h"

const char chntpw_version[] = "chntpw version 0.99.6 110511 , (c) Petter N Hagen";

extern char *val_types[REG_MAX+1];

/* Global verbosity */
int gverbose = 0;


#define MAX_HIVES 10

/* Array of loaded hives */
struct hive *hive[MAX_HIVES+1];
int no_hives = 0;

/* Icky icky... globals used to refer to hives, will be
 * set when loading, so that hives can be loaded in any order
 */

int H_SAM = -1;
int H_SYS = -1;
int H_SEC = -1;
int H_SOF = -1;

int syskeyreset = 0;
int dirty = 0;
int max_sam_lock = 0;

/*
 * of user with RID 500, because silly MS decided
 * to localize the bloody admin-username!! AAAGHH!
 */
char admuser[129]="Administrator";

/* ============================================================== */


#ifdef DOCRYPTO

/* Crypto-stuff & support for what we'll do in the V-value */

/* Zero out string for lanman passwd, then uppercase
 * the supplied password and put it in here */

void make_lanmpw(char *p, char *lm, int len)
{
   int i;
   
   for (i=0; i < 15; i++) lm[i] = 0;
   for (i=0; i < len; i++) lm[i] = toupper(p[i]);
}

/*
 * Convert a 7 byte array into an 8 byte des key with odd parity.
 */

void str_to_key(unsigned char *str,unsigned char *key)
{
	int i;

	key[0] = str[0]>>1;
	key[1] = ((str[0]&0x01)<<6) | (str[1]>>2);
	key[2] = ((str[1]&0x03)<<5) | (str[2]>>3);
	key[3] = ((str[2]&0x07)<<4) | (str[3]>>4);
	key[4] = ((str[3]&0x0F)<<3) | (str[4]>>5);
	key[5] = ((str[4]&0x1F)<<2) | (str[5]>>6);
	key[6] = ((str[5]&0x3F)<<1) | (str[6]>>7);
	key[7] = str[6]&0x7F;
	for (i=0;i<8;i++) {
		key[i] = (key[i]<<1);
	}
	DES_set_odd_parity((des_cblock *)key);
}

/*
 * Function to convert the RID to the first decrypt key.
 */

void sid_to_key1(uint32_t sid,unsigned char deskey[8])
{
	unsigned char s[7];

	s[0] = (unsigned char)(sid & 0xFF);
	s[1] = (unsigned char)((sid>>8) & 0xFF);
	s[2] = (unsigned char)((sid>>16) & 0xFF);
	s[3] = (unsigned char)((sid>>24) & 0xFF);
	s[4] = s[0];
	s[5] = s[1];
	s[6] = s[2];

	str_to_key(s,deskey);
}

/*
 * Function to convert the RID to the second decrypt key.
 */

void sid_to_key2(uint32_t sid,unsigned char deskey[8])
{
	unsigned char s[7];
	
	s[0] = (unsigned char)((sid>>24) & 0xFF);
	s[1] = (unsigned char)(sid & 0xFF);
	s[2] = (unsigned char)((sid>>8) & 0xFF);
	s[3] = (unsigned char)((sid>>16) & 0xFF);
	s[4] = s[0];
	s[5] = s[1];
	s[6] = s[2];

	str_to_key(s,deskey);
}

/* DES encrypt, for LANMAN */

void E1(uchar *k, uchar *d, uchar *out)
{
  des_key_schedule ks;
  des_cblock deskey;

  str_to_key(k,(uchar *)deskey);
#ifdef __FreeBSD__
  des_set_key(&deskey,ks);
#else /* __FreeBsd__ */
  des_set_key((des_cblock *)deskey,ks);
#endif /* __FreeBsd__ */
  des_ecb_encrypt((des_cblock *)d,(des_cblock *)out, ks, DES_ENCRYPT);
}

#endif   /* DOCRYPTO */


/* Get machines SID as binary (raw data)
 * str = pointer to buffer, first 20 bytes will be filled in
 * returns true if found, else 0
 */

int get_machine_sid(char *sidbuf)
{

  struct accountdb_V *v;
  struct keyval *kv;
  uint32_t ofs;
  uint32_t len;

  if (H_SAM >= 0) {

    /* Get accoundb V value */
    kv = get_val2buf(hive[H_SAM], NULL, 0, ACCOUNTDB_V_PATH, REG_BINARY, TPF_VK);
    if (!kv) {
      fprintf(stderr,"get_machine_sid: Machine SID not found in SAM\n");
      return(0);
    }

    //    hexdump(&(kv->data), 0, kv->len,1);

    v = (struct accountdb_V *)&kv->data;
    ofs = v->sid_ofs;
    len = v->sid_len + 4;
    ofs += 0x40;

    if (len != SID_BIN_LEN) {
      fprintf(stderr,"get_machine_sid: WARNING: SID found, but it has len=%d instead of expected %d bytes\n",len,SID_BIN_LEN);
    }

    //    printf("get_machine_sid: adjusted ofs = %x, len = %x (%d)\n",ofs,len,len);


    memcpy(sidbuf, (char *)v+ofs, len);

    // hexdump(sidbuf, 0, len, 1);

     return(1);
  }
  return(0);
}

/* Make string out of SID, in S-1-5 authority (NT authority)
 * like S-1-5-21-516312364-151943033-2698651
 * Will allocate return string (which can be of variable lenght)
 * NOTE: caller must free it
 * sidbuf = the SID binary data structure with it's type+counter first
 * 
 * str = string buffer to fill, be sure to have at least space:
 *       6 chars athority prefix (S-1-5-)
 *       4 * 10 digits (the 4 32 bit groups)
 *       3 for the - between the groups
 *       1 for null termination
 *      50 chars
 */
char *sid_to_string(struct sid_binary *sidbuf)
{

  int cnt, i;
  int *array;
  char *str = NULL;

  //   hexdump(sidbuf, 0, 24, 1);


  array = (int *)&sidbuf->array;

  if (sidbuf->unknown0 != 1) {
    fprintf(stderr,"sid_to_string: DEBUG: first byte unexpected: %d\n",sidbuf->unknown0);
  }

  cnt = sidbuf->sections;

  // printf("sid_to_string: DEBUG: sections = %d\n",cnt);

  str = str_dup("S-1-5");

  for (i = 0; i < cnt; i++) {
    str = str_catf(str,"-%u",sidbuf->array[i]);
  }

  // printf("sid_to_string: returning <%s>\n",str);


  return(str);
}




/* Check if hive is SAM, and if it is, extract some
 * global policy information from it, like lockout counts etc
 */

void check_get_samdata(int show)
{
  struct accountdb_F *f;
  struct keyval *v;

  if (H_SAM >= 0) {

    /* Get accoundb F value */
    v = get_val2buf(hive[H_SAM], NULL, 0, ACCOUNTDB_F_PATH, REG_BINARY, TPF_VK);
    if (!v) {
      fprintf(stderr,"WARNING: Login counts data not found in SAM\n");
      return;
    }
    
    f = (struct accountdb_F *)&v->data;
    max_sam_lock = f->locklimit;

    if (show) { 
      printf("\n* SAM policy limits:\n");    
      printf("Failed logins before lockout is: %d\n",max_sam_lock);
      printf("Minimum password length        : %d\n",f->minpwlen);
      printf("Password history count         : %d\n",f->minpwlen);
    }
  }
}


/* Try to decode and possibly change account lockout etc
 * This is \SAM\Domains\Account\Users\<RID>\F
 * It's size seems to always be 0x50.
 * Params: RID - user ID, mode - 0 silent, 1 silent, 2 edit.
 * Returns: ACB bits with high bit set if lockout count is >0
 */

short handle_F(int rid, int mode)
{

  struct user_F *f;
  char s[200];
  struct keyval *v;
  unsigned short acb;
  int b;

  if (H_SAM < 0) return(0);

  /* Get users F value */
  snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\%08X\\F",rid);
  v = get_val2buf(hive[H_SAM], NULL, 0, s, REG_BINARY, TPF_VK_EXACT);
  if (!v) {
    printf("Cannot find value <%s>\n",s);
    return(0);
  }

  if (v->len < 0x48) {
    printf("handle_F: F value is 0x%x bytes, need >= 0x48, unable to check account flags!\n",v->len);
    FREE(v);
    return(0);
  }

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
    
  if (mode == 2) {
    acb |= ACB_PWNOEXP;
    acb &= ~ACB_DISABLED;
    acb &= ~ACB_AUTOLOCK;
    f->ACB_bits = acb;
    f->failedcnt = 0;
    put_buf2val(hive[H_SAM], v, 0, s, REG_BINARY,TPF_VK_EXACT);
    printf("Unlocked!\n");
  }
  return (acb | ( (f->failedcnt > 0 && f->failedcnt >= max_sam_lock)<<15 ) | (acb & ACB_AUTOLOCK)<<15 | (acb & ACB_DISABLED)<<15);
}


/* Stuff SID binary list into more easily handled arrays
 * sidbuf = binary list buffer (not changed, may point into value structure)
 * size = number of bytes of raw data
 * returns pointer to array, terminated with NULL pointer.
 * Keeps full binary data from each SID
 * All array space is allocated, call free_sid_array() to free it.
 */

struct sid_array *make_sid_array(struct sid_binary *sidbuf, int size)
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

void free_sid_array(struct sid_array *array)
{

  int num = 0;

  while (array[num].sidptr) {
    free(array[num].sidptr);
    num++;
  }

  free(array);
}

/* Compare two SIDs, and return like strcmp */
int sid_cmp(struct sid_binary *s1, struct sid_binary *s2)
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



/* Get list of group members for a group
 * Will get the SID list (as binary) into a buffer that will be allocated
 * according to the neccessary size (based on member count)
 * NOTE: Caller must free the buffer when not needed any more
 * grp = group ID
 * sidarray = pointer to pointer to sid array which will be allocated
 * Returns number of members in the group
 */

int get_grp_members_sid(int grp, struct sid_array **sarray)
{
  char g[200];
  // char groupname[128];

  struct sid_array *marray;
  struct keyval *c = NULL;
  struct group_C *cd;
  // int grpnamoffs, grpnamlen;
  int mofs, mlen;

  snprintf(g,180,"\\SAM\\Domains\\Builtin\\Aliases\\%08X\\C",grp);
  c = get_val2buf(hive[H_SAM], NULL, 0, g, 0, TPF_VK_EXACT);
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

    marray = make_sid_array((struct sid_binary *)&cd->data[mofs], mlen);

    *sarray = marray;
    // free_sid_array(marray);

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

int put_grp_members_sid(int grp, struct sid_array *sarray)
{
  char g[200];
  char groupname[128];

  struct keyval *c = NULL;
  struct group_C *cd;
  int grpnamoffs, grpnamlen;
  int mofs, mlen;
  int sidlen = 0;
  void *sidptr;
  int i;
  char *str;

  snprintf(g,180,"\\SAM\\Domains\\Builtin\\Aliases\\%08X\\C",grp);
  c = get_val2buf(hive[H_SAM], NULL, 0, g, 0, TPF_VK_EXACT);
  if (c) {
    cd = (struct group_C *)&c->data;
    
    grpnamoffs = cd->grpname_ofs + 0x34;
    grpnamlen  = cd->grpname_len;
    
    cheap_uni2ascii((char *)cd + grpnamoffs, groupname, grpnamlen);
    
    if (gverbose) printf("put_grp_members_sid: group %x named %s has %d members\n",grp,groupname,cd->grp_members);

    mofs = cd->members_ofs;
    mlen = cd->members_len;

     if (gverbose) printf("put_grp_members_sid: ajusted: mofs = %x, mlen = %x (%d)\n", mofs + 0x34 ,mlen,mlen);

     if (gverbose) hexdump(&c->data, 0, c->len, 1);

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
      if (gverbose) printf("  copying : %d len %x, at %x\n",i,sarray[i].len, sidptr);
      str = sid_to_string(sarray[i].sidptr);
      if (gverbose) printf("  Member # %d = <%s>\n", i, str);
      FREE(str);      
      memcpy(sidptr, sarray[i].sidptr, sarray[i].len);
      sidptr += sarray[i].len;
    }

    cd->members_len = sidlen;  /* Update member count in C struct */
    cd->grp_members = i;

    if (gverbose) hexdump(&c->data, 0, c->len, 1);

    if (!put_buf2val(hive[H_SAM], c, 0, g, 0, TPF_VK_EXACT)) {
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


/* List groups, optionally with members */

void list_groups(int listmembers) {

  struct ex_data ex;
  struct sid_array *sids = NULL;
  int nkofs;
  unsigned int grp;
  int count = 0, countri = 0;
  struct keyval *c = NULL;
  struct group_C *cd;
  int grpnamoffs, grpnamlen, i;
  char groupname[200];
  char *str;


  if (H_SAM < 0) return;


  nkofs = trav_path(hive[H_SAM], 0,"\\SAM\\Domains\\Builtin\\Aliases",0);
  if (!nkofs) {
    printf("list_groups: Cannot find group list in registry! (is this a SAM-hive?)\n");
    return;
  }

  /* Pick up all subkeys here, they are local groups */
  while ((ex_next_n(hive[H_SAM], nkofs+4, &count, &countri, &ex) > 0)) {

    // printf("Group ID %s\n",ex.name);
    sscanf(ex.name,"%x",&grp);

    /* Groups keys have a C value, get it and pick up the name etc */
    /* Some other keys also exists (Members, Names at least), but we skip them */

    c = get_val2buf(hive[H_SAM], NULL, ex.nkoffs+4, "C", 0, TPF_VK_EXACT);
    if (c) {
      cd = (struct group_C *)&c->data;
      grpnamoffs = cd->grpname_ofs + 0x34;
      grpnamlen  = cd->grpname_len;
      
      cheap_uni2ascii((char *)cd + grpnamoffs, groupname, grpnamlen);
      
      printf("Group #%x named <%s> has %d members\n",grp,groupname,cd->grp_members);

      if (listmembers) {
	get_grp_members_sid(grp, &sids); 

	for (i = 0; sids[i].sidptr; i++) {
	  str = sid_to_string(sids[i].sidptr);
	  printf("  Member # %d = <%s>\n", i, str);
	  FREE(str);
	}
	free_sid_array(sids);
      }
    }

  }

}

/* Get group IDs a user is member of
 * rid = user ID
 * returns: since value data is just an array of grp ids (4 bytes each),
 *          just return the keyval structure (size + data)
 * caller must free() keyval
 */

struct keyval *get_user_grpids(int rid)
{
  char s[200];
  struct sid_binary sid;
  char *sidstr;

  int nk = 0;
  struct keyval *m = NULL;
  int count = 0;
  int size;

  if (!rid || (H_SAM < 0)) return(NULL);

  if (!get_machine_sid((char *)&sid)) {
    fprintf(stderr,"get_user_grpids: Could not find machine SID\n");
    return(0);
  }

  sidstr = sid_to_string(&sid);

  /* Get member list for user on this machine */
  snprintf(s,180,"\\SAM\\Domains\\Builtin\\Aliases\\Members\\%s\\%08X",sidstr,rid);

  free(sidstr);

  /* Now, the TYPE field is the number of groups the user is member of */
  /* Don't we just love the inconsistent use of fields!! */
  nk = trav_path(hive[H_SAM], 0, s, 0);
  if (!nk) {
    /* This probably means user is not in any group. Seems to be the case
       for a couple of XPs built in support / guest users. So just return */
    if (gverbose) printf("get_user_grpids: Cannot find RID under computer SID <%s>\n",s);
    return(NULL);
  }
  nk += 4;
  count = get_val_type(hive[H_SAM],nk,"@",TPF_VK_EXACT);
  if (count == -1) {
    printf("get_user_grpids: Cannot find value <%s\\@>\n",s);
    return(NULL);
  }

  //  printf("get_user_grpids: User is member of %d groups:\n",count);
  
  /* This is the data size */
  size = get_val_len(hive[H_SAM],nk,"@",TPF_VK_EXACT);
  
  /* It should be 4 bytes for each group */
  if (gverbose) printf("Data size %d bytes.\n",size);
  if (size != count * 4) {
    printf("get_user_grpids: DEBUG: Size is not 4 * count! May not matter anyway. Continuing..\n");
  }
  
  m = get_val2buf(hive[H_SAM], NULL, nk, "@", 0, TPF_VK_EXACT);
  if (!m) {
    printf("get_user_grpids: Could not get value data! Giving up.\n");
    return(NULL);
  }
  
  return(m);
}

/* Put/set group IDs a user is member of
 * rid = user ID
 * val = keyval structure of data, actual value data is a list
 *       of ints, one per group
 * returns true if successful setting the value
 */

int put_user_grpids(int rid, struct keyval *val)
{
  char s[200];
  struct sid_binary sid;
  char *sidstr;

  int newcount = 0;
  int nk = 0;
  int count = 0;

  if (!rid || (H_SAM < 0)) return(0);

  if (!val || !val->len) return(0);

  if (!get_machine_sid((char *)&sid)) {
    fprintf(stderr,"put_user_grpids: Could not find machine SID\n");
    return(0);
  }

  sidstr = sid_to_string(&sid);

  /* Get member list for user on this machine */
  snprintf(s,180,"\\SAM\\Domains\\Builtin\\Aliases\\Members\\%s\\%08X",sidstr,rid);

  free(sidstr);

  /* Now, the TYPE field is the number of groups the user is member of */

  nk = trav_path(hive[H_SAM], 0, s, 0);
  if (!nk) {
    /* This probably means user is not in any group. Seems to be the case
       for a couple of XPs built in support / guest users. So just return */
    if (gverbose) printf("put_user_grpids: Cannot find RID under computer SID <%s>\n",s);
    return(0);
  }

  nk += 4;

  count = get_val_type(hive[H_SAM],nk,"@",TPF_VK_EXACT);
  if (count == -1) {
    printf("put_user_grpids: Cannot find value <%s\\@>\n",s);
    return(1);
  }

  if (gverbose) printf("put_user_grpids: User was member of %d groups:\n",count);
  
  /* This is the data size */
  /* It should be 4 bytes for each group */

  newcount = val->len >> 2;

  if (gverbose) printf("Data size %d bytes.\n",val->len);
  if (val->len != newcount << 2) {
    printf("set_user_grpids: DEBUG: Size is not 4 * count! May not matter anyway. Continuing..\n");
  }
  
  if (gverbose) printf("put_user_grpids: User is NOW member of %d groups:\n",newcount);

  set_val_type(hive[H_SAM],nk,"@",TPF_VK_EXACT,newcount);

  if (!put_buf2val(hive[H_SAM], val, nk, "@", 0, TPF_VK_EXACT) ) {
    printf("put_user_grpids: Could not set reg value data!\n");
    return(0);
  }
  
  return(1);
}





/* List users membership or check if admin (is in admin group)
 * rid   - users rid
 * check - if 1 just check if admin, do not list
 * returns true if user is admin
 */

int list_user_groups(int rid, int check)
{
  char g[200];

  char groupname[128];
  struct keyval *m = NULL, *c = NULL;
  struct group_C *cd;
  unsigned int *grps;
  int count = 0, isadmin = 0;
  int i, grp, grpnamoffs, grpnamlen;

  if (!rid || (H_SAM < 0)) return(0);

  m = get_user_grpids(rid);

  if (!m) return(0);

  grps = (unsigned int *)&m->data;
  count = m->len >> 2;

  for (i = 0; i < count; i++) {
    grp = grps[i];
    if (!check) printf("%08x ",grp);

    if (grp == 0x220) isadmin = 1;

    if (!check) {
      snprintf(g,180,"\\SAM\\Domains\\Builtin\\Aliases\\%08X\\C",grp);
      c = get_val2buf(hive[H_SAM], NULL, 0, g, 0, TPF_VK_EXACT);
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




/* Add user to a group
 * rid = user RID
 * grp = group ID
 * return true if success
 */

int add_user_to_grp(int rid, int grp)
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



  if (!rid || !grp || (H_SAM < 0)) return(0);

  /* Build user SID (add RID to machine SID) */

  if (!get_machine_sid((char *)&msid)) {
    fprintf(stderr,"get_user_grpids: Could not find machine SID\n");
    return(0);
  }

  /* well, and hope that machine SID is always same size here too */
  ALLOC(usid, sizeof(struct sid_binary) +4, 1);

  memcpy(usid, &msid, sizeof(struct sid_binary));

  usid->array[4] = rid; /* Tack RID on at end */
  usid->sections = 5;

  str = sid_to_string(usid);

  if (gverbose) printf("add_user_to_grp: user SID is <%s>\n", str);

  free(str);

  /* With all of the above functions, it should now just be to get
   * the list of groups the user account has listed under it
   * and the list of users the group has listed under it
   */

  usrgrplist = (struct keyvala *)get_user_grpids(rid);

  if (!usrgrplist) {
    printf("add_user_to_grp: user # %x not found!\n",rid);
    return(0);
  }
  

  members = get_grp_members_sid(grp, &sarray);

  if (!sarray) {
    printf("add_user_to_grp: group # %x not found!\n",grp);
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
    str = sid_to_string(sarray[o].sidptr);
    printf("  Member # %d = <%s>\n", o, str);
    FREE(str);
  }
  }

  newmembers = members + 1;
  ALLOC(narray, sizeof(struct sid_array) * (newmembers + 2), 1);  /* Add one entry size */
  
  if (gverbose) printf("members = %d\n", members);

  hit = 0;
  for (o = 0, n = 0; o <= members; o++, n++) {
    c = sid_cmp(sarray[o].sidptr, usid);     /* Compare slot with new SID */
    if (gverbose) printf("sid_cmp returns %d\n",c);
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
    str = sid_to_string(narray[o].sidptr);
    printf("  Member # %d = <%s>\n", o, str);
    FREE(str);
  }
  }

  /* Write new lists back to registry */
  if (!put_user_grpids(rid, (struct keyval *)newusrgrplist)) {
    fprintf(stderr, "add_user_to_grp: failed storing users group list\n");
  } else if (!put_grp_members_sid(grp, narray)) {
    fprintf(stderr,"add_user_to_grp: failed storing groups user list\n");
    put_user_grpids(rid, (struct keyval *)usrgrplist);      /* Try to roll back */
  }
  
  FREE(usrgrplist);
  FREE(newusrgrplist);
  free_sid_array(narray);
  FREE(sarray);     /* Pointers was copied to narray, and freed above, just free the array here */

  return(1);

}

/* Remove user from a group
 * rid = user RID
 * grp = group ID
 * return true if success
 */

int remove_user_from_grp(int rid, int grp)
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



  if (!rid || !grp || (H_SAM < 0)) return(0);

  /* Build user SID (add RID to machine SID) */

  if (!get_machine_sid((char *)&msid)) {
    fprintf(stderr,"get_user_grpids: Could not find machine SID\n");
    return(0);
  }

  /* well, and hope that machine SID is always same size here too */
  ALLOC(usid, sizeof(struct sid_binary) +4, 1);

  memcpy(usid, &msid, sizeof(struct sid_binary));

  usid->array[4] = rid; /* Tack RID on at end */
  usid->sections = 5;

  if (gverbose) {
    str = sid_to_string(usid);
    printf("remove_user_from_grp: user SID is <%s>\n", str);
    free(str);
  }

  /* With all of the above functions, it should now just be to get
   * the list of groups the user account has listed under it
   * and the list of users the group has listed under it
   */

  usrgrplist = (struct keyvala *)get_user_grpids(rid);

  if (!usrgrplist) {
    printf("remove_user_from_grp: user # %x not found!\n",rid);
    return(0);
  }
  

  members = get_grp_members_sid(grp, &sarray);

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
    str = sid_to_string(sarray[o].sidptr);
    printf("  Member # %d = <%s>\n", o, str);
    FREE(str);
  }
  }

  newmembers = members;
  ALLOC(narray, sizeof(struct sid_array) * (newmembers + 2), 1);
  
  if (gverbose) printf("members = %d\n", members);


  hit = 0;
  for (o = 0, n = 0; o <= members; o++, n++) {
    c = sid_cmp(sarray[o].sidptr, usid);     /* Compare slot with new SID */
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
    str = sid_to_string(narray[o].sidptr);
    printf("  Member # %d = <%s>\n", o, str);
    FREE(str);
  }
  }

  /* Write new lists back to registry */
  if (!put_user_grpids(rid, (struct keyval *)newusrgrplist)) {
    fprintf(stderr, "remove_user_from_grp: failed storing users group list\n");
  } else if (!put_grp_members_sid(grp, narray)) {
    fprintf(stderr,"remvoe_user_from_grp: failed storing groups user list\n");
    put_user_grpids(rid, (struct keyval *)usrgrplist);      /* Try to roll back */
  }
  
  FREE(usrgrplist);
  FREE(newusrgrplist);
  free_sid_array(narray);
  FREE(sarray);     /* Pointers was copied to narray, and freed above, just free the array here */

  return(1);

}




/* Promote user into administrators group (group ID 0x220)
 * And remove from all others...
 * rid   - users rid
 * no returns yet
 */

void promote_user(int rid)
{

  char yn[5];

  if (!rid || (H_SAM < 0)) return;
  
  printf("\n=== PROMOTE USER\n\n");
  printf("Will add the user to the administrator group (0x220)\n"
	 "and to the users group (0x221). That should usually be\n"
	 "what is needed to log in and get administrator rights.\n"
	 "Also, remove the user from the guest group (0x222), since\n"
	 "it may forbid logins.\n\n");
  printf("(To add or remove user from other groups, please other menu selections)\n\n");
  printf("Note: You may get some errors if the user is already member of some\n"
	 "of these groups, but that is no problem.\n\n");

  fmyinput("Do it? (y/n) [n] : ", yn, 3);

  if (*yn == 'y') {

    printf("* Adding to 0x220 (Administrators) ...\n");
    add_user_to_grp(rid, 0x220);
    printf("* Adding to 0x221 (Users) ...\n");
    add_user_to_grp(rid, 0x221);

    printf("* Removing from 0x222 (Guests) ...\n");
    remove_user_from_grp(rid, 0x222);

    printf("\nPromotion DONE!\n");

  } else {
    printf("Nothing done, going back..\n");
  }

}


void interactive_remusrgrp(int rid)
{
  char inp[20];
  int grp, l;

  printf("\n=== REMOVE USER FROM A GROUP\n");

  list_user_groups(rid,0);

  printf("\nPlease enter group number (for example 220), or 0 to go back\n");
  l = fmyinput("Group number? : ",inp,16);
  sscanf(inp, "%x", &grp);

  if (!grp) {
    printf("Going back..\n");
    return;
  }

  printf("Removing user from group 0x%x (%d)\n",grp,grp);
  printf("Error messages if the user was not member of the group are harmless\n\n");

  remove_user_from_grp(rid, grp);

  printf("\nFinished removing user from group\n\n");

}


void interactive_addusrgrp(int rid)
{
  char inp[20];
  int grp, l;

  printf("\n == ADD USER TO A GROUP\n");

  list_groups(0);

  printf("\nPlease enter group number (for example 220), or 0 to go back\n");
  l = fmyinput("Group number? : ",inp,16);
  sscanf(inp, "%x", &grp);

  if (!grp) {
    printf("Going back..\n");
    return;
  }

  printf("Adding user to group 0x%x (%d)\n",grp,grp);
  printf("Error messages if the user was already member of the group are harmless\n\n");

  add_user_to_grp(rid, grp);

  printf("\nFinished adding user to group\n\n");


}


/* Decode the V-struct, and change the password
 * vofs - offset into SAM buffer, start of V struct
 * rid - the users RID, required for the DES decrypt stage
 *
 * Some of this is ripped & modified from pwdump by Jeremy Allison
 * 
 */
char *change_pw(char *buf, int rid, int vlen, int stat)
{
   
   int pl;
   char *vp;
   static char username[128],fullname[128];
   char comment[128], homedir[128], newp[20];
   int username_offset,username_len;
   int fullname_offset,fullname_len;
   int comment_offset,comment_len;
   int homedir_offset,homedir_len;
   int ntpw_len,lmpw_len,ntpw_offs,lmpw_offs;
   int dontchange = 0;
   unsigned short acb;
   struct user_V *v;

#ifdef DOCRYPT
   int i;
   char md4[32],lanman[32];
   char newunipw[34], despw[20], newlanpw[16], newlandes[20];
   des_key_schedule ks1, ks2;
   des_cblock deskey1, deskey2;
   MD4_CTX context;
   unsigned char digest[16];
   uchar x1[] = {0x4B,0x47,0x53,0x21,0x40,0x23,0x24,0x25};
#endif


   v = (struct user_V *)buf;
   vp = buf;
 
   username_offset = v->username_ofs;
   username_len    = v->username_len; 
   fullname_offset = v->fullname_ofs;
   fullname_len    = v->fullname_len;
   comment_offset  = v->comment_ofs;
   comment_len     = v->comment_len;
   homedir_offset  = v->homedir_ofs;
   homedir_len     = v->homedir_len;
   lmpw_offs       = v->lmpw_ofs;
   lmpw_len        = v->lmpw_len;
   ntpw_offs       = v->ntpw_ofs;
   ntpw_len        = v->ntpw_len;

   if (!rid) {
     printf("No RID given. Unable to change passwords..\n");
     return(0);
   }

   if (gverbose) {
     printf("lmpw_offs: 0x%x, lmpw_len: %d (0x%x)\n",lmpw_offs,lmpw_len,lmpw_len);
     printf("ntpw_offs: 0x%x, ntpw_len: %d (0x%x)\n",ntpw_offs,ntpw_len,ntpw_len);
   }

   *username = 0;
   *fullname = 0;
   *comment = 0;
   *homedir = 0;
   
   if(username_len <= 0 || username_len > vlen ||
      username_offset <= 0 || username_offset >= vlen ||
      comment_len < 0 || comment_len > vlen   ||
      fullname_len < 0 || fullname_len > vlen ||
      homedir_offset < 0 || homedir_offset >= vlen ||
      comment_offset < 0 || comment_offset >= vlen ||
      lmpw_offs < 0 || lmpw_offs >= vlen)
     {
	if (stat != 1) printf("change_pw: Not a legal V struct? (negative struct lengths)\n");
	return(NULL);
     }

   /* Offsets in top of struct is relative to end of pointers, adjust */
   username_offset += 0xCC;
   fullname_offset += 0xCC;
   comment_offset += 0xCC;
   homedir_offset += 0xCC;
   ntpw_offs += 0xCC;
   lmpw_offs += 0xCC;
   
   cheap_uni2ascii(vp + username_offset,username,username_len);
   cheap_uni2ascii(vp + fullname_offset,fullname,fullname_len);
   cheap_uni2ascii(vp + comment_offset,comment,comment_len);
   cheap_uni2ascii(vp + homedir_offset,homedir,homedir_len);
   
#if 0
   /* Reset hash-lengths to 16 if syskey has been reset */
   if (syskeyreset && ntpw_len > 16 && !stat) {
     ntpw_len = 16;
     lmpw_len = 16;
     ntpw_offs -= 4;
     (unsigned int)*(vp+0xa8) = ntpw_offs - 0xcc;
     *(vp + 0xa0) = 16;
     *(vp + 0xac) = 16;
   }
#endif

   printf("\nRID     : %04d [%04x]\n",rid,rid);
   printf("Username: %s\n",username);
   printf("fullname: %s\n",fullname);
   printf("comment : %s\n",comment);
   printf("homedir : %s\n\n",homedir);
   
   list_user_groups(rid,0);
   printf("\n");

   acb = handle_F(rid,1);

   if (lmpw_len < 16 && gverbose) {
      printf("** LANMAN password not set. User MAY have a blank password.\n** Usually safe to continue. Normal in Vista\n");
   }

   if (ntpw_len < 16) {
      printf("** No NT MD4 hash found. This user probably has a BLANK password!\n");
      if (lmpw_len < 16) {
	printf("** No LANMAN hash found either. Try login with no password!\n");
	dontchange = 1;
      } else {
	printf("** LANMAN password IS however set. Will now install new password as NT pass instead.\n");
	printf("** NOTE: Continue at own risk!\n");
	ntpw_offs = lmpw_offs;
	*(vp+0xa8) = ntpw_offs - 0xcc;
	ntpw_len = 16;
	lmpw_len = 0;
      }
   }
   
   if (gverbose) {
     hexprnt("Crypted NT pw: ",(unsigned char *)(vp+ntpw_offs),16);
     hexprnt("Crypted LM pw: ",(unsigned char *)(vp+lmpw_offs),16);
   }

#ifdef DOCRYPTO
   /* Get the two decrpt keys. */
   sid_to_key1(rid,(unsigned char *)deskey1);
   des_set_key((des_cblock *)deskey1,ks1);
   sid_to_key2(rid,(unsigned char *)deskey2);
   des_set_key((des_cblock *)deskey2,ks2);
   
   /* Decrypt the NT md4 password hash as two 8 byte blocks. */
   des_ecb_encrypt((des_cblock *)(vp+ntpw_offs ),
		   (des_cblock *)md4, ks1, DES_DECRYPT);
   des_ecb_encrypt((des_cblock *)(vp+ntpw_offs + 8),
		   (des_cblock *)&md4[8], ks2, DES_DECRYPT);

   /* Decrypt the lanman password hash as two 8 byte blocks. */
   des_ecb_encrypt((des_cblock *)(vp+lmpw_offs),
		   (des_cblock *)lanman, ks1, DES_DECRYPT);
   des_ecb_encrypt((des_cblock *)(vp+lmpw_offs + 8),
		   (des_cblock *)&lanman[8], ks2, DES_DECRYPT);
      
   if (gverbose) {
     hexprnt("MD4 hash     : ",(unsigned char *)md4,16);
     hexprnt("LANMAN hash  : ",(unsigned char *)lanman,16);
   }
#endif  /* DOCRYPTO */


   printf("\n- - - - User Edit Menu:\n");
   printf(" 1 - Clear (blank) user password\n");
   printf("%s2 - Unlock and enable user account%s\n", (acb & 0x8000) ? " " : "(", 
	  (acb & 0x8000) ? " [probably locked now]" : ") [seems unlocked already]");
   printf(" 3 - Promote user (make user an administrator)\n");
   printf(" 4 - Add user to a group\n");
   printf(" 5 - Remove user from a group\n");
#ifdef DOCRYPTO
   printf(" 9 - Edit (set new) user password (careful with this on XP or Vista)\n");
#endif
   printf(" q - Quit editing user, back to user select\n");

   pl = fmyinput("Select: [q] > ",newp,16);

   if ( (pl < 1) || (*newp == 'q') || (*newp == 'Q')) return(0);


   if (*newp == '2') {
     acb = handle_F(rid,2);
     return(username);
   }

   if (*newp == '3') {
     promote_user(rid);
     return(username);
   }

   if (*newp == '4') {
     interactive_addusrgrp(rid);
     return(username);
   }

   if (*newp == '5') {
     interactive_remusrgrp(rid);
     return(username);
   }


#ifdef DOCRYPT
   if (*newp == '9') {   /* Set new password */

     if (dontchange) {
       printf("Sorry, unable to edit since password seems blank already (thus no space for it)\n");
       return(0);
     }

     pl = fmyinput("New Password: ",newp,16);

     if (pl < 1) {
       printf("No change.\n");
       return(0);
     }

     cheap_ascii2uni(newp,newunipw,pl);
   
     make_lanmpw(newp,newlanpw,pl);

     /*   printf("Ucase Lanman: %s\n",newlanpw); */
   
     MD4Init (&context);
     MD4Update (&context, newunipw, pl<<1);
     MD4Final (digest, &context);
     
     if (gverbose) hexprnt("\nNEW MD4 hash    : ",digest,16);
     
     E1((uchar *)newlanpw,   x1, (uchar *)lanman);
     E1((uchar *)newlanpw+7, x1, (uchar *)lanman+8);
     
     if (gverbose) hexprnt("NEW LANMAN hash : ",(unsigned char *)lanman,16);
     
     /* Encrypt the NT md4 password hash as two 8 byte blocks. */
     des_ecb_encrypt((des_cblock *)digest,
		     (des_cblock *)despw, ks1, DES_ENCRYPT);
     des_ecb_encrypt((des_cblock *)(digest+8),
		     (des_cblock *)&despw[8], ks2, DES_ENCRYPT);
     
     des_ecb_encrypt((des_cblock *)lanman,
		     (des_cblock *)newlandes, ks1, DES_ENCRYPT);
     des_ecb_encrypt((des_cblock *)(lanman+8),
		     (des_cblock *)&newlandes[8], ks2, DES_ENCRYPT);
     
     if (gverbose) {
       hexprnt("NEW DES crypt   : ",(unsigned char *)despw,16);
       hexprnt("NEW LANMAN crypt: ",(unsigned char *)newlandes,16);
     }

     /* Reset hash length to 16 if syskey enabled, this will cause
      * a conversion to syskey-hashes upon next boot */
     if (syskeyreset && ntpw_len > 16) { 
       ntpw_len = 16;
       lmpw_len = 16;
       ntpw_offs -= 4;
       *(vp+0xa8) = (unsigned int)(ntpw_offs - 0xcc);
       *(vp + 0xa0) = 16;
       *(vp + 0xac) = 16;
     }
     
     for (i = 0; i < 16; i++) {
       *(vp+ntpw_offs+i) = (unsigned char)despw[i];
       if (lmpw_len >= 16) *(vp+lmpw_offs+i) = (unsigned char)newlandes[i];
     }

     printf("Password changed!\n");


   } /* new password */
#endif /* DOCRYPT */

   if (pl == 1 && *newp == '1') {
     /* Setting hash lengths to zero seems to make NT think it is blank
      * However, since we cant cut the previous hash bytes out of the V value
      * due to missing resize-support of values, it may leak about 40 bytes
      * each time we do this.
      */
     v->ntpw_len = 0;
     v->lmpw_len = 0;

     printf("Password cleared!\n");
   }
   
#if 0
   hexprnt("Pw in buffer: ",(vp+ntpw_offs),16);
   hexprnt("Lm in buffer: ",(vp+lmpw_offs),16);
#endif
   dirty = 1;
   return(username);
}


/* Registry edit wrapper */

void mainloop(void)
{
  regedit_interactive(hive, no_hives);
}


/* Iterate over users in SAM file, and do things with it
 * automode - if null, just list, else handle auto change
 *            f = reset first user that is in admin group
 *            a = reset all users in admin group
 *            0x1f4 (built-in administrator account) will only be reset
 *            if no other users are found to be admin group
 */

int list_users(int readable)
{
  char s[200];
  struct keyval *v;
  int nkofs /* ,vkofs */ ;
  int rid;
  int count = 0, countri = 0;
  int ntpw_len;

  unsigned short acb;

  struct user_V *vpwd;
  struct ex_data ex;
  
  if (H_SAM < 0) return(1);
  nkofs = trav_path(hive[H_SAM], 0,"\\SAM\\Domains\\Account\\Users\\Names\\",0);
  if (!nkofs) {
    printf("list_users: Cannot find usernames in registry! (is this a SAM-hive?)\n");
    return(1);
  }

  if (readable) printf("| RID -|---------- Username ------------| Admin? |- Lock? --|\n");

  while ((ex_next_n(hive[H_SAM], nkofs+4, &count, &countri, &ex) > 0)) {

    /* Extract the value out of the username-key, value is RID  */
    snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\Names\\%s\\@",ex.name);
    rid = get_dword(hive[H_SAM], 0, s, TPF_VK_EXACT|TPF_VK_SHORT);
    if (rid == 500) strncpy(admuser,ex.name,128); /* Copy out admin-name */

    /* Now that we have the RID, build the path to, and get the V-value */
    snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\%08X\\V",rid);
    v = get_val2buf(hive[H_SAM], NULL, 0, s, REG_BINARY, TPF_VK_EXACT);
    if (!v) {
      printf("Cannot find value <%s>\n",s);
      return(1);
    }
    
    if (v->len < 0xcc) {
      printf("list_users: Value <%s> is too short (only %d bytes) to be a SAM user V-struct!\n",
	     s, v->len);
    } else {

      vpwd = (struct user_V *)&(v->data);
      ntpw_len = vpwd->ntpw_len;

      acb = handle_F(rid,0);
      if (readable) {
	printf("| %04x | %-30.30s | %-6s | %-8s |\n",
	       rid, ex.name, (list_user_groups(rid,1) ? "ADMIN" : "") , (  acb & 0x8000 ? "dis/lock" : (ntpw_len < 16) ? "*BLANK*" : "")  );
      } else {
	printf("%04x:%s:%d:%x:%x\n",
	       rid, ex.name, list_user_groups(rid,1) , acb, ntpw_len );
      }
      

      //      change_pw( (char *)&v->data , rid, v->len, (*automode == 'l') ? 2 : 1);

    }
    FREE(v);
    FREE(ex.name);
  }
  return(0);
}


/* Find a username in the SAM registry, then get it's V-value,
 * and feed it to the password changer.
 */

void find_n_change(char *username)
{
  char s[200];
  struct keyval *v;
  int rid = 0;

  if ((H_SAM < 0) || (!username)) return;
  if (*username == '0' && *(username+1) == 'x') sscanf(username,"%i",&rid);
  
  if (!rid) { /* Look up username */
    /* Extract the unnamed value out of the username-key, value is RID  */
    snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\Names\\%s\\@",username);
    rid = get_dword(hive[H_SAM],0,s, TPF_VK_EXACT|TPF_VK_SHORT);
    if (rid == -1) {
      printf("Cannot find value <%s>\n",s);
      return;
    }
  }

  /*
  printf("Username: %s, RID = %d (0x%0x)\n",username,rid,rid);
  */

  /* Now that we have the RID, build the path to, and get the V-value */
  snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\%08X\\V",rid);
  v = get_val2buf(hive[H_SAM], NULL, 0, s, REG_BINARY, TPF_VK_EXACT);
  if (!v) {
    printf("Cannot find value <%s>\n",s);
    return;
  }

  if (v->len < 0xcc) {
    printf("Value <%s> is too short (only %d bytes) to be a SAM user V-struct!\n",
	   s, v->len);
  } else {
    change_pw( (char *)&v->data , rid, v->len, 0);
    if (dirty) {
      if (!(put_buf2val(hive[H_SAM], v, 0, s, REG_BINARY, TPF_VK_EXACT))) {
	printf("Failed to write updated <%s> to registry! Password change not completed!\n",s);
      }
    }
  }
  FREE(v);
}

/* Check for presence of syskey and possibly disable it if
 * user wants it.
 * This is tricky, and extremely undocumented!
 * See docs for more info on what's going on when syskey is installed
 */

#undef LSADATA

void handle_syskey(void)
{

  /* This is \SAM\Domains\Account\F */
  struct samkeyf {
    char unknown[0x50];       /* 0x0000 - Unknown. May be machine SID */
    char unknown2[0x14];
    char syskeymode;          /* 0x0064 - Type/mode of syskey in use     */
    char syskeyflags1[0xb];   /* 0x0065 - More flags/settings            */
    char syskeyobf[0x30];     /* 0x0070 - This may very well be the obfuscated syskey */
  };    /* There may be more, usually 8 null-bytes? */

  /* Security\Policy\SecretEncryptionKey\@, only on NT5 */
  /* Probably contains some keyinfo for syskey. Second DWORD seems to be syskeymode */
  struct secpoldata {
    int  unknown1;             /* Some kind of flag? usually 1 */
    int  syskeymode;           /* Is this what we're looking for? */
    int  unknown2;             /* Usually 0? */
    char keydata[0x40];        /* Some kind of scrambled keydata? */
  };

#ifdef LSADATA
  /* SYSTEM\CurrentControlSet\Control\Lsa\Data, only on NT5?? */
  /* Probably contains some keyinfo for syskey. Byte 0x34 seems to be mode */
  struct lsadata {
    char keydata[0x34];        /* Key information */
    int  syskeymode;           /* Is this what we're looking for? */
  };
#endif

  /* void *fdata; */
  struct samkeyf *ff = NULL;
  struct secpoldata *sf = NULL;
  /* struct lsadata *ld = NULL; */
  int /* len, */ i,secboot, samfmode, secmode /* , ldmode */ ;
  struct keyval *samf, *secpol /* , *lsad */ ;
  char *syskeytypes[4] = { "off", "key-in-registry", "enter-passphrase", "key-on-floppy" }; 
  char yn[5];

  printf("\n---------------------> SYSKEY CHECK <-----------------------\n");


  if (H_SAM < 0) {
    printf("ERROR: SAM hive not loaded!\n");
    return;
  }
  samf = get_val2buf(hive[H_SAM], NULL, 0, "\\SAM\\Domains\\Account\\F", REG_BINARY, TPF_VK_EXACT);

  if (samf && samf->len > 0x70 ) {
    ff = (struct samkeyf *)&samf->data;
    samfmode = ff->syskeymode;
  } else {
    samfmode = -1;
  }

  secboot = -1;
  if (H_SYS >= 0) {
    secboot = get_dword(hive[H_SYS], 0, "\\ControlSet001\\Control\\Lsa\\SecureBoot", TPF_VK_EXACT );
  }

  secmode = -1;
  if (H_SEC >=0) {
    secpol = get_val2buf(hive[H_SEC], NULL, 0, "\\Policy\\PolSecretEncryptionKey\\@", REG_NONE, TPF_VK_EXACT);
    if (secpol) {     /* Will not be found in NT 4, take care of that */
      sf = (struct secpoldata *)&secpol->data;
      secmode = sf->syskeymode;
    }
  }

#ifdef LSADATA
  lsad = get_val2buf(hive[H_SYS], NULL, 0, "\\ControlSet001\\Control\\Lsa\\Data\\Pattern", REG_BINARY, TPF_VK_EXACT);

  if (lsad && lsad->len >= 0x38) {
    ld = (struct lsadata *)&lsad->data;
    ldmode = ld->syskeymode;
  } else {
    ldmode = -1;
  }
#endif

  printf("SYSTEM   SecureBoot            : %d -> %s\n", secboot,
	 (secboot < 0 || secboot > 3) ? "Not Set (not installed, good!)" : syskeytypes[secboot]);
  printf("SAM      Account\\F             : %d -> %s\n", samfmode,
	 (samfmode < 0 || samfmode > 3) ? "Not Set" : syskeytypes[samfmode]);
  printf("SECURITY PolSecretEncryptionKey: %d -> %s\n", secmode,
	 (secmode < 0 || secmode > 3) ? "Not Set (OK if this is NT4)" : syskeytypes[secmode]);

#ifdef LSADATA
  printf("SYSTEM   LsaData               : %d -> %s\n\n", ldmode,
	 (ldmode < 0 || ldmode > 3) ? "Not Set (strange?)" : syskeytypes[ldmode]);
#endif

  if (secboot != samfmode && secboot != -1) {
    printf("WARNING: Mismatch in syskey settings in SAM and SYSTEM!\n");
    printf("WARNING: It may be dangerous to continue (however, resetting syskey\n");
    printf("         may very well fix the problem)\n");
  }

  if (secboot > 0 || samfmode > 0) {
    printf("\n***************** SYSKEY IS ENABLED! **************\n");
    printf("This installation very likely has the syskey passwordhash-obfuscator installed\n");
    printf("It's currently in mode = %d, %s-mode\n",secboot,
	   (secboot < 0 || secboot > 3) ? "Unknown" : syskeytypes[secboot]);

    if (no_hives < 2) {
      printf("\nSYSTEM (and possibly SECURITY) hives not loaded, unable to disable syskey!\n");
      printf("Please start the program with at least SAM & SYSTEM-hive filenames as arguments!\n\n");
      return;
    }
    printf("SYSKEY is on! However, DO NOT DISABLE IT UNLESS YOU HAVE TO!\n");
    printf("This program can change passwords even if syskey is on, however\n");
    printf("if you have lost the key-floppy or passphrase you can turn it off,\n");
    printf("but please read the docs first!!!\n");
    printf("\n** IF YOU DON'T KNOW WHAT SYSKEY IS YOU DO NOT NEED TO SWITCH IT OFF!**\n");
    printf("NOTE: On WINDOWS 2000 and XP it will not be possible\n");
    printf("to turn it on again! (and other problems may also show..)\n\n");
    printf("NOTE: Disabling syskey will invalidate ALL\n");
    printf("passwords, requiring them to be reset. You should at least reset the\n");
    printf("administrator password using this program, then the rest ought to be\n");
    printf("done from NT.\n");
    printf("\nEXTREME WARNING: Do not try this on Vista or Win 7, it will go into endless re-boots\n\n");

    fmyinput("\nDo you really wish to disable SYSKEY? (y/n) [n] ",yn,2);
    if (*yn == 'y') {
      /* Reset SAM syskey infostruct, fill with zeroes */
      if (ff) { 
	ff->syskeymode = 0;

	for (i = 0; i < 0x3b; i++) {
	  ff->syskeyflags1[i] = 0;
	}

	put_buf2val(hive[H_SAM], samf, 0, "\\SAM\\Domains\\Account\\F", REG_BINARY, TPF_VK_EXACT);

      }
      /* Reset SECURITY infostruct (if any) */
      if (sf) { 
	memset(sf, 0, secpol->len);
	sf->syskeymode = 0;

	put_buf2val(hive[H_SEC], secpol, 0, "\\Policy\\PolSecretEncryptionKey\\@", REG_BINARY, TPF_VK_EXACT);

      }

#if LSADATA
      if (ld) { 

	ld->syskeymode = 0;

	put_buf2val(hive[H_SYS], lsad, 0, "\\ControlSet001\\Control\\Lsa\\Data\\Pattern", REG_BINARY, TPF_VK_EXACT);

      }
#endif

      /* And SYSTEM SecureBoot parameter */

      put_dword(hive[H_SYS], 0, "\\ControlSet001\\Control\\Lsa\\SecureBoot", TPF_VK_EXACT, 0);

      dirty = 1;
      syskeyreset = 1;
      printf("Updating passwordhash-lengths..\n");
      list_users(1);
      printf("* SYSKEY RESET!\nNow please set new administrator password!\n");
    } else {

      syskeyreset = 1;
    }
  } else {
    printf("Syskey not installed!\n");
    return;
  }

}


/* Interactive user edit */
void useredit(void)
{
  char iwho[100];
  int il;

  printf("\n\n===== chntpw Edit User Info & Passwords ====\n\n");

  if (H_SAM < 0) {
    printf("ERROR: SAM registry file (which contains user data) is not loaded!\n\n");
    return;
  }


  list_users(1);
  
  while (1) {
    printf("\nSelect: ! - quit, . - list users, 0x<RID> - User with RID (hex)\n");
    printf("or simply enter the username to change: [%s] ",admuser);
    il = fmyinput("",iwho,32);
    if (il == 1 && *iwho == '.') { printf("\n"); list_users(1); continue; }
    if (il == 1 && *iwho == '!') return;
    if (il == 0) strcpy(iwho,admuser);
    find_n_change(iwho);
  }

}


void recoveryconsole()
{

  int cmd = 0;
  int sec = 0;
  static char *scpath = "\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole\\SetCommand";
  static char *slpath = "\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole\\SecurityLevel";
  char yn[5];

  if (H_SOF < 0) {
    printf("\nSOFTWARE-hive not loaded, and there's where RecoveryConsole settings are..\n");
    return;
  }

  cmd = get_dword(hive[H_SOF],0,scpath,TPF_VK_EXACT);
  sec = get_dword(hive[H_SOF],0,slpath,TPF_VK_EXACT);

  if (cmd == -1 && sec == -1) {
    printf("\nDid not find registry entries for RecoveryConsole.\n(RecoveryConsole is only in Windows 2000 and XP)\n");
    return;
  }

  printf("\nRecoveryConsole:\n- Extended SET command is \t%s\n", cmd>0 ? "ENABLED (1)" : "DISABLED (0)");
  printf("- Administrator password login: %s\n", sec>0 ? "SKIPPED (1)" : "ENFORCED (0)");

  fmyinput("\nDo you want to change it? (y/n) [n] ",yn,2);
  if (*yn == 'y') {
    cmd ^= 1;
    sec ^= 1;
    if (!put_dword(hive[0], 0, scpath, TPF_VK_EXACT, cmd)) printf("Update of SET level failed registry edit\n");
    if (!put_dword(hive[0], 0, slpath, TPF_VK_EXACT, sec)) printf("Update of login level failed registry edit\n");
    printf("Done!\n");
  }

}


/* Interactive menu system */

void interactive(void)
{
  int il;
  char inbuf[20];

  while(1) {
    printf("\n\n<>========<> chntpw Main Interactive Menu <>========<>\n\n"
	   "Loaded hives:");
    for (il = 0; il < no_hives; il++) {
      printf(" <%s>",hive[il]->filename);
    }

    printf("\n\n");

    /* Make menu selection depending on what is loaded
       but it is still possible to select even if not shown */

    if (H_SAM >= 0) {
      printf("  1 - Edit user data and passwords\n");
      printf("  2 - List groups\n");
    }
    if (H_SOF >= 0) {
      printf("  3 - RecoveryConsole settings\n");
      printf("  4 - Show product key (DigitalProductID)\n");
    }
#if 0
    if (H_SAM >= 0 && H_SYS >= 0 && H_SEC >= 0) {
      printf("  8 - Syskey status & change\n");
    }
#endif

    printf("      - - -\n"
	   "  9 - Registry editor, now with full write support!\n"
	   "  q - Quit (you will be asked if there is something to save)\n"
	   "\n\n");

    il = fmyinput("What to do? [1] -> ", inbuf, 10);
    
    if (!il) useredit();
    if (il) {
      switch(inbuf[0]) {
      case '1': useredit(); break;
      case '2': list_groups(0); break;
      case '3': recoveryconsole(); break;
      case '4': cat_dpi(hive[H_SOF],0,"\\Microsoft\\Windows NT\\CurrentVersion\\DigitalProductId"); break;
      case '8': handle_syskey(); break;
      case '9': mainloop(); break;
      case 'q': return; break;
      }
    }
  }
}

  
int cmd_usrgrp(char *user, char *grp, int what)
{
  int numgrp;
  int rid = 0;
  char s[200];

  numgrp = strtol(grp, NULL, 0);

  printf("numgrp = %d (0x%x)\n", numgrp, numgrp);

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

  printf("Username: %s, RID = %d (0x%0x)\n",user,rid,rid);
  
  switch (what) {
  case 0: return(add_user_to_grp(rid, numgrp)); break;
  case 1: return(remove_user_from_grp(rid, numgrp)); break;
  }


  return(0);

}


void do_automode(char *automode, char *who, char *grp)
{
  struct sid_binary sid;
  char *sidstr;

#if 1
  printf("DEBUG: do_automode start\n");
  printf("automode = %s\n",automode);
  printf("who = %s\n",who);
  printf("grp = %s\n",grp);
#endif

  switch (*automode) {
  case 'l': list_users(0); break;
  case 's': if(get_machine_sid((char *)&sid)) { sidstr = sid_to_string(&sid); puts(sidstr); FREE(sidstr);} break;
  case 'g': list_groups(1); break;
  case 'a': cmd_usrgrp(who, grp, 0); break;  /* Add user to group */
  case 'r': cmd_usrgrp(who, grp, 1); break;  /* Remove user from group */

  }


  //  printf("DEBUG: do_automode end\n");

}


void usage(void) {
   printf("chntpw: change password of a user in a Windows SAM file,\n"
	  "or invoke registry editor. Should handle both 32 and 64 bit windows and\n"
	  "all version from NT3.x to Win7\n"
	  "chntpw [OPTIONS] <samfile> [systemfile] [securityfile] [otherreghive] [...]\n"
	  " -h          This message\n"
	  " -u <user>   Username or RID to change, Administrator is default\n"
	  " -l          list all users in SAM file\n"
	  " -i          Interactive Menu system\n"
	  " -e          Registry editor. Now with full write support!\n"
	  " -d          Enter buffer debugger instead (hex editor), \n"
          " -v          Be a little more verbose (for debuging)\n"
	  " -L          For scripts, write names of changed files to /tmp/changed\n"
	  " -N          No allocation mode. Only same length overwrites possible (very safe mode)\n"
	  " -E          No expand mode, do not expand hive file (safe mode)\n"
	  " -A <subcommand> Auto / Noninteractive. Do stuff without asking\n"
	  " -A F   reset on first admin user (lowest RID)\n"
	  " -A A   reset all admins\n"
	  " -A l   list all users, output it parseable\n"
	  " -A g   list groups\n"
	  " -A s   show machine SID\n"
	  " -A a -u <username|RID> -u <grpid>  Add user to group\n"
	  " -A r -u <username|RID> -g <grpid>  Remove user from group\n"
	  
	  "\nUsernames can be given as name or RID (in hex with 0x first)\n"
	  "<grpid> group IDs must be given as number, can be hex with 0x first\n"
	  "Example: chntpw -A a -u 0x3aa -g 1000 # Adds user with RID hex 0x3aa to group decimal 1000\n"
          "\nSee readme file on how to get to the registry files, and what they are.\n"
          "Source/binary freely distributable under GPL v2 license. See README for details.\n"
          "NOTE: This program is somewhat hackish! You are on your own!\n"
	  );
}


int main(int argc, char **argv)
{
  
  int dodebug = 0, list = 0, inter = 0,edit = 0,il,d = 0, dd = 0, logchange = 0;
  int mode = HMODE_INFO;
  extern int /* opterr, */ optind;
  extern char* optarg;
  char *filename,c;
  char *who = "Administrator";
  char *grp = NULL;
  char iwho[100];
  char *automode = "";
  FILE *ch;     /* Write out names of touched files to this */
   
  char *options = "A:LENidehlvu:g:";
  
  while((c=getopt(argc,argv,options)) > 0) {
    switch(c) {
    case 'd': dodebug = 1; break;
    case 'e': edit = 1; break;
    case 'L': logchange = 1; break;
    case 'N': mode |= HMODE_NOALLOC; break;
    case 'E': mode |= HMODE_NOEXPAND; break;
    case 'l': list = 1; break;
    case 'v': mode |= HMODE_VERBOSE; gverbose = 1; break;
    case 'i': inter = 1; break;
    case 'u': who = optarg; break;
    case 'g': grp = optarg; break;
    case 'A': automode = optarg; mode &= ~HMODE_INFO; break;
    case 'h': usage(); exit(0); break;
    default: usage(); exit(1); break;
    }
  }

  if (!*automode) printf("%s\n",chntpw_version);

  filename=argv[optind];
  if (!filename || !*filename) {
    usage(); exit(1);
  }
  do {
    if (!(hive[no_hives] = openHive(filename,
				    HMODE_RW|mode))) {
      fprintf(stderr,"%s: Unable to open/read a hive, exiting..\n",argv[0]);
      exit(1);
    }
    switch(hive[no_hives]->type) {
    case HTYPE_SAM:      H_SAM = no_hives; break;
    case HTYPE_SOFTWARE: H_SOF = no_hives; break;
    case HTYPE_SYSTEM:   H_SYS = no_hives; break;
    case HTYPE_SECURITY: H_SEC = no_hives; break;
    }
    no_hives++;
    filename = argv[optind+no_hives];
  } while (filename && *filename && no_hives < MAX_HIVES);
  
#if 0
  printf("user = %s\n",who);
  printf("automode = %s\n",automode);
#endif
  
  if (dodebug) {
    debugit(hive[0]->buffer,hive[0]->size);
  } else if (*automode) {
    check_get_samdata(0);
    do_automode(automode, who, grp);

  } else if (inter) {
    check_get_samdata(1);
    interactive();
  } else if (edit) {
    check_get_samdata(1);
     mainloop();
  } else if (list) {
    check_get_samdata(1);
    list_users(1);
  } else if (who) {
    check_get_samdata(1);
    find_n_change(who);
  }
  
  



  if (list != 1) {
    if (!*automode) printf("\nHives that have changed:\n #  Name\n");
    for (il = 0; il < no_hives; il++) {
      if (hive[il]->state & HMODE_DIRTY) {
	if (!logchange && !*automode) printf("%2d  <%s>",il,hive[il]->filename);
	if (hive[il]->state & HMODE_DIDEXPAND) printf(" WARNING: File was expanded! Expermental! Use at own risk!\n");
	if (!*automode) printf("\n");
	
	d = 1;
      }
    }
    if (d) {
      /* Only prompt user if logging of changed files has not been set */
      /* Thus we assume confirmations are done externally if they ask for a list of changes */
      if (!logchange && !*automode) fmyinput("Write hive files? (y/n) [n] : ",iwho,3);
      if (*iwho == 'y' || logchange || *automode) {
	if (logchange) {
	  ch = fopen("/tmp/changed","w");
	}
	for (il = 0; il < no_hives; il++) {
	  if (hive[il]->state & HMODE_DIRTY) {
	    if (!*automode) printf("%2d  <%s> - ",il,hive[il]->filename);
	    if (!writeHive(hive[il])) {
	      if (!*automode) printf("OK");
	      if (hive[il]->state & HMODE_DIDEXPAND) printf(" WARNING: File was expanded! Expermental! Use at own risk!\n");
	      if (!*automode) printf("\n");
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
      if (!*automode) printf("None!\n\n");
    }
  } /* list only check */
  return(dd);
}
