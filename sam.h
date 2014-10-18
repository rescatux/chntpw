/*
 * sam.h - known structures in the SAM hive of NT registry
 * 
 *****
 *
 * NTREG - Window registry file reader / writer library
 * Copyright (c) 1997-2012 Petter Nordahl-Hagen.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * See file LGPL.txt for the full license.
 *
 */ 

#ifndef _INCLUDE_SAM_H
#define _INCLUDE_SAM_H 1

#include <sys/types.h>
#include <inttypes.h>


/* Account V, contains machine SID and a lot of unknonw stuff */

#define SID_BIN_LEN 24     /* Lenght of binary machine SID, incl header */
#define SID_STR_MAX 50     /* Max string lenght of S-1-5-xxx-xxx-xxx-xxx type SID */

#define ACCOUNTDB_V_PATH "\\SAM\\Domains\\Account\\V"

struct accountdb_V {
  char unknown1[0x38];  /* No idea what it does */
  uint32_t sid_ofs;    /* 38 - Offset to machine SID */
  uint32_t sid_len;    /* 3c - Lenght of sid (should be 0x14?) */
  //  char unknown2[0x4];   /* 40 */
  /* Data start at 0x40 ?? */
  char data[4];
};

/* This contains some policy settings for the account database */

#define ACCOUNTDB_F_PATH "\\SAM\\Domains\\Account\\F"


struct accountdb_F {
  char unknown1[8]; /* 0 */
  char unknown2[8]; /* 8 */
  uint32_t updatecnt;   /* 10 Number of times policy data updated */
  char unknown3[4]; /* 14 */
  char t_maxpwage[8];  /* 18 Maximum password age, GUI shows only days */
  char t_minpwage[8];  /* 20 Minimum password age, GUI shows only days */
  char unknown4[8];    /* 28 */
  char t_lockdur[8];  /*  30 Account lockout duration, GUI shows minutes */
  char t_lockrel[8];  /*  38 Release account lockout after, GUI show minutes */
  char unknown5[8];   /*  40 */
  uint32_t rid;  /*  48 RID of user doing last edit? */
  uint32_t flags; /* 4c Some flags & options, see below */
  unsigned short minpwlen; /* 50 Minimum password lenght */
  unsigned short numhist;  /* 52 How many passwords to keep in history */
  unsigned short locklimit; /*54  How many tries before lockout */
  char unknown6[0x9a];    /* Rest is unknown */
};                         /* Total size 0xF0 bytes, seems to be constant */

/* Known bits in flags field */

#define ACF_COMPLEX    0x0001  /* Pass must meet complexity req. */
#define ACF_REVERSIBLE 0x0010  /* Store password using reversible encryption */


/* This is users F value, contains account type & state etc */

#define USER_F_PATH "\\SAM\\Domains\\Account\\Users\\%08X\\F"

struct user_F {
  char unknown1[8];
  char t_lockout[8];  /* Time of lockout */
  char unknown2[8];
  char t_creation[8]; /* Time of account creation */
  char unknown3[8];
  char t_login[8];    /* Time of last login */
  int32_t rid;
  char unknown4[4];
  unsigned short ACB_bits;  /* Account type and status flags */
  char unknown5[6];
  unsigned short failedcnt; /* Count of failed logins, if > than policy it is locked */
  unsigned short logins;    /* Total logins since creation */
  char unknown6 [0xc];
  };

#define ACB_DISABLED   0x0001  /* Act disabled */
#define ACB_HOMDIRREQ  0x0002  /* Home directory required */
#define ACB_PWNOTREQ   0x0004  /* User password not req */
#define ACB_TEMPDUP    0x0008  /* Temporary duplicate account?? */
#define ACB_NORMAL     0x0010  /* Normal user account */
#define ACB_MNS        0x0020  /* MNS logon user account */
#define ACB_DOMTRUST   0x0040  /* Interdomain trust account */
#define ACB_WSTRUST    0x0080  /* Workstation trust account */

#define ACB_SVRTRUST   0x0100  /*  Server trust account */
#define ACB_PWNOEXP    0x0200  /* User password does not expire */
/* Seems not to be used on failed console logins at least */
#define ACB_AUTOLOCK   0x0400  /* Account auto locked */

/* Account Bits Fields strings (defined in libsam.c)

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

*/


/* Users V data struct */
/* First 0xCC bytes is pointer & len table, rest is data which
 * the table points to
 * String data is unicode, not zero terminated (must use len)
 */

struct user_V {

  int unknown1_1;      /* 0x00 - always zero? */
  int unknown1_2;      /* 0x04 - points to username? */
  int unknown1_3;      /* 0x08 - always 0x02 0x00 0x01 0x00 ? */

  int username_ofs;    /* 0x0c */
  int username_len;    /* 0x10 */

  int unknown2_1;      /* 0x14 - always zero? */

  int fullname_ofs;    /* 0x18 */
  int fullname_len;    /* 0x1c */

  int unknown3_1;      /* 0x20 - always zero? */

  int comment_ofs;     /* 0x24 */
  int comment_len;     /* 0x28 */

  int unknown4_1;      /* 0x2c - alway zero? */
  int unknown4_2;      /* 0x30 - points 4 or 8 byte field before hashes */
  int unknown4_3;      /* 0x34 - zero? or size? */
  int unknown4_4;      /* 0x38 - zero? */
  int unknown4_5;      /* 0x3c - to field 8 bytes before hashes */
  int unknown4_6;      /* 0x40 - zero? or size of above? */
  int unknown4_7;      /* 0x44 - zero? */

  int homedir_ofs;     /* 0x48 */
  int homedir_len;     /* 0x4c */

  int unknown5_1;      /* 0x50 - zero? */

  int drvletter_ofs;   /* 0x54 - drive letter for home dir */
  int drvletter_len;   /* 0x58 - len of above, usually 4   */

  int unknown6_1;      /* 0x5c - zero? */

  int logonscr_ofs;    /* 0x60 - users logon script path */
  int logonscr_len;    /* 0x64 - length of string */

  int unknown7_1;      /* 0x68 - zero? */

  int profilep_ofs;    /* 0x6c - profile path string */
  int profilep_len;    /* 0x70 - profile path stringlen */

  char unknown7[0x90-0x74]; /* 0x74 */

  int unknown8_1;      /* 0x90 - pointer to some place before hashes, after comments */
  int unknown8_2;      /* 0x94 - size of above? */
  int unknown8_3;      /* 0x98 - unknown? always 1? */

  int lmpw_ofs;        /* 0x9c */
  int lmpw_len;        /* 0xa0 */

  int unknown9_1;      /* 0xa4 - zero? */

  int ntpw_ofs;        /* 0xa8 */
  int ntpw_len;        /* 0xac */

  int unknowna_1;      /* 0xb0 */
  int unknowna_2;      /* 0xb4 - points to field after hashes */
  int unknowna_3;      /* 0xb8 - size of above field */
  int unknowna_4;      /* 0xbc - zero? */
  int unknowna_5;      /* 0xc0 - points to field after that */
  int unknowna_6;      /* 0xc4 - size of above */
  int unknowna_7;      /* 0xc8 - zero ? */

  char data[4];        /* Data starts here. All pointers above is relative to this,
			  that is V + 0xCC */

};

/* Groups C data struct
 * First 0x34 bytes is pointer & len table, rest is data which
 * the table points to
 * String data is unicode, not zero terminated (must use len)
 */

struct group_C {

  int groupid;         /* 0x00 - Seems to be the group ID */
  int unknown1_1;      /* 0x04 - always zero? */
  int unknown1_2;      /* 0x08 - points to groupname? */
  int unknown1_3;      /* 0x0c - always 0x02 0x00 0x01 0x00 ? */

  int grpname_ofs;    /* 0x10 */
  int grpname_len;    /* 0x14 */

  int unknown2_1;      /* 0x18 - always zero? */

  int fullname_ofs;    /* 0x1c */
  int fullname_len;    /* 0x20 */

  int unknown3_1;      /* 0x24 - always zero? */

  int members_ofs;      /* 0x28 - offset to member list, which is SIDs */
  int members_len;      /* 0x2c - member list size */

  int grp_members;     /* 0x30 - number of group members */

  /* 0x34 - data starts here. pointers above are offset from this */

  char data[];

};

/* Variable length binary structure that most SIDs are stored in
 */

struct sid_binary {
  uint8_t revision;     /* 0x0 - Don't know. Always 1? Revision level? number of SIDs following? */
  uint8_t sections;     /* 0x1 - Number of parts, 4 bytes each (unsigne integer) */
  uint8_t unknown2;     /* 0x2 - Unknown, seems to be null padding */
  uint8_t unknown3;     /* 0x3 - Unknown, seems to be null padding */

  uint8_t unknown4;     /* 0x4 - Unknown  */
  uint8_t unknown5;     /* 0x5 - Unknown  */
  uint8_t unknown6;     /* 0x6 - Unknown  */
  uint8_t authority;     /* 0x7 - Unknown, often 5 (could this be 8bit authority number?) */


  uint32_t array[8];    /* As many as sections value says it is */
};

/* Array of SIDs */

struct sid_array {
  int len;
  struct sid_binary *sidptr;
};


/* libsam.c functions */

int sam_get_lockoutinfo(struct hive *hdesc, int show);
short sam_handle_accountbits(struct hive *hdesc, int rid, int mode);
int sam_get_machine_sid(struct hive *hdesc, char *sidbuf);
char *sam_sid_to_string(struct sid_binary *sidbuf);
struct sid_array *sam_make_sid_array(struct sid_binary *sidbuf, int size);
void sam_free_sid_array(struct sid_array *array);
int sam_sid_cmp(struct sid_binary *s1, struct sid_binary *s2);
int sam_get_grp_members_sid(struct hive *hdesc, int grp, struct sid_array **sarray);
int sam_put_grp_members_sid(struct hive *hdesc, int grp, struct sid_array *sarray);
struct keyval *sam_get_user_grpids(struct hive *hdesc, int rid);
int sam_put_user_grpids(struct hive *hdesc, int rid, struct keyval *val);
int sam_add_user_to_grp(struct hive *hdesc, int rid, int grp);
int sam_remove_user_from_grp(struct hive *hdesc, int rid, int grp);
char *sam_get_username(struct hive *hdesc, int rid);
char *sam_get_groupname(struct hive *hdesc, int grpid);
int sam_list_users(struct hive *hdesc, int readable);
int sam_list_user_groups(struct hive *hdesc, int rid, int check);
int sam_reset_pw(struct hive *hdesc, int rid);
void sam_list_groups(struct hive *hdesc, int listmembers, int human);
int sam_reset_all_pw(struct hive *hdesc, int list);



#endif
