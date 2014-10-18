
The Offline Windows Password Editor

(c) 1997-2014 Petter Nordahl-Hagen

This is free software, licensed under the following:

"ntreg" (the registry library) and
"libsam" (SAM manipulation library, user, groups etc)
is licensed under the GNU Lesser Public License. See LGPL.txt.

"chntpw" (the password reset / registry editor frontend)
"reged" (registry editor, export and import tool)
"sampasswd" (password reset command line program)
"samusrgrp" (user and group command line program)
is licensed under the GNU General Public License, see GPL.txt.


For manual to the different commands, see MANUAL.txt
Also, all have some help built in, just use the -h option.

See INSTALL.txt for compile instructions.


Where to get more info:
-----------------------

http://pogostick.net/~pnh/ntpasswd/

At that site there's a floppy and a bootable CD that use chntpw to
access the NT/2k/XP/Vista/Win7/Win8 system it is booted on to edit password etc.
The instructions below are for the standalone program itself, not the floppy.

What does chntpw do?
--------------------

This little program will enable you to view some information and
change user passwords, change user/group memberships
in a Windows (NT/XP/Vista/win7/win8) etc SAM userdatabase file.
You do not need to know the old passwords.
However, you need to get at the registry files some way or another yourself.
In addition it contains a simple registry editor with full write support,
and hex-editor which enables you to
fiddle around with bits&bytes in the file as you wish yourself.

Also have registry import or export
-----------------------------------

"reged" is a program that can do import and export of .reg files into
the registry hive (binary) files. Also has an editor, but still
rudimentary text based command line type thing.

And by popular request
Even have programs that can be used in scripts!
-----------------------------------------------
"sampasswd" can be used in scripts to get lists
of users or reset passwords automatically
"samusrgrp" can be used in scripts to list or change
memberships in groups automatically.



Why?
----

I often forget passwords. Especially on test installations (that
I just _must_ have some stuff out of half a year later..)
On most unix-based boxes you just boot the thingy off some kind
of rescue bootmedia (cd/floppy etc), and simply edit the
password file.
On Windows however, as far as I know, there is no way except reinstalling
the userdatabase, losing all users except admin.
(ok, some companies let you pay lotsa $$$$$ for some rescue service..)
(ok, from Windows Vista or something you can make a password reset
file, but you have to remember to do that BEFORE you forget your password...)

How?
----

Currently, this thing only runs under linux, but it may just happen
to compile on other platforms, too.

So, to set a new adminpassword on your Windows installation you either:

1) Take the harddrive and mount it on a linux-box

or

2) Boot a "live" linux CD with full GUI (many available: Ubuntu,
   Knoppix and more. Search for them)

In both those cases, use the "chntpw.static" program found in the
"static" zip file on my website.
or

3) Use my linux boot CD (or USB) at: http://pogostick.net/~pnh/ntpasswd/

Usage:
------

For manual to the different commands, see MANUAL.txt
Also, all have some help built in, just use the -h option.

Some old tech babble on how the password is stored
--------------------------------------------------
(still mostly valid, but should be moved somewhere else than this file)


A struct, called the V value of a key in the NT registry
was suddenly somewhat documented through the pwdump utility
included in the unix Samba distribution.
This struct contains some info on a user of the NT machine,
along with 2 crypted versions of the password associated
with the account.

One password is the NT console login password,
the other the LANMAN network share password
(which essentially is the first one in uppercase only,
 and no unicode)

This is how NT encrypts the passwords:

The logon cleartext password a user enters is:
1) Converted to unicode
2) A MD4 hash is made out of the unicode string
3) Then the hash is crypted with DES, using the RID (lower
   part of the SID, userid) as the crypt key.
   This is the so called "obfuscation" step, so
   it's not obvious on a hex dump of the file
   that two or more users have the same password.
4) The result of stage 3 (16 bytes) is put into the V struct.

For the LANMAN password:
1) Uppercased (and illegal characters probably removed)
   14 bytes max, if less the remaining bytes are zeroed.
2) A known (constant) string is DES-encrypted
   using 7 first characters of the password as the key.
   Another constant is encrypted using the last 7 chars
   as the key.
   The result of these two crypts are simply appended,
   resulting in a 16 byte string.
3) The same obfuscation DES stage as 3 above.
4) 16 bytes result put into the V struct.

Since the number of possible combinations in the lanman
password is relatively low compared to the other one,
and it's easy to see if it's shorter than 8 chars or not
it's used first in brute-force-crackers.

This program, however, don't care at all what the old
one is, it just overwrites it with the new one.

Ok. So, how do we find and identify the V struct?
Yeah.. that was the hard part.. The files structure
is not documented (as far as I know..)

But, with help from an unnamed German, and a lot of testing
and guesswork from myself, it's now possible to follow
the actual registry tree. (see source code for struct-defines
and comments on the registry structure)

The usernames are listed in:
\SAM\Domains\Account\Users\Names\

[2d18] \SAM\Domains\Account\Users\Names> l
ls of node at offset 0x2d1c
Node has 4 subkeys and 1 values
nk-offset      name
0x003290 - <Administrator>
0x003630 - <Guest>
0x001c88 - <luser>
0x003428 - <pnh>

Each name is a subkey, with one namless value containing
the RID.

[2d18] \SAM\Domains\Account\Users\Names> cd pnh

[3428] \SAM\Domains\Account\Users\Names\pnh> l
ls of node at offset 0x342c
Node has 0 subkeys and 1 values
vk-offs    size    type           name
0x003688     0  (unknown)        <> INLINE:  val (in type field?): 1000 (0x3e8)

To get the userinfo (V struct), access
\SAM\Domains\Account\Users\<RID>\V

[2c90] \SAM\Domains\Account\Users> l
ls of node at offset 0x2c94
Node has 5 subkeys and 1 values
nk-offset      name
0x003320 - <000001F4>
0x0036b8 - <000001F5>
0x003550 - <000003E8>
0x001d00 - <000003E9>
0x002d18 - <Names>

[2c90] \SAM\Domains\Account\Users> cd 000003E8

[3550] \SAM\Domains\Account\Users\000003E8> l
ls of node at offset 0x3554
Node has 0 subkeys and 2 values
vk-offs    size    type           name
0x0035a8    80  REG_BINARY       <F>
0x003228   508  REG_BINARY       <V>

For more techincal info, look it up in the source code.
