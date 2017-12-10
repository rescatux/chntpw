Git based Debian package build
==============================

Rescatux git repo uses several branches for chntpw:
 master : upstream
 debian : Official Debian package debian/ 
 chntpw-ng-1.01 : chntpw as if Rescatux developers were upstream
 chntpw-ng-0.99.9 : chntpw as if Rescatux developers were upstream
 debian-ng-1.02 : What Rescatux developers think should be in Official Debian package
.

There are also handy tags for building chntpw.
* debian-ng-1.02
* v1.0

Please enter an empty folder and follow this procedure:

git clone https://github.com/rescatux/chntpw.git -b v1.0 chntpw-1.0
# Ignore detached HEAD warning
rm -rf chntpw-1.0/.git/
tar czf chntpw_1.0.orig.tar.gz chntpw-1.0/
rm -rf chntpw-1.0/
git clone https://github.com/rescatux/chntpw.git -b debian-ng-1.02 chntpw-1.0
# Ignore detached HEAD warning
rm -rf chntpw-1.0/.git/
cd chntpw-1.0
dpkg-buildpackage -us -uc
cd ..
rm -rf chntpw-1.0/

Once the procedure has ended without any errors you will find these
package files:

chntpw_1.0-2.debian.tar.xz
chntpw_1.0-2.dsc
chntpw_1.0-2_i386.changes
chntpw_1.0-2_i386.deb
chntpw_1.0.orig.tar.gz

or

chntpw_1.0-2.debian.tar.xz
chntpw_1.0-2.dsc
chntpw_1.0-2_amd64.changes
chntpw_1.0-2_amd64.deb
chntpw_1.0.orig.tar.gz
