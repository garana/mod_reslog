#!/bin/bash

# $Id: bootstrap.sh,v 1.1.1.1 2006/10/02 15:32:43 garana Exp $

set -e

rm -rvf configure config.log config.h aclocal.m4
rm -rvf Makefile.in stamp-h.in src/Makefile.in
rm -rvf cfgaux/[a-z]* autom4te.cache/[a-z]*
rm -rvf config.status config.guess

mkdir cfgaux || true

# Generate AM macros for autoconf
aclocal 

# configure.in => configure
echo autoconf
autoconf --force

# ads ltmain.sh
echo libtoolize --copy
libtoolize --copy

# Makefile.am => Makefile.in
# build config.h.in
autoheader
echo automake --add-missing --copy
automake --add-missing --copy

exit 0

