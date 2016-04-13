#!/bin/sh

OPT=/usr/local/opt

GETTEXT="$OPT/gettext"
NSS="$OPT/nss"
NSPR="$OPT/nspr"

PATH="$GETTEXT/bin:$PATH"


./autogen.sh -I$GETTEXT/share/aclocal
CFLAGS="-I$GETTEXT/include -I$NSS/include -I$NSPR/include/nspr" LDFLAGS="-L$GETTEXT/lib -L$NSS/lib -L$NSPR/lib" ./configure
make
