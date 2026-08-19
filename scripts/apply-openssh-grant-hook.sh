#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OPENSSH_SOURCE_DIRECTORY" >&2
    exit 64
fi

WT_SOURCE=$1
WT_REPO=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
WT_HOOK_C="$WT_REPO/third_party/openssh/warptweet-grant.c"
WT_HOOK_H="$WT_REPO/third_party/openssh/warptweet-grant.h"
WT_PATCH="$WT_REPO/third_party/openssh/patches/0001-warptweet-grant-register.patch"

if [ ! -f "$WT_HOOK_C" ] || [ ! -f "$WT_HOOK_H" ]; then
    echo "missing WarpTweet OpenSSH grant hook sources" >&2
    exit 65
fi
if [ ! -f "$WT_SOURCE/sshd-session.c" ] || [ ! -f "$WT_SOURCE/monitor.c" ] ||
    [ ! -f "$WT_SOURCE/Makefile.in" ]; then
    echo "unsupported OpenSSH source tree: missing required files" >&2
    exit 65
fi
if ! grep -q mm_answer_keyverify "$WT_SOURCE/monitor.c"; then
    echo "unsupported OpenSSH source tree: missing mm_answer_keyverify insertion anchor" >&2
    exit 65
fi
if ! grep -Eq 'if \(i == 255 && (auth_attempted|monitor_auth_attempted\(\))\)' "$WT_SOURCE/sshd-session.c"; then
    echo "unsupported OpenSSH source tree: missing sshd-session insertion anchor" >&2
    exit 65
fi

install -m 0644 "$WT_HOOK_C" "$WT_SOURCE/warptweet-grant.c"
install -m 0644 "$WT_HOOK_H" "$WT_SOURCE/warptweet-grant.h"

if [ -f "$WT_PATCH" ]; then
    if (CDPATH= cd -- "$WT_SOURCE" && patch -p1 --forward --reject-file=- <"$WT_PATCH"); then
        :
    fi
fi

# configure already generated Makefile when this runs after make tests.
ensure_makefile_object() {
    WT_MAKEFILE=$1
    [ -f "$WT_MAKEFILE" ] || return 0
    WT_SESSION_OBJS='uidswap.o platform-listen.o warptweet-grant.o( \$\(P11OBJS\))? \$\(SKOBJS\)'
    if grep -Eq "$WT_SESSION_OBJS" "$WT_MAKEFILE"; then
        return 0
    fi
    if ! grep -Eq 'uidswap.o platform-listen.o( \$\(P11OBJS\))? \$\(SKOBJS\)' "$WT_MAKEFILE"; then
        echo "cannot locate sshd-session object list in $WT_MAKEFILE" >&2
        exit 65
    fi
    tmp=$(mktemp)
    sed -E 's/uidswap.o platform-listen.o( \$\(P11OBJS\))? \$\(SKOBJS\)/uidswap.o platform-listen.o warptweet-grant.o\1 $(SKOBJS)/' \
        "$WT_MAKEFILE" >"$tmp"
    if ! grep -Eq "$WT_SESSION_OBJS" "$tmp"; then
        rm -f "$tmp"
        echo "sshd-session object list was not updated in $WT_MAKEFILE" >&2
        exit 65
    fi
    cat "$tmp" >"$WT_MAKEFILE"
    rm -f "$tmp"
}

ensure_makefile_object "$WT_SOURCE/Makefile.in"
ensure_makefile_object "$WT_SOURCE/Makefile"

if ! grep -q 'warptweet-grant.h' "$WT_SOURCE/monitor.c"; then
    tmp=$(mktemp)
    awk '
        /#include "srclimit.h"/ && !done_inc {
            print
            print "#include \"warptweet-grant.h\""
            done_inc=1
            next
        }
        /if \(key_blobtype == MM_USERKEY && ret == 0\)$/ && !done_hook {
            print "	if (key_blobtype == MM_USERKEY && ret == 0) {"
            print "		if (warptweet_grant_register(blob, bloblen) != 0) {"
            print "			error(\"WarpTweet grant registration rejected public key\");"
            print "			ret = -1;"
            print "		} else"
            getline
            if ($0 ~ /auth_activate_options/) {
                print
            }
            print "	}"
            done_hook=1
            next
        }
        /\/\* Terminate process \*\// && !done_term {
            print
            print "	warptweet_grant_unregister();"
            done_term=1
            next
        }
        { print }
        END {
            if (!done_inc || !done_hook || !done_term) {
                exit 65
            }
        }
    ' "$WT_SOURCE/monitor.c" >"$tmp"
    cat "$tmp" >"$WT_SOURCE/monitor.c"
    rm -f "$tmp"
fi

if ! grep -q 'warptweet-grant.h' "$WT_SOURCE/sshd-session.c"; then
    tmp=$(mktemp)
    awk '
        /#include "dh.h"/ && !done_inc {
            print
            print "#include \"warptweet-grant.h\""
            done_inc=1
            next
        }
        /if \(i == 255 && (auth_attempted|monitor_auth_attempted\(\))\)/ && !done_hook {
            print "	warptweet_grant_unregister();"
            print
            done_hook=1
        }
        { print }
        END {
            if (!done_inc || !done_hook) {
                exit 65
            }
        }
    ' "$WT_SOURCE/sshd-session.c" >"$tmp"
    cat "$tmp" >"$WT_SOURCE/sshd-session.c"
    rm -f "$tmp"
fi
