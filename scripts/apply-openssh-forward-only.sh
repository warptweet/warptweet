#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OPENSSH_SOURCE_DIRECTORY" >&2
    exit 64
fi

WT_SOURCE=$1
if [ ! -f "$WT_SOURCE/serverloop.c" ]; then
    echo "unsupported OpenSSH source tree: missing serverloop.c" >&2
    exit 65
fi
if ! grep -q 'server_input_channel_open' "$WT_SOURCE/serverloop.c" ||
    ! grep -q 'server_input_global_request' "$WT_SOURCE/serverloop.c"; then
    echo "unsupported OpenSSH source tree: missing channel/global request handlers" >&2
    exit 65
fi

if grep -q 'WarpTweet allows only direct-tcpip channels' "$WT_SOURCE/serverloop.c"; then
    exit 0
fi

tmp=$(mktemp)
awk '
    /ctype, rchan, rwindow, rmaxpack\);/ {
        print
        print ""
        print "	if (strcmp(ctype, \"direct-tcpip\") != 0) {"
        print "		error(\"WarpTweet refused channel type %s\", ctype);"
        print "		ssh_packet_disconnect(ssh,"
        print "		    \"WarpTweet allows only direct-tcpip channels\");"
        print "	}"
        done_channel=1
        next
    }
    /debug_f\("rtype %s want_reply %d", rtype, want_reply\);/ {
        print
        print ""
        print "	if (strcmp(rtype, \"keepalive@openssh.com\") != 0 &&"
        print "	    strcmp(rtype, \"no-more-sessions@openssh.com\") != 0) {"
        print "		error(\"WarpTweet refused global request %s\", rtype);"
        print "		ssh_packet_disconnect(ssh,"
        print "		    \"WarpTweet refused SSH global request\");"
        print "	}"
        done_global=1
        next
    }
    { print }
    END {
        if (!done_channel || !done_global) {
            exit 65
        }
    }
' "$WT_SOURCE/serverloop.c" >"$tmp"
cat "$tmp" >"$WT_SOURCE/serverloop.c"
rm -f "$tmp"

if ! grep -q 'WarpTweet allows only direct-tcpip channels' "$WT_SOURCE/serverloop.c" ||
    ! grep -q 'WarpTweet refused SSH global request' "$WT_SOURCE/serverloop.c"; then
    echo "forward-only rewrite of serverloop.c failed" >&2
    exit 65
fi
