# Lab enroll from this Mac

One Linux host package, one Darwin client package, one invite, one loopback
check. This is a lab procedure, not WP8 evidence.

You already have:

- Linux host `.deb`: `dist/warptweet_0.1.0-rc.7_amd64.deb`
- Builder SSH from `.env` (`WARPTWEET_INTEROP_SERVER_HOST`)

You also need a Darwin client `.pkg` installed on this Mac. `connect` talks to
the package provisioner. A source-tree `./bin/warptweet` will not open the
tunnel.

```sh
test -x "/Library/Application Support/WarpTweet/bin/warptweet"
```

If that fails, install the matching client package first, then continue.

## 1. Install the host package

From this Mac:

```sh
HOST="$WARPTWEET_INTEROP_SERVER_HOST"
scp dist/warptweet_0.1.0-rc.7_amd64.deb ubuntu@"$HOST":/tmp/
ssh ubuntu@"$HOST" 'sudo dpkg -i /tmp/warptweet_0.1.0-rc.7_amd64.deb'
```

Open the two WarpTweet ports (SSH data plane 2222, enroll TLS 29722):

```sh
ssh ubuntu@"$HOST" 'sudo ufw allow 2222/tcp && sudo ufw allow 29722/tcp && sudo ufw status'
```

If `ufw` is inactive, open the same ports in the provider firewall instead.

## 2. Put a target on the host

The invite binds a host-local TCP service. A throwaway HTTP listener is enough:

```sh
ssh ubuntu@"$HOST" 'python3 -m http.server 18080 --bind 127.0.0.1'
```

Leave that session running.

## 3. Mint the invite on the host

In a second SSH session:

```sh
ssh -t ubuntu@"$HOST" 'sudo warptweet host --to 127.0.0.1:18080 --name macbook --out /tmp/macbook.wtinvite --yes'
```

Copy the invite to this Mac. Do not commit it.

```sh
scp ubuntu@"$HOST":/tmp/macbook.wtinvite "$HOME/Desktop/macbook.wtinvite"
```

## 4. Enroll and connect from this Mac

```sh
warptweet connect "$HOME/Desktop/macbook.wtinvite" --yes
```

Success prints `connected` and a local `open 127.0.0.1:15432` line.

## 5. Verify on this Mac

```sh
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:15432/
warptweet status macbook --json
```

Expect HTTP `200` from curl and `"phase":"ready"` (or equivalent ready status)
from `status`. If `connect` printed `enrolled_not_ready`, run:

```sh
warptweet repair macbook
```

Then repeat the curl.

## 6. Stop

```sh
warptweet down macbook
rm -f "$HOME/Desktop/macbook.wtinvite"
```

On the host, Ctrl+C the Python server. The invite is single-use. Do not reuse
the file after a successful connect.
