# Ephemeral enrollment

Hardening sequence step 3.

29722 is no longer a boot service. `warptweet-enroll.service` has no
`WantedBy=multi-user.target`. `host` starts it while minting. The listener
exits once no unexpired issued invite remains.

Rotate and revoke no longer use 29722. They use a localhost RPC on
`127.0.0.1:29723` (`warptweet-mgmt.service`), reached through a second
`LocalForward` on the already authenticated tunnel. That is not a shell.
`PermitOpen` allows the data target and `127.0.0.1:29723` only.

Daily operation can close 29722. Management stays on the host loopback.
