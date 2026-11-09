# AGENTS.md

CLI that installs Hysteria2 + VLESS REALITY (gRPC, XHTTP) on a VPS and serves Hiddify subscriptions. Server paths: README.md.

- `/var/lib/vpnctl/state.json` on the server is the single source of truth; every config is rendered from it by `internal/render`. Change the state, then `render.WriteServerFiles`.
- Pushing to `main` deploys: `vpnctl update` on the VPS builds whatever `main` has.
- Xray is pinned below 26.9.8 on purpose (Hiddify/sing-box REALITY breaks, see `internal/state/versions.go`). Bump it only after checking SagerNet/sing-box#4520.
- Client links are parsed by Hiddify's `hiddify/ray2sing`; check its parser before changing link parameters.
- Shell commands for the user and for the VPS are fish.

## Verifying changes

There are no unit tests. Check a change end to end in Docker:
- render a state with a throwaway `_test.go` and `VPNCTL_STATE=/tmp/...`, run the pinned hysteria/xray images on a user network created with `-o com.docker.network.driver.mtu=1500` (the local default MTU 1280 silently drops salamander QUIC Initials);
- hysteria: official client with the link from `render.HyLink`; REALITY: both an xray client and `ghcr.io/sagernet/sing-box` (what Hiddify is built on);
- ACME: `ghcr.io/letsencrypt/pebble` with `httpPort: 80`, `VPNCTL_ACME_DIR` and `SSL_CERT_FILE` pointing at pebble's minica.
