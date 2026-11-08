package state

// Images are pinned; `vpnctl update --check` reads these lines from the repo
// and compares them with upstream releases.
const (
	HysteriaImage = "tobyxdd/hysteria:v2.13.0"
	XrayImage     = "ghcr.io/xtls/xray-core:26.6.27"
)

// XrayHold explains why XrayImage is older than upstream. Xray 26.9.8+ rejects
// REALITY ClientHello without an X25519MLKEM768 key share, and sing-box based
// clients (Hiddify) strip it: auth fails and the client lands on the camouflage
// site. 26.7.11-26.9.7 also refuse sing-box by minClientVer. Track
// https://github.com/SagerNet/sing-box/issues/4520 before moving on.
// The MPTCP hole fixed in 26.10.31 is closed by net.mptcp.enabled = 0 (see sys).
const XrayHold = "26.9.8+ ломает REALITY у Hiddify (sing-box #4520)"
