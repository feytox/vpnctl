#!/bin/sh
# First install from a clone: build vpnctl in the Go image and run `vpnctl install`.
# Arguments go to `vpnctl install`. Later versions come with `vpnctl update`,
# which uses the same clone (~/.local/share/vpnctl/src) and build cache.
set -eu

src=$(cd "$(dirname "$0")" && pwd)
go_image=$(sed -n 's/.*goImage *= *"\(.*\)".*/\1/p' "$src/internal/cli/update.go")
sudo=""
[ "$(id -u)" -eq 0 ] || sudo=sudo

if ! command -v docker >/dev/null 2>&1; then
	echo "docker is not installed, installing it with get.docker.com"
	curl -fsSL https://get.docker.com | $sudo sh
	$sudo systemctl enable --now docker
fi

cache="$(dirname "$src")/gocache"
mkdir -p "$cache"
rev=$(git -C "$src" rev-parse --short HEAD)
echo "building vpnctl $rev in $go_image"
$sudo docker run --rm --user "$(id -u):$(id -g)" \
	-v "$src:/src" -v "$cache:/cache" -w /src \
	-e CGO_ENABLED=0 -e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod \
	"$go_image" go build -trimpath -ldflags "-s -w -X vpnctl/internal/cli.Version=$rev" -o /src/vpnctl.new ./cmd/vpnctl

mv "$src/vpnctl.new" "$src/vpnctl"
exec $sudo "$src/vpnctl" install "$@"
