#!/bin/sh
set -eu

REPO="bunzzle/bunzzle"
PREFIX="/usr/local/bin"
SRC="$(cd "$(dirname "$0")" && pwd)"

die() { echo "install: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
command -v systemctl >/dev/null || die "systemd is required"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() {
  version="${BUNZZLE_VERSION:-latest}"
  if [ -n "${BUNZZLE_RELEASE_URL:-}" ]; then
    base="$BUNZZLE_RELEASE_URL"
  elif [ "$version" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$version"
  fi
  [ -f "$tmp/SHA256SUMS" ] || curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
  echo "downloading $1 ($version)"
  curl -fsSL -o "$tmp/$1" "$base/$1"
  (cd "$tmp" && grep " $1\$" SHA256SUMS | sha256sum -c - >/dev/null) || die "checksum mismatch for $1"
}

binary="${1:-}"
if [ -z "$binary" ]; then
  case "$(uname -m)" in
    x86_64) arch=x64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
  fetch "bunzzle-linux-$arch"
  binary="$tmp/bunzzle-linux-$arch"
fi
[ -f "$binary" ] || die "binary not found: $binary"

if [ ! -d "$SRC/systemd" ]; then
  fetch bunzzle-deploy.tar.gz
  tar -xzf "$tmp/bunzzle-deploy.tar.gz" -C "$tmp"
  SRC="$tmp/deploy"
fi

install -m 0755 "$binary" "$PREFIX/bunzzle"
install -m 0644 "$SRC/systemd/bunzzle.sysusers" /usr/lib/sysusers.d/bunzzle.conf
install -m 0644 "$SRC/systemd/bunzzle.tmpfiles" /usr/lib/tmpfiles.d/bunzzle.conf
for unit in bunzzle.target bunzzle-signer.service bunzzle-core.service bunzzle-delivery.service bunzzle-api.service bunzzle-inbound.service; do
  install -m 0644 "$SRC/systemd/$unit" "/etc/systemd/system/$unit"
done
systemd-sysusers bunzzle.conf
systemd-tmpfiles --create bunzzle.conf

if [ ! -f /etc/bunzzle/bunzzle.env ]; then
  install -m 0644 "$SRC/bunzzle.env" /etc/bunzzle/bunzzle.env
  echo "created /etc/bunzzle/bunzzle.env: set BUNZZLE_EHLO_NAME, BUNZZLE_SOURCE_IPS and BUNZZLE_PUBLIC_URL"
fi
if [ ! -f /etc/bunzzle/master.key ]; then
  (umask 077 && "$PREFIX/bunzzle" master-key > /etc/bunzzle/master.key)
  echo "created /etc/bunzzle/master.key: back it up somewhere safe, losing it makes stored keys and queued email unreadable"
fi
chmod 0600 /etc/bunzzle/master.key
if [ -f "$SRC/nftables/bunzzle.nft" ]; then
  install -m 0644 "$SRC/nftables/bunzzle.nft" /etc/bunzzle/bunzzle.nft
fi

systemctl daemon-reload
systemctl enable bunzzle.target >/dev/null
systemctl restart bunzzle.target
sleep 3
failed=""
for role in signer core delivery api inbound; do
  systemctl is-active --quiet "bunzzle-$role" || failed="$failed $role"
done
if [ -n "$failed" ]; then
  die "not running:$failed (see journalctl -u 'bunzzle-*')"
fi
echo "bunzzle $("$PREFIX/bunzzle" --version) is running: systemctl status 'bunzzle-*'"
echo "optional egress filter (only delivery may connect out, on 25, 53 and 443): nft -f /etc/bunzzle/bunzzle.nft"
