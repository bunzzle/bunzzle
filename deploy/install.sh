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
if [ -n "${BUNZZLE_EGRESS:-}" ]; then
  units="bunzzle-egress.service"
elif [ -n "${BUNZZLE_NODE:-}" ]; then
  units="bunzzle-delivery.service"
else
  units="bunzzle.target bunzzle-signer.service bunzzle-dns.service bunzzle-link.service bunzzle-core.service bunzzle-delivery.service bunzzle-api.service bunzzle-inbound.service"
fi
for unit in $units; do
  install -m 0644 "$SRC/systemd/$unit" "/etc/systemd/system/$unit"
done
systemd-sysusers bunzzle.conf
if id -nG bunzzle-inbound | tr ' ' '\n' | grep -qx bunzzle-core; then gpasswd -d bunzzle-inbound bunzzle-core >/dev/null; fi
systemd-tmpfiles --create bunzzle.conf

if [ ! -f /etc/bunzzle/bunzzle.env ]; then
  install -m 0644 "$SRC/bunzzle.env" /etc/bunzzle/bunzzle.env
  echo "created /etc/bunzzle/bunzzle.env: set BUNZZLE_EHLO_NAME, BUNZZLE_SOURCE_IPS and BUNZZLE_PUBLIC_URL"
fi
if [ -f "$SRC/nftables/bunzzle.nft" ]; then
  install -m 0644 "$SRC/nftables/bunzzle.nft" /etc/bunzzle/bunzzle.nft
fi

if [ -n "${BUNZZLE_EGRESS:-}" ]; then
  systemctl daemon-reload
  systemctl add-wants multi-user.target bunzzle-egress.service >/dev/null
  echo "egress installed: set BUNZZLE_SOURCE_IPS and BUNZZLE_EGRESS_LISTEN in /etc/bunzzle/bunzzle.env"
  echo "then: sudo -u bunzzle-egress bunzzle nodes request NAME --egress"
  exit 0
fi

if [ -n "${BUNZZLE_NODE:-}" ]; then
  systemctl daemon-reload
  systemctl add-wants multi-user.target bunzzle-delivery.service >/dev/null
  echo "delivery node installed: set BUNZZLE_EHLO_NAME, BUNZZLE_SOURCE_IPS and BUNZZLE_DELIVERY_LISTEN in /etc/bunzzle/bunzzle.env"
  echo "then: sudo -u bunzzle-delivery bunzzle nodes request NAME"
  exit 0
fi

if [ ! -f /etc/bunzzle/master.key ]; then
  (umask 077 && "$PREFIX/bunzzle" master-key > /etc/bunzzle/master.key)
  echo "created /etc/bunzzle/master.key: back it up somewhere safe, losing it makes stored keys and queued email unreadable"
fi
chmod 0600 /etc/bunzzle/master.key

systemctl daemon-reload
systemctl enable bunzzle.target >/dev/null
not_running() {
  failed=""
  for role in signer dns link core delivery api inbound; do
    systemctl is-active --quiet "bunzzle-$role" || failed="$failed $role"
  done
  [ -n "$failed" ]
}
systemctl --no-block restart bunzzle.target
i=0
while not_running && [ "$i" -lt 60 ]; do
  i=$((i + 1))
  sleep 1
done
[ -n "$failed" ] || { sleep 3; not_running || true; }
if [ -n "$failed" ]; then
  for role in $failed; do
    journalctl -u "bunzzle-$role" -n 5 --no-pager -o cat >&2 || true
  done
  die "not running:$failed (see journalctl -u 'bunzzle-*')"
fi
echo "bunzzle $("$PREFIX/bunzzle" --version) is running: systemctl status 'bunzzle-*'"
echo "optional egress filter (only delivery and dns may connect out): nft -f /etc/bunzzle/bunzzle.nft"
