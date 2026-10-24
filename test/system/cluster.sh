#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."
[ -x dist/bunzzle ] || { echo "cluster: run bun run build first" >&2; exit 1; }

BUN_IMAGE="oven/bun:1.4.3@sha256:ec06c3b6cea04192ae6770c434f668ca41d343ad19fa6472216c7b48be39c598"
CORE_ADMIN=10.89.0.10
WORLD_ADMIN=10.89.0.20
CORE_NODE_LINK=10.89.1.10
NODE_LINK=10.89.1.20
CORE_EGRESS_LINK=10.89.2.10
EGRESS_LINK=10.89.2.30
NODE_IP=10.89.3.20
EGRESS_IP=10.89.3.30
MX_IP=10.89.3.40

tmp="$(mktemp -d)"
hosts="core node egress"

finish() {
  code=$?
  if [ "$code" != 0 ]; then
    for h in $hosts; do
      echo "== $h"
      docker exec "bz-$h" systemctl list-jobs --no-pager 2>/dev/null || true
      docker exec "bz-$h" systemctl status 'bunzzle*' --no-pager 2>/dev/null | head -60 || true
      docker exec "bz-$h" journalctl -u 'bunzzle-*' --no-pager 2>/dev/null | tail -80 || true
      docker exec "bz-$h" nft list table inet bunzzle 2>/dev/null | grep counter || true
    done
  fi
  docker rm -f bz-core bz-node bz-egress bz-world >/dev/null 2>&1 || true
  for n in admin link-node link-egress internet; do docker network rm "bz-$n" >/dev/null 2>&1 || true; done
  rm -rf "$tmp"
  exit "$code"
}
trap finish EXIT

step() { echo "- $*"; }
on() { h="$1"; shift; timeout 120 docker exec "bz-$h" "$@"; }

docker build -q -t bunzzle-host:test test/system/cluster >/dev/null
docker network create --internal --subnet 10.89.0.0/24 bz-admin >/dev/null
docker network create --internal --subnet 10.89.1.0/24 bz-link-node >/dev/null
docker network create --internal --subnet 10.89.2.0/24 bz-link-egress >/dev/null
docker network create --internal --subnet 10.89.3.0/24 bz-internet >/dev/null

host() {
  docker run -d --name "bz-$1" --hostname "$1" --privileged --cgroupns=private \
    --tmpfs /run:exec --tmpfs /run/lock -v "$PWD:/src:ro" \
    --network "bz-$2" --ip "$3" bunzzle-host:test >/dev/null
  docker network connect --ip "$5" "bz-$4" "bz-$1"
}
host core admin "$CORE_ADMIN" link-node "$CORE_NODE_LINK"
docker network connect --ip "$CORE_EGRESS_LINK" bz-link-egress bz-core
host node link-node "$NODE_LINK" internet "$NODE_IP"
host egress link-egress "$EGRESS_LINK" internet "$EGRESS_IP"
docker run -d --name bz-world --user 0 -v "$PWD:/src:ro" -w /src \
  --network bz-admin --ip "$WORLD_ADMIN" "$BUN_IMAGE" sleep infinity >/dev/null
docker network connect --ip "$MX_IP" bz-internet bz-world

for h in $hosts; do
  i=0
  until on "$h" systemctl is-system-running 2>/dev/null | grep -qE '^(running|degraded)$'; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || { echo "cluster: systemd did not start in $h" >&2; exit 1; }
    sleep 1
  done
done
step "core, node and egress booted with systemd"

on core /src/deploy/install.sh /src/dist/bunzzle >/dev/null
timeout 120 docker exec -e BUNZZLE_NODE=1 bz-node /src/deploy/install.sh /src/dist/bunzzle >/dev/null
timeout 120 docker exec -e BUNZZLE_EGRESS=1 bz-egress /src/deploy/install.sh /src/dist/bunzzle >/dev/null
step "installed with install.sh"

on core nft -f /etc/bunzzle/bunzzle.nft
on core nft add element inet bunzzle node_links4 "{ $NODE_LINK . 7465 }"
on core nft add element inet bunzzle egress_links4 "{ $EGRESS_LINK . 7466 }"
on node nft -f /etc/bunzzle/bunzzle.nft
on node nft add element inet bunzzle core4 "{ $CORE_NODE_LINK }"
on node nft add element inet bunzzle link_ports '{ 7465 }'
on egress nft -f /etc/bunzzle/bunzzle.nft
on egress nft add element inet bunzzle core4 "{ $CORE_EGRESS_LINK }"
on egress nft add element inet bunzzle link_ports '{ 7466 }'
step "firewall loaded on all three"

docker exec -i bz-core sh -c 'cat >> /etc/bunzzle/bunzzle.env' <<ENV
BUNZZLE_HOST=$CORE_ADMIN
BUNZZLE_EHLO_NAME=mail.bunzzle.test
BUNZZLE_SOURCE_IPS=$NODE_IP=node,$EGRESS_IP=edge
BUNZZLE_DNS_SERVERS=$WORLD_ADMIN:53
BUNZZLE_ALLOW_PRIVATE_DESTINATIONS=true
ENV
docker exec -i bz-node sh -c 'cat >> /etc/bunzzle/bunzzle.env' <<ENV
BUNZZLE_EHLO_NAME=node.bunzzle.test
BUNZZLE_SOURCE_IPS=$NODE_IP
BUNZZLE_DELIVERY_LISTEN=$NODE_LINK:7465
BUNZZLE_DNS_SERVERS=$MX_IP:53
BUNZZLE_ALLOW_PRIVATE_DESTINATIONS=true
ENV
docker exec -i bz-egress sh -c 'cat >> /etc/bunzzle/bunzzle.env' <<ENV
BUNZZLE_SOURCE_IPS=$EGRESS_IP
BUNZZLE_EGRESS_LISTEN=$EGRESS_LINK:7466
ENV
on core systemctl restart bunzzle.target

enroll() {
  h="$1" name="$2" user="$3" dir="$4" address="$5" unit="$6" flag="${7:-}"
  on "$h" runuser -u "$user" -- bunzzle nodes request "$name" $flag >/dev/null
  docker cp -q "bz-$h:$dir/request.csr" "$tmp/$name.csr"
  docker cp -q "$tmp/$name.csr" "bz-core:/root/$name.csr"
  docker exec -w /root bz-core bunzzle nodes add "$name" "$address" "$name.csr" $flag >/dev/null
  docker cp -q "bz-core:/root/$name.bundle.json" "$tmp/"
  docker cp -q "$tmp/$name.bundle.json" "bz-$h:$dir/"
  on "$h" chown "$user:$user" "$dir/$name.bundle.json"
  on "$h" chmod 0600 "$dir/$name.bundle.json"
  on "$h" runuser -u "$user" -- bunzzle nodes install "$dir/$name.bundle.json" >/dev/null
  on "$h" systemctl restart "$unit"
}
enroll node node-1 bunzzle-delivery /var/lib/bunzzle/node "$NODE_LINK:7465" bunzzle-delivery
enroll egress edge-1 bunzzle-egress /var/lib/bunzzle/egress "$EGRESS_LINK:7466" bunzzle-egress --egress
step "node and egress enrolled with nodes request, add and install"

token="$(on core bunzzle keys create --name cluster --scope full | tail -1)"
docker exec -e BUNZZLE_CLUSTER_TOKEN="$token" \
  -e BUNZZLE_CLUSTER_API="http://$CORE_ADMIN:3000" \
  -e BUNZZLE_CLUSTER_ROUTES="node=$NODE_IP,edge=$EGRESS_IP" \
  -e BUNZZLE_CLUSTER_MX="$MX_IP" \
  bz-world bun test/system/cluster.ts
