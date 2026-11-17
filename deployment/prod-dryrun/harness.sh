#!/bin/bash
# Host-side driver of the production-kit dry runs (agent 385, round 18). Runs as `ubuntu` on a build or L2 host
# (136.244.93.186 in round 18), never installs anything on the host itself: everything happens in throwaway
# containers named a385-* with systemd as PID 1 and --network none.
#
#   harness.sh build                      build the image a385-dryrun:r18 from this directory
#   harness.sh run ROLE STAGE OUT         ROLE a|b; STAGE is a directory holding:
#                                           l2-golive-next/{artifacts,kit,release-settler-v2/settler_v3.py}
#                                           dryrun/{rehearsal.pub,expect-sha256sums,expect-golive-pins,remote_prover.py}
#                                         OUT receives log.txt, steps.jsonl, host.json. The container is removed.
#   harness.sh clean                      remove every a385-* container this harness recorded (by ID)
#
# IDs of started containers are appended to $SCRATCH/pids (container ID, name, time); clean removes only those.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SCRATCH=${SCRATCH:-$HOME/l2dexbridge-20261030/l2-prod-deploy-r18}
IMAGE=a385-dryrun:r18
CIRCUITS=${CIRCUITS:-/home/ubuntu/l2-mainnet-install-20261019/circuits}
SETTLER_V2=${SETTLER_V2:-/home/ubuntu/l2dexbridge-20261030/settler-v2}
mkdir -p "$SCRATCH"
case "${1:-}" in
  build)
    docker build -t $IMAGE "$HERE"
    docker image inspect $IMAGE --format '{{.Id}}' > "$SCRATCH/image-id" ;;
  run)
    role=$2 stage=$(cd "$3" && pwd) out=$4
    mkdir -p "$out"
    name=a385-$role-$(date -u +%H%M%S)
    id=$(docker run -d --name "$name" --hostname "$name" --network none --privileged --cgroupns=private \
      --tmpfs /run --tmpfs /run/lock --memory 16g --pids-limit 4096 \
      -v "$CIRCUITS:$CIRCUITS:ro" -v "$SETTLER_V2:$SETTLER_V2:ro" $IMAGE)
    echo "$id $name $(date -u +%FT%TZ)" >> "$SCRATCH/pids"
    trap 'docker rm -f "$id" >/dev/null 2>&1 || true' EXIT
    docker exec "$id" mkdir -p /home/ubuntu /dryrun
    docker cp "$stage/l2-golive-next" "$id:/home/ubuntu/l2-golive-next"
    docker cp "$stage/dryrun/." "$id:/dryrun/"
    docker cp "$HERE/lib.sh" "$id:/dryrun/lib.sh"
    docker cp "$HERE/dryrun-$role.sh" "$id:/dryrun/dryrun-$role.sh"
    docker cp "$HERE/rpc_stub.py" "$id:/dryrun/rpc_stub.py"
    docker exec "$id" chown -R ubuntu:ubuntu /home/ubuntu/l2-golive-next
    docker exec "$id" bash -c 'for i in $(seq 1 60); do systemctl is-system-running 2>/dev/null | grep -qE "running|degraded" && exit 0; sleep 1; done; exit 0'
    # --network none leaves only `lo`: getaddrinfo(AI_ADDRCONFIG) then resolves no IPv4 literal, which the
    # installers need for IPAddressAllow. A dummy interface on TEST-NET-1 (192.0.2.0/24, RFC 5737) gives an IPv4
    # address with no route anywhere else. /run/sshd is what a booted host with sshd running already has.
    docker exec "$id" bash -c 'ip link add dummy0 type dummy && ip addr add 192.0.2.85/24 dev dummy0 && ip link set dummy0 up && mkdir -p -m 0755 /run/sshd'
    docker exec "$id" bash -c "dpkg -l | sha256sum; uname -r; systemctl --version | head -1; ip -4 route" > "$out/container-env.txt" || true
    docker exec "$id" bash /dryrun/dryrun-$role.sh | tee "$out/console.txt" || true
    docker cp "$id:/dryrun/out/." "$out/"
    python3 - "$out" "$name" "$id" "$(cat "$SCRATCH/image-id" 2>/dev/null)" <<'PY'
import json, sys, datetime
out, name, cid, image = sys.argv[1:5]
json.dump({'container': name, 'id': cid, 'image': image, 'network': 'none',
           'finished': datetime.datetime.utcnow().isoformat() + 'Z'}, open(f'{out}/host.json', 'w'), indent=2)
PY
    ;;
  clean)
    [ -f "$SCRATCH/pids" ] || exit 0
    while read -r id name _; do
      case $name in a385-*) docker rm -f "$id" >/dev/null 2>&1 && echo "removed $name" || true;; esac
    done < "$SCRATCH/pids" ;;
  *) sed -n 2,14p "$0"; exit 2 ;;
esac
