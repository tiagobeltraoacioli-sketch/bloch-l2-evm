#!/bin/bash
# Dry run of host B (second follower + replica RPC) and of the public gateway (docs/L2-PRODUCTION-DEPLOY.md,
# sections 5 and 7), inside a throwaway container with systemd as PID 1 and --network none. Agent 385, round 18.
# Deviations (each its own step, listed in the report): throwaway release signature (pinned-key check must FAIL,
# install.sh runs with --allow-unsigned); no follower or RPC unit is enabled or started; the gateway's backend
# check is answered by a stub on 127.0.0.1:18955 that returns chain id 0xab162 and nothing else; the Origin CA,
# the AOP CA and the peer certificate are throwaway self-signed files made here; nginx runs inside the container.
set -u
. /dryrun/lib.sh
G=/home/ubuntu/l2-golive-next
K=$G/kit
EXPECT_SUMS=$(cat /dryrun/expect-sha256sums)
EXPECT_PINS=$(cat /dryrun/expect-golive-pins)
DOMAIN=1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733
NETPIN=f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966
L2GEN=632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468
PEER_A=${PEER_A:-136.244.93.186}
SELF_B=${SELF_B:-IP_OF_B}

step B0.systemd 0 "systemctl is-system-running --wait || systemctl is-system-running | grep -qE 'running|degraded'"
step B0.no-net 0 "! curl -s -m 5 http://199.247.22.8:8080 >/dev/null"
step B2.sig-pinned-key nz "python3 -I $K/verify_release_signature.py --release-dir $G/artifacts --expect-sha256 $EXPECT_SUMS"
expect_out B2.sig-rehearsal-key 'signature OK' "python3 -I $K/verify_release_signature.py --release-dir $G/artifacts --expect-sha256 $EXPECT_SUMS --pubkey-file /dryrun/rehearsal.pub"
step B2.pins 0 "cd $G && grep ' artifacts/' kit/GO-LIVE-PINS.sha256 | grep -v ' artifacts/SHA256SUMS\$' | sha256sum -c && sha256sum artifacts/SHA256SUMS kit/GO-LIVE-PINS.sha256"
expect_out B2.pins-hash "^$EXPECT_PINS +kit/GO-LIVE-PINS.sha256" "cd $G && sha256sum kit/GO-LIVE-PINS.sha256"

step B3.user 0 "useradd --system --user-group --no-create-home --home-dir /var/lib/bloch-l2-mainnet-replica --shell /usr/sbin/nologin bloch-l2-mainnet-replica"
step B3.dirs 0 "install -d -m 0700 -o bloch-l2-mainnet-replica -g bloch-l2-mainnet-replica /var/lib/bloch-l2-mainnet-replica /var/lib/bloch-l2-mainnet-replica/txpool"
step B3.produce-dev 0 "install -D -m 0755 $G/artifacts/bloch-l2-produce-dev /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev"
step B3.init 0 "runuser -u bloch-l2-mainnet-replica -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev init --target /var/lib/bloch-l2-mainnet-replica/canonical --rules mainnet --domain $DOMAIN --genesis-time 1786656679"
expect_out B3.head "$L2GEN" "runuser -u bloch-l2-mainnet-replica -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev head --target /var/lib/bloch-l2-mainnet-replica/canonical --rules mainnet --domain $DOMAIN --genesis-time 1786656679"
IARGS="--artifacts $G/artifacts --l1-rpc-url http://199.247.22.8:8080 --canonical /var/lib/bloch-l2-mainnet-replica/canonical --canonical-user bloch-l2-mainnet-replica --txpool /var/lib/bloch-l2-mainnet-replica/txpool"
step B3.install-dry-pinned-key nz "bash $K/follower-rpc/install.sh $IARGS --dry-run"
step B3.install-dry 0 "bash $K/follower-rpc/install.sh $IARGS --dry-run --allow-unsigned"
step B3.install 0 "bash $K/follower-rpc/install.sh $IARGS --allow-unsigned"
step B3.dropin-dir 0 "install -d /etc/systemd/system/bloch-l2-mainnet-rpc.service.d"
step B3.dropin 0 "printf '[Service]\nExecStart=\nExecStart=/opt/bloch/l2-mainnet/bloch-l2-settled-rpc --data-dir /var/lib/bloch-l2-mainnet-replica/canonical --view-dir /var/lib/bloch-l2-mainnet-rpc/rpc-view --finality-status /var/lib/bloch-l2-mainnet-follower/status.json --network $NETPIN --port 18955 --poll-ms 2000 --rules mainnet --domain $DOMAIN --genesis-time 1786656679\n' | tee /etc/systemd/system/bloch-l2-mainnet-rpc.service.d/no-txpool.conf"
step B3.reload 0 "systemctl daemon-reload"
step B3.no-txpool 0 "! systemctl show -p ExecStart bloch-l2-mainnet-rpc | grep -q -- --txpool"
expect_out B3.nofile '^LimitNOFILE=65536' "systemctl show -p LimitNOFILE bloch-l2-mainnet-rpc"
expect_out B3.follower-disabled '^disabled' "systemctl is-enabled bloch-l2-mainnet-follower; true"
expect_out B3.follower-l1 '199.247.22.8' "cat /etc/bloch-l2-mainnet/follower.env /etc/systemd/system/bloch-l2-mainnet-follower.service.d/l1-rpc.conf"

# Replica kit (the alternative layout on port 18965): dry run only; it must refuse the settler's own L1 host.
step B4.replica-same-l1 0 "bash $K/replica/install-replica.sh install --artifacts $G/artifacts --l1-rpc-url http://80.240.16.185:8080 --settler-l1-rpc-url http://80.240.16.185:8080 --dry-run > /tmp/same.out 2>&1; r=\$?; cat /tmp/same.out; [ \$r != 0 ] && grep -q \"is the settler's L1 source\" /tmp/same.out"
# Without a reachable L1 the replica's own preflight must refuse (fail closed); every pin must pass before it.
step B4.replica-dry 0 "! bash $K/replica/install-replica.sh install --artifacts $G/artifacts --l1-rpc-url http://199.247.22.8:8080 --settler-l1-rpc-url http://80.240.16.185:8080 --dry-run > /tmp/rep.out 2>&1; cat /tmp/rep.out; grep -q 'pin ok: carryover' /tmp/rep.out && grep -q 'identity preflight' /tmp/rep.out"
step B4.replica-nothing-installed 0 "[ ! -e /etc/systemd/system/bloch-l2-replica-follower.service ] && [ ! -d /opt/bloch/l2-replica ]"

# Gateway (role replica on B). Throwaway certificates; the backend stub answers eth_chainId only.
step B7.stub 0 "nohup python3 /dryrun/rpc_stub.py 18955 > /dryrun/out/rpc_stub.log 2>&1 & echo \$! > /dryrun/out/rpc_stub.pid; sleep 1; curl -s -XPOST 127.0.0.1:18955 -d '{}' | grep -q 0xab162"
step B7.nginx-up 0 "systemctl is-active -q nginx || systemctl start nginx"
step B7.plan-missing 0 "ROLE=replica NAME=l2rpc-b PEER=$PEER_A:18956 PEER_ALLOW=$PEER_A bash $K/public-rpc/setup-gateway.sh plan | tee /dev/stderr | grep -q 'MISSING: /etc/ssl/bloch-l2rpc/aop-client-ca.pem'"
step B7.apply-refused nz "ROLE=replica NAME=l2rpc-b PEER=$PEER_A:18956 PEER_ALLOW=$PEER_A bash $K/public-rpc/setup-gateway.sh apply"
step B7.peer-cert 0 "bash $K/public-rpc/setup-gateway.sh peer-cert"
step B7.peer-self-refused 0 "cp /etc/nginx/bloch-l2rpc/peer/self.crt /etc/nginx/bloch-l2rpc/peer/peer.crt && ROLE=replica NAME=l2rpc-b PEER=$PEER_A:18956 PEER_ALLOW=$PEER_A bash $K/public-rpc/setup-gateway.sh plan | grep -q 'WRONG: peer.crt is this host'"
step B7.peer-other 0 "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=l2rpc-peer -addext subjectAltName=DNS:l2rpc-peer -keyout /tmp/peer-a.key -out /etc/nginx/bloch-l2rpc/peer/peer.crt 2>/dev/null"
step B7.origin 0 "install -d -m 0750 /etc/ssl/bloch-l2rpc && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=l2rpc.dryrun.invalid -keyout /etc/ssl/bloch-l2rpc/origin.key -out /etc/ssl/bloch-l2rpc/origin.pem 2>/dev/null"
step B7.shared-aop-refused nz "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=origin-pull.cloudflare.net -keyout /tmp/shared.key -out /etc/ssl/bloch-l2rpc/aop-client-ca.pem 2>/dev/null || { echo 'could not make the stand-in'; exit 0; }; ROLE=replica NAME=l2rpc-b PEER=$PEER_A:18956 PEER_ALLOW=$PEER_A bash $K/public-rpc/setup-gateway.sh apply; r=\$?; rm -f /etc/ssl/bloch-l2rpc/aop-client-ca.pem /etc/nginx/conf.d/bloch-l2rpc.conf; exit \$r"
step B7.aop 0 "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=dryrun-aop-ca -keyout /tmp/aop.key -out /etc/ssl/bloch-l2rpc/aop-client-ca.pem 2>/dev/null"
step B7.plan 0 "ROLE=replica NAME=l2rpc-b PEER=$PEER_A:18956 PEER_ALLOW=$PEER_A bash $K/public-rpc/setup-gateway.sh plan | tee /dev/stderr | grep -vq MISSING"
# apply ends with `curl -f /health`: with the stub (no head) the gateway must answer 503 and say why, never ok.
step B7.apply 0 "ROLE=replica NAME=l2rpc-b PEER=$PEER_A:18956 PEER_ALLOW=$PEER_A bash $K/public-rpc/setup-gateway.sh apply > /tmp/apply.out 2>&1; r=\$?; cat /tmp/apply.out; [ \$r != 0 ] && grep -q 'test is successful' /tmp/apply.out && grep -q 'rendered /etc/nginx/bloch-l2rpc/l2rpc-gateway.conf (replica' /tmp/apply.out"
expect_out B7.health-not-ok '"local":[{]"ok":false,"head":null' "curl -s http://127.0.0.1:18958/health"
expect_out B7.health-chain '"chainId":"0xab162"' "curl -s http://127.0.0.1:18958/health"
step B7.include-present 0 "grep -q 'include /etc/nginx/bloch-l2rpc/l2rpc-gateway.conf' /etc/nginx/conf.d/bloch-l2rpc.conf"
expect_out B7.hop-mode '^750 root www-data' "stat -c '%a %U %G' /run/bloch-l2rpc"
step B7.nginx-t 0 "nginx -t"
step B7.rollback 0 "PEER_ALLOW=$PEER_A bash $K/public-rpc/setup-gateway.sh rollback"
step B7.rollback-gone 0 "[ ! -e /etc/nginx/conf.d/bloch-l2rpc.conf ]"
step B7.stub-stop 0 "kill \$(cat /dryrun/out/rpc_stub.pid)"

step R.follower-disable 0 "systemctl disable --now bloch-l2-mainnet-rpc bloch-l2-mainnet-follower"
step R.final-no-active 0 "[ \$(systemctl list-units --state=active 'bloch-*' --no-legend | wc -l) = 0 ]"
summary
