#!/bin/bash
# Dry run of host A's installation (docs/L2-PRODUCTION-DEPLOY.md, sections 4 to 9), inside a throwaway container
# with systemd as PID 1 and --network none. Agent 385, round 18. Run as root inside the container by harness.sh.
#
# The owner's commands are run word for word where the container allows it. Deviations (each is a step of its own
# and is listed in the report): the release is signed by a THROWAWAY rsign key, so the pinned-key check must FAIL
# and the throwaway-key check must pass; follower-rpc/install.sh then runs with --allow-unsigned; no unit is
# enabled or started (the follower, the RPC, the settler, the shadow and the monitor never run); the settler's
# configure cannot reach an L1 RPC (no network), so its refusals are what is checked; the prover dry run takes a
# throwaway SSH public key in place of the one configure would create; `docker` is a shim that answers only the
# gnark image presence check.
set -u
. /dryrun/lib.sh
G=/home/ubuntu/l2-golive-next
K=$G/kit
EXPECT_SUMS=$(cat /dryrun/expect-sha256sums)
EXPECT_PINS=$(cat /dryrun/expect-golive-pins)
DOMAIN=1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733
NETPIN=f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966
L2GEN=632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468
L2ROOT=2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d

step A0.systemd 0 "systemctl is-system-running --wait || systemctl is-system-running | grep -qE 'running|degraded'"
step A0.no-net 0 "! curl -s -m 5 http://80.240.16.185:8080 >/dev/null"
step A0.no-bloch-units 0 "[ \$(systemctl list-units --all 'bloch-*' --no-legend | wc -l) = 0 ]"

# P2: signature, pins, build.json.
step P2.sig-pinned-key nz "python3 -I $K/verify_release_signature.py --release-dir $G/artifacts --expect-sha256 $EXPECT_SUMS"
expect_out P2.sig-rehearsal-key 'signature OK' "python3 -I $K/verify_release_signature.py --release-dir $G/artifacts --expect-sha256 $EXPECT_SUMS --pubkey-file /dryrun/rehearsal.pub"
step P2.sig-wrong-target nz "python3 -I $K/verify_release_signature.py --release-dir $G/artifacts --expect-sha256 0000000000000000000000000000000000000000000000000000000000000000 --pubkey-file /dryrun/rehearsal.pub"
step P2.sha256sums 0 "cd $G/artifacts && sha256sum -c --strict SHA256SUMS"
step P2.assemble-1 0 "cp $G/artifacts/bloch-l2-produce-dev $G/artifacts/mainnet.manifest $K/install-settler-mainnet.py $K/l2_reorg_recover.py $G/release-settler-v2/"
step P2.assemble-2 0 "cp /home/ubuntu/l2dexbridge-20261030/settler-v2/release-settler/bloch-evm-sp1-settlement-v3 /home/ubuntu/l2dexbridge-20261030/settler-v2/release-settler/settlement_v3_mainnet /home/ubuntu/l2dexbridge-20261030/settler-v2/release-settler/bloch-pos $G/release-settler-v2/"
expect_out P2.pins-hash "^$EXPECT_PINS +kit/GO-LIVE-PINS.sha256" "cd $G && sha256sum kit/GO-LIVE-PINS.sha256 artifacts/SHA256SUMS"
expect_out P2.target-hash "^$EXPECT_SUMS +artifacts/SHA256SUMS" "cd $G && sha256sum artifacts/SHA256SUMS"
step P2.pins-check 0 "cd $G && grep -v ' artifacts/SHA256SUMS\$' kit/GO-LIVE-PINS.sha256 | sha256sum -c --quiet"
step P2.pins-sums-line 0 "cd $G && grep -q \"^$EXPECT_SUMS  artifacts/SHA256SUMS\$\" kit/GO-LIVE-PINS.sha256"
expect_out P2.shadow-verify 'verify OK' "bash $K/install-shadow.sh --verify $G/artifacts"
# A changed kit file must be caught by the pin check (negative control on a copy).
step P2.pins-tamper nz "rm -rf /tmp/t && cp -a $G /tmp/t && echo >> /tmp/t/kit/l2_monitor.py && cd /tmp/t && grep -v ' artifacts/SHA256SUMS\$' kit/GO-LIVE-PINS.sha256 | sha256sum -c --quiet; r=\$?; rm -rf /tmp/t; exit \$r"

# P6 step 1: prepare (throwaway DA key inside the container).
step P6.prepare 0 "python3 $G/release-settler-v2/install-settler-mainnet.py prepare --release $G/release-settler-v2"
step P6.prepare-again nz "python3 $G/release-settler-v2/install-settler-mainnet.py prepare --release $G/release-settler-v2"
step P6.passphrase-mode 0 "[ \$(stat -c %a:%U /etc/bloch-l2-mainnet-settler/da.passphrase) = 400:root ]"
step P6.da-dir-mode 0 "[ \$(stat -c %a:%U /var/lib/bloch-l2-mainnet-da) = 700:bloch-l2-mainnet-settler ]"
step P6.backup-key 0 "tar czf - -C /var/lib bloch-l2-mainnet-da | gpg --batch --symmetric --pinentry-mode loopback --passphrase dryrun-only-1 -o /home/ubuntu/da-keystore.tgz.gpg"
step P6.backup-pass 0 "cat /etc/bloch-l2-mainnet-settler/da.passphrase | gpg --batch --symmetric --pinentry-mode loopback --passphrase dryrun-only-2 -o /home/ubuntu/da-passphrase.gpg"
step P6.backup-readback 0 "gpg --batch --pinentry-mode loopback --passphrase dryrun-only-1 -d /home/ubuntu/da-keystore.tgz.gpg | tar tzf - | grep -q bloch-l2-mainnet-da/"
step P6.circuits-1 0 "cp -a /home/ubuntu/l2-mainnet-install-20261019/circuits /var/lib/bloch-l2-mainnet-settler/.sp1-circuits-tmp"
step P6.circuits-2 0 "mkdir -p /var/lib/bloch-l2-mainnet-settler/.sp1"
step P6.circuits-3 0 "mv /var/lib/bloch-l2-mainnet-settler/.sp1-circuits-tmp /var/lib/bloch-l2-mainnet-settler/.sp1/circuits"
step P6.circuits-4 0 "chown -R bloch-l2-mainnet-settler:bloch-l2-mainnet-settler /var/lib/bloch-l2-mainnet-settler/.sp1"

# P3 A: canonical database at the pinned genesis, follower and RPC units (installed, never enabled).
step P3.produce-dev 0 "install -D -m 0755 $G/artifacts/bloch-l2-produce-dev /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev"
step P3.init 0 "runuser -u bloch-l2-mainnet-settler -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev init --target /var/lib/bloch-l2-mainnet-settler/canonical --rules mainnet --domain $DOMAIN --genesis-time 1786656679"
expect_out P3.head "$L2GEN" "runuser -u bloch-l2-mainnet-settler -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev head --target /var/lib/bloch-l2-mainnet-settler/canonical --rules mainnet --domain $DOMAIN --genesis-time 1786656679"
expect_out P3.head-root "$L2ROOT" "runuser -u bloch-l2-mainnet-settler -- /opt/bloch/l2-mainnet-tools/bloch-l2-produce-dev head --target /var/lib/bloch-l2-mainnet-settler/canonical --rules mainnet --domain $DOMAIN --genesis-time 1786656679"
IARGS="--artifacts $G/artifacts --l1-rpc-url http://80.240.16.185:8080 --canonical /var/lib/bloch-l2-mainnet-settler/canonical --canonical-user bloch-l2-mainnet-settler --txpool /var/lib/bloch-l2-mainnet-settler/txpool --rpc-user bloch-l2-mainnet-rpc --read-group bloch-l2-mainnet-l2read"
step P3.install-dry-pinned-key nz "bash $K/follower-rpc/install.sh $IARGS --dry-run"
step P3.install-dry 0 "bash $K/follower-rpc/install.sh $IARGS --dry-run --allow-unsigned"
# The container resolves no host: the installer needs the L1 host's IPv4 for IPAddressAllow. /etc/hosts gives it.
step P3.hosts 0 "grep -q 80.240.16.185 /etc/hosts || echo '80.240.16.185 dryrun-l1-a' >> /etc/hosts"
step P3.install 0 "bash $K/follower-rpc/install.sh $IARGS --allow-unsigned"
step P3.install-again nz "bash $K/follower-rpc/install.sh $IARGS --allow-unsigned"
step P3.dropin-dir 0 "install -d /etc/systemd/system/bloch-l2-mainnet-rpc.service.d"
step P3.dropin 0 "printf '[Service]\nExecStart=\nExecStart=/opt/bloch/l2-mainnet/bloch-l2-settled-rpc --data-dir /var/lib/bloch-l2-mainnet-settler/canonical --view-dir /var/lib/bloch-l2-mainnet-rpc/rpc-view --finality-status /var/lib/bloch-l2-mainnet-follower/status.json --network $NETPIN --port 18955 --poll-ms 2000 --rules mainnet --domain $DOMAIN --genesis-time 1786656679\n' | tee /etc/systemd/system/bloch-l2-mainnet-rpc.service.d/no-txpool.conf"
step P3.daemon-reload 0 "systemctl daemon-reload"
step P3.units-verify 0 "systemd-analyze verify /etc/systemd/system/bloch-l2-mainnet-follower.service /etc/systemd/system/bloch-l2-mainnet-rpc.service 2>&1 | grep -vE 'network-online|Unknown key name|bloch-l2-mainnet-rpc-restart' ; true"
step P3.no-txpool 0 "! systemctl show -p ExecStart bloch-l2-mainnet-rpc | grep -q -- --txpool"
expect_out P3.nofile '^LimitNOFILE=65536' "systemctl show -p LimitNOFILE bloch-l2-mainnet-rpc"
expect_out P3.rpc-user 'User=bloch-l2-mainnet-rpc' "systemctl show -p User -p SupplementaryGroups bloch-l2-mainnet-rpc"
expect_out P3.rpc-group 'SupplementaryGroups=bloch-l2-mainnet-l2read' "systemctl show -p User -p SupplementaryGroups bloch-l2-mainnet-rpc"
expect_out P3.follower-disabled '^disabled' "systemctl is-enabled bloch-l2-mainnet-follower; true"
expect_out P3.rpc-disabled '^disabled' "systemctl is-enabled bloch-l2-mainnet-rpc; true"
expect_out P3.follower-sha "$(awk '$2=="bloch-l2-native-follower"{print $1}' $G/artifacts/SHA256SUMS)" "sha256sum /opt/bloch/l2-mainnet/bloch-l2-native-follower"
expect_out P3.rpc-sha "$(awk '$2=="bloch-l2-settled-rpc"{print $1}' $G/artifacts/SHA256SUMS)" "sha256sum /opt/bloch/l2-mainnet/bloch-l2-settled-rpc"

# P6 step 2: configure. No network here: what is checked is that configure refuses before writing config.json.
step P6.configure-placeholder nz "python3 $G/release-settler-v2/install-settler-mainnet.py configure --rpc-urls http://80.240.16.185:8080,http://199.247.22.8:8080,THIRD_L1_RPC_URL --prover-threads 6 --remote-prover bloch-l2-prover-mainnet@127.0.0.1 --prover-host-key /etc/ssh/ssh_host_ed25519_key.pub --skip-idle-blocks --max-idle-seconds 86400 --min-block-interval 1800"
step P6.configure-two-urls nz "python3 $G/release-settler-v2/install-settler-mainnet.py configure --rpc-urls http://80.240.16.185:8080,http://199.247.22.8:8080 --prover-threads 6 --remote-prover bloch-l2-prover-mainnet@127.0.0.1 --prover-host-key /etc/ssh/ssh_host_ed25519_key.pub --skip-idle-blocks --max-idle-seconds 86400 --min-block-interval 1800"
step P6.configure-repeated-host nz "python3 $G/release-settler-v2/install-settler-mainnet.py configure --rpc-urls http://80.240.16.185:8080,http://199.247.22.8:8080,http://80.240.16.185:8081 --prover-threads 6 --remote-prover bloch-l2-prover-mainnet@127.0.0.1 --prover-host-key /etc/ssh/ssh_host_ed25519_key.pub --skip-idle-blocks --max-idle-seconds 86400 --min-block-interval 1800"
step P6.configure-unreachable nz "python3 $G/release-settler-v2/install-settler-mainnet.py configure --rpc-urls http://80.240.16.185:8080,http://199.247.22.8:8080,http://139.180.173.231:8080 --prover-threads 6 --remote-prover bloch-l2-prover-mainnet@127.0.0.1 --prover-host-key /etc/ssh/ssh_host_ed25519_key.pub --skip-idle-blocks --max-idle-seconds 86400 --min-block-interval 1800"
step P6.no-config 0 "[ ! -e /etc/bloch-l2-mainnet-settler/config.json ]"
step P6.start-refused nz "python3 $G/release-settler-v2/install-settler-mainnet.py start --confirm-mainnet"
step P6.no-settler-unit 0 "[ ! -e /etc/systemd/system/bloch-l2-mainnet-settler.service ]"

# P5: prover. The release-prover-v2 directory as the plan assembles it; the pin file must pass first.
step P5.copy-remote 0 "cp /dryrun/remote_prover.py $G/remote_prover.py"
step P5.mkdir 0 "mkdir -p $G/release-prover-v2"
step P5.assemble 0 "cp /home/ubuntu/l2dexbridge-20261030/settler-v2/release-prover/bloch-evm-sp1-settlement-v3 /home/ubuntu/l2dexbridge-20261030/settler-v2/release-prover/settlement_v3_mainnet $K/prover/install-prover-mainnet.py $G/remote_prover.py $G/release-prover-v2/"
step P5.pins 0 "cd $G && sha256sum -c kit/GO-LIVE-PINS-PROVER.sha256 && cd release-prover-v2 && sha256sum bloch-evm-sp1-settlement-v3 settlement_v3_mainnet remote_prover.py > SHA256SUMS"
step P5.settler-key 0 "ssh-keygen -q -t ed25519 -N '' -C bloch-l2-mainnet-settler -f /dryrun/settler_id && ls /dryrun/settler_id.pub"
expect_out P5.install-dry '"dry_run": true' "python3 $G/release-prover-v2/install-prover-mainnet.py install --settler-pubkey /dryrun/settler_id.pub --settler-host 127.0.0.1 --circuits /home/ubuntu/l2-mainnet-install-20261019/circuits --memory-gib 100 --threads 32 --prover-env ELEMENT_THRESHOLD=268435456 --timeout-seconds 5400 --dry-run"
expect_out P5.install-dry-identity '6e4c8440' "python3 $G/release-prover-v2/install-prover-mainnet.py install --settler-pubkey /dryrun/settler_id.pub --settler-host 127.0.0.1 --circuits /home/ubuntu/l2-mainnet-install-20261019/circuits --memory-gib 100 --threads 32 --prover-env ELEMENT_THRESHOLD=268435456 --timeout-seconds 5400 --dry-run"
expect_out P5.install-dry-forced 'restrict,from=.{1,2}127[.]0[.]0[.]1.{1,2},command=.{1,2}/usr/bin/python3 /opt/bloch/l2-mainnet-prover/remote_prover.py' "python3 $G/release-prover-v2/install-prover-mainnet.py install --settler-pubkey /dryrun/settler_id.pub --settler-host 127.0.0.1 --circuits /home/ubuntu/l2-mainnet-install-20261019/circuits --memory-gib 100 --threads 32 --prover-env ELEMENT_THRESHOLD=268435456 --timeout-seconds 5400 --dry-run"
# MemAvailable >= cap + 20 GiB is the installer's own gate: recorded, not forced (the real install refuses below it).
step P5.memory-gate any "python3 $G/release-prover-v2/install-prover-mainnet.py install --settler-pubkey /dryrun/settler_id.pub --settler-host 127.0.0.1 --circuits /home/ubuntu/l2-mainnet-install-20261019/circuits --memory-gib 100 --threads 32 --prover-env ELEMENT_THRESHOLD=268435456 --timeout-seconds 5400 --dry-run | grep -E 'mem_available_gib|memory_ok'"
step P5.tamper-remote nz "cp -a $G/release-prover-v2 /tmp/rp && echo '#' >> /tmp/rp/remote_prover.py && cd /tmp/rp && sha256sum bloch-evm-sp1-settlement-v3 settlement_v3_mainnet remote_prover.py > SHA256SUMS && python3 /tmp/rp/install-prover-mainnet.py install --settler-pubkey /dryrun/settler_id.pub --settler-host 127.0.0.1 --circuits /home/ubuntu/l2-mainnet-install-20261019/circuits --dry-run; r=\$?; rm -rf /tmp/rp; exit \$r"
step P5.rollback-dry nz "python3 $G/release-prover-v2/install-prover-mainnet.py rollback --dry-run"
step P5.no-prover-user 0 "! id bloch-l2-prover-mainnet"

# P7: shadow. Without a settler config the L1 RPCs come from L1_RPC_URLS; the read-only check cannot reach L1 here.
step P7.print-rpcs-none nz "bash $K/install-shadow.sh --print-l1-rpcs"
step P7.print-rpcs-env 0 "L1_RPC_URLS=http://80.240.16.185:8080,http://199.247.22.8:8080,http://139.180.173.231:8080 bash $K/install-shadow.sh --print-l1-rpcs"
step P7.install-nostart any "L1_RPC_URLS=http://80.240.16.185:8080,http://199.247.22.8:8080,http://139.180.173.231:8080 bash $K/install-shadow.sh $G/artifacts"
step P7.not-started 0 "! systemctl is-active -q bloch-l2-mainnet-shadow"
step P7.rollback any "bash $K/install-shadow.sh --rollback"
step P7.no-unit-after-rollback 0 "[ ! -e /etc/systemd/system/bloch-l2-mainnet-shadow.service ]"

# P9: monitor files (installed, timer NOT enabled), then one manual run in prelaunch phase.
step P9.user 0 "useradd --system --user-group --no-create-home --home-dir /var/lib/bloch-l2-monitor --shell /usr/sbin/nologin bloch-l2-monitor"
step P9.install 0 "install -D -m 0644 $K/l2_monitor.py /opt/bloch/l2-monitor/l2_monitor.py"
step P9.etc 0 "install -d -m 0755 /etc/bloch-l2-monitor"
step P9.env 0 "sed -e 's/--phase prelaunch/--phase live/' -e 's# --l2-rpc B=http://TBD-owner:18955##' -e 's#http://TBD-owner:8080#http://139.180.173.231:8080#' -e 's#\$# --max-idle-seconds 86400 --backlog-state /var/lib/bloch-l2-monitor/backlog.json --set block_interval_seconds=1800#' $K/monitor/monitor.env.example | tee /etc/bloch-l2-monitor/monitor.env"
expect_out P9.env-no-tbd '^0$' "grep -c TBD-owner /etc/bloch-l2-monitor/monitor.env; true"
step P9.alert 0 "install -m 0644 $K/monitor/alert.json.example /etc/bloch-l2-monitor/alert.json"
step P9.units 0 "install -m 0644 $K/monitor/bloch-l2-mainnet-monitor.service $K/monitor/bloch-l2-mainnet-monitor.timer /etc/systemd/system/"
step P9.reload 0 "systemctl daemon-reload"
step P9.units-verify any "systemd-analyze verify /etc/systemd/system/bloch-l2-mainnet-monitor.service /etc/systemd/system/bloch-l2-mainnet-monitor.timer"
expect_out P9.timer-disabled '^disabled' "systemctl is-enabled bloch-l2-mainnet-monitor.timer; true"
step P9.manual-prelaunch nz "timeout 300 python3 $K/l2_monitor.py --profile mainnet --phase prelaunch --max-idle-seconds 86400 --backlog-state /tmp/backlog.json --set block_interval_seconds=1800 --l2-rpc A=http://127.0.0.1:18955 --l1-rpc http://80.240.16.185:8080 --l1-rpc http://199.247.22.8:8080 --l1-rpc http://139.180.173.231:8080 --follower-status A=/var/lib/bloch-l2-mainnet-follower/status.json --unit settler=bloch-l2-mainnet-settler.service --unit shadow=bloch-l2-mainnet-shadow.service --binary /opt/bloch/l2-mainnet/bloch-l2-settled-rpc --build-json $G/artifacts/build.json --json"

# Rollbacks of what was installed (the plan's rollback lines).
step R.settler-rollback any "python3 $G/release-settler-v2/install-settler-mainnet.py rollback"
step R.settler-keeps-key 0 "[ -d /var/lib/bloch-l2-mainnet-da ] && [ -f /etc/bloch-l2-mainnet-settler/da.passphrase ]"
step R.follower-disable 0 "systemctl disable --now bloch-l2-mainnet-rpc bloch-l2-mainnet-follower"
step R.follower-remove 0 "rm -rf /etc/systemd/system/bloch-l2-mainnet-rpc.service.d /etc/systemd/system/bloch-l2-mainnet-follower.service.d /etc/systemd/system/bloch-l2-mainnet-rpc.service /etc/systemd/system/bloch-l2-mainnet-follower.service && systemctl daemon-reload"
step R.monitor-disable 0 "systemctl disable --now bloch-l2-mainnet-monitor.timer"
step R.final-no-active 0 "[ \$(systemctl list-units --state=active 'bloch-*' --no-legend | wc -l) = 0 ]"
summary
