#!/bin/bash
# a223: policy_v2_check.py on 45.77 (execute-only, private database). Usage: SCENARIOS=S1,S2,S3,S5,S6 run.sh TAG
set -u
R=$HOME/l2dexbridge-20261030/policy-v2-int-r11; T=${1:-a}; cd $R/lib
export SC_WORK=$R/run-$T SC_PRODUCE=$R/rel-a/out/bloch-l2-produce-dev SC_HOST=$R/host-a/bloch-evm-sp1-settlement-v3 \
  SC_GUEST=$R/bin/settlement_v3_mainnet SC_ANCHOR=$R/anchor SC_SOURCE=$R/source.txt SC_LIB=$PWD
rm -f $R/check-$T.done
ls /dev/shm > $R/check-$T-shm-before.txt
pgrep -f sp1-native-runner > $R/check-$T-runners-before.txt
SCENARIOS=${SCENARIOS:-S1,S2,S3,S5,S6} S3_PREFLIGHT_SECONDS=${S3_PREFLIGHT_SECONDS:-20} S6_PREFLIGHT_SECONDS=${S6_PREFLIGHT_SECONDS:-30} S6_ATTACKERS=${S6_ATTACKERS:-3} timeout 5400 systemd-run --user --scope -q -p MemoryMax=24G -p MemorySwapMax=0 nice -n 10 python3 -B policy_v2_check.py > $R/check-$T.out 2>&1
echo rc=$? > $R/check-$T.done
sleep 2
ls /dev/shm > $R/check-$T-shm-after.txt
pgrep -f sp1-native-runner > $R/check-$T-runners-after.txt
