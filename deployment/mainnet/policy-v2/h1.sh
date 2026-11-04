#!/bin/bash
# a223: h1_cycle_limit.py on 45.77 (execute-only). Waits for this area's check run to end first.
set -u
R=$HOME/l2dexbridge-20261030/policy-v2-int-r11; cd $R/lib
while pgrep -f "policy-v2-int-r11/run.sh|policy_v2_check.py" > /dev/null; do sleep 15; done
export SC_WORK=$R/h1 SC_PRODUCE=$R/rel-a/out/bloch-l2-produce-dev SC_HOST=$R/host-a/bloch-evm-sp1-settlement-v3 \
  SC_GUEST=$R/bin/settlement_v3_mainnet SC_ANCHOR=$R/anchor SC_SOURCE=$R/source.txt SC_LIB=$PWD
uptime > $R/h1.uptime
timeout 7200 systemd-run --user --scope -q -p MemoryMax=24G -p MemorySwapMax=0 nice -n 10 python3 -B h1_cycle_limit.py > $R/h1.out 2>&1
echo rc=$? > $R/h1.done
uptime >> $R/h1.uptime
