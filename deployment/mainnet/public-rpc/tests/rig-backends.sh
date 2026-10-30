#!/bin/bash
# Private copies of a settled RPC build (BIN, default run/bin/bloch-l2-settled-rpc) on loopback for the gateway tests; POLL sets --poll-ms.
# a = sequencer-like (19661, --txpool), b = replica-like (19662, no txpool).
R=${RIG:-$HOME/l2dexbridge-20261030/rpc-gateway/run}
NET=f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966
DOM=1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733
start() {
  x=$1; port=$2; extra=$3
  setsid nohup taskset -c 4-7 nice -n 10 ${BIN:-$R/bin/bloch-l2-settled-rpc} --data-dir $R/$x/canonical --view-dir $R/$x/view-$(date +%s%N) --finality-status $R/$x/status.json --network $NET --port $port --poll-ms ${POLL:-2000} --rules mainnet --domain $DOM --genesis-time 1786656679 $extra > $R/$x/rpc.log 2>&1 < /dev/null &
  echo $! > $R/$x/rpc.pid
}
stop() { x=$1; p=$(cat $R/$x/rpc.pid 2>/dev/null); [ -n "$p" ] && kill -INT $p 2>/dev/null; : > $R/$x/rpc.pid; }
case "$1" in
  start) case "${2:-ab}" in *a*) start a 19661 "--txpool $R/a/txpool";; esac; case "${2:-ab}" in *b*) start b 19662 "";; esac;;
  stop) case "${2:-ab}" in *a*) stop a;; esac; case "${2:-ab}" in *b*) stop b;; esac;;
esac
