#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# rehearsal_services.sh HOSTROOT SETHASH start|stop|is-active follower|agent
# The --service-cmd of a rehearsal `install-attestor.sh upgrade --prefix HOSTROOT`: stands in for
# `systemctl start|stop|is-active bloch-l2-attestor-follower|bloch-l2-attestor` on a --prefix install.
# follower: the unit's ExecStart (same binary path, flags and state paths, rebased to HOSTROOT), in the
#           background, cores 0-3, nice 5. agent: one `once` cycle of the installed agent (rehearsal_check.py,
#           throwaway set); is-active = that cycle exited 0. CREDENTIALS_DIRECTORY must hold `passphrase`.
set -euo pipefail
H=$(cd "$1" && pwd) SETHASH=$2 action=$3 unit=$4
HERE=$(cd "$(dirname "$0")" && pwd)
E=$H/etc/bloch-l2-attestor F=$H/var/lib/bloch-l2-attestor-follower O=$H/opt/bloch/l2-attestor
PID=$F/follower.pid LOG=$F/follower.log AEXIT=$H/agent.exit
alive() { [ -s "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; }
case $unit:$action in
follower:start)
  alive && exit 0
  . "$E/follower.env"
  echo "== $(date -u +%FT%TZ) start $(sha256sum "$O/bloch-l2-native-follower" | cut -c1-16)" >> "$LOG"
  nohup taskset -c 0-3 nice -n 5 "$O/bloch-l2-native-follower" --manifest "$E/public/mainnet.manifest" \
    --carryover "$E/public/carryover.tsv" \
    --network-pin f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966 --rpc-url "$BLOCH_L1_RPC_URL" \
    --state "$F/native" --status "$F/status.json" --poll-seconds 10 >> "$LOG" 2>&1 < /dev/null &
  echo $! > "$PID";;
follower:stop)
  if alive; then kill "$(cat "$PID")"; while alive; do sleep 1; done; fi
  rm -f "$PID";;
follower:is-active) alive;;
agent:start)
  rm -f "$AEXIT"; code=0
  python3 -I "$HERE/rehearsal_check.py" "$O" "$E/config.json" "$SETHASH" once >> "$H/agent.log" 2>&1 || code=$?
  echo $code > "$AEXIT"; tail -3 "$H/agent.log";;
agent:stop) rm -f "$AEXIT";;
agent:is-active) [ "$(cat "$AEXIT" 2>/dev/null)" = 0 ];;
*) echo "usage: $0 HOSTROOT SETHASH start|stop|is-active follower|agent" >&2; exit 2;;
esac
