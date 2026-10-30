#!/bin/bash
# Private block producer for the gateway write-path tests: extends the PRIVATE
# copy a/canonical (mainnet rules, loopback only) with the spooled transactions
# every 2 s, and mints the deposits in deposits.json once (throwaway addresses).
R=${RIG:-$HOME/l2dexbridge-20261030/rpc-gateway/run}
P=$R/bin/bloch-l2-produce-dev
ARGS="--rules mainnet --domain 1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733 --genesis-time 1786656679"
ANCHOR=$(printf 'ab%.0s' $(seq 32))
extend() {
  parent=$($P head --target $R/a/canonical $ARGS | python3 -c 'import json,sys; print(json.load(sys.stdin)["hash"])')
  slot=$(( ($(date +%s) - 1786656679) / 30 ))
  $P extend --target $R/a/canonical --parent $parent --anchor $ANCHOR --timestamp-rule 1:1786656679:30000 --anchor-slot $slot $ARGS "$@" >> $R/producer.log 2>&1
}
if [ -s $R/deposits.json ]; then extend --deposits $R/deposits.json && mv $R/deposits.json $R/deposits.done.json; fi
while :; do
  if compgen -G "$R/a/txpool/*.tx" > /dev/null; then extend --txs $R/a/txpool; fi
  sleep 2
done
