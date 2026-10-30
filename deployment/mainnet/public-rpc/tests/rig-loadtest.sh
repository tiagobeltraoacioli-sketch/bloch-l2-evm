#!/bin/bash
# Load numbers for the gateway pair (ab, keep-alive). Usage: loadtest.sh OUTDIR
set -u
O=${1:?}
mkdir -p $O
cd $O
ADDR=0x33b0C637229D7191828043fCD6Ba071eF0742b51
j() { printf '{"jsonrpc":"2.0","id":1,"method":"%s","params":%s}' "$1" "$2"; }
j eth_chainId '[]' > chainid.json
j eth_blockNumber '[]' > blocknumber.json
j eth_getBlockByNumber '["latest",true]' > block.json
j eth_getBalance "[\"$ADDR\",\"latest\"]" > balance.json
j eth_call '[{"to":"0x52641f120303fd5962546b15b1faac3353f37c63","data":"0x8381f58a"},"latest"]' > call.json
python3 -c "
import json
print(json.dumps([{'jsonrpc':'2.0','id':i,'method':'eth_getBalance','params':['0x%040x'%(i+1),'latest']} for i in range(20)]))" > batch20.json
run() {
  local label=$1 url=$2 body=$3 c=$4 n=$5
  ab -q -k -c $c -n $n -p $body -T application/json -H "CF-Connecting-IP: 198.51.100.7" "$url" > ab-$label.txt 2>&1
  printf '%-34s c=%-4s n=%-6s rps=%-9s p50=%-5s p99=%-5s fail=%s non2xx=%s\n' "$label" $c $n \
    "$(awk '/Requests per second/{print $4}' ab-$label.txt)" \
    "$(awk '/^  50%/{print $2}' ab-$label.txt)" "$(awk '/^  99%/{print $2}' ab-$label.txt)" \
    "$(awk '/Failed requests/{print $3}' ab-$label.txt)" "$(awk '/Non-2xx/{print $3}' ab-$label.txt)"
}
if [ "${QUICK:-0}" = 1 ]; then
  run "gateway-A-tls-balance" https://127.0.0.1:19671/ balance.json 64 20000
  run "gateway-A-tls-call" https://127.0.0.1:19671/ call.json 64 20000
  run "gateway-A-tls-batch20" https://127.0.0.1:19671/ batch20.json 64 20000
  run "gateway-B-via-peer-mtls-balance" https://127.0.0.1:19672/ balance.json 64 20000
  run "gateway-A-tls-balance-c256" https://127.0.0.1:19671/ balance.json 256 50000
  run "gateway-A-tls-balance-c1024" https://127.0.0.1:19671/ balance.json 1024 100000
  run "gateway-A-tls-call-c256" https://127.0.0.1:19671/ call.json 256 50000
  exit 0
fi
for t in chainid blocknumber block balance call batch20; do
  run "direct-backend-$t" http://127.0.0.1:19661/ $t.json 64 20000
  run "gateway-A-plain-$t" http://127.0.0.1:19673/ $t.json 64 20000
  run "gateway-A-tls-$t" https://127.0.0.1:19671/ $t.json 64 20000
done
run "gateway-B-via-peer-mtls-balance" https://127.0.0.1:19672/ balance.json 64 20000
run "gateway-A-tls-balance-c256" https://127.0.0.1:19671/ balance.json 256 50000
run "gateway-A-tls-balance-c1024" https://127.0.0.1:19671/ balance.json 1024 100000
run "gateway-A-tls-call-c256" https://127.0.0.1:19671/ call.json 256 50000
