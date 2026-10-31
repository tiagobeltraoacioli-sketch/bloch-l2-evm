# Bloch L2 mainnet public RPC gateway (nginx + njs)

Production front for `https://l2rpc.blochl1.com` (chain id 700770, `0xab162`).
It runs on both L2 hosts in front of `bloch-l2-settled-rpc` (loopback
`127.0.0.1:18955`, installed by `../follower-rpc/install.sh`). It needs no Cloudflare Worker:
Cloudflare proxies the DNS name, and nginx does everything else.

    wallet / dapp --HTTPS--> Cloudflare (proxied DNS, TLS, DDoS)
       --HTTPS, Full (strict) + Authenticated Origin Pulls--> nginx :443 on host 136 (role sequencer)
            validation, allowlist, CORS, limits, routing, /health
            reads  -> local settled RPC (sequencer DB), backup: peer
            tx     -> local settled RPC (--txpool spool)
            peer   <--mTLS :18956--> nginx on 45.77 (role replica, standby origin)
                                       reads -> the freshest backend; tx -> 136

## Files

| file | purpose |
|---|---|
| `l2rpc-gateway.conf.in` | nginx `http{}` template: TLS, real IP from Cloudflare, CORS map, `limit_req`/`limit_conn`, upstreams, internal locations, probe server |
| `l2rpc-gateway.js` | njs: JSON-RPC validation, method allowlist, per-IP call/tx/simulation budgets, routing, failover errors, backend probe, `/health` |
| `l2rpc-proxy.inc` | proxy settings shared by every hop to a settled RPC |
| `render.py` | renders the above for one host (`--role sequencer|replica`, peer, limits, CORS origins) |
| `setup-gateway.sh` | owner script: `peer-cert`, `plan`, `apply`, `rollback` (root, on each host) |
| `cloudflare-ips-v4.txt`, `-v6.txt` | Cloudflare edge ranges (realip, edge check, firewall); refresh from cloudflare.com/ips before apply |
| `tests/pair.sh` | private two-gateway rig (unprivileged nginx, loopback, throwaway certificates) |
| `tests/test_gateway.py` | integration checks (protocol, allowlist, limits, CORS, routing, failover, follower status with `--status-files`) |
| `tests/rig-*.sh` | private settled-RPC copies, private block producer, ab load test |
| `compat/` | ethers v6 / viem / MetaMask call sequence (`compat.mjs`, `write.mjs`), Foundry (`foundry.sh`, `foundry-write.sh`) |

## Behaviour

| area | policy (defaults; `render.py --help`) |
|---|---|
| TLS | Cloudflare Origin CA certificate; `ssl_verify_client on` with the Authenticated Origin Pulls CA; requests whose TCP peer is not a Cloudflare range get 403 |
| Client IP | `CF-Connecting-IP`, trusted only from Cloudflare ranges |
| CORS | **production: any origin** (`setup-gateway.sh` passes `--cors-any`, owner decision of 2026-10-30). `render.py` alone defaults to an allowlist: `https://blochl1.com`, `https://blochdex.com`, `https://blochbridge.com` and their `www.` names; preflight 204, max-age 1 day. Requests without `Origin` (wallet extensions, servers, forge) are not affected |
| Methods | `eth_*` reads, `net_*`, `web3_*`, `bloch_finality`, `bloch_settlement`, `bloch_chainIdentity`, `bloch_chainStatus`, `eth_sendRawTransaction`. Everything else gets -32601. Filters, subscriptions and node signing get an explanation |
| Local answers | `eth_chainId`, `net_version` |
| Body / batch | 512 KiB (the settled RPC's own cap), at most 100 calls per batch (ethers v6 batches up to 100), and an empty batch is refused |
| Withdrawal proofs | `bloch_getWithdrawalProof` takes the read route and the per-IP call budget. It needs a settled RPC with the method. Clients verify every answer against L1 (`deployment/mainnet/withdraw/`) |
| eth_getLogs | at most 2,000 blocks per call (tags resolved against the probed head) and 256 addresses |
| Per IP | 20 HTTP req/s, burst 100 (`limit_req`), 32 connections (`limit_conn`), 1,200 calls/min (a batch counts each call), 30 `eth_sendRawTransaction`/min, 16 simulations (`eth_call`, `eth_estimateGas`, `eth_createAccessList`) in flight. Over a limit: HTTP 429 and JSON-RPC -32005 with `Retry-After` |
| Timeouts | client header/body 10 s (slow-body clients never reach the backend; nginx buffers the whole request), upstream connect 2 s, read 30 s (tx 15 s) |
| Backend connections | `max_conns` shared across workers: reads 48, sequencer paths and the inbound peer path 12 each. That stays below the settled RPC's 100-connection cap (v2). Idle keepalive is 4/2 per worker for 20 s. Set `worker_processes 4`. `setup-gateway.sh` passes `--backend-conns 400` for settled RPC v2.1 (1,024 connections); 48 is `render.py`'s default for a 100-connection binary |
| Routing | reads go to the freshest backend from the probe (ties stay local), with the other as nginx backup on error/timeout/429/502/503/504. Pending nonce goes to the sequencer first. Transactions go to the sequencer only, never retried |
| Failure | reads: 503 + -32053 (retryable) with the caller's ids. tx: -32052 "outcome unknown" if the sequencer did not answer, or -32053 `submitted:false` if the probe already saw it down |
| Finality reads | A call at `safe` or `finalized`, `bloch_finality` and `bloch_settlement` go to a backend whose follower status is valid and younger than `--max-status-age` (default 900 s, as the monitor's CRIT), and to the other one when the first answers that its levels are closed (-32001). A stale status alone refuses nothing: with both backends old, reads are still served and `/health` says `finalityCurrent: false` with HTTP 200. Both closed: -32001 reaches the client. Other reads are not affected. |
| Health | `GET /health` (public) and `http://127.0.0.1:18958/health` (local): chain id, per-backend ok/head/finalized/age, sequencer reachability. 200 if any backend is ok, else 503. No addresses |
| Logs | JSON access log with the client IP, method names (first 4), upstream and timings; no bodies |

## Wallet and library compatibility (tested 2026-10-30, private copy)

| client | result |
|---|---|
| MetaMask call sequence (`eth_chainId`, `net_version`, blocks, balance, pending nonce, gas price, fee history, estimate, call, receipt, code; EIP-1559 detection via `baseFeePerGas`) | pass |
| ethers 6.17.0: network, blocks (`latest`/`pending`/`safe`/`finalized`), fee data, 60 auto-batched calls, `broadcastTransaction` mapped to `INSUFFICIENT_FUNDS`, send + `wait()`, `ContractFactory.deploy` + call | pass |
| viem 2.57.13 (with and without HTTP batching): blocks, `estimateFeesPerGas`, call, estimate, logs, EIP-1559 and legacy (EIP-155) sends, receipts | pass |
| Foundry 1.7.1: `cast` reads, `cast send` (1559 and `--legacy`), `forge script` simulation and `--broadcast` deploy + call | pass with the settled-RPC fix below (v2 failed 1 of 3 rounds) |

Notes for integrators and frontends:

- `sha3Uncles`, `nonce` and the `pending` tag are served by the v2 settled RPC itself. The DEX repo's `rpc_compat_proxy.py` is not needed anymore.
- The L2 genesis has **no Multicall3** (`0xcA11…CA11`) and no CREATE2 deployer (`0x4e59…956C`). Unprotected (pre-EIP-155) legacy transactions are refused by the L2, so the canonical keyless deployments cannot be reproduced at those addresses. Deploy Multicall3 normally and set `chain.contracts.multicall3` in viem/wagmi. Foundry scripts that use `new X{salt: …}` need a CREATE2 factory deployed and passed with `--create2-deployer`.
- ethers v6 reuses an identical `eth_getTransactionCount` answer for 250 ms (`cacheTimeout`), on every chain. Sending two transactions back to back from one wallet needs an explicit nonce or `cacheTimeout: -1`.
- If a backend loses a valid follower status (file missing, unreadable, or inconsistent with its chain), `safe` and `finalized` queries answer error `-32001` and `bloch_settlement` answers null until a valid status returns; `latest` and numbered blocks keep working. `bloch_finality.status` gives `state` (`ok`, `missing`, `invalid`), `written_at_unix` and `age_s`. A stopped follower leaves `state: ok` with a growing `age_s`, and the levels stay served: read `age_s`, since no threshold is enforced.
- `safe`/`finalized` stay at the genesis until the first settlement is finalized on L1. Wallets that confirm on `finalized` will wait until then.

### Settled RPC fix (in v2.1)

`bloch-l2-settled-rpc` reads receipts and mined transactions by hash from the
database, but serves `latest` state from an in-memory head that it refreshes every
`--poll-ms` (2 s). A client that saw its receipt and then read `latest` could
read the state from before its own transaction (forge script followed by
`cast call` returned 0 instead of 1). The branch:

1. answers `eth_getTransactionReceipt` / `eth_getTransactionByHash` only once the block is at or below the served head (`null` before that, as an Ethereum node does before import);
2. counts the pending nonce and spool admission from the database tip, not from the in-memory head;
3. raises the HTTP connection cap from jsonrpsee's 100 to 1,024 (`RPC_MAX_HTTP_CONNECTIONS`).

Merged with the spool-dos fix and released as settled RPC v2.1, `18be911a…`.

## Load (45.77, shared host, ab keep-alive, private copy)

Numbers are in requests per second. The tested build was the pre-merge settled RPC `c444c093` (the gateway branch) with the gateway limits lifted. It lacks the 4-permit simulation limit of v2.1, so its `eth_call` figures do not apply to v2.1.

| call (c=64) | backend direct | gateway HTTP | gateway TLS |
|---|---|---|---|
| eth_chainId (answered by njs) | 93,862 | 73,669 | 45,898 |
| eth_blockNumber | 119,905 | 45,123 | 36,081 |
| eth_getBlockByNumber latest full | 23,503 | 25,318 | 23,043 |
| eth_getBalance | 52,108 | 46,107 | 36,175 |
| batch of 20 eth_getBalance | 6,855 | 6,943 | 5,722 |

With simulation slots enabled (eth_call goes through njs subrequests) and
`--backend-conns 400`: eth_call 23,958 (c=64), 20,113 (c=256); eth_getBalance
23,126 (c=256), 22,243 (c=1024, no non-2xx); reads through the peer mTLS hop
12,277. A flood from one IP (50,000 requests, default limits) was absorbed at
57,900 req/s, and only 118 requests reached the backend. With the v2 binary
(100-connection cap), c=256 got 479 of 50,000 HTTP 429 from the backend. With
the default `--backend-conns 48`, concurrency above 48 per host is answered
503/-32053 (retryable).

## Running the tests (any host with nginx 1.24 + the njs module; no root)

    pair.sh needs WORK and NJS_SO; see the header of tests/pair.sh
    python3 tests/test_gateway.py --raw-tx HEX --sender ADDR --failover STOP_A START_A STOP_B START_B
    (cd compat && npm ci && NODE_TLS_REJECT_UNAUTHORIZED=0 node compat.mjs https://127.0.0.1:19672 HEX ADDR)
    compat/foundry.sh http://127.0.0.1:19674 WORKDIR

## Production install

Done by the owner, with one command per step. See the rpc-gateway report
(`~/Desktop/BLOCH-L2-DEX-BRIDGE-20261030/agents/10-rpc-gateway.md`).
