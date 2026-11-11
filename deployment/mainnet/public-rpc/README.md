# Bloch L2 mainnet public RPC gateway (nginx + njs)

Production front for `https://l2rpc.blochl1.com` (chain id 700770, `0xab162`).
It runs on both L2 hosts in front of `bloch-l2-settled-rpc` (loopback
`127.0.0.1:18955`, installed by `../follower-rpc/install.sh`). It needs no Cloudflare Worker:
Cloudflare proxies the DNS name, and nginx does everything else.

    wallet / dapp --HTTPS--> Cloudflare (proxied DNS, TLS, DDoS)
       --HTTPS, Full (strict) + per-hostname Authenticated Origin Pulls (owner's CA)--> nginx :443 on host 136 (role sequencer)
            validation, allowlist, CORS, limits, routing, /health
            reads  -> local settled RPC (sequencer DB), backup: peer
            tx     -> local settled RPC (--txpool spool)
            peer   <--mTLS :18956--> nginx on the replica host (role replica, standby origin)
                   (outbound: unix socket /run/bloch-l2rpc/peer-out.sock, 0750 root:www-data)
                                       reads -> the freshest backend; tx -> 136

## Files

| file | purpose |
|---|---|
| `l2rpc-gateway.conf.in` | nginx `http{}` template: TLS, real IP from Cloudflare, CORS map, `limit_req`/`limit_conn`, upstreams, internal locations, probe server |
| `l2rpc-gateway.js` | njs: JSON-RPC validation, method allowlist, per-IP call/tx/EVM budgets, routing, failover errors, backend probe, `/health` |
| `l2rpc-proxy.inc` | proxy settings shared by every hop to a settled RPC (the subrequest locations `/_l2s/*` set their own bounded buffer) |
| `render.py` | renders the above for one host (`--role sequencer|replica`, peer, limits, CORS origins) |
| `setup-gateway.sh` | owner script: `peer-cert`, `plan`, `apply`, `rollback` (root, on each host) |
| `cloudflare-ips-v4.txt`, `-v6.txt` | Cloudflare edge ranges (realip, edge check, firewall); refresh from cloudflare.com/ips before apply |
| `tests/pair.sh` | private two-gateway rig (unprivileged nginx, loopback, throwaway certificates) |
| `tests/test_render_r10.py` | render checks without nginx: unix-socket peer hop, fixed peer probe, owner AOP CA (refuses the shared CA) |
| `tests/review_r10_gateway.mjs`, `tests/review_r10_rig.py` | review 154: node model of the njs budgets (per /64, simulation caps, slot expiry, split-batch ids) and the real-nginx rig R1-R5 (R5: split answers above 2 MiB get a prompt -32005) |
| `tests/gateway-admission.test.mjs` | actual njs handler with controlled transport: EVM slots (transaction reserve, expiry, IPv6 /56), batches in waves, the finality retry rule, raw submission routing, fee error data and uncertain publication; run with `node --test deployment/mainnet/public-rpc/tests/*.test.mjs` |
| `tests/test_gateway.py` | integration checks (protocol, allowlist, limits, CORS, routing, failover, follower status with `--status-files`) |
| `tests/rig-*.sh` | private settled-RPC copies, private block producer, ab load test |
| `compat/` | ethers v6 / viem / MetaMask call sequence (`compat.mjs`, `write.mjs`), Foundry (`foundry.sh`, `foundry-write.sh`) |

## Behaviour

| area | policy (defaults; `render.py --help`) |
|---|---|
| TLS | Cloudflare Origin CA certificate; `ssl_verify_client on`, depth 1, with **the owner's own per-hostname Authenticated Origin Pulls CA** (`/etc/ssl/bloch-l2rpc/aop-client-ca.pem`; `render.py` refuses Cloudflare's shared AOP CA, which every Cloudflare zone presents); requests whose TCP peer is not a Cloudflare range get 403 |
| Peer hop | the outbound hop to the other host's mTLS listener is a unix socket in `/run/bloch-l2rpc` (0750 root:www-data, `/etc/tmpfiles.d/bloch-l2rpc.conf`): only root and the nginx workers can send with this host's peer certificate. The peer probe uses a loopback location that always sends the same fixed read-only batch |
| Client IP | `CF-Connecting-IP`, trusted only from Cloudflare ranges |
| CORS | **production: any origin** (`setup-gateway.sh` passes `--cors-any`, owner decision of 2026-10-30). `render.py` alone defaults to an allowlist: `https://blochl1.com`, `https://blochdex.com`, `https://blochbridge.com` and their `www.` names; preflight 204, max-age 1 day. Requests without `Origin` (wallet extensions, servers, forge) are not affected |
| Methods | `eth_*` reads, `net_*`, `web3_*`, `bloch_finality`, `bloch_settlement`, `bloch_chainIdentity`, `bloch_chainStatus`, `eth_sendRawTransaction`. Everything else gets -32601. Filters, subscriptions and node signing get an explanation |
| Local answers | `eth_chainId`, `net_version` |
| Body / batch | 512 KiB (the settled RPC's own cap), at most 100 calls per batch (ethers v6 batches up to 100), and an empty batch is refused |
| Answer size (split requests) | A request that the gateway splits through njs subrequests (any request with `eth_call`, `eth_estimateGas`, `eth_createAccessList` or `eth_sendRawTransaction`, a finality read, or a batch mixing routes) gets at most **2 MiB** of backend answer per route (`--sub-answer-max`, bytes). Above that, every call of that part gets JSON-RPC **-32005** `Response too large` with `data.limitBytes` (2097152), at once, and its EVM slots are freed. The guard is a unix-socket hop in the hop dir (`guard.sock`) whose header/body filters replace the oversized answer with a marker; the subrequest buffer is 2 MiB + 64 KiB, so nginx never waits on or aborts for a body it cannot hold. A request that is not split (one route, no EVM work, e.g. a single `eth_getBlockByNumber` with full transactions) is proxied unchanged, without this limit. Before this, a split answer above the 2 MiB proxy buffers held the request open until the client gave up (agent 201, rig R4/R5) |
| Withdrawal proofs | `bloch_getWithdrawalProof` takes the read route and the per-IP call budget. It needs a settled RPC with the method. Clients verify every answer against L1 (`deployment/mainnet/withdraw/`) |
| eth_getLogs | at most 2,000 blocks per call (tags resolved against the probed head) and 256 addresses |
| Per IP | 20 HTTP req/s, burst 100 (`limit_req`), 32 connections (`limit_conn`), 1,200 calls/min (a batch counts each call), 30 `eth_sendRawTransaction`/min. A client is an IPv4 address or an IPv6 /64 (`l2rpc.client`, also the `limit_req`/`limit_conn` key). Over a limit: HTTP 429 and JSON-RPC -32005 with `Retry-After` |
| EVM slots | In flight per client: 2 simulations (`eth_call`, `eth_estimateGas`, `eth_createAccessList`; `--sim-per-ip`) and, counted apart, 2 `eth_sendRawTransaction` admissions (`--tx-per-ip`, default: the same number). In flight for all clients together: 8 (`--sim-total`; each backend has 4 shared EVM permits), of which simulations use at most 6: 2 are kept for transactions (`--tx-reserve`), so simulations cannot starve transaction admission (review R308-27); transactions may use all 8. Raw admission may simulate storage writes under policy-v2; the independent 30 tx/min budget still applies. Traffic concentrated on the sequencer can also receive its bounded-queue overload error. For these slots a client is an IPv4 address or an IPv6 **/56** (one subscriber line). A batch with more EVM calls than its client may have in flight is served: it runs them 2 at a time, in request order (a batch of 100 `eth_call` is 50 round trips, one after the other). If the gateway is full when the request arrives it is refused whole: HTTP 429, -32005, `Retry-After: 1`. If it fills up between two waves of a batch, the calls that did not run get -32005 per entry with `data: {run: false, submitted: false}` in an HTTP 200 answer; resend those. A slot is a key in the shared dictionary `l2slots` that its request deletes on return; a request that never returns (client connection lost) stops counting after 60 s (`--slot-ttl`, 45 to 600 s) |
| Timeouts | client header/body 10 s (slow-body clients never reach the backend; nginx buffers the whole request), upstream connect 2 s, read 30 s (including tx admission: 10 s permit wait + 5 s execution + transport margin) |
| Backend connections | `max_conns` shared across workers: reads 48, sequencer paths and the inbound peer path 12 each. That stays below the settled RPC's 100-connection cap (v2). Idle keepalive is 4/2 per worker for 20 s. Set `worker_processes 4`. `setup-gateway.sh` passes `--backend-conns 400` for settled RPC v2.1 (1,024 connections); 48 is `render.py`'s default for a 100-connection binary |
| Routing | reads go to the freshest backend from the probe (ties stay local), with the other as nginx backup on error/429/502/503/504; a timeout is not retried on the other backend (G4: the settled RPC answers within 15 s, so a 30 s timeout is a stuck backend, and a replayed eth_call or write would run twice). The same holds for the gateway's own second try of a finality read (`safe`/`finalized`, `bloch_finality`, `bloch_settlement`, `bloch_getWithdrawalProof`): it goes to the other backend only after a parsed "closed" answer or a 429/502/503 of the first, never after a 504, a failed subrequest or an answer that does not parse (review R308-28). Pending nonce goes to the sequencer first. Transactions go to the sequencer only, never retried |
| Admission fees | A sequencer `-32000` error with `data.kind=sequencer-fee-underpriced` passes through unchanged, including the signed transaction hash and snapshot-bound fee requirement. The gateway does not retry, re-sign or raise a transaction fee. A lost reply is an unknown submission, even if the backend might have refused it. |
| Failure | reads: 503 + -32053 (retryable) with the caller's ids. tx: -32052 "outcome unknown" if the sequencer did not answer, or -32053 `submitted:false` if the probe already saw it down |
| Finality reads | A call at `safe` or `finalized`, `bloch_finality`, `bloch_settlement` and `bloch_getWithdrawalProof` go to a backend whose follower status is valid and younger than `--max-status-age` (default 900 s, as the monitor's CRIT) and, among those, the one with the higher finalized level. A backend with no status view, or whose database lags its follower, is not current. A call goes to the other backend when the first answers -32001, answers null, or lacks the proof (-32041, -32042, -32043, -32045, -32046). A stale status alone refuses nothing: with both backends old, reads are still served and `/health` says `finalityCurrent: false` with HTTP 200. Both closed: -32001 reaches the client. Other reads are not affected. |
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

## Authenticated Origin Pulls with the owner's own certificate (per hostname)

Cloudflare's zone-level Authenticated Origin Pulls certificate is shared by all
Cloudflare customers: any Cloudflare zone pointed at the origin IPs passes
`ssl_verify_client` and the edge-range check, and skips the WAF and rate rules
of the `blochl1.com` zone. Per-hostname AOP makes Cloudflare present a
certificate only the owner holds, for `l2rpc.blochl1.com` only, and the origin
trusts only the owner's CA (`ssl_verify_depth 1`). The owner's steps, one
command per block, are in the rpc-limits report
(`~/Desktop/BLOCH-L2-DEX-BRIDGE-20261030/agents/195-rpc-limits.md`, "Owner
steps: per-hostname AOP"). In short:

1. On the Mac, create a private CA (RSA 2048, CA key kept offline) and one client
   certificate signed by it with `extendedKeyUsage=clientAuth`.
2. Upload the client certificate and key to the zone
   (`POST /zones/{zone_id}/origin_tls_client_auth/hostnames/certificates`) and
   wait until it is `active`.
3. Install the CA certificate (not its key) as
   `/etc/ssl/bloch-l2rpc/aop-client-ca.pem` on both hosts and run
   `setup-gateway.sh plan` and `apply`.
4. Enable it for the hostname
   (`PUT /zones/{zone_id}/origin_tls_client_auth/hostnames`,
   `{"hostname":"l2rpc.blochl1.com","cert_id":…,"enabled":true}`) and check
   `https://l2rpc.blochl1.com/health`.

A gateway already running with the shared CA switches with a bundle: install the
owner's CA followed by the shared CA as `aop-client-ca.pem`, apply with
`EXTRA=--allow-shared-aop-ca`, enable the hostname, check, then install the
owner's CA alone and apply again without the flag. Renew the client
certificate (825 days) before it expires: a new client certificate from the
same CA changes nothing on the origin.

## Host users (review 154, G6)

Run **no untrusted local user** on either gateway host, and no account with
`sudo` that is not the owner's. The settled RPC listens on `127.0.0.1:18955`
without authentication (on the sequencer it spools transactions), the probe
server on `127.0.0.1:18958` answers `/health` and the fixed peer probe, and
root can use the peer key. The unix-socket hop only stops other unprivileged
users from reaching the *other* host's settled RPC with this host's
certificate. The shared build host 45.77 does not meet this today (many
`ubuntu` sessions with `sudo`): the replica must be a dedicated host, or 45.77
must first be cleared of other users' sessions, keys and work.

## Production install

Done by the owner, with one command per step. See the rpc-gateway report
(`~/Desktop/BLOCH-L2-DEX-BRIDGE-20261030/agents/10-rpc-gateway.md`).
