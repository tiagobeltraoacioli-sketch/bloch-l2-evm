# Bloch L2 website and explorer

English static project site plus a read-only Cloudflare Pages Function.
Deploy from this directory so `functions/api/rpc.js` is included:

```sh
wrangler pages deploy . --project-name blochl2 --branch main
```

The explorer queries the existing legacy EVM RPC at
`https://l2rpc.posternlabs.com` (chain ID 8400, client
`bloch-l2-node/0.0.0-devnet/devnet`). It is distinct from the execution core
and Genesis-4 source adapter in this repository. No settlement or bridge backing
is inferred from these RPC records. No wallet connection or transaction
submission is implemented. The proxy permits only explicitly validated read
methods, bounds responses to 1 MiB and uses a 10-second upstream timeout.
The explorer reports partial/missing RPC records rather than using fixtures.

JavaScript syntax checks and HTTP/API integration checks accompany deployment.
Browser visual and wallet-extension testing are not claimed.

The explorer defaults to DEX testnet 84001 (Anvil, no L1 settlement).
Use `/explorer?network=dex` or `/explorer?network=legacy` for direct links.
The proxy accepts only those two fixed network keys, never an upstream URL.
The DEX gateway is `http://45.76.138.60.nip.io/rpc`, reached server-side;
browser requests remain same-origin HTTPS. Legacy history remains selectable.
