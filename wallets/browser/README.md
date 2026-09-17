# Real MetaMask developer-node acceptance

This test uses an unmodified official MetaMask extension in real headless Chrome,
a fresh disposable profile, a public test mnemonic, and an isolated synthetic
Bloch node. No RPC requests, wallet controllers, signatures, or extension storage
are mocked or injected. It never opens a personal profile or uses real funds.

The acceptance covers:

- UI import, password setup, declining passkeys and optional metrics.
- EIP-6963 selection of the real MetaMask provider and the existing EIP-1193 adapter.
- Adding/switching to chain 700771 and granting account access through the UI.
- Rejecting a transfer through the UI: error `4001`, unchanged account nonce.
- Approving contract deployment and a storage/log-emitting call through the UI,
  with wallet-selected nonce, gas and fees. Ethers independently recovers the
  signers from the transactions returned by the node; it does not sign them.
- Real receipts, bytecode, logs, storage and nonce; orderly node shutdown/reopen
  at the same endpoint, then another state query through MetaMask itself.

Every accepted or rejected operation requires an observed UI click. A successful
EIP-1193 return without that evidence fails the test. Request sequence numbers and
completed approval URLs prevent stale screens/results from approving a later
operation. Neither rejection nor signing falls back to direct controller access.

## Reproduce

Build `integrations/reth-execution/target/debug/bloch-evm-dev` using the host
integration instructions. Then, from the repository root:

```sh
npm ci --prefix wallets --ignore-scripts --no-audit --no-fund
python3 wallets/browser/prepare-metamask.py
python3 wallets/browser/prepare-chrome.py
npm --prefix wallets run test:browser
```

Preparation downloads are explicit. The test verifies the cached MetaMask ZIP and
every extracted extension file offline before launch. The pinned Chrome helper
currently supplies mac-x64; on other platforms, set `CHROME` to a compatible real
Chrome executable. `BLOCH_DEVNODE_BIN` can select another compiled developer node.
`BROWSER_TRACE=1` prints additional UI/target diagnostics. Chrome and node processes,
the profile, and the synthetic database are cleaned up after each test.

The fixture mnemonic in `metamask.mjs` was deterministically derived from the first
16 bytes of `keccak256("Bloch isolated synthetic MetaMask acceptance fixture 2026-09-17")`.
It is public and must never receive real funds. Its EVM account is
`0x679bbcbcc7d3a7a768425ac9c97120b87dd8f365` (case-insensitive).

Playwright 1.58.2 is pinned in the parent package lock. Extension loading uses
Chrome's `Extensions.loadUnpacked` API, with the default `--disable-extensions`
argument removed. LavaMoat remains enabled. The harness uses visible UI selectors,
keyboard input and CDP mouse input. The isolated CDP world reads UI text/geometry
and scrolls buttons into view.
It does not invoke application controllers or alter extension settings directly.

The display preference is changed using the official “Switch to popup” menu.
MetaMask still presented confirmation sidepanel targets in the qualified browser;
the driver supports those actual targets because Playwright does not enumerate
them as ordinary pages. It never fabricates a confirmation page or approves a
request that has no visible matching button.

## Pinned artifacts

**MetaMask 13.48.0**, normal Chrome build, not Flask:

- [Official release](https://github.com/MetaMask/metamask-extension/releases/tag/v13.48.0).
- [Official ZIP](https://github.com/MetaMask/metamask-extension/releases/download/v13.48.0/metamask-chrome-13.48.0.zip).
- Size: 23,917,559 bytes.
- SHA-256: `d95e4c23001ed7485ccdc86c879b4e944806ababdf52e0fc578e277131e48cea`.

The locally calculated ZIP hash matched the official GitHub release API asset
digest. This is not independent signature or Sigstore verification.

**Chrome for Testing 153.0.8010.47**, mac-x64:

- [Official availability](https://googlechromelabs.github.io/chrome-for-testing/).
- [Official ZIP](https://storage.googleapis.com/chrome-for-testing-public/153.0.8010.47/mac-x64/chrome-mac-x64.zip).
- Locally calculated SHA-256: `7cdb5ad92cd19c3e3e25054e4c5fed7fd42b1f27d52447bdfc7b16fca870dd95`.

No independent Chrome ZIP signature verification is claimed. Both archives and
extracted bundles stay in ignored `.cache`. The test browser does not replace the
installed browser.

## Recorded validation

On 2026-09-17, the complete test passed twice with MetaMask 13.48.0 and
Chrome for Testing 153.0.8010.47 in headless mode. The final run, including
independent transaction signature recovery and stale-approval guards, passed
**1/1 in 51.356 seconds** (52.081 seconds including runner overhead).

The final trace recorded distinct UI clicks for network confirmation, account
connection, transfer cancellation, deployment confirmation, and call confirmation.
Deployment transaction: `0x5eaf17d927bbdeaca7e707a90e2a1c8bd7ba36541745f26b6aa73877b532eb41`.
Call transaction: `0x426aea46f417244c71c22c5469a847bc5d3e9ef5cada1b40347c95c10aa8cba5`.
Hashes can vary across runs because the wallet fills fees from the live synthetic
chain. The assertions verify recovered sender and actual persisted state, rather
than requiring these particular hashes.

Earlier headed-mode diagnosis produced a success without an observed driver
click and was rejected by the test. It is not part of the qualification. The
qualified headless flow requires the explicit UI clicks described above.

## Scope

This qualifies the automated UI flow for the pinned extension/browser and the
synthetic local developer domain. It does not qualify every wallet/version,
manual browser installation, hardware wallets, native L1 authorization, external
deposit authenticity, finality, or production operation. Pending block RPC remains
unsupported; this flow does not request a pending block or bypass that limitation.
