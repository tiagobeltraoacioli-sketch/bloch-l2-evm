// SPDX-License-Identifier: MIT OR Apache-2.0
// EIP-1193 adapter: pass a user-selected MetaMask/EIP-6963/other EVM provider.
// This is a client integration, not an RPC server or an L1 signature adapter.

export const BLOCH_L2_SECURITY = Object.freeze({
  layer: "L2",
  authorization: "ECDSA-secp256k1",
  postQuantumAccounts: false,
  notice: "Bloch L2 uses ECDSA accounts. These accounts are not post-quantum; native Bloch L1 requires PQ signatures.",
});
export const BLOCH_L2_TESTNET_CHAIN_ID = 700771n; // Placeholder, not a registered/public network.

const address = /^0x[0-9a-fA-F]{40}$/;
const quantity = /^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/;
const data = /^0x(?:[0-9a-fA-F]{2})*$/;
const MAX_U256_HEX_LENGTH = 66;
const U64_HEX_LENGTH = 18;
const MAX_ACCOUNT_COUNT = 1024;
const MAX_CALLDATA_BYTES = 128 * 1024;
const MAX_ENCODED_TRANSACTION_BYTES = 128 * 1024;
// Covers the typed/RLP envelope, bounded scalar fields, destination, access-list
// outer prefix and signature at their maximum encoded widths.
const MAX_TRANSACTION_ENVELOPE_BYTES = 256;
const MAX_ACCESS_LIST_ENTRIES = 1024;
const MAX_ACCESS_LIST_STORAGE_KEYS = 8192;
const MAX_U64 = 0xffffffffffffffffn;
const MAX_U128 = 0xffffffffffffffffffffffffffffffffn;

function isAddress(value) {
  return typeof value === "string" && value.length === 42 && address.test(value);
}

function boundedArrayLength(value, maximum) {
  if (!Array.isArray(value)) return -1;
  const length = value.length;
  return Number.isSafeInteger(length) && length >= 0 && length <= maximum ? length : -1;
}

function chainHex(value) {
  if (typeof value === "number" && !Number.isSafeInteger(value)) throw new TypeError("Unsafe chain ID");
  if (!["string", "number", "bigint"].includes(typeof value)) throw new TypeError("Invalid chain ID");
  if (typeof value === "string" &&
      (value.length > 22 || !/^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(value))) {
    throw new TypeError("Invalid chain ID");
  }
  const id = BigInt(value);
  if (id <= 0n || id > 0xffffffffffffffffn) throw new RangeError("Chain ID must be a positive u64");
  return `0x${id.toString(16)}`;
}

function checkedRpcUrl(value) {
  if (typeof value !== "string" || !value || value.length > 2048) {
    throw new TypeError("RPC must be a bounded URL string");
  }
  const url = new URL(value);
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(url.protocol === "http:" && local)) || url.username || url.password || url.hash) {
    throw new TypeError("RPC must use HTTPS (HTTP is allowed for localhost), without credentials or fragments");
  }
  return url.href;
}

/**
 * Construct a reusable L2 client. The application displays `security.notice`
 * when offering this network and supplies its actual configured RPC endpoint.
 * No endpoint is guessed and no secret key is requested or stored here.
 */
export function createBlochL2Wallet(provider, { rpcUrl, chainId = BLOCH_L2_TESTNET_CHAIN_ID } = {}) {
  const requestMethod = provider?.request;
  if (typeof requestMethod !== "function") throw new TypeError("An EIP-1193 provider is required");
  // The selected provider is part of this wallet's identity. Capture its request
  // method once so later page-side property replacement cannot split network
  // checks and signing across different implementations.
  const request = Function.prototype.bind.call(requestMethod, provider);
  const id = chainHex(chainId);
  const rpc = checkedRpcUrl(rpcUrl);
  const network = Object.freeze({
    chainId: id,
    chainName: "Bloch L2 (ECDSA)",
    nativeCurrency: Object.freeze({ name: "Bridged BLCH", symbol: "BLCH", decimals: 18 }),
    rpcUrls: Object.freeze([rpc]),
  });

  async function assertNetwork() {
    const current = await request({ method: "eth_chainId" });
    if (typeof current !== "string" || current.length > U64_HEX_LENGTH ||
        !quantity.test(current) || chainHex(current) !== id) {
      throw new Error("Wallet is not connected to the configured Bloch L2");
    }
  }

  async function connect() {
    try {
      await request({ method: "wallet_switchEthereumChain", params: [{ chainId: id }] });
    } catch (error) {
      if (error?.code !== 4902) throw error; // Includes user rejection: do not retry it.
      await request({ method: "wallet_addEthereumChain", params: [{
        ...network, nativeCurrency: { ...network.nativeCurrency }, rpcUrls: [...network.rpcUrls],
      }] });
      // EIP-3085 does not guarantee that adding a chain also selects it.
      await request({ method: "wallet_switchEthereumChain", params: [{ chainId: id }] });
    }
    await assertNetwork();
    const accounts = await request({ method: "eth_requestAccounts" });
    const accountCount = boundedArrayLength(accounts, MAX_ACCOUNT_COUNT);
    if (accountCount <= 0) {
      throw new Error("Wallet did not return valid Ethereum accounts");
    }
    const accountSnapshot = new Array(accountCount);
    for (let i = 0; i < accountCount; i += 1) {
      const account = accounts[i];
      if (!isAddress(account)) throw new Error("Wallet did not return valid Ethereum accounts");
      accountSnapshot[i] = account;
    }
    await assertNetwork(); // The user may change chains while approving accounts.
    return Object.freeze({ accounts: Object.freeze(accountSnapshot), chainId: id, security: BLOCH_L2_SECURITY });
  }

  async function sendTransaction(transaction) {
    if (!transaction || typeof transaction !== "object" || Array.isArray(transaction)) throw new TypeError("Transaction object required");
    const allowed = new Set(["from", "to", "value", "data", "gas", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "nonce", "type", "chainId", "accessList"]);
    for (const field of Reflect.ownKeys(transaction)) {
      if (typeof field !== "string" || !allowed.has(field)) {
        throw new TypeError(`Unsupported Cancun transaction field: ${String(field)}`);
      }
    }
    // Snapshot caller input before awaiting the provider (including access lists).
    const tx = { ...transaction };
    if (!isAddress(tx.from)) throw new TypeError("Explicit Ethereum from address required");
    if (tx.to !== undefined && !isAddress(tx.to)) throw new TypeError("Invalid destination address");
    if (tx.chainId !== undefined && chainHex(tx.chainId) !== id) throw new Error("Transaction targets another chain");
    if (tx.type !== undefined && !["0x0", "0x1", "0x2"].includes(tx.type)) throw new TypeError("Only transaction types 0, 1 and 2 are supported");
    if (tx.data !== undefined && (typeof tx.data !== "string" ||
        tx.data.length > 2 + 2 * MAX_CALLDATA_BYTES || !data.test(tx.data))) {
      throw new TypeError("Invalid transaction data");
    }
    for (const field of ["value", "gas", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "nonce"]) {
      if (tx[field] !== undefined &&
          (typeof tx[field] !== "string" || tx[field].length > MAX_U256_HEX_LENGTH || !quantity.test(tx[field]))) {
        throw new TypeError(`Invalid hex quantity: ${field}`);
      }
    }
    for (const field of ["gas", "nonce"]) {
      if (tx[field] !== undefined && BigInt(tx[field]) > MAX_U64) {
        throw new RangeError(`${field} exceeds the L2 transaction field width`);
      }
    }
    for (const field of ["gasPrice", "maxFeePerGas", "maxPriorityFeePerGas"]) {
      if (tx[field] !== undefined && BigInt(tx[field]) > MAX_U128) {
        throw new RangeError(`${field} exceeds the L2 transaction field width`);
      }
    }
    const dynamicFees = tx.maxFeePerGas !== undefined || tx.maxPriorityFeePerGas !== undefined;
    if ((tx.gasPrice !== undefined && dynamicFees) ||
        (tx.type === "0x0" && (dynamicFees || tx.accessList !== undefined)) ||
        (tx.type === "0x1" && dynamicFees) ||
        (tx.type === "0x2" && tx.gasPrice !== undefined)) {
      throw new TypeError("Transaction type and fee fields are inconsistent");
    }
    if (tx.maxFeePerGas !== undefined && tx.maxPriorityFeePerGas !== undefined &&
        BigInt(tx.maxPriorityFeePerGas) > BigInt(tx.maxFeePerGas)) {
      throw new RangeError("Priority fee exceeds the maximum fee");
    }
    let accessListEncodedBytes = 0;
    if (tx.accessList !== undefined) {
      const accessListCount = boundedArrayLength(tx.accessList, MAX_ACCESS_LIST_ENTRIES);
      if (accessListCount < 0) {
        throw new TypeError("Invalid access list");
      }
      let storageKeyCount = 0;
      const accessListSnapshot = new Array(accessListCount);
      for (let i = 0; i < accessListCount; i += 1) {
        const item = tx.accessList[i];
        const itemAddress = item?.address;
        const storageKeys = item?.storageKeys;
        const itemStorageKeyCount = boundedArrayLength(storageKeys, MAX_ACCESS_LIST_STORAGE_KEYS - storageKeyCount);
        if (!item || !isAddress(itemAddress) || itemStorageKeyCount < 0) {
          throw new TypeError("Invalid access list entry");
        }
        const storageKeySnapshot = new Array(itemStorageKeyCount);
        for (let j = 0; j < itemStorageKeyCount; j += 1) {
          const key = storageKeys[j];
          if (typeof key !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(key)) {
            throw new TypeError("Invalid access list entry");
          }
          storageKeySnapshot[j] = key;
        }
        storageKeyCount += itemStorageKeyCount;
        // RLP upper bound: tuple/list prefixes, 20-byte address and 33 bytes
        // for each encoded 32-byte storage key.
        accessListEncodedBytes += 29 + 33 * itemStorageKeyCount;
        accessListSnapshot[i] = { address: itemAddress, storageKeys: storageKeySnapshot };
      }
      tx.accessList = accessListSnapshot;
    }
    const calldataBytes = tx.data === undefined ? 0 : (tx.data.length - 2) / 2;
    if (MAX_TRANSACTION_ENVELOPE_BYTES + calldataBytes + accessListEncodedBytes >
        MAX_ENCODED_TRANSACTION_BYTES) {
      throw new RangeError("Transaction exceeds the encoded L2 size limit");
    }
    tx.chainId = id; // The signing request carries the configured replay domain.
    await assertNetwork();
    const accounts = await request({ method: "eth_accounts" });
    let authorized = false;
    const accountCount = boundedArrayLength(accounts, MAX_ACCOUNT_COUNT);
    if (accountCount >= 0) {
      for (let i = 0; i < accountCount; i += 1) {
        const account = accounts[i];
        // Treat provider responses as untrusted: validating the fixed-width
        // address before case-folding also bounds work on hostile strings.
        if (isAddress(account) && account.toLowerCase() === tx.from.toLowerCase()) {
          authorized = true;
          break;
        }
      }
    }
    if (!authorized) {
      throw new Error("Transaction sender is not an authorized wallet account");
    }
    await assertNetwork();
    const transactionHash = await request({ method: "eth_sendTransaction", params: [tx] });
    if (typeof transactionHash !== "string" || transactionHash.length !== 66 ||
        !/^0x[0-9a-fA-F]{64}$/.test(transactionHash)) {
      throw new Error("Wallet returned an invalid transaction hash");
    }
    return transactionHash;
  }

  return Object.freeze({ network, security: BLOCH_L2_SECURITY, connect, sendTransaction });
}
