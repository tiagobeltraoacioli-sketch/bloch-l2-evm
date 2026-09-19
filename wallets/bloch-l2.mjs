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
export const BLOCH_L2_IDENTITY_FORMAT = "bloch-chain-identity-v1";
export const BLOCH_L2_HEADER_FORMAT = "bloch-node-header-v2-fixed-width";
export const BLOCH_L2_STATUS_FORMAT = "bloch-chain-status-v1";

const address = /^0x[0-9a-fA-F]{40}$/;
const hash = /^0x[0-9a-fA-F]{64}$/;
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
const identityFields = Object.freeze(["format", "chainId", "domain", "genesisHash", "headerFormat"]);
const statusFields = Object.freeze(["format", "challenge", "identity", "headNumber", "headHash", "stateRoot"]);
const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const ownKeys = Reflect.ownKeys;
const cryptoSource = globalThis.crypto;
const getRandomValues = typeof cryptoSource?.getRandomValues === "function"
  ? Function.prototype.bind.call(cryptoSource.getRandomValues, cryptoSource)
  : null;

function isAddress(value) {
  return typeof value === "string" && value.length === 42 && address.test(value);
}

function checkedHash(value, name) {
  if (typeof value !== "string" || value.length !== 66 || !hash.test(value)) {
    throw new TypeError(`${name} must be a 32-byte hex hash`);
  }
  return value.toLowerCase();
}

function checkedIdentityResponse(value, expected) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    const keys = ownKeys(value);
    if (keys.length !== identityFields.length) throw new Error();
    const response = Object.create(null);
    for (let i = 0; i < identityFields.length; i += 1) {
      const key = identityFields[i];
      const descriptor = getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor)) throw new Error();
      response[key] = descriptor.value;
    }
    if (response.format !== expected.format || response.headerFormat !== expected.headerFormat ||
        response.chainId !== expected.chainId || response.domain !== expected.domain ||
        response.genesisHash !== expected.genesisHash) throw new Error();
  } catch {
    throw new Error("RPC does not match the configured Bloch L2 identity");
  }
}

function checkedBlockFields(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
  const response = Object.create(null);
  for (let i = 0; i < fields.length; i += 1) {
    const key = fields[i];
    const descriptor = getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) throw new Error();
    response[key] = descriptor.value;
  }
  return response;
}

function freshChallenge() {
  if (!getRandomValues) throw new Error("Secure randomness is required for Bloch L2 status checks");
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const bytes = new Uint8Array(32);
    getRandomValues(bytes);
    let encoded = "0x";
    let nonzero = false;
    for (let i = 0; i < bytes.length; i += 1) {
      const byte = bytes[i];
      nonzero ||= byte !== 0;
      encoded += byte.toString(16).padStart(2, "0");
    }
    if (nonzero) return encoded;
  }
  throw new Error("Secure randomness returned an invalid Bloch L2 challenge");
}

function checkedStatusResponse(value, expectedIdentity, challenge) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    const keys = ownKeys(value);
    if (keys.length !== statusFields.length) throw new Error();
    const response = Object.create(null);
    for (let i = 0; i < statusFields.length; i += 1) {
      const key = statusFields[i];
      const descriptor = getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor)) throw new Error();
      response[key] = descriptor.value;
    }
    if (response.format !== BLOCH_L2_STATUS_FORMAT || response.challenge !== challenge) throw new Error();
    checkedIdentityResponse(response.identity, expectedIdentity);
    if (typeof response.headNumber !== "string" || response.headNumber.length > U64_HEX_LENGTH ||
        !quantity.test(response.headNumber) || BigInt(response.headNumber) > MAX_U64) throw new Error();
    response.headHash = checkedHash(response.headHash, "RPC canonical head hash");
    response.stateRoot = checkedHash(response.stateRoot, "RPC canonical state root");
    return response;
  } catch {
    throw new Error("RPC did not return a fresh canonical Bloch L2 status");
  }
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
export function createBlochL2Wallet(provider, {
  rpcUrl,
  chainId = BLOCH_L2_TESTNET_CHAIN_ID,
  genesisHash,
  domain,
} = {}) {
  const requestMethod = provider?.request;
  if (typeof requestMethod !== "function") throw new TypeError("An EIP-1193 provider is required");
  // The selected provider is part of this wallet's identity. Capture its request
  // method once so later page-side property replacement cannot split network
  // checks and signing across different implementations.
  const request = Function.prototype.bind.call(requestMethod, provider);
  const id = chainHex(chainId);
  const rpc = checkedRpcUrl(rpcUrl);
  const genesis = checkedHash(genesisHash, "Genesis hash");
  const executionDomain = checkedHash(domain, "Execution domain");
  const identity = Object.freeze({
    format: BLOCH_L2_IDENTITY_FORMAT,
    chainId: id,
    domain: executionDomain,
    genesisHash: genesis,
    headerFormat: BLOCH_L2_HEADER_FORMAT,
  });
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
    const blockValue = await request({ method: "eth_getBlockByNumber", params: ["0x0", false] });
    let block;
    try {
      block = checkedBlockFields(blockValue, ["number", "hash"]);
    } catch {
      throw new Error("Wallet is not connected to the configured Bloch L2 genesis");
    }
    if (block.number !== "0x0" || checkedHash(block.hash, "RPC genesis hash") !== genesis) {
      throw new Error("Wallet is not connected to the configured Bloch L2 genesis");
    }
    const reportedIdentity = await request({ method: "bloch_chainIdentity", params: [] });
    checkedIdentityResponse(reportedIdentity, identity);
    const challenge = freshChallenge();
    const reportedStatus = await request({ method: "bloch_chainStatus", params: [challenge] });
    const status = checkedStatusResponse(reportedStatus, identity, challenge);
    const headValue = await request({ method: "eth_getBlockByNumber", params: [status.headNumber, false] });
    let head;
    try {
      head = checkedBlockFields(headValue, ["number", "hash", "stateRoot"]);
    } catch {
      throw new Error("RPC canonical Bloch L2 status does not match its selected block");
    }
    if (head.number !== status.headNumber ||
        checkedHash(head.hash, "RPC selected head hash") !== status.headHash ||
        checkedHash(head.stateRoot, "RPC selected state root") !== status.stateRoot) {
      throw new Error("RPC canonical Bloch L2 status does not match its selected block");
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
    return Object.freeze({
      accounts: Object.freeze(accountSnapshot),
      chainId: id,
      genesisHash: genesis,
      identity,
      security: BLOCH_L2_SECURITY,
    });
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

  return Object.freeze({ network, genesisHash: genesis, identity, security: BLOCH_L2_SECURITY, connect, sendTransaction });
}
