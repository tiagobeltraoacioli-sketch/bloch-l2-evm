import { readFile, readdir } from "node:fs/promises";
import { dirname } from "node:path";
import { createFilesystemFinalityCustodian } from "../finality-quorum-custodian-checkpoint.mjs";

const storePath = process.argv[2];
const checkpoint = JSON.parse(await readFile(storePath, "utf8"));
let current = checkpoint.stateHash;
const anchor = {
  async load() { return current; },
  async compareAndSwap(expected, replacement) {
    if (current !== expected) return { status: "conflict", currentStateHash: current };
    current = replacement;
    return { status: "committed" };
  },
};
const client = await createFilesystemFinalityCustodian({
  storePath,
  expectedStateHash: checkpoint.stateHash,
  authentication: { key: new Uint8Array(32).fill(0x41), clientId: "wallet-finality",
    custodianId: "independent-finality" },
  transport: { async exchange() { throw new Error("transport must not be reached"); } },
  anchor,
});
try {
  await client.load();
  throw new Error("final-window checkpoint substitution was accepted");
} catch (error) {
  if (!/requires inspection/.test(error?.message)) throw error;
}
const names = await readdir(dirname(storePath));
for (const prefix of ["client.json.lock", "client.json.tmp-", "client.json.previous-",
  "client.json.displaced-"]) {
  if (!names.some(name => name.startsWith(prefix))) {
    throw new Error(`missing retained checkpoint evidence: ${prefix}`);
  }
}
process.stdout.write("rejected final-window checkpoint substitution\n");
