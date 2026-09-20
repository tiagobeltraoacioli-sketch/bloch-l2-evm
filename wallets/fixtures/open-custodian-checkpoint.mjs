import { createFilesystemFinalityCustodian }
  from "../finality-quorum-custodian-checkpoint.mjs";

const expectedStateHash = process.argv[3];
const authentication = { key: new Uint8Array(32).fill(0x41), clientId: "wallet-finality",
  custodianId: "independent-finality" };

try {
  await createFilesystemFinalityCustodian({ storePath: process.argv[2], expectedStateHash,
    authentication, transport: { async exchange() { throw new Error("unexpected exchange"); } },
    anchor: { async load() { return expectedStateHash; }, async compareAndSwap() {
      throw new Error("unexpected anchor mutation");
    } } });
  throw new Error("unsafe custodian checkpoint startup was accepted");
} catch (error) {
  if (!/directory changed/.test(error?.message)) throw error;
  process.stdout.write("rejected custodian checkpoint startup race\n");
}
