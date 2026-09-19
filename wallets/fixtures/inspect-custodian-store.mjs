import { inspectFilesystemFinalityCustodianStore }
  from "../finality-quorum-custodian-store.mjs";

try {
  await inspectFilesystemFinalityCustodianStore(process.argv[2]);
  throw new Error("unsafe custodian store mutation was accepted");
} catch (error) {
  if (!/changed while being read|exceeds its size limit/.test(error?.message)) throw error;
  process.stdout.write("rejected custodian store mutation\n");
}
