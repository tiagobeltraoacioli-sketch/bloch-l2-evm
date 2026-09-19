import { inspectFinalityCustodianCheckpoint }
  from "../finality-quorum-custodian-checkpoint.mjs";

try {
  await inspectFinalityCustodianCheckpoint(process.argv[2]);
  throw new Error("unsafe custodian checkpoint mutation was accepted");
} catch (error) {
  if (!/changed while being read|exceeds its size limit/.test(error?.message)) throw error;
  process.stdout.write("rejected custodian checkpoint mutation\n");
}
