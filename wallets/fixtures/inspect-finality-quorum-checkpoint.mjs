import { inspectFinalityQuorumCheckpoint } from "../finality-quorum-checkpoint.mjs";

try {
  await inspectFinalityQuorumCheckpoint(process.argv[2]);
  throw new Error("unsafe finality quorum checkpoint mutation was accepted");
} catch (error) {
  if (!/changed while being read|exceeds its size limit/.test(error?.message)) throw error;
  process.stdout.write("rejected finality quorum checkpoint mutation\n");
}
