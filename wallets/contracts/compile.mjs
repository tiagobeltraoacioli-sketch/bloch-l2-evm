// SPDX-License-Identifier: MIT OR Apache-2.0
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import solc from "solc";

export const COMPILER_VERSION = "0.8.30+commit.73712a01.Emscripten.clang";
// npm solc@0.8.30 artifact, independently constrained by package-lock.json SRI.
export const SOLJSON_SHA256 = "3bb491a777f76dff9b2fe73ce29ca20e21a971b59a2f2cf8f73415424f00be06";

export async function compileCounter() {
  assert.equal(solc.version(), COMPILER_VERSION);
  const require = createRequire(import.meta.url);
  const compiler = await readFile(require.resolve("solc/soljson.js"));
  assert.equal(createHash("sha256").update(compiler).digest("hex"), SOLJSON_SHA256);
  const source = await readFile(new URL("./DeveloperCounter.sol", import.meta.url), "utf8");
  const settings = JSON.parse(await readFile(new URL("./compiler-settings.json", import.meta.url), "utf8"));
  assert.equal(settings.evmVersion, "cancun");
  const input = {
    language: "Solidity",
    sources: { "DeveloperCounter.sol": { content: source } },
    settings,
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors ?? []).filter(error => error.severity === "error");
  assert.deepEqual(errors, [], errors.map(error => error.formattedMessage).join("\n"));
  const compiled = output.contracts["DeveloperCounter.sol"].DeveloperCounter;
  assert.match(compiled.evm.bytecode.object, /^(?:[0-9a-f]{2})+$/);
  assert.match(compiled.evm.deployedBytecode.object, /^(?:[0-9a-f]{2})+$/);
  return {
    abi: compiled.abi,
    bytecode: `0x${compiled.evm.bytecode.object}`,
    deployedBytecode: `0x${compiled.evm.deployedBytecode.object}`,
  };
}
