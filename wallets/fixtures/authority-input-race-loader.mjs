// Test-only ESM loader. It mutates one authority input after the bounded
// descriptor read reaches EOF and before readSafe performs its post-read stats.
const facade = String.raw`
import { promises as fs } from "node:fs";

let attacked = false;

async function attackPinnedPathname() {
  if (attacked) return;
  attacked = true;
  const target = process.env.BLOCH_AUTHORITY_RACE_TARGET;
  const attack = process.env.BLOCH_AUTHORITY_RACE_ATTACK;
  if (!target || !["same-inode-rewrite", "pathname-replacement", "growth"].includes(attack)) {
    throw new Error("Authority input race test configuration is invalid");
  }

  const original = await fs.readFile(target);
  if (attack === "growth") {
    await fs.chmod(target, 0o600);
    const writer = await fs.open(target, "a");
    try {
      await writer.write(Buffer.alloc(128 * 1024, 0x20));
      await writer.sync();
    } finally {
      await writer.close();
    }
    await fs.chmod(target, 0o444);
    return;
  }
  const changed = Buffer.from(original);
  changed[0] = changed[0] === 0x7b ? 0x5b : 0x7b;
  if (attack === "same-inode-rewrite") {
    await fs.chmod(target, 0o600);
    const writer = await fs.open(target, "r+");
    try {
      await writer.write(changed, 0, changed.length, 0);
      await writer.sync();
    } finally {
      await writer.close();
    }
    await fs.chmod(target, 0o444);
    return;
  }

  const replacement = target + ".race-replacement";
  await fs.writeFile(replacement, changed, { mode: 0o444, flag: "wx" });
  await fs.chmod(replacement, 0o444);
  await fs.rename(replacement, target);
}

function wrap(handle) {
  return new Proxy(handle, {
    get(target, property) {
      if (property === "read") {
        return async (...args) => {
          const result = await target.read(...args);
          const growth = process.env.BLOCH_AUTHORITY_RACE_ATTACK === "growth";
          if (growth ? result.bytesRead > 0 : result.bytesRead === 0) {
            await attackPinnedPathname();
          }
          return result;
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

export const lstat = (...args) => fs.lstat(...args);
export const realpath = (...args) => fs.realpath(...args);
export const rename = (...args) => fs.rename(...args);
export const unlink = (...args) => fs.unlink(...args);
export async function open(path, ...args) {
  const handle = await fs.open(path, ...args);
  return path === process.env.BLOCH_AUTHORITY_RACE_TARGET ? wrap(handle) : handle;
}
`;

export async function load(url, context, nextLoad) {
  if (url === "node:fs/promises") {
    return { format: "module", shortCircuit: true, source: facade };
  }
  return nextLoad(url, context);
}
