// Test-only ESM loader that mutates a client checkpoint between bounded
// descriptor reads and the post-read inode/pathname checks.
const facade = String.raw`
import { promises as fs } from "node:fs";
import { basename, dirname } from "node:path";

let attacked = false;

async function attackCheckpoint() {
  if (attacked) return;
  attacked = true;
  const target = process.env.BLOCH_CHECKPOINT_RACE_TARGET;
  const attack = process.env.BLOCH_CHECKPOINT_RACE_ATTACK;
  if (!target || !["same-inode-rewrite", "pathname-replacement", "parent-directory-replacement",
    "parent-directory-metadata-change", "growth", "post-rename-pathname-replacement"].includes(attack)) {
    throw new Error("Custodian checkpoint race test configuration is invalid");
  }
  const original = await fs.readFile(target);
  if (attack === "growth") {
    const writer = await fs.open(target, "a");
    try {
      await writer.write(Buffer.alloc(80 * 1024, 0x20));
      await writer.sync();
    } finally {
      await writer.close();
    }
    return;
  }
  const changed = Buffer.from(original);
  changed[0] = changed[0] === 0x7b ? 0x5b : 0x7b;
  if (attack === "same-inode-rewrite") {
    const writer = await fs.open(target, "r+");
    try {
      await writer.write(changed, 0, changed.length, 0);
      await writer.sync();
    } finally {
      await writer.close();
    }
    return;
  }
  if (attack === "parent-directory-replacement") {
    const directory = dirname(target);
    const moved = directory + ".race-moved";
    await fs.rename(directory, moved);
    await fs.mkdir(directory, { mode: 0o700 });
    await fs.rename(moved + "/" + basename(target), target);
    return;
  }
  if (attack === "parent-directory-metadata-change") {
    await fs.writeFile(dirname(target) + "/.race-sibling", "changed\n", { mode: 0o600, flag: "wx" });
    return;
  }
  const replacement = target + ".race-replacement";
  await fs.writeFile(replacement, changed, { mode: 0o600, flag: "wx" });
  await fs.chmod(replacement, 0o600);
  await fs.rename(replacement, target);
}

function wrap(handle) {
  return new Proxy(handle, {
    get(target, property) {
      if (property === "read") {
        return async (...args) => {
          const result = await target.read(...args);
          if (process.env.BLOCH_CHECKPOINT_RACE_ATTACK === "post-rename-pathname-replacement") {
            return result;
          }
          const growth = process.env.BLOCH_CHECKPOINT_RACE_ATTACK === "growth";
          if (growth ? result.bytesRead > 0 : result.bytesRead === 0) await attackCheckpoint();
          return result;
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

export const lstat = (...args) => fs.lstat(...args);
export const readFile = (...args) => fs.readFile(...args);
export const readdir = (...args) => fs.readdir(...args);
export const realpath = (...args) => fs.realpath(...args);
export async function link(source, destination, ...args) {
  await fs.link(source, destination, ...args);
  const target = process.env.BLOCH_CHECKPOINT_RACE_TARGET;
  const targetName = target?.slice(target.lastIndexOf("/") + 1);
  if (!attacked && targetName && String(destination).endsWith("/" + targetName) &&
      String(source).includes(".tmp-") &&
      process.env.BLOCH_CHECKPOINT_RACE_ATTACK === "post-rename-pathname-replacement") {
    attacked = true;
    const bytes = await fs.readFile(destination);
    await fs.rename(destination, destination + ".race-installed");
    await fs.writeFile(destination, bytes, { mode: 0o600, flag: "wx" });
  }
}
export async function rename(source, destination, ...args) {
  await fs.rename(source, destination, ...args);
  const target = process.env.BLOCH_CHECKPOINT_RACE_TARGET;
  const targetName = target?.slice(target.lastIndexOf("/") + 1);
  if (!attacked && targetName && String(destination).endsWith("/" + targetName) &&
      String(source).includes(".tmp-") &&
      process.env.BLOCH_CHECKPOINT_RACE_ATTACK === "post-rename-pathname-replacement") {
    attacked = true;
    const bytes = await fs.readFile(destination);
    await fs.rename(destination, destination + ".race-installed");
    await fs.writeFile(destination, bytes, { mode: 0o600, flag: "wx" });
  }
}
export const unlink = (...args) => fs.unlink(...args);
export async function open(path, ...args) {
  const handle = await fs.open(path, ...args);
  return path === process.env.BLOCH_CHECKPOINT_RACE_TARGET ? wrap(handle) : handle;
}
`;

export async function load(url, context, nextLoad) {
  if (url === "node:fs/promises") {
    return { format: "module", shortCircuit: true, source: facade };
  }
  return nextLoad(url, context);
}
