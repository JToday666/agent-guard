/** Real npm pack + actual installed bytes; explicitly synthetic RC, no admission. */
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import {
  chmod,
  mkdtemp,
  readFile,
  rm,
  writeFile,
  symlink,
  link,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { gzipSync, gunzipSync } from "node:zlib";
import {
  createSyntheticProductPackage,
  packSyntheticProductPackage,
} from "../../../tests/support/openclaw-product-transport-package.mjs";
let root, fixture, packed, verify;
before(async () => {
  root = await mkdtemp(path.join(tmpdir(), "agentguard-candidate-test-"));
  fixture = await createSyntheticProductPackage({
    directory: path.join(root, "installed"),
  });
  packed = await packSyntheticProductPackage({
    packageRoot: fixture.packageRoot,
    directory: path.join(root, "candidate"),
  });
  await chmod(packed.candidateTgzPath, 0o600);
  ({ verifyInstalledOpenClawCandidate: verify } = await import(
    pathToFileURL(
      path.join(fixture.packageRoot, "dist/runtime/product-candidate.js"),
    )
  ));
});
after(async () => {
  await rm(root, { recursive: true, force: true });
});
test("real synthetic npm archive matches all actual installed files", async () => {
  const candidate = await verify(packed.candidateTgzPath);
  assert.equal(candidate.artifactDigest, packed.artifactDigest);
  assert.equal(candidate.packageVersion, "0.1.0-rc.1");
  assert.equal(candidate.runtimeVersion, "2026.7.1-2");
  assert.match(candidate.installedTreeDigest, /^sha256:[0-9a-f]{64}$/u);
  candidate.assertCurrent();
});
test("installed executable mutation invalidates prior and new candidate evidence", async () => {
  const candidate = await verify(packed.candidateTgzPath);
  const file = path.join(fixture.packageRoot, "product-runtime/marker.mjs"),
    original = await readFile(file);
  try {
    await writeFile(
      file,
      Buffer.concat([original, Buffer.from("\n// changed\n")]),
    );
    assert.throws(
      () => candidate.assertCurrent(),
      /product_candidate_invalid/u,
    );
    await assert.rejects(
      verify(packed.candidateTgzPath),
      /product_candidate_invalid/u,
    );
  } finally {
    await writeFile(file, original);
  }
});
test("extra installed executable is rejected", async () => {
  const file = path.join(fixture.packageRoot, "dist/unmanifested.js");
  try {
    await writeFile(file, "throw new Error('never execute');\n");
    await assert.rejects(
      verify(packed.candidateTgzPath),
      /product_candidate_invalid/u,
    );
  } finally {
    await rm(file);
  }
});
test("installed metadata cannot claim beta while archive claims RC", async () => {
  const file = path.join(fixture.packageRoot, "package.json"),
    original = await readFile(file);
  try {
    await writeFile(
      file,
      JSON.stringify({ ...JSON.parse(original), version: "0.1.0-beta.1" }),
    );
    await assert.rejects(
      verify(packed.candidateTgzPath),
      /product_candidate_invalid/u,
    );
  } finally {
    await writeFile(file, original);
  }
});
test("candidate archive final symlink and hardlink cannot be used", async () => {
  const symbolic = path.join(root, "candidate/link.tgz"),
    hard = path.join(root, "candidate/hard.tgz");
  await symlink(packed.candidateTgzPath, symbolic);
  await assert.rejects(verify(symbolic), /product_candidate_invalid/u);
  await rm(symbolic);
  try {
    await link(packed.candidateTgzPath, hard);
    await assert.rejects(
      verify(packed.candidateTgzPath),
      /product_candidate_invalid/u,
    );
  } finally {
    await rm(hard);
  }
});
test("truncated archive and raw-byte mutation cannot reuse an artifact digest", async () => {
  const original = await readFile(packed.candidateTgzPath),
    candidate = await verify(packed.candidateTgzPath);
  try {
    await writeFile(
      packed.candidateTgzPath,
      original.subarray(0, original.length - 7),
    );
    assert.throws(
      () => candidate.assertCurrent(),
      /product_candidate_invalid/u,
    );
    await assert.rejects(
      verify(packed.candidateTgzPath),
      /product_candidate_invalid/u,
    );
  } finally {
    await writeFile(packed.candidateTgzPath, original);
  }
});

async function invalidTar(change) {
  const original = await readFile(packed.candidateTgzPath);
  try {
    await writeFile(
      packed.candidateTgzPath,
      gzipSync(change(gunzipSync(original))),
    );
    await assert.rejects(
      verify(packed.candidateTgzPath),
      /product_candidate_invalid/u,
    );
  } finally {
    await writeFile(packed.candidateTgzPath, original);
  }
}
function checksum(header) {
  header.fill(32, 148, 156);
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8, "ascii");
}
test("archive traversal entry cannot resolve against the installed root", () =>
  invalidTar((tar) => {
    const header = tar.subarray(0, 512);
    header.fill(0, 0, 100);
    header.write("package/../outside.js");
    checksum(header);
    return tar;
  }));
test("archive symbolic link is rejected without following its target", () =>
  invalidTar((tar) => {
    const header = tar.subarray(0, 512);
    header[156] = 50;
    header.write("/tmp/never-read", 157);
    checksum(header);
    return tar;
  }));
test("duplicate archive entries cannot overwrite an earlier commitment", () =>
  invalidTar((tar) => {
    const firstSize = Number.parseInt(
      tar.subarray(124, 136).toString("ascii").replace(/\0.*$/u, "").trim(),
      8,
    );
    return Buffer.concat([
      tar.subarray(0, 512 + Math.ceil(firstSize / 512) * 512),
      tar,
    ]);
  }));
test("unsupported extension metadata is rejected rather than silently interpreted", () =>
  invalidTar((tar) => {
    const header = Buffer.from(tar.subarray(0, 512));
    header.fill(0, 0, 100);
    header.write("package/PaxHeader");
    header[156] = 120;
    header.fill(0, 124, 136);
    header.write("00000000000", 124);
    checksum(header);
    return Buffer.concat([header, tar]);
  }));
test("invalid tar checksum cannot be treated as the signed file set", () =>
  invalidTar((tar) => {
    tar[1] ^= 1;
    return tar;
  }));
test("group writable installed code is refused even when current bytes match", async () => {
  const file = path.join(fixture.packageRoot, "dist/index.js");
  try {
    await chmod(file, 0o664);
    await assert.rejects(
      verify(packed.candidateTgzPath),
      /product_candidate_invalid/u,
    );
  } finally {
    await chmod(file, 0o644);
  }
});
