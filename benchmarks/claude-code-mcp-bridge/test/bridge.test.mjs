import test from "node:test";
import assert from "node:assert/strict";

test("bridge package exposes the expected build entrypoint contract", async () => {
  const packageJson = await import("../package.json", { with: { type: "json" } });
  assert.equal(packageJson.default.dependencies["@modelcontextprotocol/sdk"], "1.29.0");
});

test("image helpers enforce containment and preserve PNG metadata", async () => {
  const image = await import("../dist/image.js");
  assert.equal(image.isContained("/case/browser/a.png", "/case"), true);
  assert.equal(image.isContained("/case-other/a.png", "/case"), false);
  const png = Buffer.alloc(24);
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(png, 0);
  png.writeUInt32BE(640, 16);
  png.writeUInt32BE(480, 20);
  assert.equal(image.imageMime("shot.bin", png), "image/png");
  assert.deepEqual(image.imageDimensions("image/png", png), { width: 640, height: 480 });
  assert.equal(image.imageMime("bad.gif", Buffer.from("not an image")), null);
});
