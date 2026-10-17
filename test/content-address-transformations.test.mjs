import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { base16 } from "multiformats/bases/base16";
import { CID } from "multiformats/cid";
import * as Digest from "multiformats/hashes/digest";
import { nameMultihash, inspectMultihash, compareMultihash, nameRawBlock, inspectCid, compareRawBlock, mapRawBlockNi } from "../src/content-address-transformations.mjs";
const carrier = text => ({ mediaType: "application/octet-stream", contentBase64: Buffer.from(text).toString("base64") });

test("current IPFS specification raw hello vector retains its exact block bytes", async () => {
  const result = await nameRawBlock({ carrier: carrier("hello") });
  assert.equal(result.cid, "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq");
  assert.equal(Buffer.from(result.bytesBase64url, "base64url").toString("hex"), "015512202cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  assert.equal(result.codec, 85);
  assert.equal((await compareRawBlock({ carrier: carrier("hello"), cid: result.cid })).matches, true);
  assert.equal((await compareRawBlock({ carrier: carrier("changed"), cid: result.cid })).matches, false);
});

test("CIDv0 upgrade and all five base presentations retain codec and digest", () => {
  const v0 = "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n";
  const upgraded = inspectCid({ cid: v0 });
  assert.equal(upgraded.sourceVersion, 0);
  assert.equal(upgraded.codec, 112);
  assert.equal(upgraded.cid, "bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku");
  for (const base of ["base16", "base32", "base36", "base58btc", "base64url"]) {
    const presented = inspectCid({ cid: v0, base });
    const read = inspectCid({ cid: presented.cid });
    assert.equal(read.bytesBase64url, upgraded.bytesBase64url);
    assert.equal(read.cid, upgraded.cid);
  }
  const unknown = CID.createV1(0x300001, Digest.create(0x300002, Uint8Array.of(42)));
  assert.equal(inspectCid({ cid: unknown.toString() }).codec, 0x300001);
  assert.equal(inspectCid({ cid: unknown.toString() }).multihash.code, 0x300002);
});

test("native multihash consumers retain mismatch and independent SHA2-512", async () => {
  const result = await nameMultihash({ carrier: carrier("abc"), algorithm: "sha2-512" });
  assert.deepEqual(inspectMultihash({ address: result.address }), result);
  assert.equal(result.multihash.digestBase64url, createHash("sha512").update("abc").digest("base64url"));
  assert.equal((await compareMultihash({ carrier: carrier("abc"), address: result.address })).matches, true);
  assert.equal((await compareMultihash({ carrier: carrier("abd"), address: result.address })).matches, false);
  const raw = await nameRawBlock({ carrier: carrier("abc"), algorithm: "sha2-512", base: "base16" });
  assert.equal(Buffer.from(raw.bytesBase64url, "base64url").subarray(0, 4).toString("hex"), "01551340");
});

test("malformed CID bytes and text refuse; raw verification never substitutes DAG meaning", async () => {
  for (const bytes of [[0, 85, 18, 32, ...Array(32).fill(0)], [2, 85, 18, 32, ...Array(32).fill(0)], [0x81, 0, 85, 18, 32, ...Array(32).fill(0)], [1, 85, 0x92, 0, 32, ...Array(32).fill(0)], [1, 85, 18, 32, ...Array(33).fill(0)]]) assert.throws(() => inspectCid({ cid: base16.encode(Uint8Array.from(bytes)) }));
  const raw = await nameRawBlock({ carrier: carrier("hello") });
  for (const cid of ["b" + raw.cid.slice(1).toUpperCase(), raw.cid + "=", "x" + raw.cid, "z" + "1".repeat(1025)]) assert.throws(() => inspectCid({ cid }));
  await assert.rejects(compareRawBlock({ carrier: carrier(""), cid: "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n" }), /raw multicodec/u);
  await assert.rejects(nameRawBlock({ carrier: carrier("hello"), algorithm: "identity" }));
  await assert.rejects(nameRawBlock({ carrier: carrier("hello"), base: "constructor" }));
  await assert.rejects(nameRawBlock({ carrier: { mediaType: "application/octet-stream", contentBase64: Buffer.alloc(65537).toString("base64") } }));
});

test("IPFS raw CID and canonical house NI retain distinct typed coordinates for exactly the same bytes", async () => {
  const bytes = Buffer.from("hello");
  const mapped = await mapRawBlockNi({ carrier: carrier("hello") });
  assert.equal(mapped.kind, "semiotic-content.raw-block-coordinate-pair");
  assert.equal(mapped.version, 1);
  assert.equal(mapped.ni, "ni:///sha-256;" + createHash("sha256").update(bytes).digest("base64url"));
  assert.equal(mapped.cid, "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq");
  assert.equal(mapped.codec, 85);
  assert.equal(mapped.multihash.digestBase64url, mapped.ni.slice("ni:///sha-256;".length));
  assert.equal(mapped.byteLength, bytes.length);
  assert.equal(Object.hasOwn(mapped, "sourceCid"), false);

  const foreignBase = inspectCid({ cid: mapped.cid, base: "base58btc" }).cid;
  const imported = await mapRawBlockNi({
    carrier: carrier("hello"), cid: foreignBase, expectedNi: mapped.ni, base: "base32",
  });
  assert.equal(imported.cid, mapped.cid);
  assert.equal(imported.ni, mapped.ni);
  assert.equal(imported.sourceCid, foreignBase,
    "a source carrier coordinate must be preserved, not renamed to the house NI");

  await assert.rejects(mapRawBlockNi({
    carrier: carrier("changed"), cid: mapped.cid,
  }), /received raw bytes differ from the supplied CID/);
  await assert.rejects(mapRawBlockNi({
    carrier: carrier("changed"), expectedNi: mapped.ni,
  }), /received raw bytes differ from the expected NI/);
  await assert.rejects(mapRawBlockNi({
    carrier: carrier("hello"), expectedNi: "sha256:" + createHash("sha256").update("hello").digest("hex"),
  }), /canonical house SHA-256 NI/);
  await assert.rejects(mapRawBlockNi({
    carrier: carrier("hello"), cid: "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n",
  }), /only SHA2-256 raw-block CIDs/);
  const sha512Raw = await nameRawBlock({ carrier: carrier("hello"), algorithm: "sha2-512" });
  await assert.rejects(mapRawBlockNi({
    carrier: carrier("hello"), cid: sha512Raw.cid,
  }), /only SHA2-256 raw-block CIDs/);
  await assert.rejects(mapRawBlockNi({ carrier: carrier("hello"), base: "prototype" }),
    /base must be/);
});
