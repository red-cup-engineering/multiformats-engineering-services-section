import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { base16 } from "multiformats/bases/base16";
import { CID } from "multiformats/cid";
import * as Digest from "multiformats/hashes/digest";
import { nameMultihash, inspectMultihash, compareMultihash, nameRawBlock, inspectCid, compareRawBlock, mapRawBlockNi, retainRawBlockNi } from "../src/content-address-transformations.mjs";
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


test("a verified native IPFS raw block becomes original NI custody bytes without minting another store", async () => {
  const bytes = Buffer.from("hello");
  const expectedNi = "ni:///sha-256;" + createHash("sha256").update(bytes).digest("base64url");
  const originalCid = (await mapRawBlockNi({ carrier: carrier("hello") })).cid;
  const foreignCid = inspectCid({ cid: originalCid, base: "base58btc" }).cid;
  const calls = [];
  const contentSpace = {
    async retain(raw, { mediaType }) {
      calls.push({ operation: "retain", raw: Buffer.from(raw), mediaType });
      return { ni: "ni:///sha-256;" +
        createHash("sha256").update(raw).digest("base64url"), durable: true };
    },
  };
  const written = await retainRawBlockNi({
    carrier: carrier("hello"), cid: foreignCid, expectedNi, base: "base32",
  }, { contentSpace });
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].raw, bytes);
  assert.equal(calls[0].mediaType, "application/octet-stream");
  assert.equal(written.ni, expectedNi);
  assert.equal(written.cid, originalCid);
  assert.equal(written.sourceCid, foreignCid);
  assert.deepEqual(written.custody, { ni: expectedNi, durable: true });
  assert.equal(Object.isFrozen(written), true);
  assert.equal(Object.isFrozen(written.custody), true);
});

test("the original named Merkle publisher, not the IPFS CID, chooses root and CAS publication", async () => {
  const bytes = Buffer.from([0, 1, 1, 0]);
  const ni = "ni:///sha-256;" + createHash("sha256").update(bytes).digest("base64url");
  const root = "ni:///sha-256;" + createHash("sha256").update("tree-root").digest("base64url");
  const records = [];
  const contentSpace = {
    async retain() { throw Error("named publisher must use putPath only"); },
    async putPath(input) {
      records.push(input);
      return { name: input.name, ni, rootNi: root, published: true,
        retained: { ni, durable: true } };
    },
  };
  const result = await retainRawBlockNi({
    carrier: { mediaType: "application/octet-stream", contentBase64: bytes.toString("base64") },
  }, {
    contentSpace, name: "science/l-space", expected: null, path: ["tilings", "wang"],
  });
  assert.equal(records.length, 1);
  assert.equal(records[0].name, "science/l-space");
  assert.equal(records[0].expected, null);
  assert.deepEqual(records[0].path, ["tilings", "wang"]);
  assert.deepEqual(Buffer.from(records[0].bytes), bytes);
  assert.equal(result.ni, ni);
  assert.equal(result.custody.rootNi, root);
  assert.equal(result.custody.published, true);
  assert.equal(result.custody.name, "science/l-space");
  assert.deepEqual(result.custody.path, ["tilings", "wang"]);
  assert.notEqual(result.custody.rootNi, result.custody.ni);
});

test("CID, NI and source-authority refusals prevent any call to physical custody", async () => {
  const valid = await mapRawBlockNi({ carrier: carrier("hello") });
  const sha512 = await nameRawBlock({ carrier: carrier("hello"), algorithm: "sha2-512" });
  const calls = [];
  const contentSpace = {
    async retain() { calls.push("retain"); return { ni: valid.ni }; },
    async putPath() { calls.push("putPath"); return { ni: valid.ni, retained: { ni: valid.ni } }; },
  };
  await assert.rejects(retainRawBlockNi({ carrier: carrier("hello") }),
    /installed contentSpace.retain/);
  await assert.rejects(retainRawBlockNi({ carrier: carrier("changed"), cid: valid.cid },
    { contentSpace }), /differ from the supplied CID/);
  await assert.rejects(retainRawBlockNi({ carrier: carrier("changed"), expectedNi: valid.ni },
    { contentSpace }), /differ from the expected NI/);
  await assert.rejects(retainRawBlockNi({ carrier: carrier("hello"), cid: sha512.cid },
    { contentSpace }), /only SHA2-256 raw-block CIDs/);
  await assert.rejects(retainRawBlockNi({
    carrier: carrier("hello"), contentSpace,
  }, { contentSpace }), /request requires carrier/);
  await assert.rejects(retainRawBlockNi({ carrier: carrier("hello") },
    { contentSpace, name: "science/l-space", path: ["wang"] }),
    /admitted name, path, expected root and putPath/);
  assert.deepEqual(calls, [], "unadmitted coordinates never reach the original writer");
});

test("original custody mismatch and stale compare-and-publish never produce a false IPFS retention receipt", async () => {
  const valid = await mapRawBlockNi({ carrier: carrier("hello") });
  const contentSpace = {
    async retain() { return { ni: valid.ni.slice(0, -1) + "A" }; },
    async putPath() { throw new TypeError("Persisted content reference changed before publication"); },
  };
  await assert.rejects(retainRawBlockNi({ carrier: carrier("hello") },
    { contentSpace }), /receipt disagrees/);
  await assert.rejects(retainRawBlockNi({ carrier: carrier("hello") }, {
    contentSpace, name: "science/l-space", expected: valid.ni, path: ["wang"],
  }), /changed before publication/);
});

test("carrier and foreign CID getters are captured once before async hashing and custody", async () => {
  const input = carrier("hello");
  const known = await mapRawBlockNi({ carrier: input });
  let carrierReads = 0, cidReads = 0;
  const original = {
    carrier: {
      mediaType: "application/octet-stream",
      get contentBase64() { carrierReads++; return carrierReads === 1
        ? input.contentBase64 : Buffer.from("malicious-later").toString("base64"); },
    },
    get cid() { cidReads++; return cidReads === 1 ? known.cid : "invalid-later"; },
  };
  const stored = [];
  const contentSpace = {
    async retain(raw) {
      stored.push(Buffer.from(raw));
      return { ni: known.ni };
    },
  };
  const result = await retainRawBlockNi(original, { contentSpace });
  assert.equal(result.ni, known.ni);
  assert.deepEqual(stored, [Buffer.from("hello")]);
  assert.equal(carrierReads, 1);
  assert.equal(cidReads, 1);
});
