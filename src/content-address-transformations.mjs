/** Bounded exact-byte names and CID representations; never a retrieval service. */
import { CID } from "multiformats/cid";
import { base16 } from "multiformats/bases/base16";
import { base32 } from "multiformats/bases/base32";
import { base36 } from "multiformats/bases/base36";
import { base58btc } from "multiformats/bases/base58";
import { base64url } from "multiformats/bases/base64";
import * as Digest from "multiformats/hashes/digest";
import { sha256, sha512 } from "multiformats/hashes/sha2";
import { createMultihash, readMultihash, verifyMultihash } from "@red-cup-engineering/multihash-address-service/address";
import { decodeJsonByteCarrier } from "@red-cup-engineering/json-services-section/decode-json-byte-carrier";
import { isNiUri, makeNiUri } from "@red-cup-engineering/uri-services-section/ni-uri";

const BASES = Object.freeze({ base16, base32, base36, base58btc, base64url });
const decoder = base16.decoder.or(base32.decoder).or(base36.decoder).or(base58btc.decoder).or(base64url.decoder);
const HASHERS = Object.freeze({ "sha2-256": sha256, "sha2-512": sha512 });
const RAW = 0x55;
function request(body, required, optional = []) {
  if (!body || typeof body !== "object" || Array.isArray(body) || required.some(k => !Object.hasOwn(body, k)) || Object.keys(body).some(k => !required.includes(k) && !optional.includes(k))) throw new TypeError(`request requires ${required.join(", ")}`);
}
function text(value, field) {
  if (typeof value !== "string" || value.length > 1024 || !/^[\x21-\x7e]+$/u.test(value)) throw new TypeError(`${field} must be nonempty ASCII text of at most 1024 characters`);
  return value;
}
function content(body) {
  const label = body.carrier?.mediaType;
  if (typeof label !== "string" || !label.isWellFormed() || new TextEncoder().encode(label).length > 1024) throw new TypeError("carrier.mediaType must be well-formed text of at most 1024 UTF-8 bytes");
  return Uint8Array.from(decodeJsonByteCarrier({ carrier: body.carrier }, { maximumBytes: 65536 }).bytes);
}
function native(action) {
  try { return action(); } catch (cause) { if (cause instanceof RangeError || cause instanceof TypeError) throw cause; throw new TypeError(cause.message, { cause }); }
}
function hashNamed(algorithm = "sha2-256") {
  if (!Object.hasOwn(HASHERS, algorithm)) throw new TypeError("algorithm must be sha2-256 or sha2-512");
  return HASHERS[algorithm];
}
function baseNamed(name = "base32") {
  if (!Object.hasOwn(BASES, name)) throw new TypeError("base must be base16, base32, base36, base58btc or base64url");
  return BASES[name];
}
function digestJson(digest) {
  return { code: digest.code, digestLength: digest.size, digestBase64url: Buffer.from(digest.digest).toString("base64url"), bytesBase64url: Buffer.from(digest.bytes).toString("base64url") };
}
function cid(body) {
  const source = text(body.cid, "cid");
  return native(() => {
    // Decode the original bytes ourselves through the native codec, so the
    // native CID parser's cached input string cannot hide noncanonical text.
    const bytes = source.startsWith("Qm") ? base58btc.decode("z" + source) : decoder.decode(source);
    if (bytes.length > 511) throw new RangeError("CID binary representation exceeds 511 bytes");
    const value = CID.decode(bytes);
    if (!Number.isSafeInteger(value.code) || !Number.isSafeInteger(value.multihash.code)) throw new TypeError("CID codes exceed the exact JSON integer carrier");
    const canonicalDigest = Digest.create(value.multihash.code, value.multihash.digest);
    const canonical = CID.create(value.version, value.code, canonicalDigest);
    if (!Buffer.from(canonical.bytes).equals(Buffer.from(bytes))) throw new TypeError("CID has noncanonical binary encoding");
    if (value.version === 0) {
      if (canonicalDigest.code !== 0x12 || canonicalDigest.size !== 32 || canonical.toString() !== source) throw new TypeError("CIDv0 requires unprefixed base58btc, dag-pb and a 32-byte SHA2-256 digest");
    } else {
      const base = Object.values(BASES).find(b => b.prefix === source[0]);
      if (!base || base.encode(bytes) !== source) throw new TypeError("CID text is not canonical in a supported base");
    }
    return canonical;
  });
}
function describeCid(value, base) {
  const target = value.toV1();
  return { sourceVersion: value.version, version: 1, codec: value.code, base: base.name, cid: target.toString(base), bytesBase64url: Buffer.from(target.bytes).toString("base64url"), multihash: digestJson(value.multihash) };
}

export async function nameMultihash(body) {
  request(body, ["carrier"], ["algorithm"]);
  hashNamed(body.algorithm);
  return createMultihash(content(body), { algorithm: body.algorithm });
}
export function inspectMultihash(body) {
  request(body, ["address"]);
  return native(() => readMultihash(text(body.address, "address")));
}
export async function compareMultihash(body) {
  request(body, ["carrier", "address"]);
  const claim = inspectMultihash({ address: body.address });
  return verifyMultihash(content(body), claim.address);
}
/** CIDv0 upgrades to v1, retaining codec/digest. No codec content is decoded. */
export function inspectCid(body) {
  request(body, ["cid"], ["base"]);
  const base = baseNamed(body.base);
  return describeCid(cid(body), base);
}
/** Name one caller-supplied raw block, not an encoded UnixFS/DAG file. */
export async function nameRawBlock(body) {
  request(body, ["carrier"], ["algorithm", "base"]);
  const hasher = hashNamed(body.algorithm), base = baseNamed(body.base), bytes = content(body);
  const digest = await hasher.digest(bytes), value = CID.createV1(RAW, digest);
  return { ...describeCid(value, base), byteLength: bytes.length };
}
/** Mismatch is a result; unknown/non-raw commitments are refused before payment. */
export async function compareRawBlock(body) {
  request(body, ["carrier", "cid"]);
  const claim = cid(body);
  if (claim.code !== RAW) throw new TypeError("raw-block verification requires the raw multicodec (85), not a UnixFS/DAG file CID");
  const hasher = Object.values(HASHERS).find(h => h.code === claim.multihash.code);
  if (!hasher || claim.multihash.size !== (hasher === sha256 ? 32 : 64)) throw new TypeError("raw-block verification requires a complete SHA2-256 or SHA2-512 digest");
  const bytes = content(body), digest = await hasher.digest(bytes), expected = CID.createV1(RAW, digest);
  return { matches: Digest.equals(claim.multihash, digest), claimedCid: claim.toV1().toString(), expectedCid: expected.toString(), codec: RAW, algorithm: hasher.name, byteLength: bytes.length };
}

/**
 * Typed IPFS raw-block / house-NI coordinate bridge, grounded in received bytes.
 *
 * Every mapping is reconstructed from exact caller-supplied bytes using the
 * original NI producer. The output CID is a CIDv1 raw block with SHA2-256;
 * a caller-supplied external CID is only admitted if it is a canonical raw
 * SHA2-256 CID for those same bytes. UnixFS/DAG roots, Git OIDs and Guix
 * derivation paths are NOT interchangeable with an NI of file bytes.
 *
 * This module neither retrieves content nor installs an external block.
 */
export async function mapRawBlockNi(body) {
  request(body, ["carrier"], ["base", "expectedNi", "cid"]);
  const bytes = content(body), ni = makeNiUri(bytes);
  if (body.expectedNi !== undefined) {
    if (!isNiUri(body.expectedNi))
      throw new TypeError("expectedNi must be a canonical house SHA-256 NI");
    if (body.expectedNi !== ni)
      throw new TypeError("received raw bytes differ from the expected NI");
  }
  if (body.cid !== undefined) {
    const incoming = cid({ cid: body.cid });
    if (incoming.code !== RAW || incoming.multihash.code !== sha256.code ||
        incoming.multihash.size !== 32)
      throw new TypeError("NI bridge accepts only SHA2-256 raw-block CIDs");
    const digest = await sha256.digest(bytes);
    if (!Digest.equals(incoming.multihash, digest))
      throw new TypeError("received raw bytes differ from the supplied CID");
    const mapped = CID.createV1(RAW, digest);
    return {
      kind: "semiotic-content.raw-block-coordinate-pair", version: 1,
      ni, ...describeCid(mapped, baseNamed(body.base)), byteLength: bytes.length,
      sourceCid: body.cid,
    };
  }
  const digest = await sha256.digest(bytes);
  const mapped = CID.createV1(RAW, digest);
  return {
    kind: "semiotic-content.raw-block-coordinate-pair", version: 1,
    ni, ...describeCid(mapped, baseNamed(body.base)), byteLength: bytes.length,
  };
}
