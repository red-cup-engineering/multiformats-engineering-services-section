# Exact bytes and content addresses

The content-address-transformations entry sells three SHA-2 multihash
operations and three raw-block/CID operations through the existing market
Worker. A caller supplies exact Base64-carried bytes or one address. The
result retains numeric codec/hash codes, digest bytes, canonical presentation
and comparison outcomes. Mismatch is a result; malformed commitments refuse.

Native multiformats 14.0.5 owns binary varints, base presentations, digest
framing, CID versions and SHA-2 hashing. Its exact official tarball was verified
at 94533 bytes and the registry SRI. The existing multihash service retains
its own lowercase/unpadded SHA2 profile, stable imported APIs and CLI carrier.
Its manual varint/base32/hash machinery is removed, not kept as a fallback.

CID inspection converts valid v0 to v1 and changes presentation among base16,
base32, base36, base58btc and base64url without changing codec or digest.
Unknown codes remain numbers; inspection supplies no content verification.
Naming and verification operate on one raw block (codec 85), up to 65536 exact
bytes, with SHA2-256 or SHA2-512. A DAG/UnixFS file CID does not mean the hash
of unencoded file bytes: raw verification refuses other codecs.

CID text is bounded to 1024 ASCII characters and its binary form to 511 bytes,
keeping the admitted carrier closed across the five presentations. Media-type
labels are bounded to 1024 well-formed UTF-8 bytes and supply no authority.
The 544768-byte HTTP carrier admits full JSON escaping of bounded inputs.
There is no upload, pinning, storage, fetching, authorship authentication or
claim of requester acceptance. Signed local proofs use an explicit facilitator
double; installed Worker delivery and standalone package publication are
different effects.


## House NI ↔ IPFS raw-block coordinate bridge

`mapRawBlockNi({ carrier, cid?, expectedNi?, base? })` is a bounded **typed
coordinate adapter** for received exact bytes, added at the existing
multiformats owner rather than implemented anew in each consuming application.

It names the identical received bytes using the original
`@red-cup-engineering/uri-services-section/ni-uri` producer and the native
`multiformats` SHA2-256 raw-block CIDv1 codec. The result carries
`{kind,version,ni,cid,sourceCid?,codec,multihash,byteLength,...}`.
`cid`, when supplied at ingress, must be an exactly canonical raw-block
SHA2-256 CID for these actual bytes; the incoming spelling remains
`sourceCid`. `expectedNi` likewise must name exactly these bytes, not an
arbitrary string used as a key. An absent supplied address means the adapter
*computes* the corresponding coordinate; it does not attest to any remote
provider, storage, authorization or Merkle-DAG installation.

```js
import { mapRawBlockNi } from
  "@red-cup-engineering/multiformats-services-section/content-address-transformations";
const bytes = new TextEncoder().encode("hello");
const pair = await mapRawBlockNi({
  carrier: {
    mediaType: "application/octet-stream",
    contentBase64: Buffer.from(bytes).toString("base64"),
  },
});
console.log(pair.ni, pair.cid);
```

This bridge is exact for **raw blocks only**. A UnixFS file, a DAG root, Git
blob OID, Git commit, Guix derivation, Plan 9 mount or FluffOS object does not
become the canonical NI of its *materialized file bytes* merely because
some encoded object refers to those bytes. Those external coordinates need
distinct typed adapters and the corresponding carrier bytes and witnesses.
The API does not introduce another canonical internal byte address.
