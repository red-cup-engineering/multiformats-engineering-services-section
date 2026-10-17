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


## Store an admitted IPFS raw block in the shared NI space

`retainRawBlockNi({ carrier, cid?, expectedNi?, base? }, { contentSpace,
name?, expected?, path? })` is the **original Multiformats owner's**
next producer-to-consumer step. The first argument contains the previously
defined, bounded raw CID/NI request; the second is a **trusted host-supplied**
instance of the existing URI Content Custody `./space` interface.

The operation snapshots the caller's exact bytes, MIME label and foreign
coordinates once; uses **the same** `mapRawBlockNi` for SHA2-256/raw-CIDv1
admission; then invokes the **original** `contentSpace.retain` or
`contentSpace.putPath` producer. It refuses an inconsistent custody NI
receipt. No new byte store, CID gateway, UnixFS decoder, network pinning
service, authority grant, hash type or relation schema is fabricated.

```js
import { retainRawBlockNi } from
  "@red-cup-engineering/multiformats-services-section/content-address-transformations";

// contentSpace is supplied by the actual installed and authorized host:
// createContentAddressedSpace({ root, durableRoot, namespaces })
// from @red-cup-engineering/immutable-content-custody-service/space.
const admitted = await retainRawBlockNi({
  carrier: {
    mediaType: "application/octet-stream",
    contentBase64: Buffer.from("hello").toString("base64"),
  },
  cid: "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq",
}, {
  contentSpace,
  name: "science/l-space",
  expected: null,
  path: ["tilings", "wang"],
});
console.log(admitted.ni, admitted.cid, admitted.custody.rootNi);
```

Omit `name`, `expected`, and `path` together to retain bytes without a
mutable namespace change. To advance a namespace, pass the actual prior
root NI as `expected`, not the CID; the original custody compare-and-publish
operation refuses stale writers. The returned `custody` object includes
the original retained NI and, when named, the resulting immutable Merkle
root. A separately admitted CAIRN reader can then use that root through
`GET /api/marks/tree` and TUFTE's `/tree` projection without another
storage format. Those read interfaces retain their own host authorization
and per-root, per-child disclosure decisions.

This is a **single raw-block interchange lane** at a bounded 64 KiB.
For real IPFS multi-block exchange, CAR archive transport, UnixFS DAG
decoding, Guix derivation realization, Git object provenance, Plan 9 mounts,
FluffOS virtual objects, and sheaf/Chu/Wang interpretation, a block CID is
only an input coordinate. None of those distinct behaviors follows from
`cid`, `ni`, or the existence of a slot in a Merkle tree.

As with the original coordinate bridge, merged source does not establish a
published new Multiformats edition, a live configured custodian, IPFS
networking, or independently received CAIRN/TUFTE/public service.
