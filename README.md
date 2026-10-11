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
