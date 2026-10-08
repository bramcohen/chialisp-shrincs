# SHRINCS in Chialisp 26

A self-contained verifier for the current SHRINCS BIP draft, implemented in
Chialisp 26. It has no gaming dependencies and can be used by any CLVM puzzle.

`verify.clsp` takes the environment `(PUBLIC_KEY MESSAGE_HASH SIGNATURE)`:

- `PUBLIC_KEY`: one 48-byte atom, `pk_seed || sl_root || sf_root`.
- `MESSAGE_HASH`: one 32-byte atom, the exact digest bytes that were signed.
- `SIGNATURE`: one binary atom in the draft's SHRINCS wire format.

Valid signatures return `()`. Invalid signatures, incorrect lengths, and pair
inputs raise. Both stateful FXMSS/WOTS+C and stateless SLH-DSA verification are
implemented. The digest is passed as the message to SHRINCS, with an empty
context; the BIP's internal message hashing and `0x0000` context prefix still
apply. This is not a separate prehash mode. A signer must sign those same digest
bytes with `ctx=b''`.

The implementation is pinned to [SHRINCS BIP revision
a5891ec5](https://github.com/SHRINCS/shrincs-bip/blob/a5891ec5b360a732c097e1d6af1ae59515a2560a/SHRINCS.md).
The draft is evolving; updating it requires regenerating vectors and reviewing
wire formats, parameters, and domain separation. This implementation has not
undergone a cryptographic security review.

## Key generation and signing

This repository implements verification in Chialisp. Key generation and signing
run off-chain; the examples below use the pinned [upstream Python reference](https://github.com/SHRINCS/shrincs-bip/blob/a5891ec5b360a732c097e1d6af1ae59515a2560a/impl/shrincs.py).
That reference is demonstration code without persistent state management or
secret-key protection, rather than a production wallet signer.

The reference API does **not** take a bare 32-byte private key:

| Value | Size | Contents |
| --- | ---: | --- |
| Key-generation seed | 48 bytes | `sk_seed[16] || sk_prf[16] || pk_seed[16]` |
| Stateful tree configuration | 2 bytes | Shape byte followed by depth byte |
| Expanded secret key | 82 bytes | `sk_seed || sk_prf || pk_seed || sl_root || sf_structure || sf_root` |
| Public key | 48 bytes | `pk_seed || sl_root || sf_root` |

Generate the seed with a cryptographically secure random source. The stateful
counter is separate from the 82-byte secret key; the signer must store and
manage it. A seed backup must also preserve the two-byte tree configuration to
reconstruct the same keypair.

Fetch the exact reference revision (Python standard library only):

```sh
curl --fail -L https://raw.githubusercontent.com/SHRINCS/shrincs-bip/a5891ec5b360a732c097e1d6af1ae59515a2560a/impl/shrincs.py -o /tmp/shrincs_reference.py
```

Save the following as `/tmp/shrincs_example.py` and run it with
`python3 /tmp/shrincs_example.py`. It generates a fresh disposable key and uses
its first stateful counter exactly once:

```python
import hashlib
from pathlib import Path
import secrets

# Verify the downloaded reference before importing it.
reference_path = Path('/tmp/shrincs_reference.py')
assert hashlib.sha256(reference_path.read_bytes()).hexdigest() == (
    '16510baf94a06c678c3eea242115ae2278151d5af41669c35a08b3150e2acff5'
)
import shrincs_reference as shrincs

seed = secrets.token_bytes(48)
# UXMSS (unbalanced), depth 255: counters 0 through 255 are usable.
sf_structure = bytes([shrincs.FXMSS_SHAPE_UNBALANCED, 255])
secret_key, public_key = shrincs.shrincs_keygen(seed, sf_structure)
assert len(secret_key) == 82 and len(public_key) == 48

# An existing expanded secret key already contains the public key components.
assert secret_key[32:64] + secret_key[66:82] == public_key

message_hash = hashlib.sha256(b'the thing being signed').digest()

# Demonstration only: this fresh key uses counter 0 once and is discarded.
# A persistent signer must reserve counters durably as described below.
stateful_signature = shrincs.shrincs_sign(
    message=message_hash,
    ctx=b'',
    shrincs_seckey=secret_key,
    state_ctr=0,
    opt_rand=None,  # Ignored on the stateful path.
)
assert stateful_signature is not None
assert shrincs.shrincs_verify(message_hash, stateful_signature, b'', public_key)

# Stateless fallback: no state counter required, under the same public key.
stateless_signature = shrincs.shrincs_sign(
    message=message_hash,
    ctx=b'',
    shrincs_seckey=secret_key,
    state_ctr=None,
    opt_rand=secrets.token_bytes(16),  # None selects deterministic signing.
)
assert stateless_signature is not None
assert shrincs.shrincs_verify(message_hash, stateless_signature, b'', public_key)

print('Public key bytes:', len(public_key))
print('Stateful signature bytes:', len(stateful_signature))
print('Stateless signature bytes:', len(stateless_signature))
```

Pass `public_key`, `message_hash`, and either signature directly as the three
binary atoms to `verify.clsp`. They are raw bytes, not ASCII hex strings. The
Python `shrincs_verify` call above returns a boolean; this repository's Chialisp
verifier returns nil on success and raises on rejection.

### Stateful signing and backups

Never sign different messages with the same key and stateful counter. For a
persistent signer, reserve a counter exclusively and durably advance the stored
next counter **before releasing its signature**. Reservations must survive
crashes and resist rollback; concurrent signers must not allocate the same
counter. A failed signing attempt can burn a reserved counter. The reference's
`shrincs_sign` does not perform any of this bookkeeping.

If a backup is restored without trustworthy current counter state, use
`state_ctr=None` for stateless signing; do not reset the counter to zero.
Stateless signing requires no persistent counter, but the draft still limits
its per-key signature budget to `2**40` signatures.

The unbalanced depth-255 configuration above supports 256 stateful signatures,
starting with the smallest signatures. A balanced tree uses
`bytes([shrincs.FXMSS_SHAPE_BALANCED, depth])` and, for positive depths, supports
`2**depth` stateful signatures of constant size. Balanced key generation costs
exponential work in the depth, so do not substitute 255 as a balanced depth.
The reference automatically falls back to stateless signing when the chosen
stateful tree is exhausted.

## Build and test

Use a compiler supporting `(include *standard-cl-26*)`. The tests use
standalone compiler tools.
With `run`, `opc`, and `brun` on `PATH`:

```sh
python3 test_shrincs.py
```

Alternatively set `CHIALISP_RUN`, `CHIALISP_OPC`, and `CHIALISP_BRUN` to their
executable paths. The tests compile and assemble into a temporary directory,
run fixtures offline, check nil on success and failure on rejected inputs, and
report program size and execution costs. If `chia_rs` is installed in the Python
environment, an additional test runs all positive fixtures and context rejection
fixtures through its consensus runner with `MEMPOOL_MODE`, including heap limits.

To produce a persistent binary artifact, run from this directory:

```sh
run --fail-on-error --symbol-output-file verify.sym verify.clsp > verify.clvm
opc verify.clvm > verify.hex
```

The modern compiler emits CLVM source even when `run -d` is specified; `opc`
performs the serialization. `verify.hex` is serialized CLVM in hex, suitable for
`brun -x` or conversion to bytes by a host application.

## Coverage and measured limits

The checked-in fixtures come from upstream's unmodified Python reference:
18 valid signatures and two signatures valid only under a nonempty context
(which this API must reject). They cover balanced and unbalanced trees, depth
1 through 255, byte-width transitions in the leaf index, full-width unsigned
64-bit indices, deterministic and randomized stateless signing, and all-zero
and all-`0xff` messages. Sparse-tree fixtures commit to a real WOTS+C leaf and
fixed sibling hashes, avoiding the need to generate an enormous balanced tree.
The tests also mutate each public-key component, the message, signature headers,
WOTS data, FORS/hypertree data and authentication paths; reject truncation,
trailing data, out-of-range leaf indices and non-atom inputs; and test oversized
signature atoms.

With the local Chialisp compiler revision `14934c71901161eb819a8c5092d0091217218925`:

| Item | Measured value |
| --- | ---: |
| Compiled verifier | 4,704 bytes |
| Stateful signature sizes | 548–4,619 bytes |
| Stateless signature size | 5,777 bytes |
| Stateful execution cost in fixtures | 4.36–9.63 million |
| Stateless execution cost in fixtures | 27.47–28.35 million |

The largest signatures successfully execute as a **single atom**, including
with `chia_rs` mempool flags. There is no atom-length obstacle at these sizes
in the tested runtime. These costs measure verifier execution; transaction
serialization byte costs and other spend costs are additional. The measured
stateless values are samples, not a proven worst-case bound.

## Signature byte costs

Chia allows **11,000,000,000 cost units per transaction block** and charges
**12,000 units per serialized byte**. See the [consensus constants](https://github.com/Chia-Network/chia-blockchain/blob/main/chia/consensus/default_constants.py)
and [cost documentation](https://docs.chia.net/chia-blockchain/coin-set-model/costs/).
The signature payload alone therefore costs:

| Signature | Payload bytes | Byte cost | Share of block budget |
| --- | ---: | ---: | ---: |
| Smallest stateful | 548 | 6,576,000 | 0.060% |
| Largest stateful | 4,619 | 55,428,000 | 0.504% |
| Stateless | 5,777 | 69,324,000 | 0.630% |

For the stateless path, adding the measured verification cost gives roughly
**97–98 million units, or 0.88–0.89% of a block**, for signature payload plus
verification. The smallest stateful fixture uses about **10.94 million units
(0.099%)**, and the largest uses about **65.05 million units (0.591%)**, for
those same two components.

### Verifier code and combined cost

The compiled validation program is **4,704 bytes**. At 12,000 units per byte,
one uncompressed copy costs **56,448,000 units**, or **0.513% of a block**,
separate from its execution cost. Including that copy gives these estimates:

| Signature | Signature bytes + measured execution | Including one verifier copy | Share of block budget including code |
| --- | ---: | ---: | ---: |
| Smallest stateful | 10.94 million | 67.39 million | 0.613% |
| Largest stateful | 65.05 million | 121.50 million | 1.105% |
| Stateless | 96.80–97.67 million | 153.24–154.12 million | 1.393–1.401% |

The verifier can be deduplicated when used multiple times in the same block
generator. If a generator shares one copy across `N` validations, its code
contributes approximately **56,448,000 / N units per validation**, plus the
encoding/reference overhead needed to share it. Signature payload and
verification execution still contribute their respective per-validation costs.
This sharing must be represented in the generator; the table above assumes a
full uncompressed copy for each validation, and deduplication does not persist
across blocks.

These estimates exclude public-key and message-hash bytes, atom/list encoding
(including the signature atom's length prefix), generator overhead, conditions
and other spend costs. Full transaction cost depends on how the puzzle and
generator encode and share these bytes. The execution figures remain measured
samples rather than proven worst-case bounds.

## Regenerate vectors

Normal testing does not fetch or execute upstream code. To regenerate fixtures,
fetch the pinned reference explicitly, then run:

```sh
curl --fail -L https://raw.githubusercontent.com/SHRINCS/shrincs-bip/a5891ec5b360a732c097e1d6af1ae59515a2560a/impl/shrincs.py -o /tmp/shrincs-reference.py
python3 generate_vectors.py /tmp/shrincs-reference.py
```

The generator verifies the reference file's SHA-256 before loading it and
asserts that every fixture has the expected upstream result. It uses fixed,
public test seeds. The reference and specification are published under
CC0-1.0 or MIT in the upstream repository.

## License

The verifier and tooling are licensed under Apache-2.0; see [LICENSE](LICENSE).
