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

These totals exclude the verifier's serialized code, public key, message hash,
atom/list encoding, generator overhead, conditions and other spend costs.
For example, a full 4,704-byte copy of the verifier would add **56,448,000**
byte-cost units before any block-generator compression or sharing. The payload
figures above exclude even the signature atom's length prefix. Full transaction
cost depends on how the puzzle and generator encode and share these bytes.

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
