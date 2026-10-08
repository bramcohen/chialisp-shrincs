"""Regenerate fixtures with the pinned, unmodified upstream Python reference.

Fetch impl/shrincs.py from UPSTREAM_COMMIT, then pass its local path. The
reference is deliberately external; normal tests are offline and need no signer.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

UPSTREAM_COMMIT = 'a5891ec5b360a732c097e1d6af1ae59515a2560a'
REFERENCE_SHA256 = '16510baf94a06c678c3eea242115ae2278151d5af41669c35a08b3150e2acff5'
HERE = Path(__file__).resolve().parent


def main():
    path = Path(sys.argv[1])
    if hashlib.sha256(path.read_bytes()).hexdigest() != REFERENCE_SHA256:
        raise ValueError('reference does not match the pinned upstream revision')
    spec = importlib.util.spec_from_file_location('shrincs_reference', path)
    reference = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = reference
    spec.loader.exec_module(reference)
    s = reference
    seed = bytes(range(48))
    message = s.sha256(b'Chialisp SHRINCS interoperability test')
    vectors = []

    def record(name, public_key, signature, msg=message):
        assert signature is not None
        assert s.shrincs_verify(msg, signature, b'', public_key)
        vectors.append(dict(name=name, public_key=public_key.hex(),
                            message_hash=msg.hex(), signature=signature.hex()))

    for shape, depth, counters in [(0, 255, [0, 7, 8, 63, 64, 254, 255, None]),
                                   (1, 3, [0, 7])]:
        print(f'Generating shape={shape}, depth={depth}', flush=True)
        secret_key, public_key = s.shrincs_keygen(seed, bytes([shape, depth]))
        for counter in counters:
            record(f'{shape}-{depth}-{counter}', public_key,
                   s.shrincs_sign(message, b'', secret_key, counter, None))
        if shape == 1:
            for msg, randomness in [(bytes(32), bytes(16)),
                                    (bytes([255]) * 32, bytes([255]) * 16)]:
                record(f'stateless-{msg[0]}', public_key,
                       s.shrincs_sign(msg, b'', secret_key, None, randomness), msg)

    # Sparse test trees: commit to a real WOTS+C leaf and arbitrary sibling hashes.
    # This avoids constructing 2**64 leaves while testing full-width unsigned indices.
    for depth in (8, 9, 63, 64, 65, 255):
        height = 255 - depth
        index = 2 ** min(depth, 64) - 1
        sk_seed, sk_prf, pk_seed = seed[:16], seed[16:32], seed[32:]
        sl_root = s.sha256(b'sparse-tree stateless root')[:16]
        auth = [s.sha256(bytes([i]))[:16] for i in range(depth)]
        root = s.wots_c_pubkey_gen(sk_seed, pk_seed, height, index, True, depth)
        for k, sibling in enumerate(auth):
            children = sibling + root if (index >> k) & 1 else root + sibling
            root = s.H(pk_seed, s.FxmssTree(height + k + 1, index >> (k + 1)), children)
        public_key = pk_seed + sl_root + root
        bound_message = b'\x00\x00' + sl_root + message
        randomizer = s.PRF_msg_sf(sk_prf, pk_seed, height, index, bound_message)
        digest = s.H_msg_sf(randomizer, pk_seed, root, height, index, bound_message)
        wots = s.wots_c_sign(digest, sk_seed, pk_seed, height, index, True, depth)
        signature = (bytes([height]) + randomizer
                     + index.to_bytes((min(depth, 64) + 7) // 8, 'big')
                     + wots + b''.join(auth))
        record(f'sparse-{depth}-max-index', public_key, signature)

    rejected = []
    context_public_key = secret_key[32:64] + secret_key[66:82]
    for counter in (1, None):
        signature = s.shrincs_sign(message, b'Chia', secret_key, counter, None)
        assert s.shrincs_verify(message, signature, b'Chia', context_public_key)
        assert not s.shrincs_verify(message, signature, b'', context_public_key)
        rejected.append(dict(name=f'nonempty-context-{counter}',
                             public_key=context_public_key.hex(), message_hash=message.hex(),
                             signature=signature.hex()))

    (HERE / 'vectors.json').write_text(json.dumps(
        dict(upstream_commit=UPSTREAM_COMMIT, vectors=vectors,
             rejected_vectors=rejected), indent=2) + '\n')


if __name__ == '__main__':
    main()
