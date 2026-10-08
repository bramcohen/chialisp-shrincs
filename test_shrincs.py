"""Compile Chialisp 26 and check upstream signatures plus hostile inputs."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

try:
    from chia_rs import MEMPOOL_MODE, run_chia_program
except ImportError:
    run_chia_program = None

HERE = Path(__file__).resolve().parent


def atom(value):
    size = len(value)
    if size == 0:
        return b'\x80'
    if size == 1 and value[0] < 128:
        return value
    for width in range(1, 6):
        if size < 1 << (7 * width - 1):
            prefix = ((0xff << (8 - width)) & 0xff) | size >> (8 * (width - 1))
            tail = size & ((1 << (8 * (width - 1))) - 1)
            return bytes([prefix]) + tail.to_bytes(width - 1, 'big') + value
    raise ValueError('atom too large')


def args(*values):
    return b''.join(b'\xff' + atom(value) for value in values) + b'\x80'


class ShrincsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((HERE / 'vectors.json').read_text())
        cls.vectors = cls.data['vectors']
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.program = Path(cls.temp.name) / 'verify.hex'
        compiled = subprocess.run(
            [os.environ.get('CHIALISP_RUN', 'run'), '--fail-on-error', '-d',
             '--symbol-output-file', str(Path(cls.temp.name) / 'verify.sym'),
             str(HERE / 'verify.clsp')],
            text=True, capture_output=True, check=True,
        )
        source = Path(cls.temp.name) / 'verify.clvm'
        source.write_text(compiled.stdout)
        assembled = subprocess.run(
            [os.environ.get('CHIALISP_OPC', 'opc'), str(source)],
            text=True, capture_output=True, check=True,
        )
        cls.program.write_text(assembled.stdout.strip())
        print(f'Compiled verifier: {len(bytes.fromhex(assembled.stdout.strip()))} bytes')
        cls.costs = {}

    def execute(self, encoded):
        return subprocess.run(
            [os.environ.get('CHIALISP_BRUN', 'brun'), '--fail-on-error', '-x', '-d',
             '-c', '-m', '11000000000', str(self.program), encoded.hex()],
            text=True, capture_output=True, timeout=30,
        )

    def verify(self, pk, msg, sig, valid):
        result = self.execute(args(pk, msg, sig))
        if valid:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip().splitlines()[-1], '80', result.stdout)
            cost = int(result.stdout.split('cost = ')[1].splitlines()[0])
            self.costs[len(sig)] = max(self.costs.get(len(sig), 0), cost)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def inputs(self, vector):
        return [bytes.fromhex(vector[k]) for k in ('public_key', 'message_hash', 'signature')]

    def test_reference_vectors(self):
        for vector in self.vectors:
            with self.subTest(vector=vector['name']):
                self.verify(*self.inputs(vector), True)
        print('Signature bytes -> measured CLVM cost:', dict(sorted(self.costs.items())))

    def test_modified_inputs(self):
        # Exercise both paths, every public key component, and each signature region.
        for vector in (self.vectors[0], self.vectors[7], self.vectors[-1]):
            pk, msg, sig = self.inputs(vector)
            cases = [(pk[:i] + bytes([pk[i] ^ 1]) + pk[i+1:], msg, sig) for i in (0, 16, 32)]
            cases += [(pk, bytes([msg[0] ^ 1]) + msg[1:], sig)]
            offsets = (0, 1, 17, 19, len(sig) // 2, len(sig) - 1)
            cases += [(pk, msg, sig[:i] + bytes([sig[i] ^ 1]) + sig[i+1:]) for i in offsets]
            cases += [(pk, msg, sig[:-1]), (pk, msg, sig + b'\x00')]
            for i, case in enumerate(cases):
                with self.subTest(vector=vector['name'], mutation=i):
                    self.verify(*case, False)

    def test_nonempty_context(self):
        for vector in self.data['rejected_vectors']:
            with self.subTest(vector=vector['name']):
                self.verify(*self.inputs(vector), False)

    @unittest.skipUnless(run_chia_program, 'optional chia_rs consensus runner is unavailable')
    def test_consensus_runner(self):
        program = bytes.fromhex(self.program.read_text())
        for vector in self.vectors:
            with self.subTest(vector=vector['name']):
                cost, result = run_chia_program(program, args(*self.inputs(vector)),
                                                11000000000, MEMPOOL_MODE)
                self.assertEqual(result.atom, b'')
                self.assertLess(cost, 11000000000)
        for vector in self.data['rejected_vectors']:
            with self.subTest(vector=vector['name']):
                with self.assertRaises(ValueError):
                    run_chia_program(program, args(*self.inputs(vector)),
                                     11000000000, MEMPOOL_MODE)

    def test_malformed_inputs(self):
        pk, msg, sig = self.inputs(self.vectors[0])
        for size in (0, 1, 47, 49):
            self.verify(bytes(size), msg, sig, False)
        for size in (0, 1, 31, 33):
            self.verify(pk, bytes(size), sig, False)
        for size in (0, 1, 17, 547, 548, 4619, 5776, 5777, 5778, 65536):
            for indicator in (0, 254, 255):
                candidate = (bytes([indicator]) + bytes(size))[:size]
                self.verify(pk, msg, candidate, False)
        # A depth-one index has seven unused high bits, all of which must be zero.
        self.verify(pk, msg, sig[:17] + b'\x02' + sig[18:], False)
        # Pairs are not binary strings; all three positions must fail.
        for position in range(3):
            values = [atom(pk), atom(msg), atom(sig)]
            values[position] = b'\xff\x01\x80'
            result = self.execute(b''.join(b'\xff' + value for value in values) + b'\x80')
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
