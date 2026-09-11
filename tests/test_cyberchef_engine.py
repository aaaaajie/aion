from __future__ import annotations

import hashlib

from tools.cyberchef.engine import OPERATIONS, execute_recipe


def bake(data: bytes, *steps: dict) -> bytes:
    output, _ = execute_recipe(data, list(steps))
    return output


def test_first_version_allowlist_excludes_removed_capabilities() -> None:
    assert 'AES Encrypt' in OPERATIONS
    assert 'RSA Decrypt' in OPERATIONS
    for removed in ('OCR', 'Extract image', 'PGP Decrypt', 'GOST', 'Run JavaScript', 'Magic'):
        assert removed not in OPERATIONS


def test_aes_gcm_nist_vector() -> None:
    key = {'option': 'Hex', 'string': '00000000000000000000000000000000'}
    nonce = {'option': 'Hex', 'string': '000000000000000000000000'}
    args = {'key': key, 'iv': nonce, 'mode': 'GCM', 'input': 'Hex', 'output': 'Hex'}
    ciphertext = bake(
        b'00000000000000000000000000000000',
        {'op': 'AES Encrypt', 'args': args},
    )
    assert ciphertext == b'0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf'
    assert bake(ciphertext, {'op': 'AES Decrypt', 'args': args}) == b'00000000000000000000000000000000'


def test_des_sm4_and_classic_roundtrips() -> None:
    des_args = {'key': {'option': 'Hex', 'string': '133457799bbcdff1'}, 'mode': 'ECB/NoPadding', 'input': 'Hex', 'output': 'Hex'}
    assert bake(b'0123456789abcdef', {'op': 'DES Encrypt', 'args': des_args}) == b'85e813540f0ab405'
    sm4_args = {'key': {'option': 'Hex', 'string': '0123456789abcdeffedcba9876543210'}, 'mode': 'ECB/NoPadding', 'input': 'Hex', 'output': 'Hex'}
    assert bake(b'0123456789abcdeffedcba9876543210', {'op': 'SM4 Encrypt', 'args': sm4_args}) == b'681edf34d206965e86b3e94f536e4246'


def test_kdf_and_hash_vectors() -> None:
    assert bake(b'', {'op': 'PBKDF2', 'args': {'password': 'password', 'salt': 'salt', 'iterations': 1, 'keySize': 20, 'hash': 'SHA-1'}}) == hashlib.pbkdf2_hmac('sha1', b'password', b'salt', 1, 20)
    assert bake(b'abc', {'op': 'SHA2', 'args': {'size': '256'}}) == hashlib.sha256(b'abc').hexdigest().encode()
