"""Small, Python-native CyberChef-compatible recipe engine.

The module intentionally contains only operations that are useful to an offline
crypto/encoding CLI.  The operation registry is the single source of truth for
the wrapper schema, the CLI dispatcher, and the generated operation files.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import html
import hmac
import json
import re
import urllib.parse
import zlib
from dataclasses import dataclass
from gzip import compress as gzip_compress, decompress as gzip_decompress
from typing import Any, Callable

try:
    import bcrypt
except ImportError:  # pragma: no cover - the image always ships bcrypt
    bcrypt = None

try:
    from Crypto.Cipher import AES as CryptoAES
    from Crypto.Cipher import ARC2, ARC4, Blowfish, DES, DES3
    from Crypto.Cipher import ChaCha20 as CryptoChaCha20
    from Crypto.Cipher import Salsa20
    from Crypto.Hash import CMAC as CryptoCMAC
except ImportError:  # pragma: no cover - packaging check catches this
    CryptoAES = ARC2 = ARC4 = Blowfish = DES = DES3 = None
    CryptoChaCha20 = Salsa20 = CryptoCMAC = None

from cryptography import x509
from cryptography.hazmat.primitives import hashes, keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class OperationError(Exception):
    def __init__(self, code: str, message: str, detail: Any = None):
        super().__init__(message)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Operation:
    name: str
    function: Callable[[bytes, dict[str, Any]], bytes]
    args: tuple[dict[str, Any], ...] = ()
    description: str = ''


def _arg(name: str, description: str = '', default: Any = None, kind: str = 'string') -> dict[str, Any]:
    value = {'name': name, 'type': kind, 'description': description}
    if default is not None:
        value['default'] = default
    return value


def _norm(value: Any) -> str:
    return re.sub(r'[^a-z0-9]', '', str(value).casefold())


def _params(raw: Any, operation: Operation) -> dict[str, Any]:
    if raw is None:
        values: dict[str, Any] = {}
    elif isinstance(raw, dict):
        allowed = {_norm(item['name']) for item in operation.args}
        unknown = [key for key in raw if _norm(key) not in allowed]
        if unknown:
            raise OperationError('invalid_arguments', f'Unknown argument(s): {", ".join(unknown)}')
        values = {_norm(key): value for key, value in raw.items()}
    elif isinstance(raw, list):
        if len(raw) != len(operation.args):
            raise OperationError('invalid_arguments', 'Positional arguments must contain every declared argument')
        values = {_norm(item['name']): raw[index] for index, item in enumerate(operation.args)}
    else:
        raise OperationError('invalid_arguments', 'Arguments must be an object or array')
    for item in operation.args:
        key = _norm(item['name'])
        if key not in values and 'default' in item:
            values[key] = item['default']
    return values


def _value(params: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        key = _norm(name)
        if key in params:
            return params[key]
    return default


def _text(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get('string', value.get('value', ''))
    return str(value if value is not None else '')


def _bytes(value: Any, option: str = 'UTF8') -> bytes:
    if isinstance(value, dict):
        option = value.get('option', option)
        value = value.get('string', value.get('value', ''))
    option = _norm(option)
    text = _text(value)
    try:
        if option in {'hex', 'hexadecimal'}:
            compact = re.sub(r'\s+', '', text)
            if len(compact) % 2:
                raise ValueError('hex input must contain complete bytes')
            return bytes.fromhex(compact)
        if option in {'base64', 'base64standard'}:
            return base64.b64decode(re.sub(r'\s+', '', text), validate=True)
        if option in {'base64url', 'urlbase64'}:
            return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
        if option in {'base32', 'base32standard'}:
            return base64.b32decode(re.sub(r'\s+', '', text).upper() + '=' * (-len(re.sub(r'\s+', '', text)) % 8))
        if option in {'latin1', 'binary'}:
            return text.encode('latin-1')
        if option in {'ascii'}:
            return text.encode('ascii')
        return text.encode('utf-8')
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise OperationError('invalid_arguments', f'Invalid {option} value') from exc


def _output(data: bytes, option: str | None) -> bytes:
    if option is None:
        return data
    option = _norm(option)
    if option in {'hex', 'hexadecimal'}:
        return data.hex().encode('ascii')
    if option in {'base64', 'base64standard'}:
        return base64.b64encode(data)
    if option in {'base64url', 'urlbase64'}:
        return base64.urlsafe_b64encode(data).rstrip(b'=')
    if option in {'utf8', 'text'}:
        try:
            return data.decode('utf-8').encode('utf-8')
        except UnicodeDecodeError as exc:
            raise OperationError('recipe_failed', 'Output is not valid UTF-8') from exc
    if option in {'latin1', 'binary'}:
        return data.decode('latin-1').encode('utf-8')
    return data


def _base58_encode(data: bytes) -> bytes:
    alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if not data:
        return b''
    number = int.from_bytes(data, 'big')
    result = bytearray()
    while number:
        number, remainder = divmod(number, 58)
        result.append(alphabet[remainder])
    result.reverse()
    return alphabet[:1] * (len(data) - len(data.lstrip(b'\0'))) + bytes(result or alphabet[:1])


def _base58_decode(data: bytes) -> bytes:
    alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    try:
        number = 0
        for char in data.strip():
            number = number * 58 + alphabet.index(char)
        raw = number.to_bytes((number.bit_length() + 7) // 8, 'big') if number else b''
        return b'\0' * (len(data) - len(data.lstrip(b'1'))) + raw
    except ValueError as exc:
        raise OperationError('invalid_arguments', 'Invalid Base58 input') from exc


def _encode(data: bytes, params: dict[str, Any]) -> bytes:
    return data


def _to_base64(data: bytes, params: dict[str, Any]) -> bytes:
    return base64.b64encode(data)


def _from_base64(data: bytes, params: dict[str, Any]) -> bytes:
    text = data.decode('ascii', errors='strict')
    url_safe = bool(_value(params, 'urlSafe', default=False))
    remove = bool(_value(params, 'removeNonAlphabetChars', default=True))
    if remove:
        text = re.sub(r'[^A-Za-z0-9+/_=-]', '', text)
    try:
        padded = text + '=' * (-len(text) % 4)
        if url_safe:
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded, validate=not remove)
    except (ValueError, binascii.Error) as exc:
        raise OperationError('invalid_arguments', 'Invalid Base64 input') from exc


def _to_base32(data: bytes, params: dict[str, Any]) -> bytes:
    return base64.b32encode(data)


def _from_base32(data: bytes, params: dict[str, Any]) -> bytes:
    try:
        text = re.sub(r'\s+', '', data.decode('ascii')).upper()
        return base64.b32decode(text + '=' * (-len(text) % 8))
    except (UnicodeError, binascii.Error, ValueError) as exc:
        raise OperationError('invalid_arguments', 'Invalid Base32 input') from exc


def _to_base58(data: bytes, params: dict[str, Any]) -> bytes:
    return _base58_encode(data)


def _from_base58(data: bytes, params: dict[str, Any]) -> bytes:
    return _base58_decode(data)


def _to_hex(data: bytes, params: dict[str, Any]) -> bytes:
    separator = _text(_value(params, 'delimiter', default=''))
    return separator.join(f'{item:02x}' for item in data).encode('ascii')


def _from_hex(data: bytes, params: dict[str, Any]) -> bytes:
    try:
        return bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', data.decode('ascii')))
    except (ValueError, UnicodeError) as exc:
        raise OperationError('invalid_arguments', 'Invalid hexadecimal input') from exc


def _to_binary(data: bytes, params: dict[str, Any]) -> bytes:
    separator = _text(_value(params, 'delimiter', default=' '))
    return separator.join(f'{item:08b}' for item in data).encode('ascii')


def _from_binary(data: bytes, params: dict[str, Any]) -> bytes:
    text = re.sub(r'[^01]', '', data.decode('ascii'))
    if len(text) % 8:
        raise OperationError('invalid_arguments', 'Binary input must contain complete octets')
    return bytes(int(text[index:index + 8], 2) for index in range(0, len(text), 8))


def _to_charcode(data: bytes, params: dict[str, Any]) -> bytes:
    return ' '.join(str(item) for item in data).encode('ascii')


def _from_charcode(data: bytes, params: dict[str, Any]) -> bytes:
    try:
        values = [int(item) for item in data.decode('ascii').split() if item]
        if any(item < 0 or item > 255 for item in values):
            raise ValueError
        return bytes(values)
    except (ValueError, UnicodeError) as exc:
        raise OperationError('invalid_arguments', 'Invalid charcode input') from exc


def _url_encode(data: bytes, params: dict[str, Any]) -> bytes:
    return urllib.parse.quote_from_bytes(data, safe=b'-_.!~*\'()').encode('ascii')


def _url_decode(data: bytes, params: dict[str, Any]) -> bytes:
    return urllib.parse.unquote_to_bytes(data.decode('ascii'))


def _html_encode(data: bytes, params: dict[str, Any]) -> bytes:
    return html.escape(data.decode('utf-8')).encode('utf-8')


def _html_decode(data: bytes, params: dict[str, Any]) -> bytes:
    return html.unescape(data.decode('utf-8')).encode('utf-8')


def _rot13(data: bytes, params: dict[str, Any]) -> bytes:
    return codecs.encode(data.decode('utf-8'), 'rot_13').encode('utf-8')


def _rot47(data: bytes, params: dict[str, Any]) -> bytes:
    return bytes((33 + ((item - 33 + 47) % 94) if 33 <= item <= 126 else item) for item in data)


def _atbash(data: bytes, params: dict[str, Any]) -> bytes:
    result = bytearray(data)
    for index, item in enumerate(result):
        if 65 <= item <= 90:
            result[index] = 90 - (item - 65)
        elif 97 <= item <= 122:
            result[index] = 122 - (item - 97)
    return bytes(result)


def _vigenere(data: bytes, params: dict[str, Any], decrypt: bool) -> bytes:
    key = re.sub('[^A-Za-z]', '', _text(_value(params, 'key', default=''))).upper()
    if not key:
        raise OperationError('invalid_arguments', 'Vigenere key is required')
    offset = 0
    result = bytearray(data)
    for index, item in enumerate(result):
        if 65 <= item <= 90 or 97 <= item <= 122:
            shift = ord(key[offset % len(key)]) - 65
            if decrypt:
                shift = -shift
            base = 65 if 65 <= item <= 90 else 97
            result[index] = (item - base + shift) % 26 + base
            offset += 1
    return bytes(result)


def _a1z26(data: bytes, params: dict[str, Any], decode: bool) -> bytes:
    if decode:
        values = re.findall(r'\d+', data.decode('ascii'))
        try:
            return ''.join(chr(64 + int(value)) if 1 <= int(value) <= 26 else ' ' for value in values).encode()
        except ValueError as exc:
            raise OperationError('invalid_arguments', 'Invalid A1Z26 input') from exc
    return ' '.join(str(ord(char.upper()) - 64) if char.isalpha() else '0' for char in data.decode('utf-8')).encode()


def _xor(data: bytes, params: dict[str, Any]) -> bytes:
    key = _bytes(_value(params, 'key', 'passphrase', default=''), _value(params, 'inputFormat', default='UTF8'))
    if not key:
        raise OperationError('invalid_arguments', 'XOR key is required')
    return bytes(item ^ key[index % len(key)] for index, item in enumerate(data))


def _padding(data: bytes, block: int, enabled: bool, remove: bool) -> bytes:
    if not enabled:
        return data
    if remove:
        if not data or len(data) % block:
            raise OperationError('recipe_failed', 'Invalid padded ciphertext length')
        size = data[-1]
        if size == 0 or size > block or data[-size:] != bytes([size]) * size:
            raise OperationError('recipe_failed', 'Invalid PKCS#7 padding')
        return data[:-size]
    size = block - (len(data) % block)
    return data + bytes([size]) * size


def _cipher_params(params: dict[str, Any], block: int) -> tuple[bytes, bytes, str, bool]:
    key = _bytes(_value(params, 'key', 'passphrase', default=''), _value(params, 'keyFormat', default='UTF8'))
    iv = _bytes(_value(params, 'iv', 'nonce', default=''), _value(params, 'ivFormat', default='UTF8'))
    mode = _text(_value(params, 'mode', default='CBC'))
    no_padding = 'nopadding' in _norm(mode) or _norm(_value(params, 'padding', default='')) in {'nopadding', 'none'}
    mode = mode.split('/')[0].upper()
    if mode != 'ECB' and not iv:
        iv = b'\0' * block
    return key, iv, mode, no_padding


def _symmetric(data: bytes, params: dict[str, Any], cipher: Any, block: int, decrypt: bool = False) -> bytes:
    input_format = _value(params, 'input', default='Raw')
    if _norm(input_format) not in {'raw', 'binary'}:
        data = _bytes(data.decode('utf-8'), input_format)
    key, iv, mode, no_padding = _cipher_params(params, block)
    if not key:
        raise OperationError('invalid_arguments', 'Cipher key is required')
    try:
        if mode == 'ECB':
            obj = cipher.new(key, cipher.MODE_ECB)
        elif mode == 'CBC':
            obj = cipher.new(key, cipher.MODE_CBC, iv=iv)
        elif mode == 'CFB':
            obj = cipher.new(key, cipher.MODE_CFB, iv=iv, segment_size=128)
        elif mode == 'OFB':
            obj = cipher.new(key, cipher.MODE_OFB, iv=iv)
        elif mode == 'CTR':
            obj = cipher.new(key, cipher.MODE_CTR, nonce=b'', initial_value=int.from_bytes(iv, 'big'))
        else:
            raise OperationError('invalid_arguments', f'Unsupported {cipher.__name__} mode: {mode}')
        payload = data if decrypt else _padding(data, block, mode in {'ECB', 'CBC'} and not no_padding, False)
        result = obj.decrypt(payload) if decrypt else obj.encrypt(payload)
        result = _padding(result, block, mode in {'ECB', 'CBC'} and not no_padding, decrypt)
        return _output(result, _value(params, 'output')) if _norm(_value(params, 'output', default='Raw')) not in {'raw', 'binary'} else result
    except OperationError:
        raise
    except (ValueError, TypeError) as exc:
        raise OperationError('recipe_failed', 'Invalid cipher key, IV, mode, or block length') from exc


def _aes(data: bytes, params: dict[str, Any], decrypt: bool) -> bytes:
    key, iv, mode, no_padding = _cipher_params(params, 16)
    if len(key) not in {16, 24, 32}:
        raise OperationError('recipe_failed', 'AES key must be 128, 192, or 256 bits')
    try:
        if mode == 'GCM':
            nonce = iv or b'\0' * 12
            tag = _bytes(_value(params, 'tag', default=''), _value(params, 'tagFormat', default='Hex'))
            if _norm(_value(params, 'input', default='Raw')) not in {'raw', 'binary'}:
                data = _bytes(data.decode('utf-8'), _value(params, 'input'))
            if decrypt:
                if not tag:
                    data, tag = data[:-16], data[-16:]
                obj = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=nonce)
                result = obj.decrypt_and_verify(data, tag)
                return _output(result, _value(params, 'output')) if _norm(_value(params, 'output', default='Raw')) not in {'raw', 'binary'} else result
            obj = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=nonce)
            ciphertext, tag = obj.encrypt_and_digest(data)
            result = ciphertext + tag
            return _output(result, _value(params, 'output')) if _norm(_value(params, 'output', default='Raw')) not in {'raw', 'binary'} else result
        return _symmetric(data, params, CryptoAES, 16, decrypt)
    except ValueError as exc:
        raise OperationError('recipe_failed', 'AES authentication failed or parameters are invalid') from exc


def _des(data: bytes, params: dict[str, Any], decrypt: bool) -> bytes:
    return _symmetric(data, params, DES, 8, decrypt)


def _triple_des(data: bytes, params: dict[str, Any], decrypt: bool) -> bytes:
    return _symmetric(data, params, DES3, 8, decrypt)


def _rc2(data: bytes, params: dict[str, Any], decrypt: bool) -> bytes:
    key, iv, mode, no_padding = _cipher_params(params, 8)
    effective = int(_value(params, 'effectiveKeyLength', 'effectiveKeyBits', default=len(key) * 8))
    try:
        if mode == 'ECB':
            cipher = ARC2.new(key, ARC2.MODE_ECB, effective_keylen=effective)
        else:
            cipher = ARC2.new(key, ARC2.MODE_CBC, iv=iv, effective_keylen=effective)
        payload = data if decrypt else _padding(data, 8, mode in {'ECB', 'CBC'} and not no_padding, False)
        result = cipher.decrypt(payload) if decrypt else cipher.encrypt(payload)
        return _padding(result, 8, mode in {'ECB', 'CBC'} and not no_padding, decrypt)
    except (ValueError, TypeError) as exc:
        raise OperationError('recipe_failed', 'Invalid RC2 parameters') from exc


def _blowfish(data: bytes, params: dict[str, Any], decrypt: bool) -> bytes:
    return _symmetric(data, params, Blowfish, 8, decrypt)


def _rc4(data: bytes, params: dict[str, Any]) -> bytes:
    key = _bytes(_value(params, 'passphrase', 'key', default=''), _value(params, 'inputFormat', default='UTF8'))
    if not key:
        raise OperationError('invalid_arguments', 'RC4 key is required')
    try:
        result = ARC4.new(key, drop=int(_value(params, 'drop', default=0))).encrypt(data)
        return _output(result, _value(params, 'outputFormat'))
    except (ValueError, TypeError) as exc:
        raise OperationError('recipe_failed', 'Invalid RC4 parameters') from exc


def _chacha(data: bytes, params: dict[str, Any], decrypt: bool) -> bytes:
    key = _bytes(_value(params, 'key', default=''), _value(params, 'keyFormat', default='Hex'))
    nonce = _bytes(_value(params, 'nonce', 'iv', default=''), _value(params, 'nonceFormat', default='Hex'))
    if len(key) != 32 or len(nonce) not in {8, 12, 24}:
        raise OperationError('invalid_arguments', 'ChaCha20 requires a 256-bit key and 8/12/24-byte nonce')
    try:
        return CryptoChaCha20.new(key=key, nonce=nonce).encrypt(data)
    except (ValueError, TypeError) as exc:
        raise OperationError('recipe_failed', 'Invalid ChaCha20 parameters') from exc


def _salsa(data: bytes, params: dict[str, Any], decrypt: bool) -> bytes:
    key = _bytes(_value(params, 'key', default=''), _value(params, 'keyFormat', default='Hex'))
    nonce = _bytes(_value(params, 'nonce', default=''), _value(params, 'nonceFormat', default='Hex'))
    if len(key) not in {16, 32} or len(nonce) != 8:
        raise OperationError('invalid_arguments', 'Salsa20 requires a 128/256-bit key and 8-byte nonce')
    return Salsa20.new(key=key, nonce=nonce).encrypt(data)


def _sm4(data: bytes, params: dict[str, Any], decrypt: bool) -> bytes:
    input_format = _value(params, 'input', default='Raw')
    if _norm(input_format) not in {'raw', 'binary'}:
        data = _bytes(data.decode('utf-8'), input_format)
    key, iv, mode, no_padding = _cipher_params(params, 16)
    if len(key) != 16:
        raise OperationError('recipe_failed', 'SM4 key must be 128 bits')
    if mode == 'ECB':
        cipher_mode = modes.ECB()
    elif mode == 'CBC':
        cipher_mode = modes.CBC(iv)
    else:
        raise OperationError('invalid_arguments', 'SM4 supports ECB and CBC modes')
    try:
        context = Cipher(algorithms.SM4(key), cipher_mode).decryptor() if decrypt else Cipher(algorithms.SM4(key), cipher_mode).encryptor()
        payload = data if decrypt else _padding(data, 16, not no_padding, False)
        result = context.update(payload) + context.finalize()
        result = _padding(result, 16, not no_padding, decrypt)
        return _output(result, _value(params, 'output')) if _norm(_value(params, 'output', default='Raw')) not in {'raw', 'binary'} else result
    except (ValueError, TypeError) as exc:
        raise OperationError('recipe_failed', 'Invalid SM4 parameters') from exc


def _hash(data: bytes, params: dict[str, Any], algorithm: str) -> bytes:
    try:
        return hashlib.new(algorithm, data).hexdigest().encode('ascii')
    except ValueError as exc:
        raise OperationError('unsupported_operation', f'Hash is unavailable: {algorithm}') from exc


def _sha2(data: bytes, params: dict[str, Any]) -> bytes:
    size = int(_text(_value(params, 'size', default='256')).replace('SHA-', ''))
    if size not in {224, 256, 384, 512}:
        raise OperationError('invalid_arguments', 'SHA-2 size must be 224, 256, 384, or 512')
    return _hash(data, params, f'sha{size}')


def _sha3(data: bytes, params: dict[str, Any]) -> bytes:
    size = int(_text(_value(params, 'size', default='256')).replace('SHA-', ''))
    if size not in {224, 256, 384, 512}:
        raise OperationError('invalid_arguments', 'SHA-3 size must be 224, 256, 384, or 512')
    return _hash(data, params, f'sha3_{size}')


def _blake(data: bytes, params: dict[str, Any], algorithm: str) -> bytes:
    size = int(_value(params, 'size', default=256))
    if algorithm == 'blake2b' and size not in {160, 256, 384, 512}:
        raise OperationError('invalid_arguments', 'BLAKE2b size must be 160, 256, 384, or 512')
    if algorithm == 'blake2s' and size not in {128, 160, 224, 256}:
        raise OperationError('invalid_arguments', 'BLAKE2s size must be 128, 160, 224, or 256')
    return getattr(hashlib, algorithm)(data, digest_size=size // 8).hexdigest().encode('ascii')


def _hmac(data: bytes, params: dict[str, Any]) -> bytes:
    key = _bytes(_value(params, 'key', default=''), _value(params, 'keyFormat', default='UTF8'))
    algorithm = _norm(_value(params, 'hash', 'algorithm', default='SHA-256'))
    digest = {'sha1': hashlib.sha1, 'sha224': hashlib.sha224, 'sha256': hashlib.sha256,
              'sha384': hashlib.sha384, 'sha512': hashlib.sha512, 'md5': hashlib.md5,
              'sha3256': hashlib.sha3_256, 'sha3512': hashlib.sha3_512}.get(algorithm)
    if digest is None:
        raise OperationError('invalid_arguments', 'Unsupported HMAC hash')
    return hmac.new(key, data, digest).hexdigest().encode('ascii')


def _cmac(data: bytes, params: dict[str, Any]) -> bytes:
    key = _bytes(_value(params, 'key', default=''), _value(params, 'keyFormat', default='Hex'))
    algorithm = _norm(_value(params, 'algorithm', 'cipher', default='AES'))
    cipher = CryptoAES if algorithm == 'aes' else DES3
    try:
        return CryptoCMAC.new(key, ciphermod=cipher).update(data).digest().hex().encode('ascii')
    except (ValueError, TypeError) as exc:
        raise OperationError('recipe_failed', 'Invalid CMAC parameters') from exc


def _hash_algorithm(name: Any) -> hashes.HashAlgorithm:
    name = _norm(name or 'SHA-256')
    mapping = {'sha1': hashes.SHA1, 'sha224': hashes.SHA224, 'sha256': hashes.SHA256,
               'sha384': hashes.SHA384, 'sha512': hashes.SHA512, 'sha3224': hashes.SHA3_224,
               'sha3256': hashes.SHA3_256, 'sha3384': hashes.SHA3_384, 'sha3512': hashes.SHA3_512}
    try:
        return mapping[name]()
    except KeyError as exc:
        raise OperationError('invalid_arguments', f'Unsupported hash: {name}') from exc


def _kdf_password(params: dict[str, Any]) -> bytes:
    return _bytes(_value(params, 'password', 'passphrase', 'key', default=''), _value(params, 'passwordFormat', default='UTF8'))


def _pbkdf2(data: bytes, params: dict[str, Any]) -> bytes:
    password = _kdf_password(params) or data
    salt = _bytes(_value(params, 'salt', default=''), _value(params, 'saltFormat', default='UTF8'))
    length = int(_value(params, 'keySize', 'length', 'size', default=32))
    iterations = int(_value(params, 'iterations', 'iterationCount', default=100000))
    kdf = PBKDF2HMAC(algorithm=_hash_algorithm(_value(params, 'hash', default='SHA-256')), length=length, salt=salt, iterations=iterations)
    return kdf.derive(password)


def _hkdf(data: bytes, params: dict[str, Any]) -> bytes:
    password = _kdf_password(params) or data
    salt = _bytes(_value(params, 'salt', default=''), _value(params, 'saltFormat', default='UTF8')) or None
    info = _bytes(_value(params, 'info', default=''), _value(params, 'infoFormat', default='UTF8'))
    length = int(_value(params, 'keySize', 'length', 'size', default=32))
    return HKDF(algorithm=_hash_algorithm(_value(params, 'hash', default='SHA-256')), length=length, salt=salt, info=info).derive(password)


def _scrypt(data: bytes, params: dict[str, Any]) -> bytes:
    password = _kdf_password(params) or data
    salt = _bytes(_value(params, 'salt', default=''), _value(params, 'saltFormat', default='UTF8'))
    length = int(_value(params, 'keySize', 'length', 'size', default=32))
    n = int(_value(params, 'N', 'cost', default=16384))
    r = int(_value(params, 'r', default=8))
    p = int(_value(params, 'p', default=1))
    try:
        return Scrypt(salt=salt, length=length, n=n, r=r, p=p).derive(password)
    except ValueError as exc:
        raise OperationError('invalid_arguments', 'Invalid scrypt parameters') from exc


def _evp(data: bytes, params: dict[str, Any]) -> bytes:
    password = _kdf_password(params) or data
    salt = _bytes(_value(params, 'salt', default=''), _value(params, 'saltFormat', default='UTF8'))
    key_length = int(_value(params, 'keySize', default=32))
    iv_length = int(_value(params, 'ivSize', default=16))
    digest_name = _norm(_value(params, 'hash', default='MD5'))
    digest = getattr(hashlib, digest_name)
    output = b''
    previous = b''
    while len(output) < key_length + iv_length:
        previous = digest(previous + password + salt).digest()
        output += previous
    return output[:key_length + iv_length]


def _bcrypt_hash(data: bytes, params: dict[str, Any]) -> bytes:
    if bcrypt is None:
        raise OperationError('unsupported_operation', 'bcrypt is unavailable')
    password = _kdf_password(params) or data
    rounds = int(_value(params, 'rounds', 'cost', default=12))
    return bcrypt.hashpw(password, bcrypt.gensalt(rounds)).decode('ascii').encode('ascii')


def _bcrypt_verify(data: bytes, params: dict[str, Any]) -> bytes:
    if bcrypt is None:
        raise OperationError('unsupported_operation', 'bcrypt is unavailable')
    password = _kdf_password(params) or data
    hashed = _bytes(_value(params, 'hash', default=''), 'UTF8')
    try:
        return str(bcrypt.checkpw(password, hashed)).lower().encode('ascii')
    except ValueError as exc:
        raise OperationError('invalid_arguments', 'Invalid bcrypt hash') from exc


def _compression(data: bytes, params: dict[str, Any], kind: str, decode: bool) -> bytes:
    try:
        if kind == 'gzip':
            return gzip_decompress(data) if decode else gzip_compress(data)
        wbits = -zlib.MAX_WBITS if kind == 'raw' else zlib.MAX_WBITS
        return zlib.decompress(data, wbits) if decode else zlib.compress(data)
    except zlib.error as exc:
        raise OperationError('recipe_failed', 'Invalid compressed data') from exc


def _load_private(value: Any):
    try:
        return serialization.load_pem_private_key(_bytes(value, 'UTF8'), password=None)
    except (ValueError, TypeError) as exc:
        raise OperationError('invalid_arguments', 'Invalid PEM private key') from exc


def _load_public(value: Any):
    try:
        raw = _bytes(value, 'UTF8')
        try:
            return serialization.load_pem_public_key(raw)
        except ValueError:
            return serialization.load_der_public_key(raw)
    except (ValueError, TypeError) as exc:
        raise OperationError('invalid_arguments', 'Invalid public key') from exc


def _rsa_padding(params: dict[str, Any], decrypt: bool = False):
    name = _norm(_value(params, 'padding', 'scheme', default='OAEP'))
    if name in {'pkcs1', 'pkcs1v15', 'pkcs1v1.5'}:
        return padding.PKCS1v15()
    if name in {'oaep', ''}:
        return padding.OAEP(mgf=padding.MGF1(_hash_algorithm(_value(params, 'hash', 'oaepHash', default='SHA-1'))), algorithm=_hash_algorithm(_value(params, 'hash', 'oaepHash', default='SHA-1')), label=None)
    raise OperationError('invalid_arguments', 'Only OAEP and PKCS#1 v1.5 RSA padding are supported')


def _rsa_encrypt(data: bytes, params: dict[str, Any]) -> bytes:
    key = _load_public(_value(params, 'RSA Public Key (PEM)', 'publicKey', 'key', default=''))
    if not isinstance(key, rsa.RSAPublicKey):
        raise OperationError('invalid_arguments', 'RSA public key is required')
    try:
        return key.encrypt(data, _rsa_padding(params))
    except ValueError as exc:
        raise OperationError('recipe_failed', 'RSA plaintext is too long or parameters are invalid') from exc


def _rsa_decrypt(data: bytes, params: dict[str, Any]) -> bytes:
    key = _load_private(_value(params, 'RSA Private Key (PEM)', 'privateKey', 'key', default=''))
    if not isinstance(key, rsa.RSAPrivateKey):
        raise OperationError('invalid_arguments', 'RSA private key is required')
    try:
        return key.decrypt(data, _rsa_padding(params, True))
    except ValueError as exc:
        raise OperationError('recipe_failed', 'RSA decryption failed') from exc


def _rsa_sign(data: bytes, params: dict[str, Any]) -> bytes:
    key = _load_private(_value(params, 'RSA Private Key (PEM)', 'privateKey', 'key', default=''))
    scheme = _norm(_value(params, 'padding', 'scheme', default='PKCS1'))
    digest = _hash_algorithm(_value(params, 'hash', default='SHA-256'))
    chosen = padding.PSS(mgf=padding.MGF1(digest), salt_length=padding.PSS.MAX_LENGTH) if scheme == 'pss' else padding.PKCS1v15()
    return key.sign(data, chosen, digest)


def _rsa_verify(data: bytes, params: dict[str, Any]) -> bytes:
    key = _load_public(_value(params, 'RSA Public Key (PEM)', 'publicKey', 'key', default=''))
    signature = _bytes(_value(params, 'signature', default=''), _value(params, 'signatureFormat', default='Base64'))
    digest = _hash_algorithm(_value(params, 'hash', default='SHA-256'))
    scheme = _norm(_value(params, 'padding', 'scheme', default='PKCS1'))
    chosen = padding.PSS(mgf=padding.MGF1(digest), salt_length=padding.PSS.MAX_LENGTH) if scheme == 'pss' else padding.PKCS1v15()
    try:
        key.verify(signature, data, chosen, digest)
        return b'true'
    except Exception:
        return b'false'


def _rsa_generate(data: bytes, params: dict[str, Any]) -> bytes:
    size = int(_value(params, 'size', 'modulusLength', default=2048))
    key = rsa.generate_private_key(public_exponent=65537, key_size=size)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _ec_private(value: Any):
    try:
        return serialization.load_pem_private_key(_bytes(value, 'UTF8'), password=None)
    except (ValueError, TypeError) as exc:
        raise OperationError('invalid_arguments', 'Invalid EC private key') from exc


def _ec_public(value: Any):
    return _load_public(value)


def _ec_curve(name: Any) -> ec.EllipticCurve:
    return {'secp256r1': ec.SECP256R1, 'prime256v1': ec.SECP256R1,
            'secp384r1': ec.SECP384R1, 'secp521r1': ec.SECP521R1}.get(_norm(name), ec.SECP256R1)()


def _ecdsa_sign(data: bytes, params: dict[str, Any]) -> bytes:
    key = _ec_private(_value(params, 'privateKey', 'EC Private Key (PEM)', 'key', default=''))
    return key.sign(data, ec.ECDSA(_hash_algorithm(_value(params, 'hash', default='SHA-256'))))


def _ecdsa_verify(data: bytes, params: dict[str, Any]) -> bytes:
    key = _ec_public(_value(params, 'publicKey', 'EC Public Key (PEM)', 'key', default=''))
    signature = _bytes(_value(params, 'signature', default=''), _value(params, 'signatureFormat', default='Base64'))
    try:
        key.verify(signature, data, ec.ECDSA(_hash_algorithm(_value(params, 'hash', default='SHA-256'))))
        return b'true'
    except Exception:
        return b'false'


def _ecdsa_generate(data: bytes, params: dict[str, Any]) -> bytes:
    key = ec.generate_private_key(_ec_curve(_value(params, 'curve', default='secp256r1')))
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _aes_wrap(data: bytes, params: dict[str, Any], unwrap: bool) -> bytes:
    key = _bytes(_value(params, 'key', 'kek', default=''), _value(params, 'keyFormat', default='Hex'))
    try:
        return keywrap.aes_key_unwrap(key, data) if unwrap else keywrap.aes_key_wrap(key, data)
    except ValueError as exc:
        raise OperationError('recipe_failed', 'Invalid AES key wrap data') from exc


def _pem_to_hex(data: bytes, params: dict[str, Any]) -> bytes:
    return data.hex().encode('ascii')


def _pem_to_der(data: bytes, params: dict[str, Any]) -> bytes:
    try:
        if b'CERTIFICATE' in data:
            return x509.load_pem_x509_certificate(data).public_bytes(serialization.Encoding.DER)
        try:
            key = serialization.load_pem_private_key(data, password=None)
            return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        except ValueError:
            key = serialization.load_pem_public_key(data)
            return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError) as exc:
        raise OperationError('invalid_arguments', 'Invalid PEM key or certificate') from exc


def _der_to_pem(data: bytes, params: dict[str, Any]) -> bytes:
    try:
        if data.startswith(b'0'):
            try:
                cert = x509.load_der_x509_certificate(data)
                return cert.public_bytes(serialization.Encoding.PEM)
            except ValueError:
                pass
        try:
            key = serialization.load_der_private_key(data, password=None)
            return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        except ValueError:
            key = serialization.load_der_public_key(data)
            return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError) as exc:
        raise OperationError('invalid_arguments', 'Invalid DER key or certificate') from exc


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _unb64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def _pem_to_jwk(data: bytes, params: dict[str, Any]) -> bytes:
    try:
        try:
            key = serialization.load_pem_private_key(data, password=None)
            private = True
        except ValueError:
            key = serialization.load_pem_public_key(data)
            private = False
        if isinstance(key, rsa.RSAPrivateKey):
            numbers = key.private_numbers()
            public = numbers.public_numbers
            value = {'kty': 'RSA', 'n': _b64u(public.n.to_bytes((public.n.bit_length() + 7) // 8, 'big')), 'e': _b64u(public.e.to_bytes((public.e.bit_length() + 7) // 8, 'big'))}
            if private:
                value.update({'d': _b64u(numbers.d.to_bytes((numbers.d.bit_length() + 7) // 8, 'big')), 'p': _b64u(numbers.p.to_bytes((numbers.p.bit_length() + 7) // 8, 'big')), 'q': _b64u(numbers.q.to_bytes((numbers.q.bit_length() + 7) // 8, 'big'))})
        elif isinstance(key, rsa.RSAPublicKey):
            numbers = key.public_numbers()
            value = {'kty': 'RSA', 'n': _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')), 'e': _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big'))}
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            numbers = key.private_numbers()
            public = numbers.public_numbers
            size = (key.curve.key_size + 7) // 8
            value = {'kty': 'EC', 'crv': key.curve.name, 'x': _b64u(public.x.to_bytes(size, 'big')), 'y': _b64u(public.y.to_bytes(size, 'big'))}
            if private:
                value['d'] = _b64u(numbers.private_value.to_bytes(size, 'big'))
        elif isinstance(key, ec.EllipticCurvePublicKey):
            numbers = key.public_numbers()
            size = (key.curve.key_size + 7) // 8
            value = {'kty': 'EC', 'crv': key.curve.name, 'x': _b64u(numbers.x.to_bytes(size, 'big')), 'y': _b64u(numbers.y.to_bytes(size, 'big'))}
        else:
            raise ValueError('unsupported key type')
        return json.dumps(value, separators=(',', ':')).encode('utf-8')
    except (ValueError, TypeError, KeyError) as exc:
        raise OperationError('invalid_arguments', 'PEM does not contain a supported RSA or EC key') from exc


def _jwk_to_pem(data: bytes, params: dict[str, Any]) -> bytes:
    try:
        value = json.loads(data.decode('utf-8'))
        if value.get('kty') == 'RSA':
            n = int.from_bytes(_unb64u(value['n']), 'big')
            e = int.from_bytes(_unb64u(value['e']), 'big')
            if 'd' in value:
                d = int.from_bytes(_unb64u(value['d']), 'big')
                p = int.from_bytes(_unb64u(value['p']), 'big')
                q = int.from_bytes(_unb64u(value['q']), 'big')
                key = rsa.RSAPrivateNumbers(
                    p=p, q=q, d=d, dmp1=int.from_bytes(_unb64u(value['dp']), 'big') if 'dp' in value else d % (p - 1),
                    dmq1=int.from_bytes(_unb64u(value['dq']), 'big') if 'dq' in value else d % (q - 1),
                    iqmp=int.from_bytes(_unb64u(value['qi']), 'big') if 'qi' in value else pow(q, -1, p),
                    public_numbers=rsa.RSAPublicNumbers(e, n),
                ).private_key()
                return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            key = rsa.RSAPublicNumbers(e, n).public_key()
            return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        if value.get('kty') == 'EC':
            curve = _ec_curve(value.get('crv', 'secp256r1'))
            size = (curve.key_size + 7) // 8
            x = int.from_bytes(_unb64u(value['x']), 'big')
            y = int.from_bytes(_unb64u(value['y']), 'big')
            public = ec.EllipticCurvePublicNumbers(x, y, curve)
            if 'd' in value:
                key = ec.derive_private_key(int.from_bytes(_unb64u(value['d']), 'big'), curve)
                if key.public_key().public_numbers() != public:
                    raise ValueError('JWK EC public coordinates do not match private key')
                return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            return public.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        raise ValueError('unsupported JWK key type')
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise OperationError('invalid_arguments', 'Invalid RSA or EC JWK') from exc


def _parse_asn1(data: bytes, params: dict[str, Any]) -> bytes:
    try:
        if len(data) < 2:
            raise ValueError
        tag = data[0]
        length_byte = data[1]
        if length_byte & 0x80:
            count = length_byte & 0x7f
            length = int.from_bytes(data[2:2 + count], 'big')
            header = 2 + count
        else:
            length = length_byte
            header = 2
        return json.dumps({'tag': tag, 'length': length, 'header_length': header, 'constructed': bool(tag & 0x20)}, separators=(',', ':')).encode('ascii')
    except (ValueError, IndexError) as exc:
        raise OperationError('invalid_arguments', 'Invalid ASN.1 DER input') from exc


def _hex_to_pem(data: bytes, params: dict[str, Any]) -> bytes:
    raw = _from_hex(data, params)
    try:
        key = serialization.load_der_private_key(raw, password=None)
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    except ValueError:
        try:
            key = serialization.load_der_public_key(raw)
            return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        except ValueError as exc:
            raise OperationError('invalid_arguments', 'DER data is not a supported key') from exc


def _parse_x509(data: bytes, params: dict[str, Any]) -> bytes:
    try:
        cert = x509.load_pem_x509_certificate(data) if b'BEGIN' in data else x509.load_der_x509_certificate(data)
        return cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    except ValueError as exc:
        raise OperationError('invalid_arguments', 'Invalid X.509 certificate') from exc


def _crc32(data: bytes, params: dict[str, Any]) -> bytes:
    return f'{zlib.crc32(data) & 0xffffffff:08x}'.encode('ascii')


def _checksum(data: bytes, params: dict[str, Any]) -> bytes:
    return f'{sum(data) & 0xffffffff:08x}'.encode('ascii')


def _decode_text(data: bytes, params: dict[str, Any]) -> bytes:
    encoding = _text(_value(params, 'encoding', default='UTF-8')).replace('-', '').lower()
    try:
        return data.decode(encoding).encode('utf-8')
    except (LookupError, UnicodeDecodeError) as exc:
        raise OperationError('invalid_arguments', f'Unable to decode text as {encoding}') from exc


def _encode_text(data: bytes, params: dict[str, Any]) -> bytes:
    encoding = _text(_value(params, 'encoding', default='UTF-8')).replace('-', '').lower()
    try:
        return data.decode('utf-8').encode(encoding)
    except (LookupError, UnicodeError) as exc:
        raise OperationError('invalid_arguments', f'Unable to encode text as {encoding}') from exc


def _op(name: str, function: Callable[[bytes, dict[str, Any]], bytes], args: tuple[dict[str, Any], ...] = (), description: str = '') -> Operation:
    return Operation(name, function, args, description or name)


COMMON_KEY_ARGS = (_arg('key', 'Encryption key', default=''), _arg('iv', 'Initialization vector', default=''),
                   _arg('mode', 'Cipher mode', default='CBC'), _arg('input', 'Input encoding', default='Raw'),
                   _arg('output', 'Output encoding', default='Raw'), _arg('keyFormat', 'Key encoding', default='UTF8'),
                   _arg('ivFormat', 'IV encoding', default='UTF8'), _arg('padding', 'Padding mode', default='PKCS7'),
                   _arg('tag', 'Authentication tag', default=''), _arg('tagFormat', 'Tag encoding', default='Hex'))
BLOCK_ARGS = (_arg('key', 'Encryption key', default=''), _arg('iv', 'Initialization vector', default=''),
              _arg('mode', 'Cipher mode', default='CBC'), _arg('input', 'Input encoding', default='Raw'),
              _arg('output', 'Output encoding', default='Raw'))
RC4_ARGS = (_arg('passphrase', 'RC4 key', default=''), _arg('inputFormat', 'Key encoding', default='UTF8'), _arg('outputFormat', 'Output encoding', default='Raw'))
BASE64_ARGS = (_arg('alphabet', 'Alphabet', default='A-Za-z0-9+/='), _arg('removeNonAlphabetChars', 'Ignore non-alphabet characters', default=True, kind='boolean'), _arg('urlSafe', 'URL-safe alphabet', default=False, kind='boolean'))
KDF_ARGS = (_arg('password', 'Password', default=''), _arg('salt', 'Salt', default=''), _arg('iterations', 'Iterations', default=100000, kind='number'), _arg('keySize', 'Output bytes', default=32, kind='number'), _arg('hash', 'Hash algorithm', default='SHA-256'))


OPERATIONS: dict[str, Operation] = {
    'From Base64': _op('From Base64', _from_base64, BASE64_ARGS), 'To Base64': _op('To Base64', _to_base64),
    'From Base32': _op('From Base32', _from_base32), 'To Base32': _op('To Base32', _to_base32),
    'From Base58': _op('From Base58', _from_base58), 'To Base58': _op('To Base58', _to_base58),
    'From Hex': _op('From Hex', _from_hex), 'To Hex': _op('To Hex', _to_hex, (_arg('delimiter', 'Byte delimiter', default=' '),)),
    'From Binary': _op('From Binary', _from_binary), 'To Binary': _op('To Binary', _to_binary, (_arg('delimiter', 'Bit-group delimiter', default=' '),)),
    'From Charcode': _op('From Charcode', _from_charcode), 'To Charcode': _op('To Charcode', _to_charcode),
    'URL Decode': _op('URL Decode', _url_decode), 'URL Encode': _op('URL Encode', _url_encode),
    'From HTML Entity': _op('From HTML Entity', _html_decode), 'To HTML Entity': _op('To HTML Entity', _html_encode),
    'Decode text': _op('Decode text', _decode_text, (_arg('encoding', 'Source encoding', default='UTF-8'),)),
    'Encode text': _op('Encode text', _encode_text, (_arg('encoding', 'Target encoding', default='UTF-8'),)),
    'ROT13': _op('ROT13', _rot13), 'ROT47': _op('ROT47', _rot47), 'Atbash': _op('Atbash', _atbash),
    'Vigenere Decode': _op('Vigenere Decode', lambda d, p: _vigenere(d, p, True), (_arg('key', 'Vigenere key'),)),
    'Vigenere Encode': _op('Vigenere Encode', lambda d, p: _vigenere(d, p, False), (_arg('key', 'Vigenere key'),)),
    'A1Z26 Decode': _op('A1Z26 Decode', lambda d, p: _a1z26(d, p, True)), 'A1Z26 Encode': _op('A1Z26 Encode', lambda d, p: _a1z26(d, p, False)),
    'XOR': _op('XOR', _xor, (_arg('key', 'XOR key', default=''), _arg('inputFormat', 'Key encoding', default='UTF8'))),
    'AES Encrypt': _op('AES Encrypt', lambda d, p: _aes(d, p, False), COMMON_KEY_ARGS), 'AES Decrypt': _op('AES Decrypt', lambda d, p: _aes(d, p, True), COMMON_KEY_ARGS),
    'AES Key Wrap': _op('AES Key Wrap', lambda d, p: _aes_wrap(d, p, False), (_arg('key', 'Key encryption key', default=''),)),
    'AES Key Unwrap': _op('AES Key Unwrap', lambda d, p: _aes_wrap(d, p, True), (_arg('key', 'Key encryption key', default=''),)),
    'DES Encrypt': _op('DES Encrypt', lambda d, p: _des(d, p, False), BLOCK_ARGS), 'DES Decrypt': _op('DES Decrypt', lambda d, p: _des(d, p, True), BLOCK_ARGS),
    'Triple DES Encrypt': _op('Triple DES Encrypt', lambda d, p: _triple_des(d, p, False), BLOCK_ARGS), 'Triple DES Decrypt': _op('Triple DES Decrypt', lambda d, p: _triple_des(d, p, True), BLOCK_ARGS),
    '3DES Encrypt': _op('3DES Encrypt', lambda d, p: _triple_des(d, p, False), BLOCK_ARGS), '3DES Decrypt': _op('3DES Decrypt', lambda d, p: _triple_des(d, p, True), BLOCK_ARGS),
    'RC2 Encrypt': _op('RC2 Encrypt', lambda d, p: _rc2(d, p, False), BLOCK_ARGS), 'RC2 Decrypt': _op('RC2 Decrypt', lambda d, p: _rc2(d, p, True), BLOCK_ARGS),
    'RC4': _op('RC4', _rc4, RC4_ARGS), 'RC4 Drop': _op('RC4 Drop', _rc4, RC4_ARGS + (_arg('drop', 'Bytes to discard', default=768, kind='number'),)),
    'Blowfish Encrypt': _op('Blowfish Encrypt', lambda d, p: _blowfish(d, p, False), BLOCK_ARGS), 'Blowfish Decrypt': _op('Blowfish Decrypt', lambda d, p: _blowfish(d, p, True), BLOCK_ARGS),
    'ChaCha20 Encrypt': _op('ChaCha20 Encrypt', lambda d, p: _chacha(d, p, False), (_arg('key', default=''), _arg('nonce', default=''))), 'ChaCha20 Decrypt': _op('ChaCha20 Decrypt', lambda d, p: _chacha(d, p, True), (_arg('key', default=''), _arg('nonce', default=''))),
    'Salsa20 Encrypt': _op('Salsa20 Encrypt', lambda d, p: _salsa(d, p, False), (_arg('key', default=''), _arg('nonce', default=''))), 'Salsa20 Decrypt': _op('Salsa20 Decrypt', lambda d, p: _salsa(d, p, True), (_arg('key', default=''), _arg('nonce', default=''))),
    'SM4 Encrypt': _op('SM4 Encrypt', lambda d, p: _sm4(d, p, False), BLOCK_ARGS), 'SM4 Decrypt': _op('SM4 Decrypt', lambda d, p: _sm4(d, p, True), BLOCK_ARGS),
    'RSA Encrypt': _op('RSA Encrypt', _rsa_encrypt, (_arg('RSA Public Key (PEM)', default=''), _arg('padding', default='OAEP'), _arg('hash', default='SHA-1'))),
    'RSA Decrypt': _op('RSA Decrypt', _rsa_decrypt, (_arg('RSA Private Key (PEM)', default=''), _arg('padding', default='OAEP'), _arg('hash', default='SHA-1'))),
    'RSA Sign': _op('RSA Sign', _rsa_sign, (_arg('RSA Private Key (PEM)', default=''), _arg('padding', default='PKCS1'), _arg('hash', default='SHA-256'))),
    'RSA Verify': _op('RSA Verify', _rsa_verify, (_arg('RSA Public Key (PEM)', default=''), _arg('signature', default=''), _arg('signatureFormat', default='Base64'), _arg('padding', default='PKCS1'), _arg('hash', default='SHA-256'))),
    'Generate RSA Key Pair': _op('Generate RSA Key Pair', _rsa_generate, (_arg('size', default=2048, kind='number'),)),
    'ECDSA Sign': _op('ECDSA Sign', _ecdsa_sign, (_arg('privateKey', default=''), _arg('hash', default='SHA-256'))), 'ECDSA Verify': _op('ECDSA Verify', _ecdsa_verify, (_arg('publicKey', default=''), _arg('signature', default=''), _arg('signatureFormat', default='Base64'), _arg('hash', default='SHA-256'))),
    'Generate ECDSA Key Pair': _op('Generate ECDSA Key Pair', _ecdsa_generate, (_arg('curve', default='secp256r1'),)),
    'MD5': _op('MD5', lambda d, p: _hash(d, p, 'md5')), 'SHA1': _op('SHA1', lambda d, p: _hash(d, p, 'sha1')), 'SHA-1': _op('SHA-1', lambda d, p: _hash(d, p, 'sha1')),
    'SHA2': _op('SHA2', _sha2, (_arg('size', default='256'),)), 'SHA3': _op('SHA3', _sha3, (_arg('size', default='256'),)),
    'BLAKE2b': _op('BLAKE2b', lambda d, p: _blake(d, p, 'blake2b'), (_arg('size', default=512, kind='number'),)), 'BLAKE2s': _op('BLAKE2s', lambda d, p: _blake(d, p, 'blake2s'), (_arg('size', default=256, kind='number'),)),
    'RIPEMD-160': _op('RIPEMD-160', lambda d, p: _hash(d, p, 'ripemd160')), 'HMAC': _op('HMAC', _hmac, (_arg('key', default=''), _arg('keyFormat', default='UTF8'), _arg('hash', default='SHA-256'))),
    'CMAC': _op('CMAC', _cmac, (_arg('key', default=''), _arg('keyFormat', default='Hex'), _arg('algorithm', default='AES'))),
    'CRC32': _op('CRC32', _crc32), 'Checksum': _op('Checksum', _checksum),
    'PBKDF2': _op('PBKDF2', _pbkdf2, KDF_ARGS), 'Derive PBKDF2 key': _op('Derive PBKDF2 key', _pbkdf2, KDF_ARGS),
    'HKDF': _op('HKDF', _hkdf, KDF_ARGS + (_arg('info', default=''),)), 'Derive HKDF key': _op('Derive HKDF key', _hkdf, KDF_ARGS + (_arg('info', default=''),)),
    'Scrypt': _op('Scrypt', _scrypt, KDF_ARGS + (_arg('N', default=16384, kind='number'), _arg('r', default=8, kind='number'), _arg('p', default=1, kind='number'))),
    'EVP_BytesToKey': _op('EVP_BytesToKey', _evp, (_arg('password', default=''), _arg('salt', default=''), _arg('keySize', default=32, kind='number'), _arg('ivSize', default=16, kind='number'), _arg('hash', default='MD5'))),
    'Bcrypt': _op('Bcrypt', _bcrypt_hash, (_arg('password', default=''), _arg('rounds', default=12, kind='number'))), 'Bcrypt Verify': _op('Bcrypt Verify', _bcrypt_verify, (_arg('password', default=''), _arg('hash', default=''))),
    'Gzip': _op('Gzip', lambda d, p: _compression(d, p, 'gzip', False)), 'Gunzip': _op('Gunzip', lambda d, p: _compression(d, p, 'gzip', True)),
    'Zlib Deflate': _op('Zlib Deflate', lambda d, p: _compression(d, p, 'zlib', False)), 'Zlib Inflate': _op('Zlib Inflate', lambda d, p: _compression(d, p, 'zlib', True)),
    'Raw Deflate': _op('Raw Deflate', lambda d, p: _compression(d, p, 'raw', False)), 'Raw Inflate': _op('Raw Inflate', lambda d, p: _compression(d, p, 'raw', True)),
    'PEM to Hex': _op('PEM to Hex', _pem_to_hex), 'Hex to PEM': _op('Hex to PEM', _hex_to_pem), 'PEM to DER': _op('PEM to DER', _pem_to_der), 'DER to PEM': _op('DER to PEM', _der_to_pem),
    'PEM to JWK': _op('PEM to JWK', _pem_to_jwk), 'JWK to PEM': _op('JWK to PEM', _jwk_to_pem), 'Parse ASN.1': _op('Parse ASN.1', _parse_asn1), 'Parse X.509 certificate': _op('Parse X.509 certificate', _parse_x509),
}


def operation_config() -> dict[str, dict[str, Any]]:
    return {name: {'name': name, 'description': operation.description, 'args': list(operation.args)} for name, operation in OPERATIONS.items()}


def execute_recipe(data: bytes, recipe: list[dict[str, Any]]) -> tuple[bytes, list[dict[str, Any]]]:
    steps: list[dict[str, Any]] = []
    if len(recipe) > 32:
        raise OperationError('invalid_arguments', 'Recipe contains more than 32 steps')
    for index, step in enumerate(recipe):
        name = step.get('op') if isinstance(step, dict) else None
        operation = OPERATIONS.get(name)
        if operation is None:
            raise OperationError('unsupported_operation', f'Unsupported operation: {name}', {'step_index': index, 'operation': name})
        try:
            params = _params(step.get('args'), operation)
            data = operation.function(data, params)
        except OperationError as exc:
            if exc.detail is None:
                exc.detail = {'step_index': index, 'operation': name}
            elif isinstance(exc.detail, dict):
                exc.detail.setdefault('step_index', index)
                exc.detail.setdefault('operation', name)
            raise
        if len(data) > 4 * 1024 * 1024:
            raise OperationError('recipe_failed', 'Intermediate output exceeds 4 MiB', {'step_index': index, 'operation': name})
        steps.append({'operation': name, 'output_length': len(data)})
    return data, steps
