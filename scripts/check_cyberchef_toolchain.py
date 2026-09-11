"""Run with --network=none on Linux amd64 to verify the shipped CLI."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'tools/binaries/bin/cyberchef'


def main():
    assert not (CLI.parent / 'node').exists()
    assert not list((CLI.parent.parent / 'cyberchef').glob('node_modules'))
    assert not list((CLI.parent.parent / 'cyberchef').glob('package*.json'))
    assert not any(path.name.casefold() in {'tesseract-core', 'jimp'} for path in (CLI.parent.parent / 'cyberchef').rglob('*'))
    results = []
    def run(name, job, expected=None, code=None, artifacts=False):
        started = time.monotonic()
        with tempfile.TemporaryDirectory() as directory:
            command = [str(CLI)]
            if artifacts: command += ['--output-dir', str(Path(directory)/'result')]
            process = subprocess.run(command, input=json.dumps(job), text=True, capture_output=True, timeout=135)
            result = json.loads(process.stdout)
            if code:
                assert result.get('code') == code, (name,result,process.stderr)
                assert process.returncode != 0
            else:
                assert result['state'] == 'completed' and process.returncode == 0, (name,result,process.stderr)
                if expected is not None:
                    output = Path(result['output_path']).read_bytes() if artifacts else base64.b64decode(result['output_base64'])
                    assert output == expected, (name,result)
                    assert result['sha256'] == hashlib.sha256(expected).hexdigest()
                if artifacts:
                    assert Path(result['report_path']).is_file()
                    assert 'output_base64' not in result
            results.append({'name':name,'passed':True,'seconds':round(time.monotonic()-started,3)})
            return result
    operation_query = run('operation arguments', {'action':'operations','query':'AES Decrypt'})
    assert operation_query['operations'] == ['AES Decrypt']
    supported = run('supported operation list', {'action':'operations','query':''})
    assert supported['operations'] and all('OCR' not in name for name in supported['operations'])
    run('base64 hex recipe', {'input':'aGVsbG8=','recipe':[{'op':'From Base64'},{'op':'To Hex'}]}, b'68 65 6c 6c 6f')
    run('binary exact output', {'input':'AP+A','recipe':[{'op':'From Base64'}]}, b'\x00\xff\x80', artifacts=True)
    run('unicode', {'input':'你好','recipe':[{'op':'To Base64'},{'op':'From Base64'}]}, '你好'.encode())
    aes = {'key':{'option':'Hex','string':'000102030405060708090a0b0c0d0e0f'}, 'iv':{'option':'Hex','string':'00000000000000000000000000000000'}, 'mode':'CBC','input':'Hex','output':'Hex'}
    run('AES CBC known vector', {'input':'7649abac8119b246cee98e9b12e9197d', 'recipe':[{'op':'AES Decrypt','args':{**aes,'key':{'option':'Hex','string':'2b7e151628aed2a6abf7158809cf4f3c'},'iv':{'option':'Hex','string':'000102030405060708090a0b0c0d0e0f'},'mode':'CBC/NoPadding'}}]}, b'6bc1bee22e409f96e93d7e117393172a')
    run('gzip roundtrip', {'input':'fixture compression','recipe':[{'op':'Gzip'},{'op':'Gunzip'}]}, b'fixture compression')
    run('XOR known bytes', {'input':'000102ff','input_encoding':'hex','recipe':[{'op':'XOR','args':{'key':{'option':'Hex','string':'42'}}}]}, b'BC@\xbd')
    run('DES known vector', {'input':'85e813540f0ab405','recipe':[{'op':'DES Decrypt','args':{'key':{'option':'Hex','string':'133457799bbcdff1'},'mode':'ECB/NoPadding','input':'Hex','output':'Hex'}}]}, b'0123456789abcdef')
    run('base32 base58 roundtrip', {'input':'fixture','recipe':[{'op':'To Base32'},{'op':'From Base32'},{'op':'To Base58'},{'op':'From Base58'}]}, b'fixture')
    run('web positional recipe', {'input':'aGVsbG8=','recipe':[{'op':'From Base64','args':['A-Za-z0-9+/=',True,False]}]}, b'hello')
    run('RC4 known vector', {'input':'Plaintext','recipe':[{'op':'RC4','args':{'passphrase':{'option':'UTF8','string':'Key'},'inputFormat':'UTF8','outputFormat':'Hex'}}]}, b'bbf316e8d940af0ad3')
    fixture_code = """
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import base64, json
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
cipher = key.public_key().encrypt(b'local RSA fixture', padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
print(json.dumps({'key': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode(), 'cipher': base64.b64encode(cipher).decode()}))
"""
    fixture = json.loads(subprocess.check_output([sys.executable, '-c', fixture_code], text=True))
    run('RSA OAEP interoperability', {'input':fixture['cipher'],'input_encoding':'base64','recipe':[{'op':'RSA Decrypt','args':{'RSA Private Key (PEM)':fixture['key']}}]}, b'local RSA fixture')
    run('hash', {'input':'abc','recipe':[{'op':'SHA2','args':{'size':'256'}}]}, hashlib.sha256(b'abc').hexdigest().encode())
    run('unknown operation', {'input':'abc','recipe':[{'op':'Missing'}]}, code='unsupported_operation')
    run('network operation rejected', {'input':'http://127.0.0.1','recipe':[{'op':'HTTP request'}]}, code='unsupported_operation')
    for removed in ('OCR', 'Extract image', 'PGP Decrypt', 'GOST', 'Run JavaScript'):
        run(f'removed operation: {removed}', {'input':'abc','recipe':[{'op':removed}]}, code='unsupported_operation')
    run('bad named argument', {'input':'abc','recipe':[{'op':'XOR','args':{'kee':'42'}}]}, code='invalid_arguments')
    run('malformed binary encoding', {'input':'0xz','input_encoding':'hex','recipe':[{'op':'MD5'}]}, code='invalid_input')
    run('bad key', {'input':'abcd','recipe':[{'op':'AES Decrypt','args':{'key':{'option':'Hex','string':'00'}}}]}, code='recipe_failed')
    print(json.dumps({'ok':True,'platform':'linux/amd64','network':'disabled by caller','cases':results},indent=2))


if __name__ == '__main__': main()
