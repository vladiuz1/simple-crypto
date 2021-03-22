"""
A simple aes encryption / decryption based on modern cryptography module. Meant for encryption/decryption
of small texts with a passphrase of any length.

Uses AES 256 bit encryption with a 128 bit IV using CBC mode. The key is expanded with HKDFExpand standard using
SHA256, 256 bits lengh with an empty info. Well you can check this with the code.

Cryptographic strength of the passprase is the resposnibility of the user!!

"""
import os, click, json, random, getpass, qrcode
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

block_size = 32

def aes_encrypt(text, passphrase = None):
    """
    Encrypt text with passphrase
    :param text: The text to be encrypted.
    :param passphrase:
    :return:
    """
    if not passphrase:
        passphrase = getpass.getpass('Enter passphrase: ').encode('utf-8')
        passphrase_cfm = getpass.getpass('Confirm passphrase: ').encode('utf-8')
        if passphrase_cfm != passphrase:
            raise ValueError('Passphrases must match. Be very careful!')
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=block_size, info=None).derive(passphrase)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(hkdf), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encode = 'plain'
    if isinstance(text, bytes):
        text = hexlify(text)
        encode = 'hex'
    r = ''
    while True:
        payload = json.dumps({'t': text, 'r': r, 'e': encode}).encode('utf-8')
        if len(payload) % block_size == 0:
            break
        r = r + chr(random.randrange(57,122))
    ct = encryptor.update(payload) + encryptor.finalize()
    return {
        'iv': hexlify(iv).decode('ascii'),
        'cipher-text': hexlify(ct).decode('ascii'),
        'cipher-algo': algorithms.AES(hkdf).name,
        'cipher-algo-key-size-bits': block_size * 8,
        'cipher-mode': 'CBC',
        'cipher-key-derivation-algo': f'HKDFExpand(algorithm=hashes.SHA256(), length={block_size}, info=None)'
    }

def aes_decrypt(cipher_obj, passphrase = None):
    cipher_text = unhexlify(cipher_obj.get('cipher-text'))
    iv = unhexlify(cipher_obj.get('iv'))
    if not passphrase:
        passphrase = getpass.getpass('Enter passphrase: ').encode('utf-8')
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=block_size, info=None).derive(passphrase)
    cipher = Cipher(algorithms.AES(hkdf), modes.CBC(iv))
    decryptor = cipher.decryptor()
    payload = decryptor.update(cipher_text) + decryptor.finalize()
    try:
        text = json.loads(payload.decode('utf-8')).get('t')
        if json.loads(payload.decode('utf-8')).get('e') == 'hex':
            text = unhexlify(text)
    except Exception as e:
        click.secho('Error occured during parsing the payload. Most likely wrong password!', fg = 'red')
        click.secho(f'({e})', fg = 'white')
        return
    return text

def print_ascii_qr(value, invert = False):
    qr = qrcode.QRCode(border=1)
    qr.add_data(value)
    qr.print_ascii(invert=invert)

if __name__ == '__main__':
    @click.group()
    @click.option('-s', '--stdin', is_flag=True)
    @click.option('-f', '--file', type=click.Path(exists=True,readable=True))
    @click.option('-t', '--text', type=str)
    @click.option('-q', '--qr', is_flag=True)
    @click.option('-i', '--invert', is_flag=True)
    @click.pass_context
    def cli(ctx, stdin, file, text, qr, invert):
        "Encrypt or decrypt file, text or stdin"
        ctx.ensure_object(dict)
        ctx.obj['qr'] = qr
        ctx.obj['invert'] = invert
        if text:
            ctx.obj['input'] = text
            return
        elif file:
            f = open(file,'r')
        elif stdin:
            f = click.get_text_stream('stdin')
        try:
            tt = f.read()
        except:
            tt = click.prompt('Enter the text to be encrypted/decrypted', )
            pass
        ctx.obj['input'] = tt

    @cli.command()
    @click.pass_context
    def encrypt(ctx):
        '''Encrypt string or file'''
        s = json.dumps(aes_encrypt(ctx.obj.get('input')),indent=2)
        if ctx.obj.get('qr'):
            print_ascii_qr(s, ctx.obj['invert'])
        print(s)

    @cli.command()
    @click.pass_context
    def decrypt(ctx):
        '''Decrypt string or file'''
        s = aes_decrypt(json.loads(ctx.obj.get('input').encode('utf-8')))
        if ctx.obj.get('qr'):
            print_ascii_qr(s, ctx.obj['invert'])
        print(s)
    cli()
