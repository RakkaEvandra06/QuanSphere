#!/usr/bin/env python3

import argparse
import base64
import sys
import hmac
from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, SHA512
from Crypto.Signature import pss
from Crypto.Protocol.KDF import PBKDF2

VERSION = "4.0"

MAGIC_HEADER = b"RKY4\x01"
NONCE_SIZE = 16
TAG_SIZE = 16
PBKDF2_ITER = 200000
SALT_SIZE = 16
KEY_SIZE = 32


# ================= UTIL =================

def read_input(path):
    if path == "-":
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def write_output(path, data):
    if path == "-":
        sys.stdout.buffer.write(data)
    else:
        Path(path).write_bytes(data)


def validate_input_data(data, min_size):
    if len(data) < min_size:
        raise ValueError(f"Input data too small. Minimum {min_size} bytes required")


# ================= CORE =================

class ZeroTrace:

    @staticmethod
    def aes_encrypt(data, password=None):
        if not data:
            raise ValueError("Input data is empty")

        if password:
            salt = get_random_bytes(SALT_SIZE)
            key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITER, hmac_hash_module=SHA256)
        else:
            salt = b""
            key = get_random_bytes(KEY_SIZE)

        nonce = get_random_bytes(NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return (
            MAGIC_HEADER +
            salt +
            nonce +
            tag +
            ciphertext
        ), key if not password else None

    @staticmethod
    def aes_decrypt(data, password=None, key_b64=None):
        validate_input_data(data, len(MAGIC_HEADER) + SALT_SIZE + NONCE_SIZE + TAG_SIZE)

        if data[:5] != MAGIC_HEADER:
            raise ValueError("Invalid file format")

        pos = len(MAGIC_HEADER)
        salt = data[pos:pos+SALT_SIZE]
        pos += SALT_SIZE
        nonce = data[pos:pos+NONCE_SIZE]
        pos += NONCE_SIZE
        tag = data[pos:pos+TAG_SIZE]
        pos += TAG_SIZE
        ciphertext = data[pos:]

        if password:
            key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITER, hmac_hash_module=SHA256)
        elif key_b64:
            key = base64.b64decode(key_b64)
        else:
            raise ValueError("Provide password or key")

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
        return cipher.decrypt_and_verify(ciphertext, tag)

    @staticmethod
    def rsa_encrypt(message, pub_file):

        pub = RSA.import_key(read_input(pub_file))

        cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)

        return base64.b64encode(cipher.encrypt(message.encode()))

    @staticmethod
    def rsa_decrypt(ciphertext_b64, priv_file):

        priv = RSA.import_key(read_input(priv_file))

        cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)

        ciphertext = base64.b64decode(ciphertext_b64)

        return cipher.decrypt(ciphertext)

    @staticmethod
    def sign(data, priv_file):

        priv = RSA.import_key(read_input(priv_file))

        h = SHA256.new(data)

        return pss.new(priv).sign(h)

    @staticmethod
    def verify(data, signature, pub_file):

        pub = RSA.import_key(read_input(pub_file))

        h = SHA256.new(data)

        try:
            pss.new(pub).verify(h, signature)
            return True
        except:
            return False


# ================= CLI BANNER =================

def cli_banner():

    banner = r"""
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                        │
│   ███████╗███████╗██████╗  ██████╗ ████████╗██████╗  █████╗  ██████╗███████╗██████╗    │
│   ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗   │
│     ███╔╝ █████╗  ██████╔╝██║   ██║   ██║   ██████╔╝███████║██║     █████╗  ██████╔╝   │
│    ███╔╝  ██╔══╝  ██╔══██╗██║   ██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══██╗   │
│   ███████╗███████╗██║  ██║╚██████╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗██║  ██║   │
│   ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝   │
│                                                                                        │
│                 ZeroTrace v{version} - Crypto Toolkit - Rakka06Evandra                 │
│                                                                                        │
│                 AES-256-GCM | RSA-OAEP | RSA-PSS | PBKDF2 | SHA-256/512                │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
""".format(version=VERSION)

    print(banner)


# ================= CLI =================

def build_parser():

    parser = argparse.ArgumentParser(
        prog="zerotrace",
        description="ZeroTrace v4 - Hardened Unix-style Cryptographic Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )

    sub = parser.add_subparsers(dest="command")

    aes = sub.add_parser("aes")
    aes_sub = aes.add_subparsers(dest="action")

    aes_enc = aes_sub.add_parser("encrypt")
    aes_enc.add_argument("-i","--input",default="-")
    aes_enc.add_argument("-o","--output",default="-")
    aes_enc.add_argument("--password")

    aes_dec = aes_sub.add_parser("decrypt")
    aes_dec.add_argument("-i","--input",default="-")
    aes_dec.add_argument("-o","--output",default="-")
    aes_dec.add_argument("--password")
    aes_dec.add_argument("--key")

    return parser


# ================= MAIN =================

def main():

    try:

        cli_banner()

        parser = build_parser()

        args = parser.parse_args()

        if args.command == "aes":

            if args.action == "encrypt":

                data = read_input(args.input)

                result, key = ZeroTrace.aes_encrypt(data, args.password)

                write_output(args.output, result)

            elif args.action == "decrypt":

                data = read_input(args.input)

                result = ZeroTrace.aes_decrypt(data, args.password, args.key)

                write_output(args.output, result)

        else:

            parser.print_help()

    except KeyboardInterrupt:

        print("\nCancelled", file=sys.stderr)

        sys.exit(130)

    except Exception as e:

        print(f"Error: {e}", file=sys.stderr)

        sys.exit(1)


if __name__ == "__main__":

    main()