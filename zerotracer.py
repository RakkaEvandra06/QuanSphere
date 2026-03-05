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

    # AES ===============================
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
            raise ValueError("Invalid file format: Incorrect magic header")

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
            try:
                key = base64.b64decode(key_b64)
                if len(key) != KEY_SIZE:
                    raise ValueError(f"Invalid key length. Expected {KEY_SIZE} bytes")
            except Exception as e:
                raise ValueError(f"Invalid base64 key: {e}")
        else:
            raise ValueError("Provide either password or key for decryption")

        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            raise ValueError(f"Decryption failed: {e}. Possible causes: wrong password/key or corrupted data")

    # RSA ===============================
    @staticmethod
    def rsa_encrypt(message, pub_file):
        if not message:
            raise ValueError("Message cannot be empty")

        pub_key_data = read_input(pub_file)
        try:
            pub = RSA.import_key(pub_key_data)
        except Exception as e:
            raise ValueError(f"Invalid public key: {e}")

        if pub.size_in_bits() < 2048:
            raise ValueError("RSA key size too small. Minimum 2048 bits recommended")

        cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
        message_bytes = message.encode('utf-8')

        max_msg_length = (pub.size_in_bytes() - 2 - 2 * SHA256.digest_size)
        if len(message_bytes) > max_msg_length:
            raise ValueError(f"Message too long for this RSA key. Max {max_msg_length} bytes")

        return base64.b64encode(cipher.encrypt(message_bytes))

    @staticmethod
    def rsa_decrypt(ciphertext_b64, priv_file):
        if not ciphertext_b64:
            raise ValueError("Ciphertext cannot be empty")

        priv_key_data = read_input(priv_file)
        try:
            priv = RSA.import_key(priv_key_data)
        except Exception as e:
            raise ValueError(f"Invalid private key: {e}")

        try:
            ciphertext = base64.b64decode(ciphertext_b64)
        except Exception as e:
            raise ValueError(f"Invalid base64 ciphertext: {e}")

        cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
        try:
            return cipher.decrypt(ciphertext)
        except ValueError as e:
            raise ValueError(f"RSA decryption failed: {e}. Possibly wrong key or corrupted data")

    # SIGN ===============================
    @staticmethod
    def sign(data, priv_file):
        if not data:
            raise ValueError("Data to sign cannot be empty")

        priv_key_data = read_input(priv_file)
        try:
            priv = RSA.import_key(priv_key_data)
        except Exception as e:
            raise ValueError(f"Invalid private key: {e}")

        if priv.size_in_bits() < 2048:
            raise ValueError("RSA key size too small. Minimum 2048 bits recommended")

        h = SHA256.new(data)
        return pss.new(priv).sign(h)

    @staticmethod
    def verify(data, signature, pub_file):
        if not data or not signature:
            raise ValueError("Data and signature cannot be empty")

        pub_key_data = read_input(pub_file)
        try:
            pub = RSA.import_key(pub_key_data)
        except Exception as e:
            raise ValueError(f"Invalid public key: {e}")

        h = SHA256.new(data)
        try:
            pss.new(pub).verify(h, signature)
            return True
        except (ValueError, TypeError) as e:
            return False


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

    sub = parser.add_subparsers(dest="command", required=False)

    # AES
    aes = sub.add_parser("aes", help="AES-GCM operations")
    aes_sub = aes.add_subparsers(dest="action", required=True)

    aes_enc = aes_sub.add_parser("encrypt", help="Encrypt data")
    aes_enc.add_argument("-i", "--input", default="-", help="Input file (default: stdin)")
    aes_enc.add_argument("-o", "--output", default="-", help="Output file (default: stdout)")
    aes_enc.add_argument("--password", help="Password for encryption")
    aes_enc.add_argument("--save-key", action="store_true", help="Save generated key to stderr")

    aes_dec = aes_sub.add_parser("decrypt", help="Decrypt data")
    aes_dec.add_argument("-i", "--input", default="-", help="Input file (default: stdin)")
    aes_dec.add_argument("-o", "--output", default="-", help="Output file (default: stdout)")
    aes_dec.add_argument("--password", help="Password for decryption")
    aes_dec.add_argument("--key", help="Base64 encoded key for decryption")

    # RSA
    rsa = sub.add_parser("rsa", help="RSA operations")
    rsa_sub = rsa.add_subparsers(dest="action", required=True)

    rsa_enc = rsa_sub.add_parser("encrypt")
    rsa_enc.add_argument("-m", "--message", required=True, help="Message to encrypt")
    rsa_enc.add_argument("--pub", required=True, help="Public key file")

    rsa_dec = rsa_sub.add_parser("decrypt")
    rsa_dec.add_argument("-c", "--ciphertext", required=True, help="Base64 ciphertext")
    rsa_dec.add_argument("--priv", required=True, help="Private key file")

    # SIGN
    sign = sub.add_parser("sign", help="Digital signature operations")
    sign_sub = sign.add_subparsers(dest="action", required=True)

    sign_create = sign_sub.add_parser("create")
    sign_create.add_argument("-i", "--input", default="-", help="Input file (default: stdin)")
    sign_create.add_argument("--priv", required=True, help="Private key file")

    sign_verify = sign_sub.add_parser("verify")
    sign_verify.add_argument("-i", "--input", default="-", help="Input file (default: stdin)")
    sign_verify.add_argument("--sig", required=True, help="Signature file")
    sign_verify.add_argument("--pub", required=True, help="Public key file")

    return parser


def main():
    try:
        parser = build_parser()
        args = parser.parse_args()

        if args.command == "aes":

            if args.action == "encrypt":
                data = read_input(args.input)
                result, key = ZeroTrace.aes_encrypt(data, args.password)
                write_output(args.output, result)

                if key and args.save_key:
                    print(f"\n[KEY] {base64.b64encode(key).decode()}", file=sys.stderr)

            elif args.action == "decrypt":
                data = read_input(args.input)
                result = ZeroTrace.aes_decrypt(data, args.password, args.key)
                write_output(args.output, result)

        elif args.command == "rsa":

            if args.action == "encrypt":
                result = ZeroTrace.rsa_encrypt(args.message, args.pub)
                sys.stdout.buffer.write(result + b'\n')

            elif args.action == "decrypt":
                result = ZeroTrace.rsa_decrypt(args.ciphertext, args.priv)
                sys.stdout.buffer.write(result)

        elif args.command == "sign":

            if args.action == "create":
                data = read_input(args.input)
                sig = ZeroTrace.sign(data, args.priv)
                sys.stdout.buffer.write(sig)

            elif args.action == "verify":
                data = read_input(args.input)
                signature = read_input(args.sig)
                if ZeroTrace.verify(data, signature, args.pub):
                    print("VALID")
                else:
                    print("INVALID")
                    sys.exit(1)

        else:
            parser.print_help()

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()