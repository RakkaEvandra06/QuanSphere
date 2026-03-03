#!/usr/bin/env python3

import argparse
import base64
from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, SHA512
from Crypto.Signature import pss
from Crypto.Protocol.KDF import PBKDF2

MAGIC_HEADER = b"RKY3\x01"
NONCE_SIZE = 16
TAG_SIZE = 16
PBKDF2_ITER = 200000

class zerotrace:

    # ================= AES =================
    @staticmethod
    def aes_encrypt(input_file, output_file, password=None, save_key=False):
        try:
            data = Path(input_file).read_bytes()

            if password:
                salt = get_random_bytes(16)
                key = PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITER)
            else:
                salt = b""
                key = get_random_bytes(32)

            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data)

            with open(output_file, "wb") as f:
                f.write(MAGIC_HEADER)
                f.write(salt.ljust(16, b"\0"))
                f.write(cipher.nonce)
                f.write(tag)
                f.write(ciphertext)

            if not password and save_key:
                Path(output_file + ".key").write_text(
                    base64.b64encode(key).decode()
                )

            print("[+] AES encryption successful")

        except Exception as e:
            print("[-] AES encryption failed:", e)

    @staticmethod
    def aes_decrypt(input_file, output_file, key_b64=None, password=None):
        try:
            with open(input_file, "rb") as f:
                if f.read(5) != MAGIC_HEADER:
                    raise ValueError("Invalid file format")

                salt = f.read(16).rstrip(b"\0")
                nonce = f.read(NONCE_SIZE)
                tag = f.read(TAG_SIZE)
                ciphertext = f.read()

            if password:
                key = PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITER)
            elif key_b64:
                key = base64.b64decode(key_b64)
            else:
                raise ValueError("Provide password or key")

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            Path(output_file).write_bytes(plaintext)
            print("[+] AES decryption successful")

        except ValueError as e:
            print("[-] Decryption failed:", e)
        except Exception as e:
            print("[-] Unexpected error:", e)

    # ================= RSA =================
    @staticmethod
    def generate_rsa(size=2048):
        key = RSA.generate(size)
        Path("private.pem").write_bytes(key.export_key())
        Path("public.pem").write_bytes(key.publickey().export_key())
        print("[+] RSA key pair generated")

    @staticmethod
    def rsa_encrypt(message, pub_file):
        try:
            pub = RSA.import_key(Path(pub_file).read_bytes())
            cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)

            max_len = pub.size_in_bytes() - 2 * SHA256.digest_size - 2
            if len(message.encode()) > max_len:
                raise ValueError("Message too long for RSA")

            ciphertext = cipher.encrypt(message.encode())
            print(base64.b64encode(ciphertext).decode())

        except Exception as e:
            print("[-] RSA encryption failed:", e)

    @staticmethod
    def rsa_decrypt(ciphertext_b64, priv_file):
        try:
            priv = RSA.import_key(Path(priv_file).read_bytes())
            cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
            plaintext = cipher.decrypt(base64.b64decode(ciphertext_b64))
            print(plaintext.decode())

        except Exception:
            print("[-] RSA decryption failed")

    # ================= HYBRID =================
    @staticmethod
    def hybrid_encrypt(input_file, output_file, pub_file):
        try:
            pub = RSA.import_key(Path(pub_file).read_bytes())
            aes_key = get_random_bytes(32)

            data = Path(input_file).read_bytes()
            cipher_aes = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data)

            cipher_rsa = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
            enc_key = cipher_rsa.encrypt(aes_key)

            with open(output_file, "wb") as f:
                f.write(MAGIC_HEADER)
                f.write(len(enc_key).to_bytes(2, "big"))
                f.write(enc_key)
                f.write(cipher_aes.nonce)
                f.write(tag)
                f.write(ciphertext)

            print("[+] Hybrid encryption successful")

        except Exception as e:
            print("[-] Hybrid encryption failed:", e)

    @staticmethod
    def hybrid_decrypt(input_file, output_file, priv_file):
        try:
            priv = RSA.import_key(Path(priv_file).read_bytes())

            with open(input_file, "rb") as f:
                if f.read(5) != MAGIC_HEADER:
                    raise ValueError("Invalid file format")

                key_len = int.from_bytes(f.read(2), "big")
                enc_key = f.read(key_len)
                nonce = f.read(NONCE_SIZE)
                tag = f.read(TAG_SIZE)
                ciphertext = f.read()

            cipher_rsa = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
            aes_key = cipher_rsa.decrypt(enc_key)

            cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

            Path(output_file).write_bytes(plaintext)
            print("[+] Hybrid decryption successful")

        except Exception:
            print("[-] Hybrid decryption failed")

    # ================= SIGNATURE =================
    @staticmethod
    def sign(file_path, priv_file):
        try:
            priv = RSA.import_key(Path(priv_file).read_bytes())
            data = Path(file_path).read_bytes()

            h = SHA256.new(data)
            signature = pss.new(priv).sign(h)

            Path(file_path + ".sig").write_bytes(signature)
            print("[+] Signature created")

        except Exception as e:
            print("[-] Signing failed:", e)

    @staticmethod
    def verify(file_path, sig_file, pub_file):
        try:
            pub = RSA.import_key(Path(pub_file).read_bytes())
            data = Path(file_path).read_bytes()
            signature = Path(sig_file).read_bytes()

            h = SHA256.new(data)
            pss.new(pub).verify(h, signature)

            print("[+] Signature VALID")

        except Exception:
            print("[-] Signature INVALID")

    # ================= HASH =================
    @staticmethod
    def hash_file(file_path, algo):
        data = Path(file_path).read_bytes()

        if algo == "sha256":
            h = SHA256.new(data)
        else:
            h = SHA512.new(data)

        print(h.hexdigest())


# ================= CLI =================
def main():
    parser = argparse.ArgumentParser(description="ZeroTrace v3 - Hardened Crypto Toolkit - Rakka06Evandra")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("genrsa")

    aes = sub.add_parser("aes")
    aes.add_argument("--encrypt")
    aes.add_argument("--decrypt")
    aes.add_argument("--out")
    aes.add_argument("--key")
    aes.add_argument("--password")
    aes.add_argument("--save-key", action="store_true")

    rsa = sub.add_parser("rsa")
    rsa.add_argument("--encrypt")
    rsa.add_argument("--decrypt")
    rsa.add_argument("--pub")
    rsa.add_argument("--priv")

    hybrid = sub.add_parser("hybrid")
    hybrid.add_argument("--encrypt")
    hybrid.add_argument("--decrypt")
    hybrid.add_argument("--out")
    hybrid.add_argument("--pub")
    hybrid.add_argument("--priv")

    sign = sub.add_parser("sign")
    sign.add_argument("--file")
    sign.add_argument("--verify")
    sign.add_argument("--sig")
    sign.add_argument("--pub")
    sign.add_argument("--priv")

    h = sub.add_parser("hash")
    h.add_argument("--file")
    h.add_argument("--algo", choices=["sha256", "sha512"], required=True)

    args = parser.parse_args()

    if args.cmd == "genrsa":
        zerotrace.generate_rsa()

    elif args.cmd == "aes":
        if args.encrypt and args.out:
            zerotrace.aes_encrypt(args.encrypt, args.out, args.password, args.save_key)
        elif args.decrypt and args.out:
            zerotrace.aes_decrypt(args.decrypt, args.out, args.key, args.password)
        else:
            print("[-] AES requires --encrypt/--decrypt and --out")

    elif args.cmd == "rsa":
        if args.encrypt and args.pub:
            zerotrace.rsa_encrypt(args.encrypt, args.pub)
        elif args.decrypt and args.priv:
            zerotrace.rsa_decrypt(args.decrypt, args.priv)
        else:
            print("[-] RSA requires proper parameters")

    elif args.cmd == "hybrid":
        if args.encrypt and args.out and args.pub:
            zerotrace.hybrid_encrypt(args.encrypt, args.out, args.pub)
        elif args.decrypt and args.out and args.priv:
            zerotrace.hybrid_decrypt(args.decrypt, args.out, args.priv)
        else:
            print("[-] Hybrid requires proper parameters")

    elif args.cmd == "sign":
        if args.file and args.priv:
            zerotrace.sign(args.file, args.priv)
        elif args.verify and args.sig and args.pub:
            zerotrace.verify(args.verify, args.sig, args.pub)
        else:
            print("[-] Sign/Verify parameters invalid")

    elif args.cmd == "hash":
        zerotrace.hash_file(args.file, args.algo)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
